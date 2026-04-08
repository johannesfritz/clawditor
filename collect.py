#!/usr/bin/env python3
"""Clawditor Evidence Collector.

SSHs into Metis, collects git logs, filesystem state, cron logs,
and queries Linear API. Produces evidence-YYYYMMDD.json.
"""

import json
import os
import re
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from fnmatch import fnmatch
from pathlib import Path

import requests
import yaml


def load_config(path: str = "config.yaml") -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


def ssh_command(host: str, cmd: str, timeout: int = 30, retries: int = 2) -> str | None:
    """Run a command on the remote host via SSH. Returns stdout or None on failure."""
    for attempt in range(retries + 1):
        try:
            result = subprocess.run(
                ["ssh", "-o", "ConnectTimeout=10", "-o", "BatchMode=yes", host, cmd],
                capture_output=True, text=True, timeout=timeout
            )
            if result.returncode == 0:
                return result.stdout
            if attempt < retries:
                import time
                time.sleep(30)
        except subprocess.TimeoutExpired:
            if attempt < retries:
                import time
                time.sleep(30)
    return None


def parse_cron_log(log_text: str, since: datetime) -> list[dict]:
    """Parse cron-cycle.log into session records.

    Each session is bounded by:
      [TIMESTAMP] === Cron cycle YYMMDD-HHMM started ... ===
      [TIMESTAMP] === Cron cycle YYMMDD-HHMM finished (exit N) ===
    With a JSON blob from Claude CLI between them.
    """
    sessions = []
    lines = log_text.split("\n")

    start_re = re.compile(
        r"\[(\d{4}-\d{2}-\d{2}T[\d:]+Z)\] === Cron cycle (\S+) started"
    )
    finish_re = re.compile(
        r"\[(\d{4}-\d{2}-\d{2}T[\d:]+Z)\] === Cron cycle (\S+) finished \(exit (\d+)\)"
    )
    warn_re = re.compile(r"WARN: (.+)$")

    i = 0
    while i < len(lines):
        start_match = start_re.search(lines[i])
        if not start_match:
            i += 1
            continue

        start_ts = datetime.fromisoformat(start_match.group(1).replace("Z", "+00:00"))
        cycle_id = start_match.group(2)

        if start_ts < since:
            i += 1
            continue

        session: dict = {
            "cycle_id": cycle_id,
            "cron_start": start_ts.isoformat(),
            "cron_end": None,
            "cron_exit_code": None,
            "warnings": [],
            "cli_result": None,
            "session_id": None,
            "cost_usd": None,
            "permission_denials": [],
            "model_usage": None,
        }

        # Scan lines until we find the finish marker
        i += 1
        json_lines: list[str] = []
        in_json = False
        while i < len(lines):
            finish_match = finish_re.search(lines[i])
            if finish_match:
                session["cron_end"] = datetime.fromisoformat(
                    finish_match.group(1).replace("Z", "+00:00")
                ).isoformat()
                session["cron_exit_code"] = int(finish_match.group(3))
                i += 1
                break

            warn_match = warn_re.search(lines[i])
            if warn_match:
                session["warnings"].append(warn_match.group(1))

            line = lines[i].strip()
            if line.startswith("{") and not in_json:
                in_json = True
                json_lines = [line]
                # Try parsing immediately (single-line JSON blobs)
                try:
                    blob = json.loads(line)
                    in_json = False
                    session["cli_result"] = blob.get("result", "")
                    session["session_id"] = blob.get("session_id")
                    session["cost_usd"] = blob.get("total_cost_usd")
                    session["permission_denials"] = blob.get("permission_denials", [])
                    session["model_usage"] = blob.get("modelUsage")
                except json.JSONDecodeError:
                    pass  # multi-line JSON, keep accumulating
            elif in_json:
                json_lines.append(line)
                try:
                    blob = json.loads("\n".join(json_lines))
                    in_json = False
                    session["cli_result"] = blob.get("result", "")
                    session["session_id"] = blob.get("session_id")
                    session["cost_usd"] = blob.get("total_cost_usd")
                    session["permission_denials"] = blob.get("permission_denials", [])
                    session["model_usage"] = blob.get("modelUsage")
                except json.JSONDecodeError:
                    pass  # keep accumulating

            i += 1
        else:
            # Reached end of log without finish marker — incomplete session
            session["cron_exit_code"] = -1

        sessions.append(session)

    return sessions


def collect_git_evidence(
    host: str, repos: list[str], since: datetime, until: datetime
) -> list[dict]:
    """Collect git commits from each repo in the time window."""
    all_events = []
    since_str = since.strftime("%Y-%m-%dT%H:%M:%S")
    until_str = until.strftime("%Y-%m-%dT%H:%M:%S")

    for repo in repos:
        cmd = (
            f"cd {repo} 2>/dev/null && "
            f"git log --after='{since_str}' --before='{until_str}' "
            f"--format='COMMIT_START%n%H%n%aI%n%an <%ae>%n%s%nCOMMIT_END' "
            f"--stat"
        )
        output = ssh_command(host, cmd, timeout=60)
        if output is None:
            continue

        repo_name = repo.rstrip("/").split("/")[-1]
        commits = parse_git_log(output, repo_name)
        all_events.extend(commits)

    return all_events


def parse_git_log(output: str, repo_name: str) -> list[dict]:
    """Parse git log output into structured commit records."""
    commits = []
    blocks = output.split("COMMIT_START\n")

    for block in blocks[1:]:  # skip first empty
        end_idx = block.find("COMMIT_END")
        if end_idx == -1:
            continue
        header = block[:end_idx].strip()
        stat_section = block[end_idx + len("COMMIT_END"):].strip()

        header_lines = header.split("\n")
        if len(header_lines) < 4:
            continue

        # Parse stat section for files changed, insertions, deletions
        files_changed = []
        insertions = 0
        deletions = 0
        for stat_line in stat_section.split("\n"):
            stat_line = stat_line.strip()
            if "|" in stat_line and stat_line[0] != " ":
                fname = stat_line.split("|")[0].strip()
                if fname:
                    files_changed.append(fname)
            summary_match = re.search(
                r"(\d+) files? changed(?:, (\d+) insertions?\(\+\))?(?:, (\d+) deletions?\(-\))?",
                stat_line
            )
            if summary_match:
                insertions = int(summary_match.group(2) or 0)
                deletions = int(summary_match.group(3) or 0)

        commits.append({
            "repo": repo_name,
            "hash": header_lines[0],
            "timestamp": header_lines[1],
            "author": header_lines[2],
            "message": header_lines[3],
            "files_changed": files_changed,
            "insertions": insertions,
            "deletions": deletions,
        })

    return commits


def collect_filesystem_evidence(
    host: str, watch_paths: list[str], config_watchlist: list[str],
    since: datetime
) -> tuple[list[dict], list[dict]]:
    """Check for recently modified files matching watch_paths and config_watchlist."""
    since_str = since.strftime("%Y%m%d%H%M")

    watched = []
    for pattern in watch_paths:
        # Use find with -newer workaround via touch
        base_dir = pattern.rsplit("/", 1)[0] if "/" in pattern else "."
        name_pattern = pattern.rsplit("/", 1)[-1] if "/" in pattern else pattern
        cmd = (
            f"find {base_dir} -name '{name_pattern}' "
            f"-newermt '{since.strftime('%Y-%m-%d %H:%M')}' "
            f"-type f 2>/dev/null | head -50"
        )
        output = ssh_command(host, cmd, timeout=30)
        if output:
            for fpath in output.strip().split("\n"):
                if fpath:
                    # Get stat info
                    stat_out = ssh_command(host, f"stat -c '%Y %s' '{fpath}' 2>/dev/null")
                    if stat_out:
                        parts = stat_out.strip().split()
                        if len(parts) == 2:
                            watched.append({
                                "path": fpath,
                                "mtime": datetime.fromtimestamp(
                                    int(parts[0]), tz=timezone.utc
                                ).isoformat(),
                                "size_bytes": int(parts[1]),
                            })

    self_mods = []
    for pattern in config_watchlist:
        if "**" in pattern or "*" in pattern:
            base_dir = pattern.split("*")[0].rstrip("/") or "/"
            cmd = (
                f"find {base_dir} -type f "
                f"-newermt '{since.strftime('%Y-%m-%d %H:%M')}' "
                f"2>/dev/null | head -50"
            )
            output = ssh_command(host, cmd, timeout=30)
            if output:
                for fpath in output.strip().split("\n"):
                    if fpath and fnmatch(fpath, pattern):
                        stat_out = ssh_command(host, f"stat -c '%Y %s' '{fpath}' 2>/dev/null")
                        if stat_out:
                            parts = stat_out.strip().split()
                            if len(parts) == 2:
                                self_mods.append({
                                    "path": fpath,
                                    "mtime": datetime.fromtimestamp(
                                        int(parts[0]), tz=timezone.utc
                                    ).isoformat(),
                                    "size_bytes": int(parts[1]),
                                    "category": "SELF-MODIFICATION",
                                })
        else:
            cmd = (
                f"test -f '{pattern}' && "
                f"stat -c '%Y %s' '{pattern}' 2>/dev/null"
            )
            output = ssh_command(host, cmd, timeout=15)
            if output:
                parts = output.strip().split()
                if len(parts) == 2:
                    mtime = datetime.fromtimestamp(int(parts[0]), tz=timezone.utc)
                    if mtime >= since:
                        self_mods.append({
                            "path": pattern,
                            "mtime": mtime.isoformat(),
                            "size_bytes": int(parts[1]),
                            "category": "SELF-MODIFICATION",
                        })

    return watched, self_mods


def collect_linear_evidence(
    team_id: str, api_key: str, since: datetime
) -> list[dict]:
    """Query Linear API for issues updated in the time window."""
    query = """
    query($teamId: String!, $after: DateTime!) {
      issues(
        filter: {
          team: { id: { eq: $teamId } }
          updatedAt: { gte: $after }
        }
        first: 50
        orderBy: updatedAt
      ) {
        nodes {
          id
          identifier
          title
          state { name }
          updatedAt
          comments {
            nodes {
              body
              createdAt
            }
          }
          history(first: 20) {
            nodes {
              fromState { name }
              toState { name }
              createdAt
            }
          }
        }
      }
    }
    """

    try:
        resp = requests.post(
            "https://api.linear.app/graphql",
            json={
                "query": query,
                "variables": {
                    "teamId": team_id,
                    "after": since.isoformat(),
                },
            },
            headers={
                "Authorization": api_key,
                "Content-Type": "application/json",
            },
            timeout=30,
        )

        if resp.status_code == 429:
            import time
            for delay in [1, 2, 4]:
                time.sleep(delay)
                resp = requests.post(
                    "https://api.linear.app/graphql",
                    json={"query": query, "variables": {"teamId": team_id, "after": since.isoformat()}},
                    headers={"Authorization": api_key, "Content-Type": "application/json"},
                    timeout=30,
                )
                if resp.status_code != 429:
                    break

        if resp.status_code == 401:
            print("WARNING: Linear API auth failed (401). Skipping Linear evidence.", file=sys.stderr)
            return []

        resp.raise_for_status()
        data = resp.json()

        issues = data.get("data", {}).get("issues", {}).get("nodes", [])
        results = []
        for issue in issues:
            transitions = []
            for h in issue.get("history", {}).get("nodes", []):
                if h.get("fromState") and h.get("toState"):
                    transitions.append({
                        "from": h["fromState"]["name"],
                        "to": h["toState"]["name"],
                        "at": h["createdAt"],
                    })

            comments = [
                c["body"] for c in issue.get("comments", {}).get("nodes", [])
            ]

            results.append({
                "issue_id": issue["identifier"],
                "title": issue["title"],
                "state": issue.get("state", {}).get("name", "Unknown"),
                "updated_at": issue["updatedAt"],
                "state_transitions": transitions,
                "comments": comments,
            })

        return results

    except requests.RequestException as e:
        print(f"WARNING: Linear API error: {e}. Skipping Linear evidence.", file=sys.stderr)
        return []


def build_evidence(config: dict, lookback_hours: int | None = None) -> dict:
    """Main evidence collection pipeline."""
    hours = lookback_hours or config["schedule"]["lookback_hours"]
    now = datetime.now(timezone.utc)
    since = now - timedelta(hours=hours)

    host = config["metis"]["host"]
    evidence: dict = {
        "collected_at": now.isoformat(),
        "lookback_hours": hours,
        "ssh_status": "ok",
        "linear_status": "ok",
        "sessions": [],
    }

    # 1. Collect cron log
    print("Collecting cron log...", file=sys.stderr)
    cron_log = ssh_command(host, f"cat {config['metis']['cron_log']}", timeout=60)
    if cron_log is None:
        evidence["ssh_status"] = "unreachable"
        print("ERROR: SSH unreachable after retries.", file=sys.stderr)
        return evidence

    sessions = parse_cron_log(cron_log, since)

    # 2. Collect git evidence
    print(f"Collecting git evidence from {len(config['metis']['repos'])} repos...", file=sys.stderr)
    git_events = collect_git_evidence(host, config["metis"]["repos"], since, now)

    # 3. Collect filesystem evidence
    print("Collecting filesystem evidence...", file=sys.stderr)
    fs_watched, fs_self_mods = collect_filesystem_evidence(
        host,
        config["metis"].get("watch_paths", []),
        config["metis"].get("config_watchlist", []),
        since,
    )

    # 4. Collect Linear evidence
    linear_api_key = os.environ.get(config["linear"]["api_key_env"], "")
    linear_events = []
    if linear_api_key:
        print("Collecting Linear evidence...", file=sys.stderr)
        linear_events = collect_linear_evidence(
            config["linear"]["team_id"], linear_api_key, since
        )
        if not linear_events:
            evidence["linear_status"] = "partial"
    else:
        print("WARNING: No LINEAR_API_KEY set. Skipping Linear evidence.", file=sys.stderr)
        evidence["linear_status"] = "unavailable"

    # 5. Assemble per-session evidence
    for session in sessions:
        session_start = datetime.fromisoformat(session["cron_start"])
        session_end = (
            datetime.fromisoformat(session["cron_end"])
            if session["cron_end"]
            else session_start + timedelta(hours=4)
        )

        # Filter git events to this session's window
        session_git = [
            e for e in git_events
            if session_start <= datetime.fromisoformat(e["timestamp"]) <= session_end
        ]

        # Filter filesystem events to this session's window
        session_fs = [
            e for e in fs_watched
            if session_start <= datetime.fromisoformat(e["mtime"]) <= session_end
        ]

        session_self_mods = [
            e for e in fs_self_mods
            if session_start <= datetime.fromisoformat(e["mtime"]) <= session_end
        ]

        # Match Linear events by timestamp proximity
        session_linear = [
            e for e in linear_events
            if session_start - timedelta(minutes=5)
            <= datetime.fromisoformat(e["updated_at"])
            <= session_end + timedelta(minutes=5)
        ]

        evidence["sessions"].append({
            "session_id": session.get("session_id") or session["cycle_id"],
            "cycle_id": session["cycle_id"],
            "cron_start": session["cron_start"],
            "cron_end": session["cron_end"],
            "cron_exit_code": session["cron_exit_code"],
            "cost_usd": session["cost_usd"],
            "warnings": session["warnings"],
            "permission_denials": session["permission_denials"],
            "cli_result": session["cli_result"],
            "git_events": session_git,
            "filesystem_events": session_fs,
            "self_modifications": session_self_mods,
            "linear_events": session_linear,
        })

    return evidence


def main():
    config_path = sys.argv[1] if len(sys.argv) > 1 else "config.yaml"
    config = load_config(config_path)

    lookback = int(sys.argv[2]) if len(sys.argv) > 2 else None

    evidence = build_evidence(config, lookback)

    # Write output
    output_dir = Path(config["output"]["dir"]).expanduser()
    output_dir.mkdir(parents=True, exist_ok=True)
    date_str = datetime.now().strftime("%Y%m%d")
    output_path = output_dir / f"evidence-{date_str}.json"

    with open(output_path, "w") as f:
        json.dump(evidence, f, indent=2, default=str)

    print(f"Evidence written to {output_path}", file=sys.stderr)
    print(f"Sessions found: {len(evidence['sessions'])}", file=sys.stderr)

    # Also write to stdout for piping
    json.dump(evidence, sys.stdout, indent=2, default=str)


if __name__ == "__main__":
    main()
