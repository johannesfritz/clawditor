#!/usr/bin/env python3
"""Clawditor Digest Generator.

Reads audit JSON and produces a human-readable markdown digest.
"""

import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml


def load_config(path: str = "config.yaml") -> dict:
    with open(path) as f:
        raw = f.read()
    def _resolve(m: re.Match) -> str:
        return os.environ.get(m.group(1), m.group(0))
    raw = re.sub(r"\$\{(\w+)\}", _resolve, raw)
    return yaml.safe_load(raw)


def verdict_emoji(verdict: str) -> str:
    return {
        "CLEAN": "[OK]",
        "SUSPICIOUS": "[!]",
        "FLAGGED": "[!!]",
        "CRITICAL": "[!!!]",
        "PARSE_ERROR": "[ERR]",
        "API_ERROR": "[ERR]",
    }.get(verdict, "[?]")


def generate_digest(audit: dict, config: dict) -> str:
    """Generate markdown digest from audit results."""
    lines = []
    threshold = config["output"].get("alert_threshold", 80)
    date_str = datetime.now().strftime("%Y-%m-%d")

    lines.append(f"# Clawditor Daily Digest — {date_str}")
    lines.append("")

    # Status header
    status = audit.get("status", "UNKNOWN")
    avg_score = audit.get("average_trust_score", -1)
    session_count = audit.get("session_count", 0)

    if status == "NO_SESSIONS":
        lines.append("**No agent sessions detected in the lookback window.**")
        lines.append("")
        lines.append("This is expected on weekends/holidays, or unexpected if cron should have fired.")
        lines.append("Check `cron-cycle.log` on Metis if cron was supposed to run.")
        return "\n".join(lines)

    if status == "INCOMPLETE":
        lines.append(f"**AUDIT INCOMPLETE:** {audit.get('error', 'Unknown error')}")
        lines.append("")
        lines.append("Raw evidence was saved. Reconciliation could not run.")
        return "\n".join(lines)

    score_label = "CLEAN" if avg_score >= 90 else "OK" if avg_score >= threshold else "ATTENTION NEEDED" if avg_score >= 50 else "CRITICAL"
    lines.append(f"**Status:** {score_label} | **Avg Trust Score:** {avg_score}/100 | **Sessions:** {session_count}")
    lines.append("")

    # Session table
    lines.append("## Sessions")
    lines.append("")
    lines.append("| Session | Cycle | Score | Verdict | Flags |")
    lines.append("|---------|-------|-------|---------|-------|")

    flagged_sessions = []
    for s in audit.get("sessions", []):
        sid = s.get("session_id", "?")
        cycle = s.get("cycle_id", sid)
        score = s.get("trust_score", -1)
        verdict = s.get("verdict", "?")
        flags = s.get("flags", [])
        flag_count = len(flags)
        emoji = verdict_emoji(verdict)

        score_str = str(score) if score >= 0 else "ERR"
        flag_str = f"{flag_count} flag{'s' if flag_count != 1 else ''}" if flag_count else "none"

        lines.append(f"| {sid} | {cycle} | {score_str} | {emoji} {verdict} | {flag_str} |")

        if score < threshold or flags:
            flagged_sessions.append(s)

    lines.append("")

    # Flagged sessions detail
    if flagged_sessions:
        lines.append("## Flagged Sessions")
        lines.append("")

        for s in flagged_sessions:
            sid = s.get("session_id", "?")
            lines.append(f"### {sid}")
            lines.append("")

            # Summary
            if s.get("summary"):
                lines.append(f"**Summary:** {s['summary']}")
                lines.append("")

            # Trust score breakdown
            score = s.get("trust_score", -1)
            if score >= 0:
                lines.append(f"**Trust Score:** {score}/100")
                lines.append("")

            # Flags
            flags = s.get("flags", [])
            if flags:
                lines.append("**Flags:**")
                for f in flags:
                    lines.append(f"- {f}")
                lines.append("")

            # Contradictions
            contradicted = s.get("contradicted", [])
            if contradicted:
                lines.append("**CONTRADICTED (narrative says X, evidence shows Y):**")
                for c in contradicted:
                    lines.append(f"- {c}")
                lines.append("")

            # Unreported
            unreported = s.get("unreported", [])
            if unreported:
                lines.append("**UNREPORTED (physical events not in narrative):**")
                for u in unreported:
                    lines.append(f"- {u}")
                lines.append("")

            # Self-modifications
            self_mods = s.get("self_modifications", [])
            if self_mods:
                lines.append("**SELF-MODIFICATION (config/auth/skills changes):**")
                for m in self_mods:
                    lines.append(f"- {m}")
                lines.append("")

            # Permission denials
            if s.get("permission_denials_flag"):
                lines.append("**PERMISSION DENIALS:** Agent attempted unauthorized actions.")
                lines.append("")

            # Crash correlation
            if s.get("crash_correlation"):
                lines.append(f"**CRASH CORRELATION:** {s['crash_correlation']}")
                lines.append("")

            # Forward risk
            if s.get("forward_risk"):
                lines.append(f"**FORWARD RISK (dirty state for next session):** {s['forward_risk']}")
                lines.append("")

            # Warning escalations
            escalations = s.get("warning_escalations", [])
            if escalations:
                lines.append("**WARNING ESCALATIONS (P1, 3+ consecutive):**")
                for e in escalations:
                    lines.append(f"- {e}")
                lines.append("")

            # Unverified claims
            unverified = s.get("unverified", [])
            if unverified:
                lines.append("**UNVERIFIED (claims without physical evidence):**")
                for u in unverified:
                    lines.append(f"- {u}")
                lines.append("")

            lines.append("---")
            lines.append("")

    # Clean sessions summary
    clean = [s for s in audit.get("sessions", []) if s not in flagged_sessions]
    if clean:
        lines.append("## Clean Sessions")
        lines.append("")
        for s in clean:
            sid = s.get("session_id", "?")
            score = s.get("trust_score", -1)
            verified_count = len(s.get("verified", []))
            lines.append(f"- **{sid}** — Score: {score}/100, {verified_count} claims verified")
        lines.append("")

    # Cost summary
    total_cost = sum(
        s.get("cost_usd", 0) or 0
        for s in audit.get("sessions", [])
        if isinstance(s.get("cost_usd"), (int, float))
    )
    if total_cost > 0:
        lines.append(f"## Cost Summary")
        lines.append("")
        lines.append(f"Total agent cost in lookback window: **${total_cost:.2f}**")
        lines.append("")

    # Footer
    lines.append("---")
    lines.append(f"*Generated by Clawditor at {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}*")

    return "\n".join(lines)


def main():
    config_path = sys.argv[1] if len(sys.argv) > 1 else "config.yaml"
    audit_path = sys.argv[2] if len(sys.argv) > 2 else None
    config = load_config(config_path)

    # Read audit from file or stdin
    if audit_path:
        with open(audit_path) as f:
            audit = json.load(f)
    else:
        audit = json.load(sys.stdin)

    digest = generate_digest(audit, config)

    # Write output
    output_dir = Path(config["output"]["dir"]).expanduser()
    output_dir.mkdir(parents=True, exist_ok=True)
    date_str = datetime.now().strftime("%Y%m%d")
    output_path = output_dir / f"digest-{date_str}.md"

    with open(output_path, "w") as f:
        f.write(digest)

    print(f"Digest written to {output_path}", file=sys.stderr)

    # Also print to stdout
    print(digest)


if __name__ == "__main__":
    main()
