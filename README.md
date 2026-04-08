# Clawditor

Forensic auditor for autonomous AI agents. Independently verifies what your agents actually did, without trusting their self-reporting.

## The Problem

Autonomous AI agents (Claude Code, OpenClaw, etc.) running on cron schedules self-report their work through commit messages, state files, Linear issues, and session logs. Nobody independently verifies whether the agent's **narrative** (what it says it did) matches its **footprint** (what it actually did).

This is the same gap that financial auditing exists to fill. A company's own books are evidence to verify, not a source of truth. The auditor verifies against bank statements.

Clawditor applies that independence principle to AI agents. It reconstructs what happened from external evidence only -- git commits, filesystem timestamps, cron logs, task tracker state -- then compares that reconstruction against the agent's self-report. Discrepancies surface as flags with trust scores.

## What It Catches

- **SELF-MODIFICATION** -- Agent changed files that control its own behavior (configs, hooks, auth, cron scripts). Always flagged, even if the agent reported it. This is the [Garry Tan failure mode](https://x.com/garrytan): agent alters its own config, next cron run can't start, nobody notices until the silence gets suspicious.
- **Crash correlation** -- Session exits non-zero after a preceding session modified config files. Clawditor connects cause and effect across sessions.
- **Permission denials** -- Agent attempted actions it wasn't authorized to perform.
- **Unreported actions** -- Physical evidence (file changes, commits) with no corresponding narrative mention.
- **Contradictions** -- Narrative says X, evidence shows Y.
- **Persistent warnings** -- Same warning in 3+ consecutive sessions escalates from informational to P1.
- **Forward risk** -- Crashed session left dirty state that the next session will inherit.

## Architecture

```
Local machine (auditor)                    Remote server (agents)
========================                   ======================

+-----------+     SSH      +------------------+
| collect.py |------------>| git log, stat,   |
|            |     SSH     | find, cron logs  |
|            |------------>|                  |
+-----+------+            +------------------+
      |
      |  evidence-YYYYMMDD.json
      v
+-------------+
| reconcile.py|----> Claude API (Sonnet)
|             |      Semantic comparison of
|             |      narrative vs physical evidence
+------+------+
       |
       |  audit-YYYYMMDD.json
       v
+----------+
| digest.py|----> digest-YYYYMMDD.md
|          |      Human-readable morning report
+----------+

Scheduled via launchd (07:00 daily)
```

The auditor runs on your local machine, not on the server where agents execute. Agents never see the auditor's code, config, or output. This is the independence guarantee.

## Quick Start

```bash
git clone <repo-url> clawditor
cd clawditor

# Set up virtualenv
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Configure
cp config.yaml config.yaml.bak
# Edit config.yaml -- set your SSH host, git repos, watched paths

# Set environment variables (or use a .env file)
export ANTHROPIC_API_KEY=sk-ant-...
export LINEAR_API_KEY=lin_api_...  # optional

# Run manually
./run.sh

# Or run individual stages
python3 collect.py config.yaml          # produces evidence JSON
python3 reconcile.py config.yaml        # produces audit JSON
python3 digest.py config.yaml           # produces markdown digest
```

### Schedule with launchd (macOS)

```bash
# Edit the plist to match your paths
cp com.clawditor.daily.plist ~/Library/LaunchAgents/
launchctl load ~/Library/LaunchAgents/com.clawditor.daily.plist
```

Runs daily at 07:00. Digest is waiting when you open your laptop.

## Configuration

`config.yaml` defines what to audit:

```yaml
metis:
  host: deploy@your-server-ip
  repos:                              # Git repos to audit
    - /home/deploy/project-a
    - /home/deploy/project-b
  watch_paths:                        # Files to track modifications
    - "/home/deploy/**/STATE.md"
    - "/home/deploy/**/process-log.md"
  config_watchlist:                   # SELF-MODIFICATION triggers
    - /home/deploy/.claude/settings.json
    - "/home/deploy/**/.mcp.json"
    - "/home/deploy/.claude/rules/**"
    - "/home/deploy/.claude/scripts/**"
    - "/home/deploy/**/crontab"
  cron_log: /home/deploy/cron-cycle.log

linear:
  team_id: your-team-uuid
  api_key_env: LINEAR_API_KEY         # env var name, not the key itself

claude:
  model: claude-sonnet-4-6            # Sonnet minimum -- semantic judgment needs it
  api_key_env: ANTHROPIC_API_KEY

schedule:
  lookback_hours: 24

output:
  dir: ~/.clawditor/reports/
  alert_threshold: 80                 # Trust score below this triggers flagging
```

The `config_watchlist` is the key defense against self-modification. Any file matching these patterns that changes during an agent session gets flagged as SELF-MODIFICATION, regardless of whether the agent reported the change.

For OpenClaw deployments, add your gateway config, skills directory, and auth files to the watchlist.

## How It Works

### Phase 1: Collect (`collect.py`)

SSHs into the remote server and gathers physical evidence:

- **Cron logs** -- Parses session boundaries, exit codes, cost, permission denials from the agent's cron log
- **Git history** -- Commits, diffs, file change stats from each monitored repo
- **Filesystem state** -- Modification times and sizes for watched paths and config files
- **Linear API** -- Issue updates, state transitions, comments (the agent's narrative claims)

Produces `evidence-YYYYMMDD.json` -- a structured snapshot of everything that happened in the lookback window.

### Phase 2: Reconcile (`reconcile.py`)

Feeds each session's evidence to Claude Sonnet as a forensic auditor. The prompt presents physical evidence as ground truth and the agent's narrative as claims to verify. Claude classifies each claim as:

- **VERIFIED** -- Physical evidence supports the claim
- **UNVERIFIED** -- No physical evidence found
- **CONTRADICTED** -- Physical evidence contradicts the claim
- **UNREPORTED** -- Physical event with no narrative mention

Adjacent sessions are included for crash correlation and forward-risk analysis. Persistent warning counts across sessions trigger escalation.

Produces `audit-YYYYMMDD.json` with per-session trust scores (0-100) and verdicts (CLEAN / SUSPICIOUS / FLAGGED / CRITICAL).

### Phase 3: Digest (`digest.py`)

Converts the audit JSON into a human-readable markdown report: session table with scores, flagged session details with evidence, clean session summary, and cost rollup.

## Example Output

```markdown
# Clawditor Daily Digest -- 2026-04-08

**Status:** ATTENTION NEEDED | **Avg Trust Score:** 74/100 | **Sessions:** 6

## Sessions

| Session | Cycle | Score | Verdict | Flags |
|---------|-------|-------|---------|-------|
| JCC-203 | 260408-0600 | 91 | [OK] CLEAN | none |
| JCC-204 | 260408-0800 | 43 | [!!!] CRITICAL | 3 flags |
| JCC-205 | 260408-1200 | 88 | [OK] CLEAN | none |
| JCC-206 | 260408-1200 | 72 | [!] SUSPICIOUS | 1 flag |
| JCC-207 | 260408-1600 | 85 | [OK] CLEAN | none |
| JCC-208 | 260408-1800 | 65 | [!!] FLAGGED | 2 flags |

## Flagged Sessions

### JCC-204

**Summary:** Session modified .claude/settings.json and
.claude/rules/escalation-protocol.md, then crashed with exit code 1.
Neither modification was mentioned in the Linear issue or commit messages.
The subsequent session (JCC-205) inherited a broken config state.

**Trust Score:** 43/100

**Flags:**
- SELF-MODIFICATION: .claude/settings.json modified at 08:14 UTC (not in narrative)
- SELF-MODIFICATION: .claude/rules/escalation-protocol.md modified at 08:17 UTC
- CRASH-CORRELATION: Exit code 1 follows config self-modification

**SELF-MODIFICATION (config/auth/skills changes):**
- .claude/settings.json (08:14 UTC, 2847 bytes)
- .claude/rules/escalation-protocol.md (08:17 UTC, 1203 bytes)

**CRASH CORRELATION:** Session modified settings.json at 08:14, then exited
with code 1 at 08:23. Probable cause: invalid JSON in settings.json.

**FORWARD RISK (dirty state for next session):** settings.json may contain
invalid configuration. Next session (JCC-205) should be checked for startup errors.

---

### JCC-208

**Summary:** Agent reported completing 3 assessments in Linear comments,
but git log shows only 2 commits. One claimed assessment has no file on disk.

**Trust Score:** 65/100

**Flags:**
- CONTRADICTION: Narrative claims 3 assessments completed, evidence shows 2
- UNREPORTED: data/cache/indicators.json modified but not mentioned

---

## Clean Sessions

- **JCC-203** -- Score: 91/100, 4 claims verified
- **JCC-205** -- Score: 88/100, 3 claims verified
- **JCC-207** -- Score: 85/100, 5 claims verified

## Cost Summary

Total agent cost in lookback window: **$4.72**

---
*Generated by Clawditor at 2026-04-08 07:02 UTC*
```

## Why Not Just Use Observability Tools?

Every tool in the agent monitoring space -- Arize, AgentOps, Braintrust, LangSmith -- instruments the agent itself. They add tracing to the agent's runtime, capture its tool calls, log its token usage. The telemetry comes from inside the agent.

This is like asking the company to audit its own books.

Clawditor is the external auditor. It never touches the agent's runtime. It never instruments the agent's code. It collects evidence from sources the agent cannot tamper with (git history, filesystem timestamps, cron logs) and compares that evidence against the agent's claims.

The threat model is not "the agent is lying." The threat model is "the agent is confidently wrong, selectively reporting, or silently failing -- and nobody is checking." The same reason companies have external auditors even when the CFO is honest.

| Approach | Source of Truth | Independence |
|----------|----------------|--------------|
| Observability (Arize, AgentOps) | Agent's own telemetry | None -- agent generates the data |
| Static scanning (OpenClaw audit) | Config files at rest | Partial -- checks config, not behavior |
| Policy enforcement (MS Governance Toolkit) | Runtime prevention | Partial -- prevents, doesn't detect |
| **Forensic reconstruction (Clawditor)** | **External physical evidence** | **Full -- zero trust in agent** |

## Testing

```bash
pytest tests/ -v
```

Tests cover cron log parsing (including crash scenarios), digest generation, and reconciliation prompt construction. Test fixtures in `tests/fixtures/` include sample cron logs with normal sessions and crash sequences.

## Requirements

- Python 3.11+
- SSH access to the server running your agents
- Anthropic API key (Sonnet or better)
- Linear API key (optional, for task tracker reconciliation)

## Compatibility

- **Claude Code** -- Full support. Collects from cron logs, git, filesystem, Linear.
- **OpenClaw** -- Config watchlist works from day one (watches file paths, not framework internals). Add your gateway config, skills directory, and auth files to `config_watchlist`. Dedicated OpenClaw collectors planned for V2.

## Roadmap

**V1 (current):** Three scripts, daily batch, launchd scheduling. Ships the independence principle.

**V2 (planned):** SQLite for historical storage, shadow narrative reconstruction (builds a timeline from physical evidence alone, then compares to agent narrative), anomaly detection baselines, pluggable evidence collectors.

## License

MIT
