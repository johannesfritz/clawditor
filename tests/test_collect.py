"""Tests for collect.py — cron log parsing, git log parsing, evidence assembly."""

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

# Add parent to path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from collect import (
    parse_cron_log,
    parse_git_log,
    collect_linear_evidence,
    build_evidence,
    load_config,
    ssh_command,
)

FIXTURES = Path(__file__).parent / "fixtures"


# --- Cron log parsing ---

class TestParseCronLog:
    def setup_method(self):
        self.log_text = (FIXTURES / "cron-log-sample.txt").read_text()
        self.since = datetime(2026, 4, 7, 0, 0, tzinfo=timezone.utc)

    def test_extracts_three_sessions(self):
        sessions = parse_cron_log(self.log_text, self.since)
        assert len(sessions) == 3

    def test_session_boundaries(self):
        sessions = parse_cron_log(self.log_text, self.since)
        first = sessions[0]
        assert first["cycle_id"] == "260407-0600"
        assert "2026-04-07T04:00:01" in first["cron_start"]
        assert "2026-04-07T04:29:43" in first["cron_end"]
        assert first["cron_exit_code"] == 0

    def test_extracts_session_id_from_json(self):
        sessions = parse_cron_log(self.log_text, self.since)
        assert sessions[0]["session_id"] == "38f4c862-c774-4db3-b457-d39f4896b7d6"
        assert sessions[1]["session_id"] == "da986d07-10dc-427f-9d3c-93acd309c264"

    def test_extracts_cost(self):
        sessions = parse_cron_log(self.log_text, self.since)
        assert sessions[0]["cost_usd"] == 27.05
        assert sessions[1]["cost_usd"] == 21.96

    def test_extracts_warnings(self):
        sessions = parse_cron_log(self.log_text, self.since)
        # First two sessions have WARN, third does not
        assert len(sessions[0]["warnings"]) == 1
        assert "ff-only pull failed" in sessions[0]["warnings"][0]
        assert len(sessions[2]["warnings"]) == 0

    def test_extracts_permission_denials(self):
        sessions = parse_cron_log(self.log_text, self.since)
        # Third session has a permission denial
        assert len(sessions[2]["permission_denials"]) == 1
        assert "rm -rf" in sessions[2]["permission_denials"][0]
        # First two have empty arrays
        assert sessions[0]["permission_denials"] == []

    def test_extracts_cli_result(self):
        sessions = parse_cron_log(self.log_text, self.since)
        assert "finished" in sessions[0]["cli_result"].lower()

    def test_extracts_model_usage(self):
        sessions = parse_cron_log(self.log_text, self.since)
        assert sessions[0]["model_usage"] is not None
        assert "claude-opus-4-6" in sessions[0]["model_usage"]

    def test_filters_by_since(self):
        # Only sessions after April 7 12:00 UTC
        since = datetime(2026, 4, 7, 12, 0, tzinfo=timezone.utc)
        sessions = parse_cron_log(self.log_text, since)
        assert len(sessions) == 1
        assert sessions[0]["cycle_id"] == "260407-1800"

    def test_empty_log(self):
        sessions = parse_cron_log("", self.since)
        assert sessions == []

    def test_malformed_json_graceful(self):
        """If JSON blob is truncated, session is still extracted with None fields."""
        malformed = (
            "[2026-04-07T04:00:01Z] === Cron cycle 260407-0600 started (full=true) ===\n"
            '{"type":"result","subtype":"success","is_error":false\n'
            "[2026-04-07T04:29:43Z] === Cron cycle 260407-0600 finished (exit 0) ===\n"
        )
        sessions = parse_cron_log(malformed, self.since)
        assert len(sessions) == 1
        assert sessions[0]["session_id"] is None  # JSON didn't parse
        assert sessions[0]["cron_exit_code"] == 0  # but boundaries worked

    def test_crash_session(self):
        crash_log = (FIXTURES / "cron-log-crash.txt").read_text()
        sessions = parse_cron_log(crash_log, self.since)
        assert len(sessions) == 1
        assert sessions[0]["cron_exit_code"] == 1

    def test_incomplete_session_no_finish(self):
        """Session started but no finish marker — still extracted."""
        incomplete = (
            "[2026-04-07T04:00:01Z] === Cron cycle 260407-0600 started (full=true) ===\n"
            "OK: metis-os — Already up to date.\n"
        )
        sessions = parse_cron_log(incomplete, self.since)
        assert len(sessions) == 1
        assert sessions[0]["cron_exit_code"] == -1  # incomplete


# --- Git log parsing ---

class TestParseGitLog:
    def test_parses_commits(self):
        log_output = (
            "COMMIT_START\n"
            "abc1234\n"
            "2026-04-07T04:23:11+00:00\n"
            "Claude <noreply@anthropic.com>\n"
            "Update assessment data\n"
            "COMMIT_END\n"
            " data/assessments/20260407.json | 47 ++++\n"
            " results/latest.md             | 12 ++--\n"
            " 2 files changed, 47 insertions(+), 12 deletions(-)\n"
        )
        commits = parse_git_log(log_output, "iran-monitor")
        assert len(commits) == 1
        assert commits[0]["repo"] == "iran-monitor"
        assert commits[0]["hash"] == "abc1234"
        assert commits[0]["message"] == "Update assessment data"
        assert commits[0]["insertions"] == 47
        assert commits[0]["deletions"] == 12

    def test_empty_git_log(self):
        commits = parse_git_log("", "some-repo")
        assert commits == []

    def test_multiple_commits(self):
        log_output = (
            "COMMIT_START\naaa\n2026-04-07T04:00:00+00:00\nAlice <a@b.com>\nFirst\nCOMMIT_END\n"
            " file1.py | 10 ++\n 1 file changed, 10 insertions(+)\n"
            "COMMIT_START\nbbb\n2026-04-07T04:10:00+00:00\nBob <b@c.com>\nSecond\nCOMMIT_END\n"
            " file2.py | 5 ++\n 1 file changed, 5 insertions(+)\n"
        )
        commits = parse_git_log(log_output, "repo")
        assert len(commits) == 2
        assert commits[0]["hash"] == "aaa"
        assert commits[1]["hash"] == "bbb"


# --- SSH command ---

class TestSSHCommand:
    @patch("collect.subprocess.run")
    def test_success(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout="hello\n")
        result = ssh_command("host", "echo hello", retries=0)
        assert result == "hello\n"

    @patch("collect.subprocess.run")
    def test_failure_returns_none(self, mock_run):
        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="error")
        result = ssh_command("host", "bad command", retries=0)
        assert result is None

    @patch("collect.subprocess.run")
    def test_timeout_returns_none(self, mock_run):
        from subprocess import TimeoutExpired
        mock_run.side_effect = TimeoutExpired("ssh", 30)
        result = ssh_command("host", "slow", timeout=1, retries=0)
        assert result is None


# --- Linear API ---

class TestCollectLinearEvidence:
    @patch("collect.requests.post")
    def test_success(self, mock_post):
        mock_post.return_value = MagicMock(
            status_code=200,
            json=lambda: {
                "data": {
                    "issues": {
                        "nodes": [
                            {
                                "id": "issue-1",
                                "identifier": "JCC-100",
                                "title": "Test issue",
                                "state": {"name": "Done"},
                                "updatedAt": "2026-04-07T05:00:00Z",
                                "comments": {"nodes": [{"body": "All done", "createdAt": "2026-04-07T05:00:00Z"}]},
                                "history": {
                                    "nodes": [
                                        {"fromState": {"name": "In Progress"}, "toState": {"name": "Done"}, "createdAt": "2026-04-07T05:00:00Z"}
                                    ]
                                },
                            }
                        ]
                    }
                }
            },
        )
        mock_post.return_value.raise_for_status = MagicMock()

        since = datetime(2026, 4, 7, 0, 0, tzinfo=timezone.utc)
        results = collect_linear_evidence("team-id", "api-key", since)
        assert len(results) == 1
        assert results[0]["issue_id"] == "JCC-100"
        assert results[0]["state"] == "Done"
        assert len(results[0]["state_transitions"]) == 1
        assert results[0]["comments"] == ["All done"]

    @patch("collect.requests.post")
    def test_auth_failure_returns_empty(self, mock_post):
        mock_post.return_value = MagicMock(status_code=401)
        since = datetime(2026, 4, 7, 0, 0, tzinfo=timezone.utc)
        results = collect_linear_evidence("team-id", "bad-key", since)
        assert results == []

    @patch("collect.requests.post")
    def test_network_error_returns_empty(self, mock_post):
        from requests.exceptions import ConnectionError
        mock_post.side_effect = ConnectionError("no network")
        since = datetime(2026, 4, 7, 0, 0, tzinfo=timezone.utc)
        results = collect_linear_evidence("team-id", "key", since)
        assert results == []


# --- Config loading ---

class TestLoadConfig:
    def test_loads_config(self):
        config_path = Path(__file__).parent.parent / "config.yaml"
        config = load_config(str(config_path))
        assert "metis" in config
        assert "linear" in config
        assert "claude" in config
        assert config["metis"]["host"] == "deploy@your-server-ip"


# --- Evidence assembly ---

class TestBuildEvidence:
    @patch("collect.ssh_command")
    @patch("collect.collect_linear_evidence")
    def test_ssh_unreachable(self, mock_linear, mock_ssh):
        mock_ssh.return_value = None  # SSH fails
        config = load_config(str(Path(__file__).parent.parent / "config.yaml"))
        evidence = build_evidence(config, lookback_hours=24)
        assert evidence["ssh_status"] == "unreachable"
        assert evidence["sessions"] == []

    @patch("collect.ssh_command")
    @patch("collect.collect_linear_evidence")
    def test_no_sessions_found(self, mock_linear, mock_ssh):
        mock_ssh.return_value = ""  # Empty cron log
        mock_linear.return_value = []
        config = load_config(str(Path(__file__).parent.parent / "config.yaml"))
        # Use a future lookback to ensure no sessions match
        evidence = build_evidence(config, lookback_hours=0)
        assert evidence["sessions"] == []
