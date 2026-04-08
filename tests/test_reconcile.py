"""Tests for reconcile.py — reconciliation logic, prompt construction, response parsing."""

import json
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from reconcile import reconcile_session, reconcile_all, load_config, RECONCILIATION_PROMPT


class TestReconcileSession:
    def setup_method(self):
        self.session = {
            "session_id": "test-session",
            "cycle_id": "260407-0600",
            "cron_start": "2026-04-07T04:00:01+00:00",
            "cron_end": "2026-04-07T04:29:43+00:00",
            "cron_exit_code": 0,
            "cost_usd": 27.05,
            "warnings": [],
            "permission_denials": [],
            "cli_result": "All workstreams complete.",
            "git_events": [
                {
                    "repo": "iran-monitor",
                    "hash": "abc1234",
                    "timestamp": "2026-04-07T04:23:11+00:00",
                    "author": "Claude",
                    "message": "Update assessment",
                    "files_changed": ["data/assessment.json"],
                    "insertions": 47,
                    "deletions": 12,
                }
            ],
            "filesystem_events": [],
            "self_modifications": [],
            "linear_events": [
                {
                    "issue_id": "JCC-100",
                    "title": "Iran Monitor update",
                    "state": "Done",
                    "state_transitions": [{"from": "In Progress", "to": "Done", "at": "2026-04-07T04:28:00+00:00"}],
                    "comments": ["Assessment complete."],
                }
            ],
        }

    @patch("reconcile.anthropic.Anthropic")
    def test_clean_session(self, mock_anthropic_cls):
        client = MagicMock()
        mock_anthropic_cls.return_value = client
        client.messages.create.return_value = MagicMock(
            content=[MagicMock(text=json.dumps({
                "session_id": "test-session",
                "trust_score": 95,
                "verdict": "CLEAN",
                "verified": ["Assessment file created"],
                "unverified": [],
                "contradicted": [],
                "unreported": [],
                "self_modifications": [],
                "permission_denials_flag": False,
                "crash_correlation": None,
                "forward_risk": None,
                "warning_escalations": [],
                "flags": [],
                "summary": "Clean session.",
            }))]
        )

        result = reconcile_session(client, "claude-sonnet-4-6", self.session)
        assert result["trust_score"] == 95
        assert result["verdict"] == "CLEAN"
        assert result["flags"] == []

    @patch("reconcile.anthropic.Anthropic")
    def test_flagged_session_with_self_modification(self, mock_anthropic_cls):
        client = MagicMock()
        self.session["self_modifications"] = [
            {"path": "/home/deploy/.claude/settings.json", "mtime": "2026-04-07T04:20:00+00:00", "category": "SELF-MODIFICATION"}
        ]
        client.messages.create.return_value = MagicMock(
            content=[MagicMock(text=json.dumps({
                "session_id": "test-session",
                "trust_score": 60,
                "verdict": "FLAGGED",
                "verified": [],
                "unverified": [],
                "contradicted": [],
                "unreported": [],
                "self_modifications": ["settings.json modified"],
                "permission_denials_flag": False,
                "crash_correlation": None,
                "forward_risk": None,
                "warning_escalations": [],
                "flags": ["SELF-MODIFICATION: settings.json"],
                "summary": "Agent modified its own configuration.",
            }))]
        )

        result = reconcile_session(client, "claude-sonnet-4-6", self.session)
        assert result["trust_score"] == 60
        assert result["verdict"] == "FLAGGED"
        assert len(result["flags"]) > 0

    @patch("reconcile.anthropic.Anthropic")
    def test_api_error_graceful(self, mock_anthropic_cls):
        client = MagicMock()
        import anthropic
        client.messages.create.side_effect = anthropic.APIError(
            message="rate limited", request=MagicMock(), body=None
        )

        result = reconcile_session(client, "claude-sonnet-4-6", self.session)
        assert result["trust_score"] == -1
        assert result["verdict"] == "API_ERROR"
        assert "RECONCILIATION_API_ERROR" in result["flags"]

    @patch("reconcile.anthropic.Anthropic")
    def test_malformed_response(self, mock_anthropic_cls):
        client = MagicMock()
        client.messages.create.return_value = MagicMock(
            content=[MagicMock(text="This is not JSON at all, just some text.")]
        )

        result = reconcile_session(client, "claude-sonnet-4-6", self.session)
        assert result["trust_score"] == -1
        assert result["verdict"] == "PARSE_ERROR"

    @patch("reconcile.anthropic.Anthropic")
    def test_json_in_markdown_code_block(self, mock_anthropic_cls):
        client = MagicMock()
        json_response = json.dumps({
            "session_id": "test-session",
            "trust_score": 88,
            "verdict": "CLEAN",
            "verified": ["ok"],
            "unverified": [],
            "contradicted": [],
            "unreported": [],
            "self_modifications": [],
            "permission_denials_flag": False,
            "crash_correlation": None,
            "forward_risk": None,
            "warning_escalations": [],
            "flags": [],
            "summary": "Clean.",
        })
        client.messages.create.return_value = MagicMock(
            content=[MagicMock(text=f"```json\n{json_response}\n```")]
        )

        result = reconcile_session(client, "claude-sonnet-4-6", self.session)
        assert result["trust_score"] == 88

    def test_prompt_includes_session_context(self):
        """Verify the prompt template has all required placeholders."""
        assert "{session_id}" in RECONCILIATION_PROMPT
        assert "{git_events}" in RECONCILIATION_PROMPT
        assert "{filesystem_events}" in RECONCILIATION_PROMPT
        assert "{permission_denials}" in RECONCILIATION_PROMPT
        assert "{self_modifications}" in RECONCILIATION_PROMPT
        assert "SELF-MODIFICATION" in RECONCILIATION_PROMPT
        assert "SCORING RUBRIC" in RECONCILIATION_PROMPT

    @patch("reconcile.anthropic.Anthropic")
    def test_adjacent_session_context_included(self, mock_anthropic_cls):
        """Verify that preceding/next session context is passed for crash correlation."""
        client = MagicMock()
        client.messages.create.return_value = MagicMock(
            content=[MagicMock(text=json.dumps({
                "session_id": "test",
                "trust_score": 50,
                "verdict": "FLAGGED",
                "verified": [], "unverified": [], "contradicted": [],
                "unreported": [], "self_modifications": [],
                "permission_denials_flag": False,
                "crash_correlation": "Preceding session modified settings.json",
                "forward_risk": None,
                "warning_escalations": [],
                "flags": ["PROBABLE-CAUSE"],
                "summary": "Crash correlated with preceding self-modification.",
            }))]
        )

        prev = {
            "cycle_id": "260407-0600",
            "self_modifications": [{"path": "settings.json"}],
            "cron_exit_code": 0,
        }
        self.session["cron_exit_code"] = 1

        result = reconcile_session(
            client, "claude-sonnet-4-6", self.session,
            prev_session=prev
        )
        # Verify the prompt was called with adjacent context
        call_args = client.messages.create.call_args
        prompt_text = call_args.kwargs["messages"][0]["content"]
        assert "PRECEDING SESSION" in prompt_text


class TestReconcileAll:
    @patch.dict("os.environ", {"ANTHROPIC_API_KEY": ""})
    def test_missing_api_key(self):
        config = load_config(str(Path(__file__).parent.parent / "config.yaml"))
        evidence = {"sessions": [{"session_id": "test"}]}
        result = reconcile_all(config, evidence)
        assert result["status"] == "INCOMPLETE"

    def test_no_sessions(self):
        config = load_config(str(Path(__file__).parent.parent / "config.yaml"))
        with patch.dict("os.environ", {"ANTHROPIC_API_KEY": "test-key"}):
            evidence = {"sessions": []}
            result = reconcile_all(config, evidence)
            assert result["status"] == "NO_SESSIONS"
