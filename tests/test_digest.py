"""Tests for digest.py — markdown report generation."""

from pathlib import Path

import pytest

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from digest import generate_digest, load_config


class TestGenerateDigest:
    def setup_method(self):
        self.config = load_config(str(Path(__file__).parent.parent / "config.yaml"))

    def test_no_sessions(self):
        audit = {"status": "NO_SESSIONS", "sessions": []}
        digest = generate_digest(audit, self.config)
        assert "No agent sessions detected" in digest

    def test_incomplete_audit(self):
        audit = {"status": "INCOMPLETE", "error": "SSH unreachable", "sessions": []}
        digest = generate_digest(audit, self.config)
        assert "AUDIT INCOMPLETE" in digest
        assert "SSH unreachable" in digest

    def test_clean_session(self):
        audit = {
            "status": "CLEAN",
            "average_trust_score": 95,
            "session_count": 1,
            "sessions": [
                {
                    "session_id": "test-123",
                    "cycle_id": "260407-0600",
                    "trust_score": 95,
                    "verdict": "CLEAN",
                    "verified": ["Assessment updated"],
                    "unverified": [],
                    "contradicted": [],
                    "unreported": [],
                    "flags": [],
                    "summary": "Clean session.",
                    "cost_usd": 27.05,
                }
            ],
        }
        digest = generate_digest(audit, self.config)
        assert "CLEAN" in digest
        assert "95" in digest
        assert "test-123" in digest

    def test_flagged_session_shows_details(self):
        audit = {
            "status": "FLAGGED",
            "average_trust_score": 45,
            "session_count": 1,
            "sessions": [
                {
                    "session_id": "bad-session",
                    "cycle_id": "260407-1800",
                    "trust_score": 45,
                    "verdict": "FLAGGED",
                    "verified": [],
                    "unverified": ["Claimed assessment complete"],
                    "contradicted": ["Said 14 agents, evidence shows 12"],
                    "unreported": ["Modified .claude/settings.json"],
                    "self_modifications": ["settings.json changed"],
                    "permission_denials_flag": True,
                    "crash_correlation": None,
                    "forward_risk": "Dirty state left in working directory",
                    "warning_escalations": ["jf-private pull failed (5 consecutive)"],
                    "flags": ["SELF-MODIFICATION", "PERMISSION_DENIAL", "CONTRADICTED"],
                    "summary": "Multiple issues found.",
                }
            ],
        }
        digest = generate_digest(audit, self.config)
        assert "Flagged Sessions" in digest
        assert "CONTRADICTED" in digest
        assert "UNREPORTED" in digest
        assert "SELF-MODIFICATION" in digest
        assert "PERMISSION DENIALS" in digest
        assert "FORWARD RISK" in digest
        assert "WARNING ESCALATIONS" in digest

    def test_cost_summary(self):
        audit = {
            "status": "CLEAN",
            "average_trust_score": 90,
            "session_count": 2,
            "sessions": [
                {"session_id": "a", "trust_score": 90, "verdict": "CLEAN", "verified": ["ok"], "flags": [], "cost_usd": 25.0},
                {"session_id": "b", "trust_score": 90, "verdict": "CLEAN", "verified": ["ok"], "flags": [], "cost_usd": 30.0},
            ],
        }
        digest = generate_digest(audit, self.config)
        assert "$55.00" in digest

    def test_below_threshold_flagged(self):
        """Sessions below the alert_threshold should appear in Flagged."""
        audit = {
            "status": "CLEAN",
            "average_trust_score": 75,
            "session_count": 1,
            "sessions": [
                {
                    "session_id": "borderline",
                    "trust_score": 75,
                    "verdict": "SUSPICIOUS",
                    "verified": ["some"],
                    "unverified": ["other"],
                    "flags": [],
                    "summary": "Borderline session.",
                }
            ],
        }
        digest = generate_digest(audit, self.config)
        assert "Flagged Sessions" in digest  # 75 < 80 threshold

    def test_mixed_sessions(self):
        """Mix of clean and flagged sessions."""
        audit = {
            "status": "FLAGGED",
            "average_trust_score": 72,
            "session_count": 2,
            "sessions": [
                {"session_id": "good", "trust_score": 95, "verdict": "CLEAN", "verified": ["ok"], "flags": []},
                {"session_id": "bad", "trust_score": 49, "verdict": "FLAGGED", "verified": [], "flags": ["CONTRADICTED"], "summary": "Bad."},
            ],
        }
        digest = generate_digest(audit, self.config)
        assert "Clean Sessions" in digest
        assert "Flagged Sessions" in digest
        assert "good" in digest
        assert "bad" in digest

    def test_digest_has_footer(self):
        audit = {"status": "NO_SESSIONS", "sessions": []}
        digest = generate_digest(audit, self.config)
        # NO_SESSIONS doesn't have footer, but clean does
        audit2 = {
            "status": "CLEAN",
            "average_trust_score": 95,
            "session_count": 1,
            "sessions": [{"session_id": "x", "trust_score": 95, "verdict": "CLEAN", "verified": ["ok"], "flags": []}],
        }
        digest2 = generate_digest(audit2, self.config)
        assert "Generated by Clawditor" in digest2
