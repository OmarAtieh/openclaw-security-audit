"""Tests for Module 4 — Channel / DM Policy Auditor."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from modules.channel_auditor import ChannelAuditor


class TestDMPolicyOpen(unittest.TestCase):
    def test_open_dm_policy_bool(self):
        cfg = {"dm_policy": {"allowDMs": True, "requireMention": False}}
        auditor = ChannelAuditor(config_override=cfg)
        findings = auditor.scan("/tmp/fake")
        titles = [f.title for f in findings]
        self.assertTrue(any("open" in t.lower() or "DM" in t for t in titles))

    def test_open_dm_policy_string(self):
        cfg = {"dm_policy": {"mode": "open"}}
        auditor = ChannelAuditor(config_override=cfg)
        findings = auditor.scan("/tmp/fake")
        self.assertTrue(any("open" in f.title.lower() for f in findings))

    def test_pairing_dm_policy_no_warning(self):
        cfg = {"dm_policy": {"mode": "pairing", "requireMention": True}}
        auditor = ChannelAuditor(config_override=cfg)
        findings = auditor.scan("/tmp/fake")
        self.assertFalse(any("open" in f.title.lower() for f in findings))


class TestRequireMention(unittest.TestCase):
    def test_mention_disabled(self):
        cfg = {"dm_policy": {"requireMention": False}}
        auditor = ChannelAuditor(config_override=cfg)
        findings = auditor.scan("/tmp/fake")
        self.assertTrue(any("requireMention" in f.title for f in findings))

    def test_mention_enabled(self):
        cfg = {"dm_policy": {"requireMention": True}}
        auditor = ChannelAuditor(config_override=cfg)
        findings = auditor.scan("/tmp/fake")
        self.assertFalse(any("requireMention" in f.title for f in findings))


class TestSessionIsolation(unittest.TestCase):
    def test_wrong_dm_scope(self):
        cfg = {"dmScope": "global"}
        auditor = ChannelAuditor(config_override=cfg)
        findings = auditor.scan("/tmp/fake")
        self.assertTrue(any("dmScope" in f.title for f in findings))

    def test_correct_dm_scope(self):
        cfg = {"dmScope": "per-channel-peer"}
        auditor = ChannelAuditor(config_override=cfg)
        findings = auditor.scan("/tmp/fake")
        self.assertFalse(any("dmScope" in f.title for f in findings))


class TestUnsolicited(unittest.TestCase):
    def test_unsolicited_allowed(self):
        cfg = {"dm_policy": {"allowUnsolicited": True}}
        auditor = ChannelAuditor(config_override=cfg)
        findings = auditor.scan("/tmp/fake")
        self.assertTrue(any("Unsolicited" in f.title for f in findings))


class TestWildcardChannel(unittest.TestCase):
    def test_wildcard_flagged(self):
        cfg = {"channels": {"*": {"requireMention": False}}}
        auditor = ChannelAuditor(config_override=cfg)
        findings = auditor.scan("/tmp/fake")
        self.assertTrue(any("Wildcard" in f.title for f in findings))

    def test_no_wildcard(self):
        cfg = {"channels": {"signal": {"requireMention": True}}}
        auditor = ChannelAuditor(config_override=cfg)
        findings = auditor.scan("/tmp/fake")
        self.assertFalse(any("Wildcard" in f.title for f in findings))


class TestChannelAuth(unittest.TestCase):
    def test_no_auth(self):
        cfg = {"channels": {"public": {"auth": {"enabled": False}}}}
        auditor = ChannelAuditor(config_override=cfg)
        findings = auditor.scan("/tmp/fake")
        self.assertTrue(any("authentication" in f.title.lower() for f in findings))

    def test_auth_bool_false(self):
        cfg = {"channels": {"public": {"authentication": False}}}
        auditor = ChannelAuditor(config_override=cfg)
        findings = auditor.scan("/tmp/fake")
        self.assertTrue(any("authentication" in f.title.lower() for f in findings))


class TestMissingConfig(unittest.TestCase):
    def test_no_config(self):
        auditor = ChannelAuditor()
        findings = auditor.scan("/tmp/nonexistent_openclaw_dir")
        self.assertTrue(any("not found" in f.title.lower() for f in findings))


class TestVulnerableFixture(unittest.TestCase):
    """Test against the existing vulnerable fixture."""

    def test_vulnerable_config(self):
        fixture = Path(__file__).parent / "fixtures" / "vulnerable" / "openclaw.json"
        if not fixture.exists():
            self.skipTest("Fixture not found")
        import json
        with open(fixture) as f:
            cfg = json.load(f)
        auditor = ChannelAuditor(config_override=cfg)
        findings = auditor.scan("/tmp/fake")
        # Should find: open DM, unsolicited, requireMention disabled
        sevs = [f.severity for f in findings]
        self.assertTrue(any(s in ("HIGH", "CRITICAL") for s in sevs),
                        f"Expected HIGH/CRITICAL findings, got: {sevs}")


if __name__ == "__main__":
    unittest.main()
