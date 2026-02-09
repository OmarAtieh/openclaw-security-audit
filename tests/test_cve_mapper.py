"""Tests for Module 2 — CVE Version Mapper."""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent))
from modules.cve_mapper import CVEMapper, _parse_version, _version_in_range


class TestParseVersion(unittest.TestCase):
    def test_simple(self):
        self.assertEqual(_parse_version("1.2.3"), (1, 2, 3))

    def test_leading_v(self):
        self.assertEqual(_parse_version("v1.0.0"), (1, 0, 0))

    def test_prerelease(self):
        self.assertEqual(_parse_version("1.2.3-beta.1"), (1, 2, 3))

    def test_build_metadata(self):
        self.assertEqual(_parse_version("1.2.3+build.42"), (1, 2, 3))

    def test_empty(self):
        self.assertIsNone(_parse_version(""))

    def test_garbage(self):
        self.assertIsNone(_parse_version("not-a-version"))


class TestVersionInRange(unittest.TestCase):
    def test_ge_lt(self):
        self.assertTrue(_version_in_range((1, 2, 0), ge="1.0.0", lt="2.0.0"))
        self.assertFalse(_version_in_range((2, 0, 0), ge="1.0.0", lt="2.0.0"))
        self.assertFalse(_version_in_range((0, 9, 0), ge="1.0.0", lt="2.0.0"))

    def test_le(self):
        self.assertTrue(_version_in_range((1, 5, 0), ge="1.0.0", le="1.5.0"))
        self.assertFalse(_version_in_range((1, 5, 1), ge="1.0.0", le="1.5.0"))

    def test_no_bounds(self):
        self.assertTrue(_version_in_range((99, 99, 99)))


class TestCVEMapperVersionDetection(unittest.TestCase):
    def test_version_from_package_json(self):
        with tempfile.TemporaryDirectory() as td:
            oc = Path(td) / ".openclaw"
            oc.mkdir()
            pkg = Path(td) / "package.json"
            pkg.write_text(json.dumps({"name": "openclaw", "version": "1.5.2"}))
            mapper = CVEMapper()
            # Mock CLI to avoid real openclaw --version
            with patch.object(mapper, '_version_from_cli', return_value=None):
                v = mapper._detect_version(str(oc))
            self.assertEqual(v, "1.5.2")

    def test_version_from_version_file(self):
        with tempfile.TemporaryDirectory() as td:
            oc = Path(td) / ".openclaw"
            oc.mkdir()
            (oc / "version").write_text("2.0.0-rc.1\n")
            mapper = CVEMapper()
            with patch.object(mapper, '_version_from_cli', return_value=None):
                v = mapper._detect_version(str(oc))
            self.assertEqual(v, "2.0.0-rc.1")

    def test_version_not_found(self):
        with tempfile.TemporaryDirectory() as td:
            oc = Path(td) / ".openclaw"
            oc.mkdir()
            mapper = CVEMapper()
            with patch.object(mapper, '_version_from_cli', return_value=None):
                v = mapper._detect_version(str(oc))
            self.assertIsNone(v)


class TestCVEMapperScan(unittest.TestCase):
    def _make_env(self, version, cves):
        td = tempfile.mkdtemp()
        oc = Path(td) / ".openclaw"
        oc.mkdir()
        (oc / "version").write_text(version)
        db_path = Path(td) / "cve_db.json"
        db_path.write_text(json.dumps({"cves": cves}))
        return str(oc), str(db_path)

    def test_matching_cve(self):
        oc, db = self._make_env("1.2.0", [
            {
                "id": "CVE-2026-0001",
                "title": "Test vuln",
                "description": "Bad thing",
                "severity": "HIGH",
                "affected_versions": {"ge": "1.0.0", "lt": "1.5.0"},
                "fix_version": "1.5.0",
            }
        ])
        mapper = CVEMapper(cve_db_path=db)
        with patch.object(mapper, '_version_from_cli', return_value=None):
            findings = mapper.scan(oc)
        titles = [f.title for f in findings]
        self.assertTrue(any("CVE-2026-0001" in t for t in titles))

    def test_no_matching_cve(self):
        oc, db = self._make_env("2.0.0", [
            {
                "id": "CVE-2026-0001",
                "title": "Old vuln",
                "severity": "HIGH",
                "affected_versions": {"ge": "1.0.0", "lt": "1.5.0"},
                "fix_version": "1.5.0",
            }
        ])
        mapper = CVEMapper(cve_db_path=db)
        with patch.object(mapper, '_version_from_cli', return_value=None):
            findings = mapper.scan(oc)
        self.assertTrue(any("No known CVEs" in f.title for f in findings))

    def test_missing_db(self):
        with tempfile.TemporaryDirectory() as td:
            oc = Path(td) / ".openclaw"
            oc.mkdir()
            (oc / "version").write_text("1.0.0")
            mapper = CVEMapper(cve_db_path="/nonexistent/db.json")
            with patch.object(mapper, '_version_from_cli', return_value=None):
                findings = mapper.scan(str(oc))
            self.assertTrue(any("not found" in f.title for f in findings))

    def test_version_not_detected(self):
        with tempfile.TemporaryDirectory() as td:
            oc = Path(td) / ".openclaw"
            oc.mkdir()
            mapper = CVEMapper()
            with patch.object(mapper, '_version_from_cli', return_value=None):
                findings = mapper.scan(str(oc))
            self.assertTrue(any("Could not detect" in f.title for f in findings))

    def test_string_affected_versions(self):
        oc, db = self._make_env("1.2.0", [
            {
                "id": "CVE-2026-0002",
                "title": "String range vuln",
                "severity": "CRITICAL",
                "affected_versions": "<1.5.0",
                "fix_version": "1.5.0",
            }
        ])
        mapper = CVEMapper(cve_db_path=db)
        with patch.object(mapper, '_version_from_cli', return_value=None):
            findings = mapper.scan(oc)
        self.assertTrue(any("CVE-2026-0002" in f.title for f in findings))


if __name__ == "__main__":
    unittest.main()
