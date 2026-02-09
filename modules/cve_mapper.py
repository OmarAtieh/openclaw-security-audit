"""Module 2 — CVE Version Mapper.

Detects the installed OpenClaw version and checks it against a local
CVE database (``data/cve_database.json``).

Version detection order:
1. ``<openclaw_path>/../package.json`` (repo install)
2. ``openclaw --version`` (CLI)
3. ``node_modules/openclaw/package.json``
4. ``<openclaw_path>/version`` file
"""

import json
import os
import re
import subprocess
from pathlib import Path
from typing import List, Optional, Tuple

from .base import BaseModule, Finding


def _parse_version(v: str) -> Optional[Tuple[int, ...]]:
    """Parse a semver string into a tuple of ints, stripping leading 'v' and pre-release tags."""
    if not v:
        return None
    v = v.strip().lstrip("v")
    # Strip pre-release / build metadata  e.g. 1.2.3-beta.1+build
    v = re.split(r"[-+]", v, 1)[0]
    parts = v.split(".")
    try:
        return tuple(int(p) for p in parts)
    except (ValueError, TypeError):
        return None


def _version_in_range(ver: Tuple[int, ...],
                      ge: Optional[str] = None,
                      lt: Optional[str] = None,
                      le: Optional[str] = None) -> bool:
    """Check if *ver* falls inside the half-open range [ge, lt) or [ge, le]."""
    if ge:
        low = _parse_version(ge)
        if low and ver < low:
            return False
    if lt:
        high = _parse_version(lt)
        if high and ver >= high:
            return False
    if le:
        high = _parse_version(le)
        if high and ver > high:
            return False
    return True


class CVEMapper(BaseModule):
    name = "cve_mapper"
    description = "Map installed OpenClaw version to known CVEs"

    def __init__(self, cve_db_path: Optional[str] = None):
        self._cve_db_path = cve_db_path

    # ------------------------------------------------------------------
    # Version detection
    # ------------------------------------------------------------------
    def _detect_version(self, openclaw_path: str) -> Optional[str]:
        oc = Path(openclaw_path)

        # 1. Repo-level package.json (parent of .openclaw)
        for candidate in [oc.parent / "package.json", oc / "package.json"]:
            ver = self._version_from_package_json(candidate)
            if ver:
                return ver

        # 2. openclaw --version
        ver = self._version_from_cli()
        if ver:
            return ver

        # 3. node_modules
        for base in [oc.parent, Path.home()]:
            candidate = base / "node_modules" / "openclaw" / "package.json"
            ver = self._version_from_package_json(candidate)
            if ver:
                return ver

        # 4. version file
        vf = oc / "version"
        if vf.exists():
            try:
                return vf.read_text().strip()
            except Exception:
                pass

        return None

    @staticmethod
    def _version_from_package_json(path: Path) -> Optional[str]:
        if not path.exists():
            return None
        try:
            with open(path) as f:
                data = json.load(f)
            return data.get("version")
        except Exception:
            return None

    @staticmethod
    def _version_from_cli() -> Optional[str]:
        try:
            r = subprocess.run(
                ["openclaw", "--version"],
                capture_output=True, text=True, timeout=5,
            )
            if r.returncode == 0:
                # output may be "openclaw v1.2.3" or just "1.2.3"
                m = re.search(r"(\d+\.\d+\.\d+[^\s]*)", r.stdout)
                if m:
                    return m.group(1)
        except Exception:
            pass
        return None

    # ------------------------------------------------------------------
    # CVE database
    # ------------------------------------------------------------------
    def _load_cve_db(self) -> Optional[list]:
        if self._cve_db_path:
            p = Path(self._cve_db_path)
        else:
            p = Path(__file__).parent.parent / "data" / "cve_database.json"
        if not p.exists():
            return None
        try:
            with open(p) as f:
                data = json.load(f)
            # Accept both {"cves": [...]} and bare [...]
            if isinstance(data, list):
                return data
            if isinstance(data, dict):
                return data.get("cves", data.get("vulnerabilities", []))
        except Exception:
            return None
        return None

    # ------------------------------------------------------------------
    # Scan
    # ------------------------------------------------------------------
    def scan(self, openclaw_path: str) -> List[Finding]:
        findings: List[Finding] = []

        version_str = self._detect_version(openclaw_path)
        if not version_str:
            findings.append(Finding(
                severity="LOW",
                category="CVE Mapping",
                title="Could not detect OpenClaw version",
                description=(
                    "Unable to determine the installed OpenClaw version. "
                    "CVE checks were skipped."
                ),
                remediation=(
                    "Ensure a package.json or version file exists in the "
                    "OpenClaw directory, or that 'openclaw --version' works."
                ),
            ))
            return findings

        ver = _parse_version(version_str)
        if ver is None:
            findings.append(Finding(
                severity="LOW",
                category="CVE Mapping",
                title=f"Unparseable OpenClaw version: {version_str}",
                description="Version string could not be parsed as semver.",
                remediation="Check the version file or package.json for a valid version string.",
            ))
            return findings

        cves = self._load_cve_db()
        if cves is None:
            findings.append(Finding(
                severity="INFO",
                category="CVE Mapping",
                title="CVE database not found",
                description="data/cve_database.json is missing. CVE checks skipped.",
                remediation="Download or generate the CVE database file.",
            ))
            return findings

        # Match CVEs
        matched = 0
        for entry in cves:
            affected = entry.get("affected_versions", entry.get("affected", {}))
            if isinstance(affected, str):
                # Simple range like "<1.5.0"
                if affected.startswith("<"):
                    if not _version_in_range(ver, lt=affected[1:]):
                        continue
                elif affected.startswith("<="):
                    if not _version_in_range(ver, le=affected[2:]):
                        continue
                else:
                    continue
            elif isinstance(affected, dict):
                ge = affected.get("ge", affected.get("from", affected.get("gte")))
                lt = affected.get("lt", affected.get("before"))
                le = affected.get("le", affected.get("through"))
                if not _version_in_range(ver, ge=ge, lt=lt, le=le):
                    continue
            else:
                continue

            cve_id = entry.get("id", entry.get("cve_id", "UNKNOWN"))
            sev = entry.get("severity", "HIGH").upper()
            if sev not in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
                sev = "HIGH"
            fix_version = entry.get("fix_version", entry.get("fixed_in", "unknown"))
            findings.append(Finding(
                severity=sev,
                category="CVE Mapping",
                title=f"{cve_id}: {entry.get('title', entry.get('summary', 'N/A'))}",
                description=(
                    f"Installed version {version_str} is affected by {cve_id}. "
                    f"{entry.get('description', '')}"
                ),
                remediation=f"Upgrade to version {fix_version} or later.",
            ))
            matched += 1

        if matched == 0:
            findings.append(Finding(
                severity="INFO",
                category="CVE Mapping",
                title=f"No known CVEs for OpenClaw {version_str}",
                description=f"Version {version_str} has no known vulnerabilities in the database.",
                remediation="Keep monitoring for new advisories.",
            ))

        return findings
