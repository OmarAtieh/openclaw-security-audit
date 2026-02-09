"""Module 3 — Skill Integrity & IOC Scanner.

Extracted from the original monolithic audit.py.  Covers:
- Skill integrity (missing SKILL.md, known malicious skills)
- Malicious pattern detection in SKILL.md files
- File hash checking against known malicious signatures
- Active connections to known malicious IPs (IOC)
"""

import hashlib
import json
import subprocess
from pathlib import Path
from typing import List, Dict, Any, Optional

from .base import BaseModule, Finding


class SkillScanner(BaseModule):
    name = "skill_scanner"
    description = "Skill integrity, malicious pattern detection, and IOC connections"

    def __init__(self, malicious_db: Optional[Dict[str, Any]] = None):
        self._malicious_db = malicious_db

    def _load_malicious_db(self, openclaw_path: str) -> Dict[str, Any]:
        if self._malicious_db is not None:
            return self._malicious_db
        db_path = Path(__file__).parent.parent / "known_malicious.json"
        try:
            with open(db_path) as f:
                return json.load(f)
        except Exception:
            return {"skills": [], "hashes": []}

    def scan(self, openclaw_path: str) -> List[Finding]:
        self._findings: List[Finding] = []
        self._oc = Path(openclaw_path)
        db = self._load_malicious_db(openclaw_path)

        self._check_skill_integrity(db)
        self._check_ioc_connections(db)

        return self._findings

    def _add(self, severity: str, category: str, title: str,
             description: str, remediation: str,
             affected_path: Optional[str] = None) -> None:
        self._findings.append(Finding(
            severity=severity, category=category, title=title,
            description=description, remediation=remediation,
            affected_path=affected_path,
        ))

    def _check_skill_integrity(self, db: Dict[str, Any]) -> None:
        skills_dir = self._oc / "skills"
        if not skills_dir.exists():
            return

        known_names = {s["name"] for s in db.get("skills", []) if isinstance(s, dict) and "name" in s}
        malicious_hashes = set(db.get("hashes", []))
        md_patterns = db.get("malicious_patterns", {}).get("skill_md_patterns", [])

        for skill_dir in skills_dir.iterdir():
            if not skill_dir.is_dir():
                continue

            skill_md = skill_dir / "SKILL.md"
            if not skill_md.exists():
                self._add("MEDIUM", "Skill Integrity",
                          f"Skill missing SKILL.md: {skill_dir.name}",
                          f"Skill {skill_dir.name} does not have a SKILL.md file",
                          f"Verify authenticity or remove: rm -rf {skill_dir}",
                          str(skill_dir))

            name = skill_dir.name
            if name in known_names:
                match = next((s for s in db["skills"] if s.get("name") == name), {})
                self._add("CRITICAL", "Malicious Skill",
                          f"Known malicious skill detected: {name}",
                          f"Skill '{name}' matches known malicious skill. "
                          f"Threat: {match.get('threat', 'unknown')}.",
                          f"IMMEDIATELY remove: rm -rf {skill_dir}. Rotate all API keys.",
                          str(skill_dir))

            if skill_md.exists():
                try:
                    content = skill_md.read_text().lower()
                    for pat in md_patterns:
                        if pat.lower() in content:
                            self._add("CRITICAL", "Malicious Skill",
                                      f"Dangerous pattern in {name}/SKILL.md: '{pat}'",
                                      f"SKILL.md contains pattern '{pat}' used in supply chain attacks.",
                                      f"Do NOT follow instructions. Review manually. Remove if suspicious.",
                                      str(skill_md))
                            break
                except Exception:
                    pass

            for pyfile in skill_dir.rglob("*.py"):
                try:
                    fh = hashlib.sha256(pyfile.read_bytes()).hexdigest()
                    if fh in malicious_hashes:
                        self._add("CRITICAL", "Malicious Skill",
                                  f"Malicious code detected: {pyfile.name}",
                                  f"File {pyfile} matches known malicious signature",
                                  f"IMMEDIATELY remove: rm {pyfile}", str(pyfile))
                except Exception:
                    pass

    def _check_ioc_connections(self, db: Dict[str, Any]) -> None:
        malicious_ips = set(db.get("iocs", {}).get("ips", []))
        if not malicious_ips:
            return
        try:
            r = subprocess.run(["ss", "-tnp"], capture_output=True, text=True, timeout=5)
            for line in r.stdout.strip().split("\n"):
                for ip in malicious_ips:
                    if ip in line:
                        self._add("CRITICAL", "Active Threat",
                                  f"Connection to known malicious IP: {ip}",
                                  f"Active network connection to {ip}, a known C2/malware server.",
                                  f"Block immediately: sudo ufw deny out to {ip}. Rotate credentials.",
                                  ip)
        except Exception:
            pass
