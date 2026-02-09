"""Module 3: Prompt Injection Scanner.

Scans SKILL.md files and workspace markdown for structural prompt-injection
indicators.  Focuses on durable, low-false-positive signals rather than
fragile content matching.
"""

import base64
import json
import os
import re
from pathlib import Path
from typing import List, Optional

from .base import BaseModule, Finding

# ---------------------------------------------------------------------------
# Popular npm packages (for typosquat detection)
# ---------------------------------------------------------------------------
POPULAR_PACKAGES = [
    "express", "react", "lodash", "axios", "webpack", "babel", "eslint",
    "typescript", "next", "vue", "angular", "jquery", "moment", "chalk",
    "commander", "dotenv", "inquirer", "nodemon", "mocha", "jest",
    "prettier", "uuid", "debug", "yargs", "glob", "minimist", "semver",
    "bluebird", "underscore", "async", "request", "body-parser",
    "mongoose", "passport", "socket.io", "redis", "pg", "mysql",
    "sequelize", "prisma", "graphql", "apollo", "cors", "helmet",
    "morgan", "multer", "sharp", "puppeteer", "cheerio", "ws",
]

# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------

# Zero-width and directional override characters
_UNICODE_ABUSE_RE = re.compile(r"[\u200b\u200c\u200d\ufeff\u202e\u202d\u202a\u202b\u2066\u2067\u2068\u2069]")

# Base64 block: 100+ base64 chars contiguous (not inside a URL)
_BASE64_BLOCK_RE = re.compile(r"(?<![/\w])([A-Za-z0-9+/]{100,}={0,2})(?![/\w])")

# Code execution keywords (outside code blocks)
_CODE_EXEC_KEYWORDS = re.compile(
    r"\b(eval\(|exec\(|subprocess|os\.system|child_process|spawn\()", re.IGNORECASE
)

# Hex-encoded commands  e.g. \x2f\x62\x69\x6e
_HEX_ENCODED_RE = re.compile(r"(\\x[0-9a-fA-F]{2}){4,}")

# Octal-encoded  e.g. \057\142\151\156
_OCTAL_ENCODED_RE = re.compile(r"(\\[0-3][0-7]{2}){4,}")

# Exfiltration tools
_EXFIL_RE = re.compile(
    r"\b(curl|wget)\s+['\"]?https?://|\bfetch\s*\(|XMLHttpRequest", re.IGNORECASE
)

# Sensitive file paths
_SENSITIVE_PATHS_RE = re.compile(
    r"/etc/passwd|~/\.ssh/|\.env\b|id_rsa|AWS_SECRET|OPENAI_API_KEY|ANTHROPIC_API_KEY",
    re.IGNORECASE,
)

# Role override phrases
_ROLE_OVERRIDE_RE = re.compile(
    r"ignore previous instructions|you are now|new system prompt:|IMPORTANT:\s*override|disregard all",
    re.IGNORECASE,
)

# Symlink indicators
_SYMLINK_RE = re.compile(r"os\.symlink|ln\s+-s\b")

# Data URI with large base64 payload
_DATA_URI_RE = re.compile(r"data:[^;]+;base64,([A-Za-z0-9+/=]{1300,})")

# HTML/script injection in markdown
_HTML_INJECT_RE = re.compile(r"<\s*(script|iframe|object|embed)\b", re.IGNORECASE)

# Obfuscation signals
_OBFUSCATION_RE = re.compile(
    r"(\\x[0-9a-fA-F]{2}){6,}|String\.fromCharCode|atob\s*\(", re.IGNORECASE
)


def _edit_distance(a: str, b: str) -> int:
    """Levenshtein distance (small strings only)."""
    if len(a) > 30 or len(b) > 30:
        return max(len(a), len(b))
    m, n = len(a), len(b)
    dp = list(range(n + 1))
    for i in range(1, m + 1):
        prev = dp[0]
        dp[0] = i
        for j in range(1, n + 1):
            tmp = dp[j]
            if a[i - 1] == b[j - 1]:
                dp[j] = prev
            else:
                dp[j] = 1 + min(prev, dp[j], dp[j - 1])
            prev = tmp
    return dp[n]


def _strip_code_blocks(text: str) -> str:
    """Remove fenced code blocks (``` ... ```) so we don't flag code examples."""
    return re.sub(r"```[\s\S]*?```", "", text)


class InjectionScanner(BaseModule):
    """Scan for prompt injection indicators in skills and workspace files."""

    name = "injection_scanner"
    description = "Detects structural prompt-injection signals in SKILL.md and workspace files"

    def scan(self, openclaw_path: str) -> List[Finding]:
        findings: List[Finding] = []
        oc = Path(openclaw_path).expanduser()

        # Gather target files
        skill_dirs = sorted(oc.glob("skills/*/")) if oc.exists() else []
        skill_md_files = [d / "SKILL.md" for d in skill_dirs if (d / "SKILL.md").exists()]
        package_jsons = [d / "package.json" for d in skill_dirs if (d / "package.json").exists()]

        # Workspace markdown (depth 2 from cwd)
        cwd = Path.cwd()
        workspace_md = sorted(set(cwd.glob("*.md")) | set(cwd.glob("*/*.md")))

        # Scan SKILL.md files
        for fp in skill_md_files:
            findings.extend(self._scan_file(fp, is_skill=True))

        # Scan workspace markdown
        for fp in workspace_md:
            findings.extend(self._scan_file(fp, is_skill=False))

        # Scan package.json for typosquatting
        for fp in package_jsons:
            findings.extend(self._scan_package_json(fp))

        return findings

    def _scan_file(self, filepath: Path, is_skill: bool) -> List[Finding]:
        findings: List[Finding] = []
        fstr = str(filepath)

        try:
            raw = filepath.read_bytes()
        except (OSError, PermissionError):
            return findings

        # 4. Null bytes
        if b"\x00" in raw:
            findings.append(Finding(
                severity="critical",
                category="injection",
                title="Null bytes in text file",
                description=f"File contains \\x00 null bytes, indicating possible binary injection",
                remediation="Remove null bytes or investigate why a text file contains binary data",
                affected_path=fstr,
            ))
            # Don't try to decode further
            return findings

        try:
            text = raw.decode("utf-8", errors="replace")
        except Exception:
            return findings

        lines = text.split("\n")

        # 1. Size anomaly (SKILL.md only)
        if is_skill and len(raw) > 50_000:
            findings.append(Finding(
                severity="high",
                category="injection",
                title="Abnormally large SKILL.md",
                description=f"File is {len(raw)//1024}KB (normal: 1-10KB). May contain hidden payload",
                remediation="Review file contents; SKILL.md should be concise skill definitions",
                affected_path=fstr,
            ))

        # Text outside code blocks for several checks
        text_no_code = _strip_code_blocks(text)

        # 2. Base64 blocks
        for m in _BASE64_BLOCK_RE.finditer(text_no_code):
            # Verify it's plausibly base64 (try decode)
            candidate = m.group(1)
            try:
                decoded = base64.b64decode(candidate)
                # If it decodes to mostly printable or binary, flag it
                findings.append(Finding(
                    severity="high",
                    category="injection",
                    title="Large base64 block in markdown",
                    description=f"Base64-encoded content ({len(candidate)} chars) found outside code blocks",
                    remediation="Investigate the encoded content; legitimate skills don't embed base64 blobs",
                    affected_path=fstr,
                ))
                break  # one finding per file is enough
            except Exception:
                pass

        # 3. Unicode abuse
        for i, line in enumerate(lines, 1):
            if _UNICODE_ABUSE_RE.search(line):
                findings.append(Finding(
                    severity="critical",
                    category="injection",
                    title="Unicode abuse detected",
                    description=f"Zero-width or directional override characters found on line {i}",
                    remediation="Remove invisible Unicode characters; they can hide malicious instructions",
                    affected_path=fstr,
                ))
                break  # one per file

        # 5. Hidden whitespace
        for i, line in enumerate(lines, 1):
            trailing = len(line) - len(line.rstrip())
            if trailing > 100:
                findings.append(Finding(
                    severity="medium",
                    category="injection",
                    title="Hidden whitespace detected",
                    description=f"Line {i} has {trailing} trailing spaces (possible hidden text)",
                    remediation="Remove excessive trailing whitespace",
                    affected_path=fstr,
                ))
                break

        # 6. Code execution keywords (outside code blocks)
        for m in _CODE_EXEC_KEYWORDS.finditer(text_no_code):
            # Find approximate line number
            pos = m.start()
            lineno = text_no_code[:pos].count("\n") + 1
            findings.append(Finding(
                severity="high",
                category="injection",
                title="Code execution pattern in markdown",
                description=f"Found `{m.group(0)}` outside code blocks",
                remediation="Code execution calls should not appear in skill definitions outside examples",
                affected_path=fstr,
            ))
            break

        # 7. Encoded commands
        for regex, label in [(_HEX_ENCODED_RE, "hex"), (_OCTAL_ENCODED_RE, "octal")]:
            if regex.search(text_no_code):
                findings.append(Finding(
                    severity="high",
                    category="injection",
                    title=f"{label.title()}-encoded commands detected",
                    description=f"Found {label}-encoded byte sequences outside code blocks",
                    remediation="Investigate encoded content; legitimate skills use plain text",
                    affected_path=fstr,
                ))
                break

        # 8. Exfiltration URLs (outside code blocks)
        if _EXFIL_RE.search(text_no_code):
            findings.append(Finding(
                severity="high",
                category="injection",
                title="Potential data exfiltration command",
                description="Found curl/wget/fetch/XMLHttpRequest outside code blocks",
                remediation="Review network calls; skills should not make external requests",
                affected_path=fstr,
            ))

        # 9. Sensitive file access
        if _SENSITIVE_PATHS_RE.search(text_no_code):
            findings.append(Finding(
                severity="medium",
                category="injection",
                title="Sensitive file path reference",
                description="References to sensitive files (ssh keys, env files, passwords)",
                remediation="Skills should not reference sensitive system files",
                affected_path=fstr,
            ))

        # 10. Role override phrases
        if _ROLE_OVERRIDE_RE.search(text):
            findings.append(Finding(
                severity="critical",
                category="injection",
                title="Role override phrase detected",
                description="Contains phrases attempting to override system prompt or instructions",
                remediation="Remove prompt injection attempts; this is a strong injection indicator",
                affected_path=fstr,
            ))

        # 11. Symlink indicators (outside code blocks)
        if _SYMLINK_RE.search(text_no_code):
            findings.append(Finding(
                severity="medium",
                category="injection",
                title="Symlink creation in skill definition",
                description="Found symlink creation commands outside code blocks",
                remediation="Skills should not create symlinks; this could enable path traversal",
                affected_path=fstr,
            ))

        # 13. Data URI payloads
        if _DATA_URI_RE.search(text):
            findings.append(Finding(
                severity="high",
                category="injection",
                title="Large data URI payload",
                description="Found data: URI with >1KB base64 content",
                remediation="Investigate embedded data URI; may contain hidden executable content",
                affected_path=fstr,
            ))

        # 14. HTML/Script injection
        if _HTML_INJECT_RE.search(text_no_code):
            findings.append(Finding(
                severity="high",
                category="injection",
                title="HTML/Script injection in markdown",
                description="Found <script>, <iframe>, <object>, or <embed> tags outside code blocks",
                remediation="Remove HTML injection tags; markdown should not contain executable HTML",
                affected_path=fstr,
            ))

        # 15. Obfuscation signals
        if _OBFUSCATION_RE.search(text_no_code):
            findings.append(Finding(
                severity="high",
                category="injection",
                title="Code obfuscation detected",
                description="Found obfuscation patterns (escape sequences, fromCharCode, atob)",
                remediation="Remove obfuscated code; legitimate skills use readable text",
                affected_path=fstr,
            ))

        return findings

    def _scan_package_json(self, filepath: Path) -> List[Finding]:
        """Check package.json dependencies for typosquatting (pattern 12)."""
        findings: List[Finding] = []
        data = self._load_json(str(filepath))
        if not data:
            return findings

        all_deps: List[str] = []
        for key in ("dependencies", "devDependencies", "peerDependencies"):
            deps = data.get(key, {})
            if isinstance(deps, dict):
                all_deps.extend(deps.keys())

        for dep in all_deps:
            if dep in POPULAR_PACKAGES:
                continue
            for popular in POPULAR_PACKAGES:
                if dep == popular:
                    continue
                dist = _edit_distance(dep, popular)
                if dist <= 2 and dist > 0:
                    findings.append(Finding(
                        severity="critical",
                        category="injection",
                        title=f"Possible typosquatted package: {dep}",
                        description=f"Package '{dep}' is edit distance {dist} from popular package '{popular}'",
                        remediation=f"Verify '{dep}' is intentional and not a typosquat of '{popular}'",
                        affected_path=str(filepath),
                    ))
                    break  # one match per dep

        return findings
