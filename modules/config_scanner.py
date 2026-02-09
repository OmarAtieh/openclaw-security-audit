"""Module 1 — Configuration & Credential Scanner.

Extracted from the original monolithic audit.py.  Covers:
- File permissions on sensitive files
- Credential exposure (API keys in config)
- Network exposure (public-facing ports)
- Session management
- MCP server config
- Audit logging
- Prompt injection surface
"""

import hashlib
import json
import os
import re
import stat
import subprocess
from pathlib import Path
from typing import List, Optional, Dict, Set

from .base import BaseModule, Finding


class ConfigScanner(BaseModule):
    name = "config_scanner"
    description = "Configuration, credentials, network, and permission checks"

    EXCLUDED_DIRS: Set[str] = {
        "backups", "backup", ".git", "node_modules", "__pycache__",
        "sessions", "transcripts", ".cache",
    }

    OPENCLAW_MANAGED_PATTERNS: Set[str] = {
        "auth-profiles.json", "models.json", "credentials.json",
        "openclaw.json", "clawdbot.json",
    }

    CREDENTIAL_PATTERNS: Dict[str, str] = {
        "OpenAI API Key": r"sk-[A-Za-z0-9]{32,}",
        "Anthropic API Key": r"sk-ant-[A-Za-z0-9-]{32,}",
        "Google API Key": r"AIza[0-9A-Za-z-_]{35}",
        "Generic API Key": r"api[_-]?key['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9-_]{32,})",
        "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    }

    def scan(self, openclaw_path: str) -> List[Finding]:
        self._findings: List[Finding] = []
        self._seen_credential_hashes: Dict[str, str] = {}
        self._oc = Path(openclaw_path)

        self._check_file_permissions()
        self._check_credential_exposure()
        self._check_network_exposure()
        self._check_session_management()
        self._check_mcp_servers()
        self._check_audit_logging()
        self._check_prompt_injection_surface()

        return self._findings

    # ------------------------------------------------------------------
    def _add(self, severity: str, category: str, title: str,
             description: str, remediation: str,
             affected_path: Optional[str] = None) -> None:
        self._findings.append(Finding(
            severity=severity, category=category, title=title,
            description=description, remediation=remediation,
            affected_path=affected_path,
        ))

    def _is_excluded(self, path: Path, base: Path) -> bool:
        parts = set(path.relative_to(base).parts)
        return bool(parts & self.EXCLUDED_DIRS) or any(
            p.startswith("backup-") or p.startswith("safe-config")
            for p in path.relative_to(base).parts
        )

    def _filtered_glob(self, base: Path, pattern: str) -> List[Path]:
        return [p for p in base.glob(pattern)
                if p.is_file() and not self._is_excluded(p, base)]

    # --- Checks -------------------------------------------------------
    def _check_file_permissions(self) -> None:
        sensitive = [
            self._oc / "openclaw.json",
            self._oc / "config.json",
            Path.home() / ".env",
            Path.home() / ".openclaw" / ".env",
        ]
        for fp in sensitive:
            if not fp.exists():
                continue
            mode = fp.stat().st_mode
            if mode & stat.S_IROTH:
                self._add("CRITICAL", "File Permissions",
                          f"World-readable sensitive file: {fp.name}",
                          f"File {fp} is readable by all users (mode: {oct(mode)})",
                          f"Run: chmod 600 {fp}", str(fp))
            elif mode & stat.S_IRGRP:
                self._add("HIGH", "File Permissions",
                          f"Group-readable sensitive file: {fp.name}",
                          f"File {fp} is readable by group (mode: {oct(mode)})",
                          f"Run: chmod 600 {fp}", str(fp))

    def _check_credential_exposure(self) -> None:
        files = self._filtered_glob(self._oc, "**/*.json")
        files.extend(self._filtered_glob(self._oc, "**/*.yaml"))
        files.extend(self._filtered_glob(self._oc, "**/*.yml"))
        files.extend(p for p in Path.home().glob(".env*") if p.is_file())

        for cf in files:
            try:
                content = cf.read_text()
            except (PermissionError, UnicodeDecodeError):
                continue
            except Exception:
                continue

            for key_type, pattern in self.CREDENTIAL_PATTERNS.items():
                matches = re.findall(pattern, content)
                if not matches:
                    continue
                unique = []
                for m in matches:
                    kv = m if isinstance(m, str) else str(m)
                    kh = hashlib.sha256(kv.encode()).hexdigest()[:16]
                    if kh not in self._seen_credential_hashes:
                        self._seen_credential_hashes[kh] = str(cf)
                        unique.append(m)
                if not unique:
                    continue

                fst = cf.stat()
                world_r = bool(fst.st_mode & stat.S_IROTH)
                managed = cf.name in self.OPENCLAW_MANAGED_PATTERNS
                owner_only = not (fst.st_mode & (stat.S_IRGRP | stat.S_IROTH))

                if world_r:
                    sev = "CRITICAL"
                elif managed and owner_only:
                    sev = "INFO"
                else:
                    sev = "HIGH"

                note = " (OpenClaw-managed auth file, permissions OK)" if managed and owner_only else ""
                self._add(sev, "Credential Exposure",
                          f"{key_type} found in config{note} ({len(unique)} unique key(s))",
                          f"Found {len(matches)} {key_type}(s) in {cf}. "
                          f"{'FILE IS WORLD-READABLE!' if world_r else 'File has weak permissions.'}",
                          "Use environment variables or encrypted secret management. "
                          "Remove keys from config files and rotate exposed keys immediately.",
                          str(cf))

    def _check_network_exposure(self) -> None:
        ports = [(8080, "OpenClaw Admin"), (8443, "OpenClaw HTTPS"),
                 (5000, "Flask Debug"), (3000, "Development Server")]
        try:
            try:
                r = subprocess.run(["ss", "-tlnp"], capture_output=True, text=True, timeout=5)
                out = r.stdout
            except FileNotFoundError:
                r = subprocess.run(["netstat", "-tlnp"], capture_output=True, text=True, timeout=5)
                out = r.stdout

            for port, svc in ports:
                if f"0.0.0.0:{port}" in out or f":::{port}" in out:
                    self._add("CRITICAL", "Network Exposure",
                              f"{svc} exposed on public interface",
                              f"Port {port} ({svc}) is listening on 0.0.0.0",
                              f"Bind to localhost (127.0.0.1:{port}) or a VPN IP.",
                              f"0.0.0.0:{port}")
        except Exception:
            pass

    def _check_session_management(self) -> None:
        for sf in [self._oc / "sessions.json", self._oc / "tokens.db",
                   Path.home() / ".config" / "claude" / "settings.json"]:
            if not sf.exists():
                continue
            mode = sf.stat().st_mode
            if mode & (stat.S_IROTH | stat.S_IRGRP):
                self._add("CRITICAL", "Session Management",
                          f"Session file has weak permissions: {sf.name}",
                          f"Session tokens in {sf} are readable by other users",
                          f"Run: chmod 600 {sf}", str(sf))

    def _check_mcp_servers(self) -> None:
        cfg = self._load_json(str(self._oc / "mcp.json"))
        if not cfg:
            return
        for name, sc in cfg.get("mcpServers", {}).items():
            url = sc.get("url", "")
            if url.startswith("http://") and not url.startswith("http://localhost"):
                self._add("HIGH", "MCP Security",
                          f"MCP server using unencrypted HTTP: {name}",
                          f"Server '{name}' uses HTTP: {url}",
                          "Use HTTPS for remote MCP servers", str(self._oc / "mcp.json"))
            if any(d in name.lower() for d in ("eval", "exec")):
                if not sc.get("requireConfirmation", False):
                    self._add("MEDIUM", "MCP Security",
                              f"Potentially dangerous MCP server: {name}",
                              f"Server '{name}' may provide code execution capabilities",
                              "Review permissions", str(self._oc / "mcp.json"))

    def _check_audit_logging(self) -> None:
        cfg = self._load_json(str(self._oc / "openclaw.json"))
        if cfg is None:
            self._add("MEDIUM", "Audit Logging", "OpenClaw config not found",
                      "Cannot verify audit logging configuration",
                      "Ensure OpenClaw is properly configured")
            return
        al = cfg.get("auditLogging", {})
        if not al.get("enabled", False):
            self._add("MEDIUM", "Audit Logging", "Audit logging is disabled",
                      "Audit logging is not enabled",
                      "Enable audit logging to track all AI actions",
                      str(self._oc / "openclaw.json"))

    def _check_prompt_injection_surface(self) -> None:
        cfg = self._load_json(str(self._oc / "openclaw.json"))
        if not cfg:
            return
        if "systemPrompt" in cfg or "system_prompt" in cfg:
            self._add("HIGH", "Prompt Injection",
                      "System prompt exposed in config file",
                      "System prompt is stored in config file",
                      "Move system prompt to application code",
                      str(self._oc / "openclaw.json"))
        for tn, tc in cfg.get("tools", {}).items():
            if any(d in tn.lower() for d in ("exec", "shell", "eval", "browser")):
                if not tc.get("requireConfirmation", False):
                    self._add("MEDIUM", "Prompt Injection",
                              f"Dangerous tool without confirmation: {tn}",
                              f"Tool '{tn}' can execute code without confirmation",
                              "Enable confirmation for dangerous tools",
                              str(self._oc / "openclaw.json"))
