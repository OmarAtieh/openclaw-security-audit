"""Module — Comprehensive Permission Auditing.

Checks file permissions on:
- Config files (openclaw.json, .env, etc.)
- Secret storage (credentials, tokens, keys)
- Skill directories
- Agent identity files
- Audit logs
- Database files
"""

import os
import stat
from pathlib import Path
from typing import List, Optional, Dict

from .base import BaseModule, Finding


class PermissionAuditorModule(BaseModule):
    name = "permission_auditor"
    description = "File and directory permission security audit"
    
    # Files that MUST have 600 (owner read/write only)
    CRITICAL_FILES = {
        "openclaw.json",
        "config.json",
        ".env",
        "credentials.json",
        "auth-profiles.json",
        "tokens.db",
        "sessions.json",
    }
    
    # Directories that should have 700 (owner access only)
    SENSITIVE_DIRS = {
        "secrets",
        "credentials",
        "sessions",
        ".ssh",
    }
    
    def scan(self, openclaw_path: str) -> List[Finding]:
        self._findings: List[Finding] = []
        self._oc = Path(openclaw_path)
        
        self._check_config_permissions()
        self._check_secrets_permissions()
        self._check_skill_permissions()
        self._check_log_permissions()
        self._check_directory_permissions()
        self._check_home_env_files()
        
        return self._findings
    
    def _add(self, severity: str, category: str, title: str,
             description: str, remediation: str,
             affected_path: Optional[str] = None) -> None:
        self._findings.append(Finding(
            severity=severity, category=category, title=title,
            description=description, remediation=remediation,
            affected_path=affected_path,
        ))
    
    def _check_file_perms(self, file_path: Path, expected_mode: int,
                          severity: str = "HIGH",
                          category: str = "Permission Audit") -> None:
        """Check a single file's permissions against expected mode."""
        if not file_path.exists():
            return
        
        try:
            stat_info = file_path.stat()
            actual_mode = stat.S_IMODE(stat_info.st_mode)
            
            # Check if more permissive than expected
            if actual_mode & ~expected_mode:
                extra_perms = actual_mode & ~expected_mode
                
                # Determine severity based on what permissions are exposed
                if extra_perms & (stat.S_IROTH | stat.S_IWOTH):
                    actual_sev = "CRITICAL"
                elif extra_perms & (stat.S_IRGRP | stat.S_IWGRP):
                    actual_sev = "HIGH"
                else:
                    actual_sev = severity
                
                self._add(actual_sev, category,
                         f"Weak permissions on {file_path.name}",
                         f"File {file_path} has mode {oct(actual_mode)} "
                         f"(expected {oct(expected_mode)}). "
                         f"Extra permissions: {oct(extra_perms)}",
                         f"Run: chmod {oct(expected_mode)[-3:]} {file_path}",
                         str(file_path))
        except (PermissionError, OSError) as e:
            self._add("MEDIUM", category,
                     f"Cannot check permissions: {file_path.name}",
                     f"Permission denied checking {file_path}: {e}",
                     "Ensure audit tool has read access to security-relevant files.",
                     str(file_path))
    
    def _check_config_permissions(self) -> None:
        """Check permissions on config files."""
        for filename in self.CRITICAL_FILES:
            file_path = self._oc / filename
            if file_path.exists():
                self._check_file_perms(file_path, 0o600, "CRITICAL")
    
    def _check_secrets_permissions(self) -> None:
        """Check permissions on secret storage files."""
        # Check for credential files in various locations
        credential_patterns = [
            self._oc / "*.key",
            self._oc / "*.pem",
            self._oc / "*.cert",
            self._oc / "secrets" / "*",
            Path.home() / ".config" / "claude" / "settings.json",
        ]
        
        for pattern in credential_patterns:
            if "*" in str(pattern):
                parent = pattern.parent
                glob_pattern = pattern.name
                if parent.exists():
                    for file_path in parent.glob(glob_pattern):
                        if file_path.is_file():
                            self._check_file_perms(file_path, 0o600, "CRITICAL")
            else:
                self._check_file_perms(pattern, 0o600, "CRITICAL")
    
    def _check_skill_permissions(self) -> None:
        """Check permissions on skill directories."""
        skills_dir = self._oc / "skills"
        if not skills_dir.exists():
            return
        
        for skill_path in skills_dir.iterdir():
            if not skill_path.is_dir():
                continue
            
            # Check if skill directory is world-writable
            try:
                stat_info = skill_path.stat()
                mode = stat.S_IMODE(stat_info.st_mode)
                
                if mode & stat.S_IWOTH:
                    self._add("CRITICAL", "Permission Audit",
                             f"Skill directory is world-writable: {skill_path.name}",
                             f"Directory {skill_path} can be modified by any user (mode: {oct(mode)}). "
                             "This allows malicious code injection.",
                             f"Run: chmod 755 {skill_path}",
                             str(skill_path))
                
                # Check executable scripts in skill
                for script_file in skill_path.rglob("*.sh"):
                    if script_file.is_file():
                        script_stat = script_file.stat()
                        script_mode = stat.S_IMODE(script_stat.st_mode)
                        
                        if script_mode & stat.S_IWOTH:
                            self._add("HIGH", "Permission Audit",
                                     f"World-writable script: {script_file.relative_to(skills_dir)}",
                                     f"Script {script_file} can be modified by any user.",
                                     f"Run: chmod 750 {script_file}",
                                     str(script_file))
            except (PermissionError, OSError):
                continue
    
    def _check_log_permissions(self) -> None:
        """Check permissions on audit logs."""
        log_patterns = [
            self._oc / "logs" / "*.log",
            self._oc / "audit" / "*.log",
            self._oc / "audit.log",
        ]
        
        for pattern in log_patterns:
            if "*" in str(pattern):
                parent = pattern.parent
                glob_pattern = pattern.name
                if parent.exists():
                    for log_file in parent.glob(glob_pattern):
                        if log_file.is_file():
                            # Logs should be readable by owner only
                            self._check_file_perms(log_file, 0o600, "MEDIUM")
            else:
                self._check_file_perms(pattern, 0o600, "MEDIUM")
    
    def _check_directory_permissions(self) -> None:
        """Check permissions on sensitive directories."""
        for dirname in self.SENSITIVE_DIRS:
            dir_path = self._oc / dirname
            if not dir_path.exists():
                continue
            
            try:
                stat_info = dir_path.stat()
                mode = stat.S_IMODE(stat_info.st_mode)
                
                # Directory should be 700 (owner access only)
                if mode & (stat.S_IRWXG | stat.S_IRWXO):
                    severity = "CRITICAL" if mode & stat.S_IRWXO else "HIGH"
                    self._add(severity, "Permission Audit",
                             f"Sensitive directory has weak permissions: {dirname}",
                             f"Directory {dir_path} has mode {oct(mode)} (should be 700)",
                             f"Run: chmod 700 {dir_path}",
                             str(dir_path))
            except (PermissionError, OSError):
                continue
    
    def _check_home_env_files(self) -> None:
        """Check .env files in home directory."""
        home = Path.home()
        env_patterns = [
            ".env",
            ".env.local",
            ".env.production",
            ".clawdbot/.env",
        ]
        
        for pattern in env_patterns:
            env_file = home / pattern
            if env_file.exists():
                self._check_file_perms(env_file, 0o600, "CRITICAL",
                                      "Environment Variable Security")
