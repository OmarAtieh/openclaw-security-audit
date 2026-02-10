"""Module — OpenClaw Configuration Hardening Checks.

Verifies openclaw.json follows security best practices specific to OpenClaw:
- Exec security mode (deny/allowlist/full)
- Tool allowlists and confirmation requirements
- Provider key exposure prevention
- Agent identity integrity
- Skill allowlisting
- Network binding security
"""

import json
import os
from pathlib import Path
from typing import List, Dict, Any, Optional

from .base import BaseModule, Finding


class ConfigHardeningModule(BaseModule):
    name = "config_hardening"
    description = "OpenClaw configuration security best practices"

    # Security best practices for OpenClaw
    DANGEROUS_TOOLS = {
        "exec", "shell", "eval", "browser", "filesystem_write",
        "nodes", "canvas", "message"
    }
    
    RECOMMENDED_EXEC_MODES = {"deny", "allowlist"}
    
    def scan(self, openclaw_path: str) -> List[Finding]:
        self._findings: List[Finding] = []
        self._oc = Path(openclaw_path)
        
        # Load openclaw.json
        config_path = self._oc / "openclaw.json"
        self._config = self._load_json(str(config_path))
        
        if not self._config:
            self._add("HIGH", "Configuration",
                     "OpenClaw configuration file not found",
                     f"Could not load {config_path}. Cannot verify security settings.",
                     "Ensure openclaw.json exists and is valid JSON.",
                     str(config_path))
            return self._findings
        
        self._check_exec_security_mode()
        self._check_tool_confirmation()
        self._check_provider_keys()
        self._check_agent_identity()
        self._check_skill_security()
        self._check_network_binding()
        self._check_audit_config()
        
        return self._findings
    
    def _add(self, severity: str, category: str, title: str,
             description: str, remediation: str,
             affected_path: Optional[str] = None) -> None:
        self._findings.append(Finding(
            severity=severity, category=category, title=title,
            description=description, remediation=remediation,
            affected_path=affected_path,
        ))
    
    def _check_exec_security_mode(self) -> None:
        """Check exec tool security mode configuration."""
        exec_config = self._config.get("exec", {})
        security_mode = exec_config.get("security", "full")
        
        if security_mode == "full":
            self._add("CRITICAL", "Config Hardening",
                     "Exec security mode set to 'full' (unrestricted)",
                     "The exec tool is configured with 'full' security mode, "
                     "allowing unrestricted command execution. This is extremely dangerous.",
                     "Set exec.security to 'deny' or 'allowlist' in openclaw.json. "
                     "Use allowlist mode to explicitly permit required commands only.",
                     str(self._oc / "openclaw.json"))
        elif security_mode not in self.RECOMMENDED_EXEC_MODES:
            self._add("HIGH", "Config Hardening",
                     f"Unknown exec security mode: {security_mode}",
                     f"Exec security mode '{security_mode}' is not a recognized value.",
                     "Set exec.security to 'deny' or 'allowlist'.",
                     str(self._oc / "openclaw.json"))
        
        # Check if allowlist mode has actual allowlist
        if security_mode == "allowlist":
            allowlist = exec_config.get("allowlist", [])
            if not allowlist:
                self._add("HIGH", "Config Hardening",
                         "Exec allowlist mode enabled but allowlist is empty",
                         "Exec security is set to allowlist mode but no commands are allowed.",
                         "Add allowed commands to exec.allowlist or use 'deny' mode.",
                         str(self._oc / "openclaw.json"))
            else:
                # Check for overly permissive patterns
                dangerous_patterns = ["/bin/sh", "/bin/bash", "sh -c", "eval"]
                for pattern in allowlist:
                    if any(d in str(pattern).lower() for d in dangerous_patterns):
                        self._add("MEDIUM", "Config Hardening",
                                 f"Overly permissive exec allowlist pattern: {pattern}",
                                 "The exec allowlist contains a pattern that may allow shell execution.",
                                 "Use specific command paths instead of shell interpreters.",
                                 str(self._oc / "openclaw.json"))
                        break
    
    def _check_tool_confirmation(self) -> None:
        """Check that dangerous tools require confirmation."""
        tools_config = self._config.get("tools", {})
        
        for tool_name in self.DANGEROUS_TOOLS:
            if tool_name in tools_config:
                tool_cfg = tools_config[tool_name]
                if isinstance(tool_cfg, dict):
                    requires_confirm = tool_cfg.get("requireConfirmation", False)
                    if not requires_confirm:
                        self._add("MEDIUM", "Config Hardening",
                                 f"Dangerous tool '{tool_name}' does not require confirmation",
                                 f"Tool '{tool_name}' can execute potentially harmful actions without user confirmation.",
                                 f"Add 'requireConfirmation: true' to tools.{tool_name} in openclaw.json.",
                                 str(self._oc / "openclaw.json"))
    
    def _check_provider_keys(self) -> None:
        """Check for API keys in config file (should use env vars)."""
        providers_config = self._config.get("providers", {})
        
        for provider_name, provider_cfg in providers_config.items():
            if isinstance(provider_cfg, dict):
                # Check for common key field names
                key_fields = ["apiKey", "api_key", "key", "token", "secret"]
                for field in key_fields:
                    if field in provider_cfg:
                        value = provider_cfg[field]
                        if value and isinstance(value, str) and not value.startswith("${"):
                            self._add("CRITICAL", "Config Hardening",
                                     f"Provider API key stored in plaintext: {provider_name}",
                                     f"Provider '{provider_name}' has API key stored directly in config file.",
                                     f"Move API key to environment variable and use ${{ENV_VAR}} syntax. "
                                     f"Rotate the exposed key immediately.",
                                     str(self._oc / "openclaw.json"))
    
    def _check_agent_identity(self) -> None:
        """Check agent identity file integrity."""
        agent_config = self._config.get("agent", {})
        identity_file = agent_config.get("identityFile")
        
        if identity_file:
            identity_path = self._oc / identity_file
            if not identity_path.exists():
                self._add("HIGH", "Config Hardening",
                         "Agent identity file not found",
                         f"Configured identity file '{identity_file}' does not exist.",
                         "Verify identity file path or remove identityFile from config.",
                         str(identity_path))
            else:
                # Check permissions
                mode = identity_path.stat().st_mode
                if mode & 0o077:  # Group or world readable/writable
                    self._add("HIGH", "Config Hardening",
                             "Agent identity file has weak permissions",
                             f"Identity file {identity_file} is accessible to other users.",
                             f"Run: chmod 600 {identity_path}",
                             str(identity_path))
        
        # Check for integrity monitoring
        integrity_enabled = agent_config.get("integrityCheck", False)
        if not integrity_enabled:
            self._add("MEDIUM", "Config Hardening",
                     "Agent identity integrity check disabled",
                     "Identity file integrity monitoring is not enabled.",
                     "Enable agent.integrityCheck in openclaw.json to detect tampering.",
                     str(self._oc / "openclaw.json"))
    
    def _check_skill_security(self) -> None:
        """Check skill installation and execution security."""
        skills_config = self._config.get("skills", {})
        
        # Check if skill allowlisting is enabled
        allowlist_mode = skills_config.get("allowlistMode", False)
        if not allowlist_mode:
            self._add("MEDIUM", "Config Hardening",
                     "Skill allowlist mode not enabled",
                     "Skills are not restricted to an allowlist. Any skill can be installed.",
                     "Enable skills.allowlistMode and define skills.allowlist in openclaw.json.",
                     str(self._oc / "openclaw.json"))
        else:
            allowlist = skills_config.get("allowlist", [])
            if not allowlist:
                self._add("LOW", "Config Hardening",
                         "Skill allowlist is empty",
                         "Allowlist mode is enabled but no skills are permitted.",
                         "Add trusted skill IDs to skills.allowlist.",
                         str(self._oc / "openclaw.json"))
        
        # Check for auto-update behavior
        auto_update = skills_config.get("autoUpdate", True)
        if auto_update:
            self._add("LOW", "Config Hardening",
                     "Skill auto-update enabled",
                     "Skills will automatically update, potentially introducing new vulnerabilities.",
                     "Set skills.autoUpdate to false for manual review before updates.",
                     str(self._oc / "openclaw.json"))
    
    def _check_network_binding(self) -> None:
        """Check network listener binding configuration."""
        server_config = self._config.get("server", {})
        
        # Check listen address
        listen = server_config.get("listen", "127.0.0.1")
        if listen == "0.0.0.0" or listen == "::":
            port = server_config.get("port", "unknown")
            self._add("CRITICAL", "Config Hardening",
                     "Server bound to all interfaces (0.0.0.0)",
                     f"OpenClaw server is listening on all network interfaces (port {port}). "
                     "This exposes the admin interface to the network.",
                     "Set server.listen to '127.0.0.1' for localhost-only access, "
                     "or bind to a specific Tailscale/VPN IP.",
                     str(self._oc / "openclaw.json"))
        
        # Check if TLS is enabled for non-localhost
        if listen not in ["127.0.0.1", "localhost", "::1"]:
            tls_enabled = server_config.get("tls", {}).get("enabled", False)
            if not tls_enabled:
                self._add("HIGH", "Config Hardening",
                         "Server exposed on network without TLS",
                         f"Server is listening on {listen} without TLS encryption.",
                         "Enable server.tls.enabled and configure certificates.",
                         str(self._oc / "openclaw.json"))
    
    def _check_audit_config(self) -> None:
        """Check audit logging configuration."""
        audit_config = self._config.get("audit", {})
        
        enabled = audit_config.get("enabled", False)
        if not enabled:
            self._add("MEDIUM", "Config Hardening",
                     "Audit logging is disabled",
                     "No audit trail is being recorded for agent actions.",
                     "Enable audit.enabled in openclaw.json for accountability.",
                     str(self._oc / "openclaw.json"))
        else:
            # Check log retention
            retention_days = audit_config.get("retentionDays")
            if retention_days is None or retention_days < 30:
                self._add("LOW", "Config Hardening",
                         "Audit log retention too short",
                         f"Audit logs are retained for only {retention_days} days. "
                         "Insufficient for forensic analysis.",
                         "Set audit.retentionDays to at least 90 for compliance.",
                         str(self._oc / "openclaw.json"))
            
            # Check if sensitive data is logged
            log_prompts = audit_config.get("logPrompts", True)
            if log_prompts:
                self._add("INFO", "Config Hardening",
                         "Audit logging includes full prompts",
                         "User prompts are being logged, which may include sensitive information.",
                         "Consider setting audit.logPrompts to false if handling PII/secrets.",
                         str(self._oc / "openclaw.json"))
