#!/usr/bin/env python3
"""
OpenClaw Security Audit Tool
Comprehensive security scanner for OpenClaw deployments
"""

import json
import os
import re
import stat
import socket
import hashlib
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any
from datetime import datetime
from dataclasses import dataclass, asdict


VERSION = "1.0.0"


@dataclass
class Finding:
    """Security finding with severity and details"""
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    category: str
    title: str
    description: str
    remediation: str
    affected_path: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class SecurityAuditor:
    """Main security auditor class"""
    
    SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    SEVERITY_COLORS = {
        "CRITICAL": "\033[91m",  # Red
        "HIGH": "\033[93m",      # Yellow
        "MEDIUM": "\033[94m",    # Blue
        "LOW": "\033[96m",       # Cyan
        "INFO": "\033[92m",      # Green
    }
    RESET_COLOR = "\033[0m"
    
    # Directories to exclude from recursive scanning (backups, caches, git)
    EXCLUDED_DIRS = {"backups", "backup", ".git", "node_modules", "__pycache__", 
                     "sessions", "transcripts", ".cache"}
    
    def __init__(self, openclaw_dir: Optional[str] = None):
        self.findings: List[Finding] = []
        self.openclaw_dir = Path(openclaw_dir or os.path.expanduser("~/.openclaw"))
        self.scan_timestamp = datetime.now().astimezone().isoformat()
        self._seen_credential_hashes: Dict[str, str] = {}  # hash → first_path for dedup
        self.load_malicious_db()
        
    def load_malicious_db(self) -> None:
        """Load known malicious skill database"""
        db_path = Path(__file__).parent / "known_malicious.json"
        try:
            with open(db_path) as f:
                self.malicious_db = json.load(f)
        except FileNotFoundError:
            self.malicious_db = {"skills": [], "hashes": []}
    
    def _is_excluded_path(self, path: Path) -> bool:
        """Check if path is in an excluded directory (backups, caches, etc.)"""
        parts = set(path.parts)
        return bool(parts & self.EXCLUDED_DIRS) or any(
            p.startswith("backup-") or p.startswith("safe-config") 
            for p in path.parts
        )
    
    def _filtered_glob(self, base: Path, pattern: str) -> List[Path]:
        """Glob with exclusion of backup/cache directories"""
        return [p for p in base.glob(pattern) 
                if p.is_file() and not self._is_excluded_path(p.relative_to(base))]
            
    def add_finding(self, severity: str, category: str, title: str, 
                   description: str, remediation: str, 
                   affected_path: Optional[str] = None):
        """Add a security finding"""
        self.findings.append(Finding(
            severity=severity,
            category=category,
            title=title,
            description=description,
            remediation=remediation,
            affected_path=affected_path
        ))
        
    def check_file_permissions(self):
        """Check file permissions on sensitive files"""
        sensitive_files = [
            self.openclaw_dir / "openclaw.json",
            self.openclaw_dir / "config.json",
            Path.home() / ".env",
            Path.home() / ".openclaw" / ".env",
        ]
        
        for filepath in sensitive_files:
            if not filepath.exists():
                continue
                
            file_stat = filepath.stat()
            mode = file_stat.st_mode
            
            # Check if world-readable
            if mode & stat.S_IROTH:
                self.add_finding(
                    "CRITICAL",
                    "File Permissions",
                    f"World-readable sensitive file: {filepath.name}",
                    f"File {filepath} is readable by all users (mode: {oct(mode)})",
                    f"Run: chmod 600 {filepath}",
                    str(filepath)
                )
                
            # Check if group-readable
            elif mode & stat.S_IRGRP:
                self.add_finding(
                    "HIGH",
                    "File Permissions",
                    f"Group-readable sensitive file: {filepath.name}",
                    f"File {filepath} is readable by group (mode: {oct(mode)})",
                    f"Run: chmod 600 {filepath}",
                    str(filepath)
                )
                
    # Files managed by OpenClaw's internal auth/config system — keys here are by-design
    OPENCLAW_MANAGED_PATTERNS = {"auth-profiles.json", "models.json", "credentials.json", 
                                  "openclaw.json", "clawdbot.json"}
    
    def check_credential_exposure(self):
        """Check for exposed API keys and credentials"""
        patterns = {
            "OpenAI API Key": r"sk-[A-Za-z0-9]{32,}",
            "Anthropic API Key": r"sk-ant-[A-Za-z0-9-]{32,}",
            "Google API Key": r"AIza[0-9A-Za-z-_]{35}",
            "Generic API Key": r"api[_-]?key['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9-_]{32,})",
            "AWS Access Key": r"AKIA[0-9A-Z]{16}",
        }
        
        config_files = self._filtered_glob(self.openclaw_dir, "**/*.json")
        config_files.extend(self._filtered_glob(self.openclaw_dir, "**/*.yaml"))
        config_files.extend(self._filtered_glob(self.openclaw_dir, "**/*.yml"))
        config_files.extend(p for p in Path.home().glob(".env*") if p.is_file())
        
        for config_file in config_files:
            try:
                content = config_file.read_text()
                
                for key_type, pattern in patterns.items():
                    matches = re.findall(pattern, content)
                    if matches:
                        # Deduplicate: only report each unique key once
                        unique_new = []
                        for match in matches:
                            key_val = match if isinstance(match, str) else str(match)
                            key_hash = hashlib.sha256(key_val.encode()).hexdigest()[:16]
                            if key_hash not in self._seen_credential_hashes:
                                self._seen_credential_hashes[key_hash] = str(config_file)
                                unique_new.append(match)
                        
                        if not unique_new:
                            continue  # All keys already reported from another file
                        
                        # Check file permissions
                        file_stat = config_file.stat()
                        is_world_readable = file_stat.st_mode & stat.S_IROTH
                        is_managed = config_file.name in self.OPENCLAW_MANAGED_PATTERNS
                        is_owner_only = not (file_stat.st_mode & (stat.S_IRGRP | stat.S_IROTH))
                        
                        # Severity: world-readable = CRITICAL, managed+owner-only = INFO, else HIGH
                        if is_world_readable:
                            severity = "CRITICAL"
                        elif is_managed and is_owner_only:
                            severity = "INFO"  # OpenClaw-managed, permissions correct
                        else:
                            severity = "HIGH"
                        
                        managed_note = " (OpenClaw-managed auth file, permissions OK)" if is_managed and is_owner_only else ""
                        self.add_finding(
                            severity,
                            "Credential Exposure",
                            f"{key_type} found in config{managed_note} ({len(unique_new)} unique key(s))",
                            f"Found {len(matches)} {key_type}(s) in {config_file}. "
                            f"{'FILE IS WORLD-READABLE!' if is_world_readable else 'File has weak permissions.'}",
                            "Use environment variables or encrypted secret management. "
                            "Remove keys from config files and rotate exposed keys immediately.",
                            str(config_file)
                        )
            except PermissionError:
                self.add_finding("INFO", "Scan Limitation",
                    f"Cannot read file: {config_file.name}",
                    f"Permission denied reading {config_file}",
                    "Verify file permissions or run audit as file owner",
                    str(config_file))
            except UnicodeDecodeError:
                pass  # Binary files — expected, skip
            except Exception as e:
                self.add_finding("INFO", "Scan Limitation",
                    f"Error scanning {config_file.name}",
                    f"Unexpected error: {type(e).__name__}: {e}",
                    "Review file manually", str(config_file))
                
    def check_network_exposure(self):
        """Check for admin ports listening on public interfaces"""
        dangerous_ports = [
            (8080, "OpenClaw Admin"),
            (8443, "OpenClaw HTTPS"),
            (5000, "Flask Debug"),
            (3000, "Development Server"),
        ]
        
        try:
            # Use netstat or ss to check listening ports
            try:
                result = subprocess.run(
                    ["ss", "-tlnp"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                netstat_output = result.stdout
            except FileNotFoundError:
                result = subprocess.run(
                    ["netstat", "-tlnp"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                netstat_output = result.stdout
                
            for port, service in dangerous_ports:
                # Check for 0.0.0.0:port or :::port (public binding)
                if f"0.0.0.0:{port}" in netstat_output or f":::{port}" in netstat_output:
                    # Check if Tailscale is available for recommendation
                    tailscale_rec = ""
                    try:
                        ts = subprocess.run(["tailscale", "ip", "-4"], 
                                          capture_output=True, text=True, timeout=3)
                        if ts.returncode == 0:
                            ts_ip = ts.stdout.strip()
                            tailscale_rec = (f" Best practice: bind to Tailscale IP ({ts_ip}) "
                                           f"for private VPN-only access. ")
                    except (FileNotFoundError, subprocess.TimeoutExpired):
                        pass
                    
                    self.add_finding(
                        "CRITICAL",
                        "Network Exposure",
                        f"{service} exposed on public interface",
                        f"Port {port} ({service}) is listening on 0.0.0.0, making it accessible "
                        f"from any network interface including the public internet.",
                        f"Bind to localhost (127.0.0.1:{port}) or a VPN IP.{tailscale_rec}"
                        f"Additionally, verify UFW/iptables rules block external access to port {port}.",
                        f"0.0.0.0:{port}"
                    )
        except Exception as e:
            self.add_finding(
                "INFO",
                "Network Exposure",
                "Could not check network exposure",
                f"Failed to run netstat/ss: {e}",
                "Manually verify listening ports with 'ss -tlnp' or 'netstat -tlnp'",
                None
            )
            
    def check_ioc_connections(self) -> None:
        """Check for active connections to known malicious IPs/domains"""
        malicious_ips = set(self.malicious_db.get("iocs", {}).get("ips", []))
        if not malicious_ips:
            return
        
        try:
            result = subprocess.run(["ss", "-tnp"], capture_output=True, text=True, timeout=5)
            for line in result.stdout.strip().split("\n"):
                for ip in malicious_ips:
                    if ip in line:
                        self.add_finding(
                            "CRITICAL",
                            "Active Threat",
                            f"Connection to known malicious IP: {ip}",
                            f"Active network connection detected to {ip}, a known C2/malware server. "
                            f"This may indicate an active compromise.",
                            f"Immediately block: sudo ufw deny out to {ip}. "
                            f"Kill the process, rotate all credentials, investigate.",
                            ip
                        )
        except Exception:
            pass  # Non-critical if ss unavailable
    
    def check_skill_integrity(self):
        """Check installed skills for tampering"""
        skills_dir = self.openclaw_dir / "skills"
        
        if not skills_dir.exists():
            return
            
        for skill_dir in skills_dir.iterdir():
            if not skill_dir.is_dir():
                continue
                
            # Check for SKILL.md (required for legitimate skills)
            skill_md = skill_dir / "SKILL.md"
            if not skill_md.exists():
                self.add_finding(
                    "MEDIUM",
                    "Skill Integrity",
                    f"Skill missing SKILL.md: {skill_dir.name}",
                    f"Skill {skill_dir.name} does not have a SKILL.md file, which is required for legitimate skills",
                    f"Verify the skill's authenticity or remove it: rm -rf {skill_dir}",
                    str(skill_dir)
                )
                
            # Check against known malicious skills (by name and author)
            skill_name = skill_dir.name
            known_names = {s["name"] for s in self.malicious_db.get("skills", []) if isinstance(s, dict)}
            if skill_name in known_names:
                match = next((s for s in self.malicious_db["skills"] if s.get("name") == skill_name), {})
                self.add_finding(
                    "CRITICAL",
                    "Malicious Skill",
                    f"Known malicious skill detected: {skill_name}",
                    f"Skill '{skill_name}' matches known malicious skill. "
                    f"Threat: {match.get('threat', 'unknown')}. "
                    f"Source: {match.get('source', 'unknown')}.",
                    f"IMMEDIATELY remove this skill: rm -rf {skill_dir}. "
                    "Rotate all API keys and review audit logs for unauthorized access.",
                    str(skill_dir)
                )
            
            # Scan SKILL.md for malicious patterns (command injection, downloads)
            if skill_md.exists():
                try:
                    content = skill_md.read_text().lower()
                    for pattern in self.malicious_db.get("malicious_patterns", {}).get("skill_md_patterns", []):
                        if pattern.lower() in content:
                            self.add_finding(
                                "CRITICAL",
                                "Malicious Skill",
                                f"Dangerous pattern in {skill_name}/SKILL.md: '{pattern}'",
                                f"SKILL.md contains command pattern '{pattern}' commonly used in supply chain attacks. "
                                f"This pattern was seen in the Feb 2026 ClawHub malware campaign.",
                                f"Do NOT follow instructions in this SKILL.md. Review manually. "
                                f"If suspicious, remove: rm -rf {skill_dir}",
                                str(skill_md)
                            )
                            break  # One finding per skill is enough
                except Exception:
                    pass
                
            # Check file hashes for known malicious code
            for file in skill_dir.rglob("*.py"):
                try:
                    file_hash = hashlib.sha256(file.read_bytes()).hexdigest()
                    if file_hash in self.malicious_db.get("hashes", []):
                        self.add_finding(
                            "CRITICAL",
                            "Malicious Skill",
                            f"Malicious code detected: {file.name}",
                            f"File {file} matches known malicious signature (SHA256: {file_hash[:16]}...)",
                            f"IMMEDIATELY remove this file and investigate: rm {file}",
                            str(file)
                        )
                except Exception:
                    pass
                    
    def check_session_management(self):
        """Check session token security"""
        session_files = [
            self.openclaw_dir / "sessions.json",
            self.openclaw_dir / "tokens.db",
            Path.home() / ".config" / "claude" / "settings.json",
        ]
        
        for session_file in session_files:
            if not session_file.exists():
                continue
                
            file_stat = session_file.stat()
            mode = file_stat.st_mode
            
            if mode & (stat.S_IROTH | stat.S_IRGRP):
                self.add_finding(
                    "CRITICAL",
                    "Session Management",
                    f"Session file has weak permissions: {session_file.name}",
                    f"Session tokens in {session_file} are readable by other users",
                    f"Run: chmod 600 {session_file}",
                    str(session_file)
                )
                
    def check_mcp_servers(self):
        """Check MCP server configuration"""
        mcp_config = self.openclaw_dir / "mcp.json"
        
        if not mcp_config.exists():
            return
            
        try:
            with open(mcp_config) as f:
                config = json.load(f)
                
            servers = config.get("mcpServers", {})
            for server_name, server_config in servers.items():
                # Check for insecure transport
                url = server_config.get("url", "")
                if url.startswith("http://") and not url.startswith("http://localhost"):
                    self.add_finding(
                        "HIGH",
                        "MCP Security",
                        f"MCP server using unencrypted HTTP: {server_name}",
                        f"Server '{server_name}' uses HTTP instead of HTTPS: {url}",
                        f"Use HTTPS for remote MCP servers or ensure they're localhost-only",
                        str(mcp_config)
                    )
                    
                # Check for unauthorized servers (basic heuristic)
                if "eval" in server_name.lower() or "exec" in server_name.lower():
                    self.add_finding(
                        "MEDIUM",
                        "MCP Security",
                        f"Potentially dangerous MCP server: {server_name}",
                        f"Server '{server_name}' may provide code execution capabilities",
                        "Review this server's permissions and ensure it's intentional",
                        str(mcp_config)
                    )
        except Exception as e:
            pass
            
    def check_audit_logging(self):
        """Check if audit logging is enabled and secure"""
        config_file = self.openclaw_dir / "openclaw.json"
        
        if not config_file.exists():
            self.add_finding(
                "MEDIUM",
                "Audit Logging",
                "OpenClaw config not found",
                "Cannot verify audit logging configuration",
                "Ensure OpenClaw is properly configured",
                None
            )
            return
            
        try:
            with open(config_file) as f:
                config = json.load(f)
                
            audit_enabled = config.get("auditLogging", {}).get("enabled", False)
            
            if not audit_enabled:
                self.add_finding(
                    "MEDIUM",
                    "Audit Logging",
                    "Audit logging is disabled",
                    "Audit logging is not enabled in OpenClaw configuration",
                    "Enable audit logging to track all AI actions and tool calls",
                    str(config_file)
                )
            else:
                # Check log file permissions
                log_path = config.get("auditLogging", {}).get("path")
                if log_path:
                    log_file = Path(log_path)
                    if log_file.exists():
                        file_stat = log_file.stat()
                        if file_stat.st_mode & stat.S_IROTH:
                            self.add_finding(
                                "HIGH",
                                "Audit Logging",
                                "Audit logs are world-readable",
                                f"Audit log file {log_file} can be read by all users",
                                f"Run: chmod 640 {log_file}",
                                str(log_file)
                            )
        except Exception as e:
            pass
            
    def check_prompt_injection_surface(self):
        """Check for prompt injection vulnerabilities"""
        config_file = self.openclaw_dir / "openclaw.json"
        
        if not config_file.exists():
            return
            
        try:
            with open(config_file) as f:
                config = json.load(f)
                
            # Check if system prompt is in config (should be in code, not config)
            if "systemPrompt" in config or "system_prompt" in config:
                self.add_finding(
                    "HIGH",
                    "Prompt Injection",
                    "System prompt exposed in config file",
                    "System prompt is stored in config file where it can be easily modified",
                    "Move system prompt to application code, not configuration",
                    str(config_file)
                )
                
            # Check for unprotected tool access
            tools = config.get("tools", {})
            dangerous_tools = ["exec", "shell", "eval", "browser"]
            
            for tool_name, tool_config in tools.items():
                if any(danger in tool_name.lower() for danger in dangerous_tools):
                    if not tool_config.get("requireConfirmation", False):
                        self.add_finding(
                            "MEDIUM",
                            "Prompt Injection",
                            f"Dangerous tool without confirmation: {tool_name}",
                            f"Tool '{tool_name}' can execute code but doesn't require user confirmation",
                            f"Enable confirmation for dangerous tools in config",
                            str(config_file)
                        )
        except Exception as e:
            pass
            
    def run_all_checks(self):
        """Run all security checks"""
        print("🔍 Running OpenClaw Security Audit...\n")
        
        checks = [
            ("File Permissions", self.check_file_permissions),
            ("Credential Exposure", self.check_credential_exposure),
            ("Network Exposure", self.check_network_exposure),
            ("Skill Integrity", self.check_skill_integrity),
            ("Session Management", self.check_session_management),
            ("MCP Security", self.check_mcp_servers),
            ("Audit Logging", self.check_audit_logging),
            ("Prompt Injection", self.check_prompt_injection_surface),
            ("Active Threats", self.check_ioc_connections),
        ]
        
        for name, check_func in checks:
            print(f"  ⚡ Checking {name}...")
            try:
                check_func()
            except Exception as e:
                print(f"    ⚠️  Error during {name}: {e}")
                
        print(f"\n✅ Scan complete. Found {len(self.findings)} issues.\n")
        
    def get_summary_stats(self) -> Dict[str, int]:
        """Get summary statistics"""
        stats = {severity: 0 for severity in self.SEVERITY_ORDER.keys()}
        for finding in self.findings:
            stats[finding.severity] += 1
        return stats
        
    def output_terminal(self):
        """Output findings to terminal with colors"""
        if not self.findings:
            print("✅ No security issues found!")
            return
            
        # Sort by severity
        sorted_findings = sorted(
            self.findings,
            key=lambda f: self.SEVERITY_ORDER[f.severity]
        )
        
        stats = self.get_summary_stats()
        
        print("=" * 80)
        print("OPENCLAW SECURITY AUDIT REPORT")
        print("=" * 80)
        print(f"Scan Time: {self.scan_timestamp}")
        print(f"OpenClaw Dir: {self.openclaw_dir}")
        print(f"\nSummary:")
        for severity in self.SEVERITY_ORDER.keys():
            count = stats[severity]
            if count > 0:
                color = self.SEVERITY_COLORS[severity]
                print(f"  {color}{severity}: {count}{self.RESET_COLOR}")
        print("\n" + "=" * 80 + "\n")
        
        for finding in sorted_findings:
            color = self.SEVERITY_COLORS[finding.severity]
            print(f"{color}[{finding.severity}] {finding.title}{self.RESET_COLOR}")
            print(f"Category: {finding.category}")
            if finding.affected_path:
                print(f"Path: {finding.affected_path}")
            print(f"\nDescription:\n  {finding.description}\n")
            print(f"Remediation:\n  {finding.remediation}\n")
            print("-" * 80 + "\n")
            
    def output_json(self, filepath: str):
        """Output findings to JSON file"""
        output = {
            "scan_timestamp": self.scan_timestamp,
            "openclaw_dir": str(self.openclaw_dir),
            "version": VERSION,
            "summary": self.get_summary_stats(),
            "findings": [f.to_dict() for f in self.findings]
        }
        
        with open(filepath, 'w') as f:
            json.dump(output, f, indent=2)
            
        print(f"📄 JSON report saved to: {filepath}")
        
    def output_markdown(self, filepath: str):
        """Output findings to Markdown file"""
        stats = self.get_summary_stats()
        sorted_findings = sorted(
            self.findings,
            key=lambda f: self.SEVERITY_ORDER[f.severity]
        )
        
        md = f"""# OpenClaw Security Audit Report

**Scan Time:** {self.scan_timestamp}  
**OpenClaw Directory:** `{self.openclaw_dir}`  
**Tool Version:** {VERSION}

## Executive Summary

| Severity | Count |
|----------|-------|
"""
        for severity in self.SEVERITY_ORDER.keys():
            count = stats[severity]
            emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "🟢"}[severity]
            md += f"| {emoji} **{severity}** | {count} |\n"
            
        md += f"\n**Total Issues:** {len(self.findings)}\n\n"
        
        if not self.findings:
            md += "✅ **No security issues found!**\n"
        else:
            md += "## Findings\n\n"
            
            for finding in sorted_findings:
                emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "🟢"}[finding.severity]
                md += f"### {emoji} [{finding.severity}] {finding.title}\n\n"
                md += f"**Category:** {finding.category}\n\n"
                
                if finding.affected_path:
                    md += f"**Affected Path:** `{finding.affected_path}`\n\n"
                    
                md += f"**Description:**\n\n{finding.description}\n\n"
                md += f"**Remediation:**\n\n{finding.remediation}\n\n"
                md += "---\n\n"
                
        md += """## Infrastructure Best Practices

Based on your scan results, here are recommended hardening steps:

### Network Security
- **VPN-only access:** Bind all services to Tailscale or WireGuard IPs, never `0.0.0.0`
- **Firewall:** Enable UFW with deny-all inbound, whitelist only required ports
- **SSH:** Key-only auth, disable password login, use fail2ban
- **TLS:** All internal services should use HTTPS with valid certificates

### Credential Management
- **Environment variables:** Store API keys in `.env` files with `600` permissions, not JSON configs
- **Rotation:** Rotate all exposed keys immediately upon detection
- **Least privilege:** Scope API tokens to minimum required permissions
- **Secret managers:** Consider HashiCorp Vault or AWS Secrets Manager for production

### Agent Security
- **Integrity monitoring:** SHA256 checksums on identity files, verified every 15 minutes
- **Trust boundaries:** Different permission levels per model provider
- **Audit logging:** Enable and review daily — silent is not secure
- **Skill vetting:** Full source review before installing any community skill
- **Tool confirmation:** Require confirmation for destructive tools (exec, file deletion)

### Backup & Recovery
- **Automated backups:** Daily snapshots of `.openclaw/` directory
- **Offsite storage:** At least one backup copy outside the primary server
- **Test restores:** Monthly restore verification
- **Git history:** All configuration changes tracked in version control

---

## Need Help?

Want a deeper assessment tailored to your specific deployment? We offer hands-on security reviews from someone who runs a hardened production AI agent.

- Architecture review for multi-agent systems
- Threat modeling for your use case
- Security hardening implementation
- Incident response planning

---

*Report generated by [OpenClaw Security Audit Tool](https://github.com/omaratieh/openclaw-security-audit)*
"""
        
        with open(filepath, 'w') as f:
            f.write(md)
            
        print(f"📝 Markdown report saved to: {filepath}")


def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="OpenClaw Security Audit Tool - Comprehensive security scanner for OpenClaw deployments"
    )
    parser.add_argument(
        "--openclaw-dir",
        help="Path to .openclaw directory (default: ~/.openclaw)",
        default=None
    )
    parser.add_argument(
        "--output-json",
        help="Save JSON report to file",
        metavar="FILE"
    )
    parser.add_argument(
        "--output-md",
        help="Save Markdown report to file",
        metavar="FILE"
    )
    parser.add_argument(
        "--quiet",
        help="Suppress terminal output",
        action="store_true"
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"OpenClaw Security Audit Tool v{VERSION}"
    )
    
    args = parser.parse_args()
    
    auditor = SecurityAuditor(openclaw_dir=args.openclaw_dir)
    auditor.run_all_checks()
    
    if not args.quiet:
        auditor.output_terminal()
        
    if args.output_json:
        auditor.output_json(args.output_json)
        
    if args.output_md:
        auditor.output_markdown(args.output_md)
        
    # Exit with appropriate code
    stats = auditor.get_summary_stats()
    if stats["CRITICAL"] > 0:
        sys.exit(2)
    elif stats["HIGH"] > 0:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
