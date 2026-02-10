"""Module — Behavioral Baseline and Anomaly Detection.

Detects anomalous patterns in:
- Unusual outbound connections in skills
- Unexpected file access patterns
- Suspicious process spawning
- Network traffic anomalies
- Skill behavior changes
"""

import json
import re
from pathlib import Path
from typing import List, Optional, Dict, Set
from collections import defaultdict

from .base import BaseModule, Finding


class BehavioralBaselineModule(BaseModule):
    name = "behavioral_baseline"
    description = "Behavioral anomaly detection and baseline analysis"
    
    # Suspicious network patterns
    SUSPICIOUS_DOMAINS = {
        "pastebin.com",
        "raw.githubusercontent.com",
        "ngrok.io",
        "*.onion",
        "duckdns.org",
    }
    
    # Suspicious command patterns
    SUSPICIOUS_COMMANDS = {
        "curl.*|.*sh",  # Pipe to shell
        "wget.*|.*sh",
        "base64.*-d",   # Base64 decode
        "eval.*\\$\\(",  # Eval with command substitution
        "nc.*-e",       # Netcat with execute
        "/dev/tcp/",    # Direct TCP connections
        ">/dev/null.*2>&1",  # Silent execution
    }
    
    # Files that should not be accessed by skills
    PROTECTED_PATHS = {
        "/etc/shadow",
        "/etc/passwd",
        "~/.ssh/id_rsa",
        "~/.ssh/id_ed25519",
        "~/.aws/credentials",
        "~/.config/gcloud",
    }
    
    def scan(self, openclaw_path: str) -> List[Finding]:
        self._findings: List[Finding] = []
        self._oc = Path(openclaw_path)
        
        self._check_skill_network_patterns()
        self._check_skill_file_access()
        self._check_skill_process_spawning()
        self._check_skill_size_anomalies()
        self._check_data_exfiltration_patterns()
        
        return self._findings
    
    def _add(self, severity: str, category: str, title: str,
             description: str, remediation: str,
             affected_path: Optional[str] = None) -> None:
        self._findings.append(Finding(
            severity=severity, category=category, title=title,
            description=description, remediation=remediation,
            affected_path=affected_path,
        ))
    
    def _check_skill_network_patterns(self) -> None:
        """Detect unusual outbound connection patterns in skills."""
        skills_dir = self._oc / "skills"
        if not skills_dir.exists():
            return
        
        for skill_path in skills_dir.iterdir():
            if not skill_path.is_dir():
                continue
            
            # Scan all code files in skill
            code_patterns = ["*.py", "*.js", "*.sh", "*.ts"]
            suspicious_connections: Dict[str, List[str]] = defaultdict(list)
            
            for pattern in code_patterns:
                for code_file in skill_path.rglob(pattern):
                    try:
                        content = code_file.read_text()
                        
                        # Check for hardcoded IPs
                        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
                        ips = re.findall(ip_pattern, content)
                        for ip in ips:
                            if not ip.startswith(("127.", "192.168.", "10.", "172.")):
                                suspicious_connections["hardcoded_ip"].append(ip)
                        
                        # Check for suspicious domains
                        for domain in self.SUSPICIOUS_DOMAINS:
                            if domain in content:
                                suspicious_connections["suspicious_domain"].append(domain)
                        
                        # Check for raw URL patterns
                        url_pattern = r'https?://[^\s\'"<>]+'
                        urls = re.findall(url_pattern, content)
                        for url in urls:
                            # Flag if connecting to IP addresses
                            if re.search(ip_pattern, url):
                                suspicious_connections["url_with_ip"].append(url)
                    
                    except (UnicodeDecodeError, PermissionError):
                        continue
            
            # Report findings
            if suspicious_connections["hardcoded_ip"]:
                ips = set(suspicious_connections["hardcoded_ip"])
                self._add("MEDIUM", "Behavioral Analysis",
                         f"Skill contains hardcoded external IPs: {skill_path.name}",
                         f"Found {len(ips)} hardcoded external IP address(es) in skill code: "
                         f"{', '.join(list(ips)[:5])}. This may indicate command & control communication.",
                         "Review skill source code. Remove if malicious.",
                         str(skill_path))
            
            if suspicious_connections["suspicious_domain"]:
                domains = set(suspicious_connections["suspicious_domain"])
                self._add("HIGH", "Behavioral Analysis",
                         f"Skill connects to suspicious domains: {skill_path.name}",
                         f"Skill references suspicious domains: {', '.join(domains)}. "
                         "These are commonly used for malware hosting.",
                         "Quarantine and review skill code immediately.",
                         str(skill_path))
    
    def _check_skill_file_access(self) -> None:
        """Detect skills accessing protected file paths."""
        skills_dir = self._oc / "skills"
        if not skills_dir.exists():
            return
        
        for skill_path in skills_dir.iterdir():
            if not skill_path.is_dir():
                continue
            
            code_patterns = ["*.py", "*.js", "*.sh"]
            protected_accesses: Set[str] = set()
            
            for pattern in code_patterns:
                for code_file in skill_path.rglob(pattern):
                    try:
                        content = code_file.read_text()
                        
                        for protected in self.PROTECTED_PATHS:
                            if protected in content:
                                protected_accesses.add(protected)
                    
                    except (UnicodeDecodeError, PermissionError):
                        continue
            
            if protected_accesses:
                self._add("CRITICAL", "Behavioral Analysis",
                         f"Skill accesses protected system files: {skill_path.name}",
                         f"Skill code references protected paths: {', '.join(protected_accesses)}. "
                         "This may indicate credential theft or privilege escalation.",
                         "Remove skill immediately and review audit logs for access attempts.",
                         str(skill_path))
    
    def _check_skill_process_spawning(self) -> None:
        """Detect suspicious process spawning patterns."""
        skills_dir = self._oc / "skills"
        if not skills_dir.exists():
            return
        
        for skill_path in skills_dir.iterdir():
            if not skill_path.is_dir():
                continue
            
            code_patterns = ["*.py", "*.js", "*.sh"]
            suspicious_patterns: Dict[str, int] = defaultdict(int)
            
            for pattern in code_patterns:
                for code_file in skill_path.rglob(pattern):
                    try:
                        content = code_file.read_text()
                        
                        # Check for suspicious command patterns
                        for cmd_pattern in self.SUSPICIOUS_COMMANDS:
                            matches = re.findall(cmd_pattern, content, re.IGNORECASE)
                            suspicious_patterns[cmd_pattern] += len(matches)
                    
                    except (UnicodeDecodeError, PermissionError):
                        continue
            
            if suspicious_patterns:
                patterns = [f"{pattern}: {count}" for pattern, count in suspicious_patterns.items()]
                self._add("HIGH", "Behavioral Analysis",
                         f"Skill uses suspicious command patterns: {skill_path.name}",
                         f"Detected suspicious command execution patterns:\n" + "\n".join(patterns),
                         "Review skill code for malicious behavior. Consider quarantine.",
                         str(skill_path))
    
    def _check_skill_size_anomalies(self) -> None:
        """Detect unusually large skills (possible data embedding)."""
        skills_dir = self._oc / "skills"
        if not skills_dir.exists():
            return
        
        skill_sizes: Dict[str, int] = {}
        
        for skill_path in skills_dir.iterdir():
            if not skill_path.is_dir():
                continue
            
            # Calculate total size of skill
            total_size = sum(
                f.stat().st_size
                for f in skill_path.rglob("*")
                if f.is_file()
            )
            skill_sizes[skill_path.name] = total_size
        
        if not skill_sizes:
            return
        
        # Calculate baseline (median size)
        sizes = sorted(skill_sizes.values())
        median_size = sizes[len(sizes) // 2]
        
        # Flag skills >10x median size
        threshold = median_size * 10
        
        for skill_name, size in skill_sizes.items():
            if size > threshold and size > 1_000_000:  # Also >1MB
                self._add("MEDIUM", "Behavioral Analysis",
                         f"Unusually large skill detected: {skill_name}",
                         f"Skill size is {size:,} bytes ({size / median_size:.1f}x median). "
                         "Large skills may contain embedded malware or exfiltrated data.",
                         "Review skill contents for unexpected large files.",
                         str(skills_dir / skill_name))
    
    def _check_data_exfiltration_patterns(self) -> None:
        """Detect patterns indicative of data exfiltration."""
        skills_dir = self._oc / "skills"
        if not skills_dir.exists():
            return
        
        exfiltration_patterns = [
            r'requests\.post\([^)]*data=',  # HTTP POST with data
            r'urllib.*urlopen.*POST',
            r'fetch\([^)]*method:\s*["\']POST',
            r'socket\.connect\(',  # Raw socket connections
            r'base64\.b64encode\([^)]*\.read\(\)',  # Encoding file contents
        ]
        
        for skill_path in skills_dir.iterdir():
            if not skill_path.is_dir():
                continue
            
            code_patterns = ["*.py", "*.js"]
            matches: Dict[str, int] = defaultdict(int)
            
            for pattern in code_patterns:
                for code_file in skill_path.rglob(pattern):
                    try:
                        content = code_file.read_text()
                        
                        for exfil_pattern in exfiltration_patterns:
                            found = re.findall(exfil_pattern, content)
                            matches[exfil_pattern] += len(found)
                    
                    except (UnicodeDecodeError, PermissionError):
                        continue
            
            if matches:
                total_matches = sum(matches.values())
                if total_matches > 2:  # Threshold: more than 2 potential exfiltration points
                    self._add("HIGH", "Behavioral Analysis",
                             f"Potential data exfiltration patterns: {skill_path.name}",
                             f"Detected {total_matches} patterns associated with data exfiltration. "
                             "Skill may be sending data to external servers.",
                             "Review network activity and skill code. Quarantine if confirmed malicious.",
                             str(skill_path))
