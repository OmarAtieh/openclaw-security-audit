#!/usr/bin/env python3
"""
OpenClaw Security Audit Tool
Comprehensive security scanner for OpenClaw deployments

v2.0.0 — Modular architecture.  Each scanner is an independent module
under ``modules/`` that inherits from ``BaseModule`` and implements
``scan(openclaw_path) -> list[Finding]``.
"""

import json
import os
import sys
import time
import signal
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any

# Allow running directly: ``python3 audit.py ~/.openclaw``
sys.path.insert(0, str(Path(__file__).parent))

from modules.base import Finding
from modules.config_scanner import ConfigScanner
from modules.skill_scanner import SkillScanner
from modules.cve_mapper import CVEMapper
from modules.channel_auditor import ChannelAuditor
from modules.config_hardening import ConfigHardeningModule
from modules.permission_auditor import PermissionAuditorModule
from modules.behavioral_baseline import BehavioralBaselineModule

VERSION = "2.1.0"

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEVERITY_COLORS = {
    "CRITICAL": "\033[91m",
    "HIGH": "\033[93m",
    "MEDIUM": "\033[94m",
    "LOW": "\033[96m",
    "INFO": "\033[92m",
}
RESET_COLOR = "\033[0m"


class SecurityAuditor:
    """Orchestrator that runs all scanner modules and collects findings."""

    def __init__(self, openclaw_dir: Optional[str] = None):
        self.openclaw_dir = Path(openclaw_dir or os.path.expanduser("~/.openclaw"))
        self.scan_timestamp = datetime.now().astimezone().isoformat()
        self.findings: List[Finding] = []

        # Register modules
        self.modules = [
            ConfigScanner(),
            ConfigHardeningModule(),
            PermissionAuditorModule(),
            SkillScanner(),
            CVEMapper(),
            ChannelAuditor(),
            BehavioralBaselineModule(),
        ]

    def run_all_checks(self) -> None:
        """Run every registered module."""
        print("🔍 Running OpenClaw Security Audit...\n")

        for mod in self.modules:
            label = getattr(mod, "description", mod.name)
            print(f"  ⚡ Checking {label}...")
            try:
                results = mod.scan(str(self.openclaw_dir))
                self.findings.extend(results)
            except Exception as e:
                print(f"    ⚠️  Error during {mod.name}: {e}")

        print(f"\n✅ Scan complete. Found {len(self.findings)} issues.\n")

    # ------------------------------------------------------------------
    # Output helpers (unchanged from v1)
    # ------------------------------------------------------------------
    def get_summary_stats(self) -> Dict[str, int]:
        stats = {s: 0 for s in SEVERITY_ORDER}
        for f in self.findings:
            stats[f.severity] = stats.get(f.severity, 0) + 1
        return stats

    def output_terminal(self) -> None:
        if not self.findings:
            print("✅ No security issues found!")
            return

        sorted_findings = sorted(self.findings,
                                 key=lambda f: SEVERITY_ORDER[f.severity])
        stats = self.get_summary_stats()

        print("=" * 80)
        print("OPENCLAW SECURITY AUDIT REPORT")
        print("=" * 80)
        print(f"Scan Time: {self.scan_timestamp}")
        print(f"OpenClaw Dir: {self.openclaw_dir}")
        print(f"\nSummary:")
        for sev in SEVERITY_ORDER:
            c = stats[sev]
            if c > 0:
                print(f"  {SEVERITY_COLORS[sev]}{sev}: {c}{RESET_COLOR}")
        print("\n" + "=" * 80 + "\n")

        for finding in sorted_findings:
            color = SEVERITY_COLORS[finding.severity]
            print(f"{color}[{finding.severity}] {finding.title}{RESET_COLOR}")
            print(f"Category: {finding.category}")
            if finding.affected_path:
                print(f"Path: {finding.affected_path}")
            print(f"\nDescription:\n  {finding.description}\n")
            print(f"Remediation:\n  {finding.remediation}\n")
            print("-" * 80 + "\n")

    def output_json(self, filepath: str) -> None:
        output = {
            "scan_timestamp": self.scan_timestamp,
            "openclaw_dir": str(self.openclaw_dir),
            "version": VERSION,
            "summary": self.get_summary_stats(),
            "findings": [f.to_dict() for f in self.findings],
        }
        with open(filepath, "w") as f:
            json.dump(output, f, indent=2)
        print(f"📄 JSON report saved to: {filepath}")

    def output_markdown(self, filepath: str) -> None:
        stats = self.get_summary_stats()
        sorted_findings = sorted(self.findings,
                                 key=lambda f: SEVERITY_ORDER[f.severity])

        emoji_map = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡",
                     "LOW": "🔵", "INFO": "🟢"}

        md = f"""# OpenClaw Security Audit Report

**Scan Time:** {self.scan_timestamp}  
**OpenClaw Directory:** `{self.openclaw_dir}`  
**Tool Version:** {VERSION}

## Executive Summary

| Severity | Count |
|----------|-------|
"""
        for sev in SEVERITY_ORDER:
            md += f"| {emoji_map[sev]} **{sev}** | {stats[sev]} |\n"

        md += f"\n**Total Issues:** {len(self.findings)}\n\n"

        if not self.findings:
            md += "✅ **No security issues found!**\n"
        else:
            md += "## Findings\n\n"
            for finding in sorted_findings:
                e = emoji_map[finding.severity]
                md += f"### {e} [{finding.severity}] {finding.title}\n\n"
                md += f"**Category:** {finding.category}\n\n"
                if finding.affected_path:
                    md += f"**Affected Path:** `{finding.affected_path}`\n\n"
                md += f"**Description:**\n\n{finding.description}\n\n"
                md += f"**Remediation:**\n\n{finding.remediation}\n\n"
                md += "---\n\n"

        md += self._best_practices_section()

        with open(filepath, "w") as f:
            f.write(md)
        print(f"📝 Markdown report saved to: {filepath}")

    @staticmethod
    def _best_practices_section() -> str:
        return """## Infrastructure Best Practices

### Network Security
- **VPN-only access:** Bind all services to Tailscale or WireGuard IPs, never `0.0.0.0`
- **Firewall:** Enable UFW with deny-all inbound, whitelist only required ports
- **SSH:** Key-only auth, disable password login, use fail2ban
- **TLS:** All internal services should use HTTPS with valid certificates

### Credential Management
- **Environment variables:** Store API keys in `.env` files with `600` permissions
- **Rotation:** Rotate all exposed keys immediately upon detection
- **Least privilege:** Scope API tokens to minimum required permissions

### Agent Security
- **Integrity monitoring:** SHA256 checksums on identity files
- **Audit logging:** Enable and review daily
- **Skill vetting:** Full source review before installing community skills
- **Tool confirmation:** Require confirmation for destructive tools

---

*Report generated by [OpenClaw Security Audit Tool](https://github.com/omaratieh/openclaw-security-audit)*
"""


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="OpenClaw Security Audit Tool — Comprehensive security scanner"
    )
    parser.add_argument(
        "openclaw_dir", nargs="?", default=None,
        help="Path to .openclaw directory (default: ~/.openclaw)",
    )
    parser.add_argument("--openclaw-dir", dest="openclaw_dir_flag", default=None,
                        help="Path to .openclaw directory (flag form)")
    parser.add_argument("--output-json", metavar="FILE",
                        help="Save JSON report to file")
    parser.add_argument("--output-md", metavar="FILE",
                        help="Save Markdown report to file")
    parser.add_argument("--report", choices=["terminal", "json", "markdown"],
                        help="Report format (shorthand for --output-* flags)")
    parser.add_argument("--watch", action="store_true",
                        help="Continuous monitoring mode - run checks periodically")
    parser.add_argument("--watch-interval", type=int, default=300, metavar="SECONDS",
                        help="Interval between scans in watch mode (default: 300)")
    parser.add_argument("--quiet", action="store_true",
                        help="Suppress terminal output")
    parser.add_argument("--version", action="version",
                        version=f"OpenClaw Security Audit Tool v{VERSION}")

    args = parser.parse_args()

    oc_dir = args.openclaw_dir or args.openclaw_dir_flag
    
    # Handle --report shorthand
    if args.report:
        if args.report == "json":
            args.output_json = f"openclaw-security-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
        elif args.report == "markdown":
            args.output_md = f"openclaw-security-{datetime.now().strftime('%Y%m%d-%H%M%S')}.md"
    
    # Watch mode
    if args.watch:
        print(f"🔄 Continuous monitoring enabled (interval: {args.watch_interval}s)")
        print("Press Ctrl+C to stop\n")
        
        # Handle graceful shutdown
        def signal_handler(sig, frame):
            print("\n\n⏹️  Monitoring stopped by user")
            sys.exit(0)
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        iteration = 0
        previous_findings = []
        
        while True:
            iteration += 1
            print(f"{'=' * 80}")
            print(f"Scan #{iteration} — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"{'=' * 80}\n")
            
            auditor = SecurityAuditor(openclaw_dir=oc_dir)
            auditor.run_all_checks()
            
            # Detect changes from previous scan
            if previous_findings:
                new_findings = set(
                    (f.severity, f.title, f.affected_path)
                    for f in auditor.findings
                )
                old_findings = set(
                    (f.severity, f.title, f.affected_path)
                    for f in previous_findings
                )
                
                added = new_findings - old_findings
                removed = old_findings - new_findings
                
                if added or removed:
                    print(f"\n🔔 CHANGES DETECTED:")
                    if added:
                        print(f"  ✅ New findings: {len(added)}")
                        for severity, title, path in list(added)[:5]:
                            print(f"     • [{severity}] {title}")
                    if removed:
                        print(f"  ✅ Resolved: {len(removed)}")
                        for severity, title, path in list(removed)[:5]:
                            print(f"     • [{severity}] {title}")
                    print()
            
            if not args.quiet:
                auditor.output_terminal()
            if args.output_json:
                # Append iteration to filename in watch mode
                base = Path(args.output_json)
                output_file = base.parent / f"{base.stem}-{iteration}{base.suffix}"
                auditor.output_json(str(output_file))
            if args.output_md:
                base = Path(args.output_md)
                output_file = base.parent / f"{base.stem}-{iteration}{base.suffix}"
                auditor.output_markdown(str(output_file))
            
            previous_findings = auditor.findings
            
            print(f"\n⏳ Next scan in {args.watch_interval} seconds...\n")
            time.sleep(args.watch_interval)
    
    else:
        # Single scan mode
        auditor = SecurityAuditor(openclaw_dir=oc_dir)
        auditor.run_all_checks()

        if not args.quiet:
            auditor.output_terminal()
        if args.output_json:
            auditor.output_json(args.output_json)
        if args.output_md:
            auditor.output_markdown(args.output_md)

        stats = auditor.get_summary_stats()
        if stats["CRITICAL"] > 0:
            sys.exit(2)
        elif stats["HIGH"] > 0:
            sys.exit(1)
        else:
            sys.exit(0)


if __name__ == "__main__":
    main()
