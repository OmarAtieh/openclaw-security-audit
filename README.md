# 🛡️ OpenClaw Security Audit Tool

**Comprehensive security scanner for OpenClaw AI agent deployments**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![OpenClaw](https://img.shields.io/badge/OpenClaw-Security-red.svg)](https://github.com/openclaw/openclaw)

---

## 🚨 The Problem

The February 2026 ClawHub supply chain attack — where malicious skills were uploaded to the official marketplace — demonstrated that AI agent security is not optional. Major security vendors (CrowdStrike, Cisco, Snyk) have published detection tools for malicious skills, but **none address the broader security posture of OpenClaw deployments**: file permissions, credential hygiene, network exposure, audit logging, and MCP server configuration.

**This tool scans your entire deployment and produces an actionable security report.**

---

## ✨ Features

### Comprehensive Security Checks

- **🔐 File Permissions** — Detect world-readable configs, `.env` files, and session tokens
- **🗝️ Credential Exposure** — Find API keys (OpenAI, Anthropic, Google, AWS) in plaintext configs
- **🌐 Network Exposure** — Identify admin ports exposed on public interfaces
- **📦 Skill Integrity** — Verify installed skills, detect tampering and missing manifests
- **☠️ Malicious Skill Detection** — Check against known malicious skill signatures (database updated as new threats emerge)
- **🔒 Session Management** — Audit token storage and rotation practices
- **🔌 MCP Security** — Check for insecure MCP server configurations
- **🔑 API Key Hygiene** — Verify proper secret management practices
- **📋 Audit Logging** — Ensure logging is enabled and properly secured
- **💉 Prompt Injection Surface** — Identify unprotected tool access and exposed system prompts

### Multiple Output Formats

- **🖥️ Terminal** — Colored, human-friendly output for quick scans
- **📄 JSON** — Machine-readable reports for CI/CD integration
- **📝 Markdown** — Beautiful reports ready to share with stakeholders

### Severity Ratings

- 🔴 **CRITICAL** — Immediate action required (exposed credentials, public admin ports)
- 🟠 **HIGH** — Significant risk (weak permissions, credential leakage)
- 🟡 **MEDIUM** — Security gap (missing integrity checks, disabled logging)
- 🔵 **LOW** — Minor issue (improvement opportunity)
- 🟢 **INFO** — Informational finding

---

## 🚀 Quick Start

### Installation

**Option 1: Direct download (no dependencies)**

```bash
git clone https://github.com/OmarAtieh/openclaw-security-audit.git
cd openclaw-security-audit
chmod +x audit.py
```

**Option 2: System-wide install**

```bash
pip install openclaw-security-audit
```

### Usage

**Basic scan (terminal output):**

```bash
./audit.py
```

**Generate all report formats:**

```bash
./audit.py --output-json report.json --output-md report.md
```

**Scan custom OpenClaw directory:**

```bash
./audit.py --openclaw-dir /opt/openclaw
```

**Quiet mode (only save reports, no terminal output):**

```bash
./audit.py --quiet --output-json report.json
```

---

## 📊 Sample Output

### Terminal Output

```
🔍 Running OpenClaw Security Audit...

  ⚡ Checking File Permissions...
  ⚡ Checking Credential Exposure...
  ⚡ Checking Network Exposure...
  ⚡ Checking Skill Integrity...
  ⚡ Checking Session Management...
  ⚡ Checking MCP Security...
  ⚡ Checking Audit Logging...
  ⚡ Checking Prompt Injection...

✅ Scan complete. Found 4 issues.

================================================================================
OPENCLAW SECURITY AUDIT REPORT
================================================================================
Scan Time: 2026-02-09T03:00:00.000000
OpenClaw Dir: /home/user/.openclaw

Summary:
  🔴 CRITICAL: 1
  🟠 HIGH: 1
  🟡 MEDIUM: 2

================================================================================

🔴 [CRITICAL] World-readable sensitive file: openclaw.json
Category: File Permissions
Path: /home/user/.openclaw/openclaw.json

Description:
  File /home/user/.openclaw/openclaw.json is readable by all users (mode: 0o644)

Remediation:
  Run: chmod 600 /home/user/.openclaw/openclaw.json

--------------------------------------------------------------------------------
```

### Markdown Report Preview

![Sample Markdown Report](https://placeholder.svg?text=Sample+Report+Screenshot)

---

## 🔧 Integration

### CI/CD Pipeline

**GitHub Actions:**

```yaml
name: Security Audit

on: [push, pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run OpenClaw Security Audit
        run: |
          python audit.py --output-json audit-report.json
      - name: Upload Report
        uses: actions/upload-artifact@v3
        with:
          name: security-audit
          path: audit-report.json
```

### Pre-deployment Check

```bash
#!/bin/bash
# deploy.sh

echo "Running security audit..."
./audit.py --quiet --output-json /tmp/audit.json

# Check exit code
if [ $? -eq 2 ]; then
    echo "❌ CRITICAL security issues found. Deployment blocked."
    cat /tmp/audit.json
    exit 1
elif [ $? -eq 1 ]; then
    echo "⚠️  HIGH security issues found. Review required."
    cat /tmp/audit.json
fi

echo "✅ Security audit passed. Proceeding with deployment..."
```

---

## 📚 Documentation

### Exit Codes

- `0` — No critical or high severity issues
- `1` — High severity issues found
- `2` — Critical severity issues found

### Checked Paths

The tool automatically scans:
- `~/.openclaw/` (or custom path via `--openclaw-dir`)
- `~/.openclaw/openclaw.json`
- `~/.openclaw/config.json`
- `~/.openclaw/sessions.json`
- `~/.openclaw/mcp.json`
- `~/.openclaw/skills/` (all installed skills)
- `~/.env`
- `~/.config/claude/settings.json`

### Adding Custom Checks

The tool is designed to be extensible. To add a custom check:

1. Add a method to `SecurityAuditor` class:

```python
def check_custom_feature(self):
    """Check custom security feature"""
    # Your check logic here
    if issue_found:
        self.add_finding(
            "HIGH",
            "Custom Category",
            "Issue title",
            "Detailed description",
            "How to fix it",
            "/path/to/affected/file"
        )
```

2. Register it in `run_all_checks()`:

```python
checks = [
    # ... existing checks
    ("Custom Feature", self.check_custom_feature),
]
```

---

## 🤝 Contributing

We welcome contributions! Here's how:

1. **Fork the repository**
2. **Create a feature branch** (`git checkout -b feature/amazing-check`)
3. **Add your check** with proper documentation
4. **Test thoroughly** on multiple OpenClaw deployments
5. **Submit a pull request**

### Contribution Guidelines

- Follow PEP 8 style guide
- Add type hints to all functions
- Include docstrings for new methods
- Update `known_malicious.json` if adding malware signatures
- Add tests for new checks (when test framework is added)

---

## 🗺️ Roadmap

- [ ] **v1.1** — Windows support
- [ ] **v1.2** — Docker container scanning
- [ ] **v1.3** — Automated remediation mode
- [ ] **v1.4** — Real-time monitoring daemon
- [ ] **v2.0** — Web dashboard with historical trends
- [ ] **v2.1** — Integration with SIEM systems
- [ ] **v2.2** — Custom check plugins via YAML

---

## ⚠️ Known Limitations

- **Network checks require root** — `netstat`/`ss` may need elevated privileges for full process info
- **Hash-based detection** — Only catches exact matches; obfuscated malware may evade
- **No runtime analysis** — Only scans static configuration (no behavioral analysis)
- **Linux-focused** — Primary support for Ubuntu/Debian; macOS and Windows support coming

---

## 🛡️ What's Next?

### Found Critical Issues?

If this tool discovered security problems in your deployment, **don't panic** — but do act quickly.

**We offer professional security services** for OpenClaw deployments:

- ✅ **Comprehensive Security Assessments** — Deep-dive audits beyond automated scanning
- ✅ **Penetration Testing** — Adversarial testing of your AI agent infrastructure
- ✅ **Secure Deployment Consulting** — Architecture review and hardening
- ✅ **Incident Response** — Already compromised? We'll help investigate and remediate
- ✅ **Security Training** — Teach your team to deploy OpenClaw securely

**Contact:** omar@omaratieh.com | [Schedule a consultation](https://omaratieh.com/contact)

---

## 📜 License

MIT License - see [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- **OpenClaw Community** — For building amazing AI agent infrastructure
- **Security Researchers** — Who identified the ClawHub supply chain attack
- **CrowdStrike, Cisco, Snyk** — For their malicious skill detection tools
- **Contributors** — Thank you for making this tool better

---

## 📞 Support

- **Issues:** [GitHub Issues](https://github.com/OmarAtieh/openclaw-security-audit/issues)
- **Discussions:** [GitHub Discussions](https://github.com/OmarAtieh/openclaw-security-audit/discussions)
- **Security Vulnerabilities:** omar@omaratieh.com (PGP key available)

---

**⭐ If this tool helped you, please star the repository!**

*Securing AI agents, one deployment at a time.*
