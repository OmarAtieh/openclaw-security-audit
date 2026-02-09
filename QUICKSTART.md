# Quick Start Guide

Get up and running with OpenClaw Security Audit Tool in 2 minutes.

## 📦 Installation

### Option 1: Quick Run (No Install)

```bash
# Clone the repo
git clone https://github.com/your-org/openclaw-security-audit.git
cd openclaw-security-audit

# Make it executable
chmod +x audit.py

# Run it!
./audit.py
```

### Option 2: Install Globally

```bash
pip install openclaw-security-audit

# Run from anywhere
openclaw-audit
```

### Option 3: Run Directly (Python)

```bash
python3 audit.py
```

## 🎯 Basic Usage

### Scan Your OpenClaw Installation

```bash
./audit.py
```

This scans `~/.openclaw` and outputs findings to your terminal.

### Generate Reports

**JSON report (for automation):**
```bash
./audit.py --output-json report.json
```

**Markdown report (for sharing):**
```bash
./audit.py --output-md report.md
```

**Both:**
```bash
./audit.py --output-json report.json --output-md report.md
```

### Custom OpenClaw Directory

```bash
./audit.py --openclaw-dir /opt/openclaw
```

### Quiet Mode (Reports Only)

```bash
./audit.py --quiet --output-json report.json
```

## 🚦 Understanding Results

### Exit Codes

- **0** — No critical or high issues (safe to proceed)
- **1** — High severity issues found (review recommended)
- **2** — Critical issues found (immediate action required)

Use these in CI/CD:

```bash
./audit.py --quiet --output-json report.json
if [ $? -eq 2 ]; then
    echo "CRITICAL issues found. Blocking deployment."
    exit 1
fi
```

### Severity Levels

| Severity | Action Required | Examples |
|----------|----------------|----------|
| 🔴 **CRITICAL** | Immediate | World-readable API keys, known malware |
| 🟠 **HIGH** | Within 24h | Weak file permissions, exposed admin ports |
| 🟡 **MEDIUM** | Within 1 week | Missing integrity checks, disabled logging |
| 🔵 **LOW** | Plan to fix | Minor permission issues |
| 🟢 **INFO** | FYI | Informational findings |

## 📊 Sample Output

### Terminal

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

🔴 [CRITICAL] World-readable sensitive file: openclaw.json
...
```

See `examples/sample-report.md` for a full example.

## 🔧 Common Workflows

### Daily Security Check

Add to cron:

```bash
# Run daily at 2 AM, save reports
0 2 * * * /usr/local/bin/openclaw-audit --quiet \
  --output-json /var/log/openclaw/audit-$(date +\%Y-\%m-\%d).json
```

### Pre-deployment Check

Add to CI/CD:

```yaml
# .github/workflows/security.yml
- name: Security Audit
  run: |
    ./audit.py --output-json audit.json
    if [ $? -eq 2 ]; then
      echo "Critical security issues found!"
      exit 1
    fi
```

### Post-incident Scan

After a security incident:

```bash
# Full scan with all report formats
./audit.py \
  --output-json incident-$(date +%Y%m%d).json \
  --output-md incident-$(date +%Y%m%d).md

# Review findings
cat incident-*.md
```

## 🆘 Troubleshooting

### "Permission denied" on network checks

Network scanning needs root for full process info:

```bash
sudo ./audit.py
```

Or accept limited network scanning as non-root.

### "OpenClaw directory not found"

Specify the correct path:

```bash
./audit.py --openclaw-dir /path/to/.openclaw
```

### False positives

Some warnings are informational. Review the finding description to understand the risk level.

### Need help?

- [Full Documentation](README.md)
- [GitHub Issues](https://github.com/your-org/openclaw-security-audit/issues)
- [GitHub Discussions](https://github.com/your-org/openclaw-security-audit/discussions)

## 📞 What's Next?

### Found Critical Issues?

1. **Don't panic** — Follow the remediation steps in the report
2. **Take action** — Fix critical issues immediately
3. **Get help** — We offer [professional security assessments](README.md#whats-next)

### No Issues Found?

Great! But consider:

- Running scans regularly (weekly/daily)
- Enabling audit logging if not already active
- Reviewing your backup and incident response procedures
- Staying updated on OpenClaw security advisories

---

**⭐ Found this tool helpful? Star the repo!**
