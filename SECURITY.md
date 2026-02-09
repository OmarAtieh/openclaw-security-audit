# Security Policy

## Reporting Security Vulnerabilities

**We take security seriously.** If you discover a security vulnerability in this tool, please help us maintain the security of the community by reporting it responsibly.

### 🔒 How to Report

**DO NOT** create a public GitHub issue for security vulnerabilities.

Instead, email us at: **security@yourcompany.com**

Include in your report:
1. **Description** — Clear explanation of the vulnerability
2. **Impact** — What an attacker could do with this vulnerability
3. **Steps to Reproduce** — Detailed steps to reproduce the issue
4. **Proof of Concept** — Code or commands demonstrating the issue (if applicable)
5. **Suggested Fix** — Your recommendation for fixing it (optional)
6. **Your Contact Info** — So we can follow up with questions or updates

### 🕐 Response Timeline

- **Within 48 hours:** Initial acknowledgment of your report
- **Within 7 days:** Assessment of the vulnerability and preliminary response
- **Within 30 days:** Fix developed, tested, and released (for valid vulnerabilities)

### 🏆 Recognition

We believe in giving credit where it's due:

- **Public acknowledgment** in release notes (unless you prefer to remain anonymous)
- **CVE assignment** for confirmed vulnerabilities (if applicable)
- **Hall of Fame** listing on our website (with your permission)

### ⚖️ Responsible Disclosure

We ask that you:

- Allow us reasonable time to investigate and fix the issue before public disclosure
- Do not exploit the vulnerability beyond what's necessary to demonstrate it
- Do not access, modify, or delete other users' data
- Act in good faith to help improve security

In return, we commit to:

- Respond promptly to your report
- Keep you updated on our progress
- Credit you appropriately (if you wish)
- Not pursue legal action for good-faith security research

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Known Limitations

This tool has known limitations documented in README.md:

- Network checks may require elevated privileges
- Hash-based detection only catches exact matches
- No runtime behavioral analysis
- Primarily tested on Linux (Ubuntu/Debian)

These are **design constraints**, not vulnerabilities. However, if you find ways to improve detection within these constraints, we'd love to hear about them!

## Security Features

This tool helps secure OpenClaw deployments by checking for:

- ✅ File permission issues
- ✅ Credential exposure
- ✅ Network misconfigurations
- ✅ Malicious skills
- ✅ Session management weaknesses
- ✅ MCP security issues
- ✅ Audit logging status
- ✅ Prompt injection surface

## False Positives

If the tool reports a false positive:

1. **Review the finding** — Sometimes legitimate configurations trigger warnings
2. **Understand the risk** — The tool errs on the side of caution
3. **Report it** — Open a GitHub issue with details so we can improve detection

## Contact

- **Security Issues:** security@yourcompany.com
- **General Issues:** [GitHub Issues](https://github.com/your-org/openclaw-security-audit/issues)
- **Questions:** [GitHub Discussions](https://github.com/your-org/openclaw-security-audit/discussions)

---

*Thank you for helping keep OpenClaw deployments secure!*
