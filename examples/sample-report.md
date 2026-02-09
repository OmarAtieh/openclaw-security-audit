# OpenClaw Security Audit Report

**Scan Time:** 2026-02-09T03:00:00.000000  
**OpenClaw Directory:** `/home/user/.openclaw`  
**Tool Version:** 1.0.0

## Executive Summary

| Severity | Count |
|----------|-------|
| 🔴 **CRITICAL** | 2 |
| 🟠 **HIGH** | 3 |
| 🟡 **MEDIUM** | 2 |
| 🔵 **LOW** | 1 |
| 🟢 **INFO** | 0 |

**Total Issues:** 8

## Findings

### 🔴 [CRITICAL] World-readable sensitive file: openclaw.json

**Category:** File Permissions

**Affected Path:** `/home/user/.openclaw/openclaw.json`

**Description:**

File /home/user/.openclaw/openclaw.json is readable by all users (mode: 0o644). This means any user on the system can view your OpenClaw configuration, including potentially sensitive settings.

**Remediation:**

Run: `chmod 600 /home/user/.openclaw/openclaw.json`

This will restrict access to only the file owner.

---

### 🔴 [CRITICAL] Known malicious skill detected: aws-credential-stealer

**Category:** Malicious Skill

**Affected Path:** `/home/user/.openclaw/skills/aws-credential-stealer`

**Description:**

Skill 'aws-credential-stealer' matches known malicious skill from ClawHub incident (Feb 2026). This skill was designed to exfiltrate AWS credentials from your environment.

**Remediation:**

IMMEDIATELY remove this skill: `rm -rf /home/user/.openclaw/skills/aws-credential-stealer`

After removal:
1. Rotate ALL AWS access keys
2. Review CloudTrail logs for unauthorized access
3. Check for unusual EC2 instances or S3 buckets
4. Review IAM policies for modifications
5. Enable AWS GuardDuty if not already active

---

### 🟠 [HIGH] Anthropic API Key found in plaintext config

**Category:** Credential Exposure

**Affected Path:** `/home/user/.openclaw/openclaw.json`

**Description:**

Found 1 Anthropic API Key(s) in /home/user/.openclaw/openclaw.json. File has weak permissions.

**Remediation:**

1. Remove the API key from openclaw.json
2. Store it in environment variables instead:
   ```bash
   export ANTHROPIC_API_KEY="sk-ant-..."
   ```
3. Update openclaw.json to reference the environment variable
4. Rotate the exposed API key at https://console.anthropic.com
5. Review API usage logs for unauthorized access

---

### 🟠 [HIGH] OpenClaw Admin exposed on public interface

**Category:** Network Exposure

**Affected Path:** `0.0.0.0:8080`

**Description:**

Port 8080 (OpenClaw Admin) is listening on 0.0.0.0, making it accessible from any network interface. This includes the public internet if your server has a public IP.

**Remediation:**

Bind to localhost only:

1. Edit your OpenClaw config to bind to `127.0.0.1:8080` instead of `0.0.0.0:8080`
2. If you need remote access, use SSH tunneling:
   ```bash
   ssh -L 8080:localhost:8080 user@server
   ```
3. Or use a firewall to restrict access:
   ```bash
   ufw allow from 192.168.1.0/24 to any port 8080
   ```

---

### 🟠 [HIGH] MCP server using unencrypted HTTP: external-api

**Category:** MCP Security

**Affected Path:** `/home/user/.openclaw/mcp.json`

**Description:**

Server 'external-api' uses HTTP instead of HTTPS: http://api.example.com. This means all communication is unencrypted and vulnerable to interception.

**Remediation:**

1. Update the URL to use HTTPS: `https://api.example.com`
2. If the server doesn't support HTTPS, consider:
   - Using a reverse proxy with TLS
   - Ensuring the connection is only over trusted networks
   - Finding an alternative MCP server

---

### 🟡 [MEDIUM] Skill missing SKILL.md: custom-helper

**Category:** Skill Integrity

**Affected Path:** `/home/user/.openclaw/skills/custom-helper`

**Description:**

Skill custom-helper does not have a SKILL.md file, which is required for legitimate skills. This could indicate:
- An incomplete installation
- A malicious skill attempting to avoid detection
- A custom/experimental skill without proper documentation

**Remediation:**

1. Verify the skill's authenticity
2. Check where you installed it from
3. If it's a custom skill, add a SKILL.md manifest
4. If uncertain, remove it: `rm -rf /home/user/.openclaw/skills/custom-helper`

---

### 🟡 [MEDIUM] Audit logging is disabled

**Category:** Audit Logging

**Affected Path:** `/home/user/.openclaw/openclaw.json`

**Description:**

Audit logging is not enabled in OpenClaw configuration. Without audit logs, you cannot:
- Track what your AI agent has done
- Investigate security incidents
- Comply with security policies
- Debug unexpected behavior

**Remediation:**

Enable audit logging in your OpenClaw config:

```json
{
  "auditLogging": {
    "enabled": true,
    "path": "/var/log/openclaw/audit.log",
    "level": "info"
  }
}
```

Then restart OpenClaw.

---

### 🔵 [LOW] Session file has weak permissions: sessions.json

**Category:** Session Management

**Affected Path:** `/home/user/.openclaw/sessions.json`

**Description:**

Session tokens in /home/user/.openclaw/sessions.json are readable by other users in your group (mode: 0o640).

**Remediation:**

Run: `chmod 600 /home/user/.openclaw/sessions.json`

This ensures only you can read your session tokens.

---

## What's Next?

Found critical issues? **We offer professional security assessments** for OpenClaw deployments.

Contact us for:
- Comprehensive security audits
- Penetration testing
- Secure deployment consulting
- Incident response

**Email:** security@yourcompany.com  
**Web:** https://yourcompany.com/openclaw-security

---

*Report generated by [OpenClaw Security Audit Tool](https://github.com/your-org/openclaw-security-audit)*
