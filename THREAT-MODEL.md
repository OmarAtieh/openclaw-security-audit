# OpenClaw Security Suite — Threat Model

> Version 1.0 | 2026-02-09 | Modules 1–7

## Adversary Profiles

### A: Malicious Skill Author (Supply Chain)
- **Motivation:** Gain code execution on target machines via ClawHub skill distribution
- **Capabilities:** Publish skills with embedded payloads, social engineering (popular skill names), obfuscated code in SKILL.md or install scripts
- **Attack Surface:** ClawHub registry, `SKILL.md` prompt injection, install hooks (`postinstall`), symlink tricks, typosquatted dependencies
- **Detection:** Static analysis of SKILL.md for injection patterns, file size anomalies, encoded payloads, dependency audit, signature verification

### B: Compromised/Manipulated LLM (Prompt Injection)
- **Motivation:** Exfiltrate user data, execute unauthorized commands, bypass safety controls
- **Capabilities:** Indirect prompt injection via skill content, conversation history manipulation, tool-call abuse, data exfiltration via crafted URLs
- **Attack Surface:** Any text the LLM processes (skills, web content, user messages), tool dispatch layer, memory/context files
- **Detection:** Output monitoring for exfiltration patterns (URLs with encoded data), tool-call anomaly detection, rate limiting on sensitive operations

### C: Network Attacker (Gateway Exposure)
- **Motivation:** Unauthorized access, lateral movement, credential theft
- **Capabilities:** Port scanning, MITM on unencrypted connections, WebSocket hijacking, exploiting known CVEs in gateway
- **Attack Surface:** Gateway HTTP/WS endpoints, TLS configuration, authentication tokens, reverse proxy misconfig
- **Detection:** Network binding audit (0.0.0.0 vs 127.0.0.1), TLS certificate validation, port exposure scanning, CVE version matching

### D: Co-tenant on Shared Machine (Privilege Escalation)
- **Motivation:** Read secrets, hijack sessions, escalate privileges
- **Capabilities:** Read world-readable files, enumerate processes, access shared /tmp, exploit weak file permissions
- **Attack Surface:** Config files with API keys, socket files, log files with tokens, `/tmp` artifacts
- **Detection:** File permission audit (config files must be 600/700), process isolation checks, socket permission validation

### E: User Misconfiguration (Self-Inflicted)
- **Motivation:** Convenience over security (unintentional)
- **Capabilities:** Full system access (it's the user's own machine)
- **Attack Surface:** Gateway bound to 0.0.0.0 with no auth, open DM policy allowing unsolicited commands, disabled sandbox, plaintext API keys, no `requireMention`
- **Detection:** Configuration audit against hardening checklist, default-deny policy verification, sandbox enablement check

## Module → Adversary Defense Matrix

| Module | Description | Defends Against |
|--------|-------------|-----------------|
| **1** | Configuration Hardening Audit | C, D, E |
| **2** | Secret Detection & Rotation | A, D, E |
| **3** | SKILL.md Injection Scanner | A, B |
| **4** | Permission & Filesystem Audit | D, E |
| **5** | Network Exposure Scanner | C, E |
| **6** | CVE Version Checker | C |
| **7** | DM Policy & Auth Audit | B, C, E |

## Risk Priority

1. **Critical:** Adversary A + B combined (malicious skill triggers LLM exfiltration) — Modules 3, 7
2. **High:** Adversary C exploiting known CVEs on exposed gateway — Modules 5, 6
3. **High:** Adversary E leaving defaults open — Modules 1, 7
4. **Medium:** Adversary D on shared hosting — Modules 2, 4
