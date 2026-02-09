# OpenClaw Security Suite — Comprehensive Plan

## Vision
The most complete security tool for OpenClaw installations. Not just a config scanner — a full security platform covering static analysis, runtime monitoring, skill vetting, and vulnerability mapping.

## Competitive Landscape (Researched Feb 9, 2026)

| Competitor | Focus | Stars | Gap |
|-----------|-------|-------|-----|
| Guardz OpenClaw Analyzer | MSP hardening (gateway, DM, sandbox) | N/A | Enterprise-only, closed approach |
| openclaw-security-scan (legendaryabhi) | CLI bash scanner + auto-fix | ~new | Simple bash, no IOC DB |
| openclaw-security-monitor (adibirzu) | 32-point defense-in-depth | ~new | Monitoring only, no fix |
| openclaw-secure-stack (yi-john-huang) | Deployment + prompt injection scanner | ~new | Stack-specific, not standalone |
| openclaw-shield (Knostic) | Runtime plugin (PII, secrets, tool blocking) | ~new | Plugin, not scanner |
| clawprint (Cyntrisec) | Tamper-evident audit trail | ~new | Forensics only |

## Our Differentiator
**One tool that does it all** — scan, detect, fix, monitor. Zero dependencies. Python 3.8+.

## Module Plan (8 modules)

### Module 1: Config Scanner ✅ DONE (v1.2.0)
- Gateway binding (loopback vs exposed)
- Auth token presence and strength
- File permissions (secrets, configs)
- Sensitive data redaction settings
- SKILL.md frontmatter scanning
- Known malicious package DB (341 IOCs from Snyk)

### Module 2: CVE Version Mapper 🆕
- Detect installed OpenClaw version
- Map against known CVEs:
  - CVE-2026-25253 (RCE via gateway chaining)
  - CVE-2026-24763 (command injection)
  - CVE-2026-25157 (command injection)
  - Authentication bypass via reverse proxy
  - WebSocket token exfiltration
- Output: which CVEs affect this installation, severity, fix version
- Auto-update CVE database from GitHub advisory feed

### Module 3: Prompt Injection Scanner 🆕
- Scan all installed SKILL.md files for injection patterns
- Detect: hidden instructions, role override attempts, data exfiltration prompts
- Pattern library: 50+ known injection techniques from OWASP LLM Top 10
- Scan workspace files for embedded instructions
- Check system prompt for anti-injection defenses

### Module 4: DM/Channel Policy Auditor 🆕
- Verify DM policy (pairing vs open)
- Check group chat settings (requireMention)
- Audit channel-specific permissions
- Verify session isolation (dmScope per-channel-peer)
- Flag overly permissive configurations

### Module 5: Sandbox & Tool Auditor 🆕
- Verify Docker sandbox is enabled and enforced
- Check tool allowlists/denylists
- Detect dangerous tool combinations (exec + browser + message = high risk)
- Verify workspace access mode (ro vs rw)
- Check for tool elevation settings

### Module 6: Network Exposure Scanner 🆕
- mDNS broadcast detection (leaks hostnames)
- Open port scanning (gateway, web UI)
- Reverse proxy misconfiguration detection
- TLS/SSL verification for external connections
- DNS leak detection

### Module 7: Secret & Credential Auditor 🆕
- Scan for plaintext API keys in config files
- Check for hardcoded tokens in SKILL.md files
- Verify environment variable usage for secrets
- Detect credential files with wrong permissions
- Check for secrets in git history (last 50 commits)

### Module 8: Runtime Monitor (Daemon Mode) 🆕
- Watch for suspicious tool calls in real-time
- Detect data exfiltration patterns (large outbound, unusual URLs)
- Alert on unauthorized skill installations
- Monitor for C2 communication patterns
- Log all tool executions with hash chain (like clawprint)

## Implementation Priority

### Wave 1 (Ship this week — highest differentiation)
1. Module 2: CVE Version Mapper
2. Module 3: Prompt Injection Scanner
3. Module 4: DM/Channel Policy Auditor

### Wave 2 (Next week)
4. Module 5: Sandbox & Tool Auditor
5. Module 7: Secret & Credential Auditor

### Wave 3 (Following week)
6. Module 6: Network Exposure Scanner
7. Module 8: Runtime Monitor

## Architecture
```
audit.py (main entry point)
├── modules/
│   ├── config_scanner.py      ✅ exists (refactor from monolith)
│   ├── cve_mapper.py          🆕
│   ├── injection_scanner.py   🆕
│   ├── channel_auditor.py     🆕
│   ├── sandbox_auditor.py     🆕
│   ├── network_scanner.py     🆕
│   ├── secret_auditor.py      🆕
│   └── runtime_monitor.py     🆕
├── data/
│   ├── known_malicious.json   ✅ exists
│   ├── cve_database.json      🆕
│   ├── injection_patterns.json 🆕
│   └── safe_defaults.json     🆕
├── tests/
│   ├── test_config_scanner.py
│   ├── test_cve_mapper.py
│   ├── test_injection_scanner.py
│   └── ...
└── reports/
    └── templates/
        ├── terminal.py        (colored CLI output)
        ├── json.py            (machine-readable)
        ├── html.py            🆕 (shareable report)
        └── markdown.py        🆕 (for docs/wikis)
```

## Quality Gates
- Every module: unit tests (≥80% coverage)
- Integration test: scan a known-vulnerable test fixture
- False positive rate: <5% (verified against 10 real installations)
- Zero dependencies (stdlib only)
- Python 3.8+ compatible

## Success Criteria
- Detects all 3 known CVEs on vulnerable versions
- Catches 90%+ of injection patterns from OWASP LLM benchmark
- Produces actionable fix recommendations (not just "found issue")
- Runs in <30 seconds on typical installation
- HTML report is shareable and professional

## Revenue Integration
- Free: Module 1 (config scanner) + Module 7 (secret auditor)
- Pro ($49): All 8 modules + HTML reports + CI integration + auto-fix
- Service ($250/audit): We run it for you + written report + remediation plan
