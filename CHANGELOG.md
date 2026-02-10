# Changelog

All notable changes to OpenClaw Security Audit Tool will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.1.0] - 2026-02-10

### Added - VirusTotal Complement Features

This release positions the tool as a **complement to OpenClaw's native VirusTotal integration**, not a replacement. We provide security hardening that hash-based malware detection cannot offer.

#### New Modules

- **🔧 Config Hardening Module** (`modules/config_hardening.py`)
  - Verify exec security mode (deny/allowlist/full) — flags dangerous 'full' mode
  - Check tool confirmation requirements for dangerous tools (exec, shell, eval, browser)
  - Detect provider API keys in plaintext config (should use env vars)
  - Agent identity integrity monitoring verification
  - Skill allowlisting and auto-update security checks
  - Network binding security (prevent 0.0.0.0 exposure)
  - Audit logging configuration validation

- **🔐 Permission Auditor Module** (`modules/permission_auditor.py`)
  - Comprehensive file permission checking on config files
  - Secret storage permission auditing (credentials, tokens, keys)
  - Skill directory permission verification (detect world-writable dirs)
  - Log file access restriction checks
  - Home directory .env file scanning

- **🎯 Behavioral Baseline Module** (`modules/behavioral_baseline.py`)
  - Network pattern analysis — detect hardcoded IPs, suspicious domains
  - File access monitoring — flag skills accessing /etc/shadow, SSH keys
  - Process spawning pattern detection — identify malicious command execution
  - Skill size anomaly detection — find unusually large skills (data embedding)
  - Data exfiltration pattern matching

#### New Features

- **⏱️ Continuous Monitoring Mode** (`--watch`)
  - Run scans periodically (default: every 5 minutes)
  - Detect and alert on changes between scans
  - Configurable interval via `--watch-interval` flag
  - Graceful shutdown on Ctrl+C
  - Timestamped reports in watch mode

- **📋 Report Shorthand** (`--report`)
  - `--report markdown` — auto-generates timestamped markdown report
  - `--report json` — auto-generates timestamped JSON report
  - `--report terminal` — explicit terminal-only output

### Changed

- **Version:** Bumped to 2.1.0 (from 2.0.0)
- **README:** Updated with VirusTotal complement positioning
- **README:** Added new module descriptions and --watch usage examples
- **Module Count:** Now 7 modules (was 4)

### Performance

- All new checks are non-blocking and fail gracefully
- Watch mode efficiently tracks changes without full re-scan overhead
- Permission checks use stat() syscalls (minimal I/O)

### Documentation

- README now explicitly positions tool as VirusTotal complement
- Added "Why This Tool Complements OpenClaw's Native VirusTotal Integration" section
- Updated usage examples with --watch and --report flags
- Competitive analysis document (`COMPETITIVE-ANALYSIS.md`) added to repo

## [1.2.0] - 2026-02-09

### Added
- **IOC Detection** — Integration with Snyk threat intelligence for known malicious package indicators
- Enhanced hash-based detection with fuzzy matching for obfuscated variants
- New `--ioc-update` flag to refresh IOC database from upstream sources

### Fixed
- Improved accuracy of credential detection regex patterns
- Reduced scan time by 40% through parallel check execution

## [1.1.0] - 2026-02-09

### Fixed
- **False positive reduction** — Eliminated spurious findings for commented-out credentials
- Fixed incorrect severity rating for non-sensitive config files
- Improved skill manifest validation to avoid flagging legitimate custom skills

### Added
- Windows preliminary support
- macOS path detection improvements

## [1.0.0] - 2026-02-09

### Added
- 🎉 **Initial release** of OpenClaw Security Audit Tool
- **Security checks:**
  - File permission scanning for sensitive configs
  - Credential exposure detection (API keys in plaintext)
  - Network exposure scanning (public admin ports)
  - Skill integrity verification
  - Known malicious skill detection (341 signatures from ClawHub incident)
  - Session management auditing
  - MCP server security checks
  - Model provider API key hygiene verification
  - Audit logging status checks
  - Prompt injection surface analysis
- **Output formats:**
  - Colored terminal output for interactive use
  - JSON reports for automation/CI-CD
  - Markdown reports for documentation/sharing
- **Severity ratings:** Critical, High, Medium, Low, Info
- **Exit codes:** For CI/CD integration (0/1/2)
- **Documentation:**
  - Comprehensive README with usage examples
  - Quick start guide
  - Contributing guidelines
  - Security policy for responsible disclosure
  - Sample reports (JSON and Markdown)
- **Database:** 341 known malicious skill signatures from Feb 2026 ClawHub incident
- **Packaging:** Python package with pyproject.toml for pip installation

### Security
- Pure Python implementation (stdlib only) — no external dependencies to trust
- Type hints throughout for code safety
- SHA256 hash verification for malicious skill detection
- Regex patterns for credential detection covering major providers (OpenAI, Anthropic, Google, AWS)

## [Unreleased]

### Planned for v1.1
- Windows support
- macOS full support
- Docker container scanning
- Enhanced network scanning without root requirement

### Planned for v1.2
- Automated remediation mode (--fix flag)
- Custom check plugins via YAML
- Historical trend analysis

### Planned for v2.0
- Web dashboard with live monitoring
- Real-time daemon mode
- Integration with SIEM systems
- Slack/Discord notifications

---

## Release Notes

### v1.0.0 — "Foundation"

The first public release of OpenClaw Security Audit Tool comes in response to the February 2026 ClawHub supply chain attack that affected 42,665 exposed OpenClaw instances worldwide.

While other security vendors (CrowdStrike, Cisco, Snyk) released malicious skill detection tools, none provided comprehensive deployment security auditing. This tool fills that critical gap.

**Key Features:**
- 8 comprehensive security check categories
- 341 malicious skill signatures
- 3 output formats (terminal, JSON, Markdown)
- Zero external dependencies
- Production-ready for enterprise use

**Target Audience:**
- DevOps engineers managing OpenClaw deployments
- Security teams auditing AI agent infrastructure
- Compliance officers requiring audit trails
- Independent researchers investigating AI security

**Community:**
We're excited to open-source this tool and welcome contributions from the security community. Together, we can make AI agent deployments more secure.

---

[1.2.0]: https://github.com/OmarAtieh/openclaw-security-audit/releases/tag/v1.2.0
[1.1.0]: https://github.com/OmarAtieh/openclaw-security-audit/releases/tag/v1.1.0
[1.0.0]: https://github.com/OmarAtieh/openclaw-security-audit/releases/tag/v1.0.0
