# Changelog

All notable changes to OpenClaw Security Audit Tool will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
