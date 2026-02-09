# Test Fixtures

## `vulnerable/` — Insecure Mock Installation

Tests that the security suite **detects** all common misconfigurations:

| File | What It Tests |
|------|---------------|
| `openclaw.json` | Gateway bound to 0.0.0.0, auth disabled, plaintext API keys, no TLS, sandbox off, open DM policy, no requireMention, unsigned skills allowed |
| `SKILL.md` | 5 injection techniques: role override, base64 payload, zero-width chars, encoded shell command, data URL payload |
| `.env` | Plaintext secrets in environment file (world-readable in test) |
| `version.txt` | v2026.1.0 — affected by CVE-2026-25253, CVE-2026-24763, CVE-2026-25157 |

**Expected:** Every module (1–7) should flag multiple issues against this fixture.

## `hardened/` — Properly Secured Installation

Tests that the security suite **passes** a well-configured system:

| File | What It Tests |
|------|---------------|
| `openclaw.json` | Localhost binding, auth enabled, env-var secrets, TLS on, sandbox on, DMs off, requireMention on, signed skills only |
| `SKILL.md` | Clean skill with no injection patterns, proper metadata, signature |
| `version.txt` | v2026.2.3 — latest, no known CVEs |

**Expected:** All modules should pass with zero or minimal informational findings.

## Usage

```python
# Point scanner at fixture directory
result = audit.scan("/path/to/tests/fixtures/vulnerable/")
assert result.critical_count > 0

result = audit.scan("/path/to/tests/fixtures/hardened/")
assert result.critical_count == 0
```
