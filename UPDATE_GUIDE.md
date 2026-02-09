# Keeping the Malicious Skills Database Updated

## Why This Matters

The AI agent security landscape changes daily. New malicious skills appear on ClawHub, GitHub, and npm. This guide explains how to keep `known_malicious.json` current.

## Sources to Monitor

### Primary Sources (Check Weekly)
| Source | URL | What to Look For |
|--------|-----|-----------------|
| **Snyk Blog** | https://snyk.io/blog/ | MCP/OpenClaw security advisories |
| **Koi Security** | https://koisecurity.com | Clawdex scanner updates, new skill alerts |
| **HackerNews** | https://news.ycombinator.com | Search "OpenClaw security" or "ClawHub malicious" |
| **The Hacker News** | https://thehackernews.com | AI agent security articles |
| **ClawHub Advisories** | https://clawhub.ai/security | Official security notices |

### Secondary Sources (Check Monthly)
| Source | URL | What to Look For |
|--------|-----|-----------------|
| **CrowdStrike Blog** | https://crowdstrike.com/blog | OpenClaw threat intelligence |
| **Bitdefender** | https://bitdefender.com/blog | AI agent exploitation advisories |
| **CyberArk** | https://cyberark.com/resources | Agent identity attack research |
| **OWASP LLM Top 10** | https://owasp.org/www-project-top-10-for-llm | Framework updates |

### Automated Monitoring
```bash
# Search for new advisories (run weekly)
# Add to cron: 0 9 * * 1 /path/to/update-check.sh

curl -s "https://api.github.com/search/repositories?q=openclaw+security+created:>$(date -d '7 days ago' +%Y-%m-%d)&sort=updated" | \
  python3 -c "import json,sys; [print(r['full_name'], r['description'][:80]) for r in json.load(sys.stdin).get('items',[])]"
```

## How to Add a New Entry

### Adding a Malicious Skill

Edit `known_malicious.json` → `skills` array:

```json
{
  "name": "skill-name-here",
  "author": "clawhub-username",
  "threat": "Brief threat type (e.g., Infostealer, Reverse Shell)",
  "description": "What it does and how it works",
  "source": "Where you learned about it (e.g., Snyk Blog, Feb 2026)",
  "downloads_at_discovery": 0,
  "status": "active_threat"
}
```

**Status values:**
- `active_threat` — Still available or actively being distributed
- `removed` — Taken down but may have been installed
- `mitigated` — Patched/neutralized but worth detecting

### Adding IOCs (Indicators of Compromise)

Add to the `iocs` section:
- `ips` — C2 server IPs, payload delivery IPs
- `domains` — Malicious domains used in attacks
- `urls` — Specific URLs (GitHub releases, paste sites)
- `github_users` — Accounts created for malware distribution
- `clawhub_users` — ClawHub accounts publishing malicious skills

### Adding Detection Patterns

Add to `malicious_patterns.skill_md_patterns`:
```json
"new-suspicious-command-pattern"
```

These patterns are checked against SKILL.md file contents during scans.

## Validation After Update

```bash
# Verify JSON is valid
python3 -c "import json; json.load(open('known_malicious.json')); print('✅ Valid JSON')"

# Run a scan to verify new entries are detected
python3 audit.py --quiet
```

## Community Contributions

If you discover a malicious skill:
1. **Report to ClawHub** — https://clawhub.ai/security
2. **Report to Snyk** — Run `mcp-scan` and submit findings
3. **Add to this database** — Submit a PR with the entry + source

## Version History

| Date | Change | Source |
|------|--------|--------|
| 2026-02-09 | Initial database: clawhub, clawdhub1, openclawcli + IOCs | Snyk Research |
| | Added SKILL.md pattern detection (17 patterns) | Snyk, Koi Security |
| | Added suspicious indicator patterns (8 patterns) | Community reports |
