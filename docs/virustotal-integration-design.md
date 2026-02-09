# VirusTotal API Integration Design

**Version:** 1.0  
**Date:** February 9, 2026  
**Status:** Design Phase  
**Author:** Najm (Security Design Sub-Agent)

---

## Executive Summary

This document defines how the OpenClaw Security Audit Tool integrates VirusTotal API to **complement** (not duplicate) OpenClaw's native SHA-256 hash matching. Our integration focuses on areas VirusTotal provides that OpenClaw doesn't expose to users: behavioral analysis, supply chain verification, and context-aware threat intelligence.

**Core Principle:** We're not competing with VirusTotal — we're surfacing insights from it that users can't access through ClawHub alone, while adding OpenClaw-specific analysis layers.

---

## Table of Contents

1. [Context & Constraints](#context--constraints)
2. [VirusTotal API Capabilities](#virustotal-api-capabilities)
3. [Integration Philosophy](#integration-philosophy)
4. [Architecture Overview](#architecture-overview)
5. [Feature Specification](#feature-specification)
6. [API Usage Strategy](#api-usage-strategy)
7. [Data Model](#data-model)
8. [User Experience](#user-experience)
9. [Implementation Phases](#implementation-phases)
10. [Risk Assessment](#risk-assessment)
11. [Open Questions](#open-questions)

---

## Context & Constraints

### The Landscape (As of Feb 9, 2026)

**OpenClaw's Native Integration:**
- SHA-256 hash matching against VirusTotal during ClawHub skill installation
- Zero-friction, built-in protection
- Users don't see detailed VirusTotal reports — just "blocked" or "allowed"

**Our Tool's Position:**
- Local scanning (not just ClawHub installs)
- Comprehensive system auditing (config, permissions, behavior)
- Open-source, self-hostable, free

**Critical Constraint:** We must NOT duplicate OpenClaw's hash checking. We must ADD VALUE beyond what the platform provides.

### VirusTotal API Limits (Free Tier)

| Metric | Limit | Implication |
|--------|-------|-------------|
| **Daily requests** | 500 | ~50 skills scanned per day (if using 10 endpoints per skill) |
| **Rate limit** | 4 req/min | Scanning takes time — not instant |
| **Quota reset** | Daily at 00:00 UTC | Strategic batching needed |
| **Commercial use** | Prohibited | Must remain free/open-source tool |

**Design Decision:** We optimize for VALUE per API call, not speed. Each call must return actionable intelligence.

---

## VirusTotal API Capabilities

### What VirusTotal Provides (That OpenClaw Doesn't Expose)

#### 1. **Multi-Engine Malware Detection**
- 70+ antivirus engines (not just hash matching)
- Community votes and comments
- Crowdsourced threat intelligence

**Our Use:** Show which engines flagged a file and why (signatures, heuristics).

---

#### 2. **Behavioral Sandbox Analysis**

VirusTotal runs files in sandboxes and captures:

| Category | Data Points |
|----------|-------------|
| **Process behavior** | Processes created/terminated/injected |
| **File operations** | Files opened, written, deleted, modified |
| **Registry activity** | Keys opened, set, deleted (Windows) |
| **Network activity** | IP traffic, HTTP conversations, DNS queries |
| **Crypto operations** | Algorithms observed, keys used, plaintext decoded |
| **IDS alerts** | Network intrusion detection signatures |
| **MITRE ATT&CK** | Mapped attack techniques |
| **Sigma rules** | SIEM rule matches |
| **Certificate analysis** | TLS certs, JA3 fingerprinting |

**Our Use:** 
- Detect skills that phone home to C2 servers
- Identify crypto miners (CPU clock access + crypto algorithms)
- Flag privilege escalation attempts
- Map to MITRE ATT&CK framework for compliance reporting

---

#### 3. **Relationships & Context**

VirusTotal tracks:
- **Contacted domains/IPs** — Where the file reaches out to
- **Dropped files** — What it creates on disk
- **Embedded files** — What's packed inside
- **Similar files** — Behavioral hash (`behash`) matching

**Our Use:**
- Supply chain verification: Does this skill download code from sketchy domains?
- Detect multi-stage attacks: Does it drop executables?
- Find related threats: "This skill is behaviorally similar to known malware"

---

#### 4. **Threat Intelligence Enrichment**

- **Community votes:** Harmless vs. Malicious ratings
- **Crowdsourced comments:** Security researcher notes
- **Tags:** `OBFUSCATED`, `RUNTIME_MODULES`, `TROJAN`, etc.
- **Verdicts:** Per-sandbox verdicts with confidence scores

**Our Use:**
- Show community consensus: "23 users marked this malicious"
- Surface expert insights: "Researcher notes: 'Uses reflective DLL injection'"

---

## Integration Philosophy

### Core Principles

1. **Complement, Don't Compete**
   - Show what VirusTotal found AND what we found independently
   - Make overlap explicit: "VirusTotal flagged this. We ALSO found X based on local analysis."

2. **Context is King**
   - VirusTotal says "malicious" — we say WHY IT MATTERS for OpenClaw users
   - Example: "This skill phones home to C2 server. Your OpenClaw API keys may be at risk."

3. **Offline-First, Enhanced Online**
   - Tool works without VirusTotal (local patterns + IOC database)
   - VirusTotal adds depth when available (behavioral intel, community votes)

4. **Privacy-Preserving**
   - Never submit files to VirusTotal without explicit user consent
   - Hash-only lookups by default (no file uploads)
   - Clear disclosure when API calls happen

5. **Quota-Conscious**
   - Smart batching: scan high-risk skills first
   - Caching: store results for 24h to avoid re-querying
   - Prioritization: use API for unknowns, skip known-clean files

---

## Architecture Overview

### Module Structure

```
modules/
├── virustotal_enrichment.py   # NEW: VT API integration module
├── skill_scanner.py            # MODIFIED: calls VT enrichment
├── config_scanner.py           # No changes
├── cve_mapper.py               # No changes
└── base.py                     # MODIFIED: add VT fields to Finding
```

### Data Flow

```
┌─────────────────────────────────────────────────────────────┐
│ 1. Skill Scanner (Local Analysis)                          │
│    - Parse SKILL.md for patterns                           │
│    - Compute SHA-256 hashes                                 │
│    - Check against local known_malicious.json              │
│    - Generate initial findings                             │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│ 2. VirusTotal Enrichment (Optional, API-dependent)         │
│    IF --vt-api-key provided:                               │
│      - Lookup file hashes (no upload)                      │
│      - Fetch behavioral reports                            │
│      - Get community votes & comments                      │
│      - Retrieve MITRE ATT&CK mappings                      │
│      - Cache results locally                               │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│ 3. Contextual Analysis (Our Value-Add)                     │
│    - Compare VT findings to OpenClaw permissions           │
│    - Flag behavioral mismatches                            │
│      Example: "Skill claims read-only, VT shows writes"   │
│    - Map network activity to known OpenClaw services       │
│    - Detect supply chain risks                             │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│ 4. Unified Reporting                                        │
│    Output shows:                                            │
│    - Local findings (always present)                       │
│    - VirusTotal enrichment (when available)                │
│    - Contextual analysis (our synthesis)                   │
└─────────────────────────────────────────────────────────────┘
```

---

## Feature Specification

### Phase 1: Basic Hash Lookup (MVP)

**Goal:** Show what VirusTotal knows about skills already in user's system.

#### Features

1. **Hash-Only Lookups**
   - Compute SHA-256 of Python scripts in skills
   - Query `/files/{hash}` endpoint (no upload)
   - Show detection ratio (e.g., "3/70 engines flagged this")

2. **Detection Summary**
   - List which engines detected threat
   - Show detection names (e.g., "Trojan.Generic", "Backdoor.Agent")
   - Display last analysis date

3. **Community Intelligence**
   - Votes: X harmless, Y malicious
   - Comments from security researchers (if public)

#### CLI Usage

```bash
# Scan with VirusTotal enrichment
python3 audit.py --vt-api-key YOUR_KEY

# Scan without VT (offline mode)
python3 audit.py
```

#### Output Example

```markdown
### 🔴 [CRITICAL] Known malicious skill detected: clawhub

**Category:** Malicious Skill  
**Affected Path:** `~/.openclaw/skills/clawhub/install.py`

**Local Analysis:**
- Matches known malicious skill from Snyk/Koi research
- Contains base64-encoded shell command pattern

**VirusTotal Enrichment:**
- **Detection:** 48/70 engines flagged as malicious
- **Top detections:** 
  - Kaspersky: Trojan.Python.Agent.a
  - Microsoft: Trojan:Python/InfoStealer
  - CrowdStrike: malicious_confidence_100%
- **Community votes:** 87 malicious, 2 harmless
- **Last analyzed:** 2026-02-03 14:22 UTC

**Behavioral Analysis (VirusTotal Sandbox):**
- ⚠️ Connected to 91.92.242.30 (known C2 server)
- ⚠️ Downloaded executable from download.setup-service.com
- ⚠️ Created files in system temp directory

**MITRE ATT&CK Mapping:**
- T1059.006 - Command and Scripting Interpreter: Python
- T1071.001 - Application Layer Protocol: Web Protocols
- T1105 - Ingress Tool Transfer

**Remediation:**
IMMEDIATELY remove: `rm -rf ~/.openclaw/skills/clawhub`  
Rotate all API keys and passwords.
```

---

### Phase 2: Behavioral Analysis

**Goal:** Surface behavioral red flags that hash matching can't catch.

#### Features

1. **Network Activity Correlation**
   - Cross-reference VT's contacted IPs/domains with:
     - Known C2 servers (our IOC database)
     - Legitimate OpenClaw services (whitelist)
   - Flag unexpected network destinations

2. **Permission Mismatch Detection**
   - Compare SKILL.md declared permissions to actual VT behavior
   - Example: Skill says "local-only" but VT shows network connections
   - Example: Skill says "read files" but VT shows registry modifications

3. **Supply Chain Verification**
   - If skill downloads npm/pip packages, check if VT has intel on those
   - Flag if downloaded files are themselves flagged by VT

4. **Behavioral Pattern Analysis**
   - Detect crypto mining indicators:
     - High CPU usage patterns
     - Crypto algorithm usage (SHA-256, Scrypt, etc.)
     - Pool server connections
   - Detect data exfiltration:
     - File reads + network uploads
     - Clipboard access + network activity

#### Example Finding

```markdown
### 🟠 [HIGH] Behavioral mismatch: skill-example

**Our Analysis:**
SKILL.md claims: "Local-only text processing, no network access"

**VirusTotal Sandbox Observed:**
- Connected to 45.33.12.89:443 (HTTPS)
- Uploaded 127KB of data
- Accessed files: ~/.openclaw/openclaw.json, ~/.env

**Risk Assessment:**
Skill has network capabilities not disclosed in SKILL.md.  
May be exfiltrating OpenClaw config and API keys.

**Recommendation:**
Remove skill and audit for credential compromise.
```

---

### Phase 3: Continuous Threat Intelligence

**Goal:** Keep threat intel fresh without hitting API limits.

#### Features

1. **Delta Scanning**
   - On first run: scan all skills, cache VT results
   - On subsequent runs: only query new/modified skills
   - Cache TTL: 7 days (balance freshness vs quota)

2. **Threat Feed Integration**
   - Daily batch job: check if known_malicious.json has new entries
   - Query VT for new IOCs only
   - Update local cache

3. **Community Intel Sync**
   - Weekly: re-check previously clean skills for new community votes
   - Prioritize high-install-count skills from ClawHub

4. **YARA Rule Matching** (Premium API only, fallback)
   - If user has premium VT API: submit YARA rules for OpenClaw-specific threats
   - Example: detect skills that access ~/.openclaw/identity/

---

## API Usage Strategy

### Quota Management

**Daily Budget:** 500 requests  
**Allocation:**

| Use Case | Requests/Day | Priority | Justification |
|----------|--------------|----------|---------------|
| **New skill scans** | 200 | P0 | Critical: unknown threats |
| **Behavioral lookups** | 150 | P1 | High value: context |
| **Community intel** | 100 | P2 | Medium value: votes/comments |
| **Re-scans (weekly)** | 50 | P3 | Low urgency: refresh |

### Request Optimization

1. **Batch by Priority**
   - Scan high-risk skills first (those with suspicious patterns in SKILL.md)
   - Skip known-clean skills (e.g., official OpenClaw skills)

2. **Smart Caching**
   ```python
   cache_key = f"{file_sha256}:{last_modified_timestamp}"
   if cache.get(cache_key) and age < 7_days:
       return cached_result
   ```

3. **Graceful Degradation**
   - If quota exhausted: continue with local-only analysis
   - Queue remaining skills for next day
   - Report: "X skills pending VirusTotal analysis"

4. **Rate Limiting**
   ```python
   # 4 requests/min = 15 seconds between requests
   time.sleep(15)
   ```

### API Endpoints Used

| Endpoint | Purpose | Requests/Skill | Priority |
|----------|---------|----------------|----------|
| `GET /files/{hash}` | Detection summary | 1 | P0 |
| `GET /files/{hash}/behaviours` | Sandbox reports | 1 | P1 |
| `GET /files/{hash}/votes` | Community votes | 1 | P2 |
| `GET /files/{hash}/comments` | Expert insights | 1 | P3 |

**Total per skill (full analysis):** 4 requests  
**Max skills per day (full):** 125 skills  
**Typical deployment:** 10-50 skills → fits comfortably in quota

---

## Data Model

### Extended Finding Object

```python
@dataclass
class Finding:
    # Existing fields
    severity: str
    category: str
    title: str
    description: str
    remediation: str
    affected_path: Optional[str]
    
    # NEW: VirusTotal enrichment
    vt_data: Optional[VTEnrichment] = None

@dataclass
class VTEnrichment:
    # Hash lookup
    file_sha256: str
    detection_ratio: str  # e.g., "48/70"
    last_analysis_date: str
    detected_engines: List[Dict[str, str]]  # [{name, result}]
    
    # Community
    community_votes: Dict[str, int]  # {harmless: 2, malicious: 87}
    community_comments: List[str]
    
    # Behavioral (if available)
    sandbox_name: Optional[str]
    network_activity: List[Dict[str, Any]]  # [{dest_ip, port, protocol}]
    files_written: List[str]
    registry_modified: List[str]
    processes_created: List[str]
    mitre_attack_techniques: List[str]  # ["T1059.006", ...]
    
    # Analysis metadata
    vt_query_timestamp: str
    cached: bool
```

### Cache Structure

**Location:** `~/.openclaw-audit/vt-cache/`

```json
{
  "file_sha256": "abc123...",
  "last_modified": "2026-02-09T12:00:00Z",
  "query_timestamp": "2026-02-09T14:30:00Z",
  "ttl_days": 7,
  "data": {
    "detection_ratio": "3/70",
    "engines": [...],
    "behavior": {...}
  }
}
```

**Cache invalidation:**
- File modified → invalidate
- Age > TTL → re-query
- Manual flag: `--vt-force-refresh`

---

## User Experience

### Configuration

**Option 1: Environment Variable**
```bash
export VIRUSTOTAL_API_KEY="your-key-here"
python3 audit.py
```

**Option 2: Config File**
```json
// ~/.openclaw-audit/config.json
{
  "virustotal": {
    "api_key": "your-key-here",
    "cache_ttl_days": 7,
    "quota_limit": 500
  }
}
```

**Option 3: CLI Flag**
```bash
python3 audit.py --vt-api-key YOUR_KEY
```

### Privacy Controls

**Interactive Mode (Default for first run):**
```
VirusTotal Integration
----------------------
This will query VirusTotal API with file hashes (no uploads).
Your API key is required (free tier: 500 requests/day).

⚠️  Privacy notice:
- File hashes will be sent to VirusTotal
- No file contents are uploaded
- VirusTotal may log your IP and query history
- Results are cached locally

Continue? [y/N]:
```

**Disable VT Entirely:**
```bash
python3 audit.py --no-virustotal
```

### Output Formats

**1. Terminal (Enhanced)**
```
[CRITICAL] Malicious skill: clawhub
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Path: ~/.openclaw/skills/clawhub/install.py

🔍 Local Analysis:
  • Matches known IOC (Snyk Research)
  • Pattern: base64-encoded shell command

🌐 VirusTotal Enrichment:
  • Detection: 48/70 engines (68% detection rate)
  • Top engines: Kaspersky, Microsoft, CrowdStrike
  • Community: 87 malicious votes, 2 harmless
  • Behavior: Network connection to 91.92.242.30 (C2 server)

⚠️  MITRE ATT&CK:
  • T1059.006 - Python scripting
  • T1105 - Ingress tool transfer

🛠️  Remediation:
  IMMEDIATELY remove: rm -rf ~/.openclaw/skills/clawhub
  Rotate all API keys and passwords.
```

**2. JSON (Machine-Readable)**
```json
{
  "findings": [{
    "severity": "CRITICAL",
    "title": "Malicious skill: clawhub",
    "vt_data": {
      "detection_ratio": "48/70",
      "detected_engines": [
        {"name": "Kaspersky", "result": "Trojan.Python.Agent.a"},
        {"name": "Microsoft", "result": "Trojan:Python/InfoStealer"}
      ],
      "community_votes": {"harmless": 2, "malicious": 87},
      "network_activity": [
        {"dest_ip": "91.92.242.30", "port": 443, "protocol": "TCP"}
      ],
      "mitre_attack": ["T1059.006", "T1105"]
    }
  }]
}
```

**3. Markdown Report**
```markdown
## VirusTotal Intelligence Summary

**Skills analyzed:** 42  
**VirusTotal queries:** 38 (4 cached)  
**Threats detected:** 2

### Detection Coverage

| Source | Detections |
|--------|------------|
| Local IOC database | 2 |
| VirusTotal (hash) | 2 |
| VirusTotal (behavior) | 1 |
| Our heuristics | 3 |

### VirusTotal Insights

1. **clawhub** - 48/70 engines detected
   - Known C2 communication
   - Credential theft behavior observed
   
2. **crypto-miner-skill** - 12/70 engines detected
   - Mining pool connection observed
   - High CPU usage pattern
```

---

## Implementation Phases

### Phase 1: Hash Lookup MVP (Week 1)

**Goals:**
- Basic VT API integration
- Hash-only lookups
- Detection ratio display
- Caching layer

**Deliverables:**
- `modules/virustotal_enrichment.py`
- Modified `modules/skill_scanner.py`
- API key configuration
- Cache system
- Tests

**Success Criteria:**
- Scan 50 skills without hitting rate limits
- Cache reduces API calls by 80% on re-scan
- Detection ratio shown in terminal output

---

### Phase 2: Behavioral Analysis (Week 2)

**Goals:**
- Fetch sandbox behavioral reports
- Network activity analysis
- MITRE ATT&CK mapping
- Community votes/comments

**Deliverables:**
- Behavioral data parsing
- Permission mismatch detection
- Enhanced reporting (MITRE ATT&CK section)
- Network IOC correlation

**Success Criteria:**
- Detect at least 1 behavioral threat local patterns miss
- MITRE ATT&CK mappings displayed for all findings
- Network activity correlated with IOC database

---

### Phase 3: Context & Intelligence (Week 3)

**Goals:**
- Supply chain verification
- Config drift detection
- Continuous intel updates
- Compliance reporting

**Deliverables:**
- Dependency analyzer (npm/pip in skills)
- Behavioral pattern library
- Weekly threat feed sync
- Compliance mapping (SOC2, ISO27001)

**Success Criteria:**
- Detect supply chain risk (malicious dependency)
- Generate compliance-ready report
- Threat intel stays fresh (weekly updates)

---

## Risk Assessment

### Technical Risks

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| **API quota exhaustion** | HIGH | MEDIUM | Smart caching, prioritization, graceful degradation |
| **Rate limit blocking** | MEDIUM | LOW | 15s sleep between requests, batch processing |
| **API key exposure** | MEDIUM | HIGH | Environment vars, config file permissions (600), .gitignore |
| **False positives** | MEDIUM | MEDIUM | Show detection ratio, community votes for context |
| **Stale cache** | LOW | MEDIUM | 7-day TTL, manual refresh flag |

### Privacy Risks

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| **User tracking by VT** | HIGH | LOW | Disclosure in docs, hash-only queries (no uploads) |
| **Metadata leakage** | MEDIUM | LOW | No filenames sent, only hashes |
| **API key theft** | LOW | HIGH | Secure storage, user education, key rotation guidance |

### Operational Risks

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| **VT API downtime** | LOW | LOW | Offline mode always works, VT is bonus |
| **VT terms violation** | LOW | CRITICAL | No commercial use, free tool only, terms compliance |
| **User dependency on VT** | MEDIUM | MEDIUM | Emphasize: local analysis is primary, VT is enrichment |

---

## Open Questions

### For Implementation Team

1. **Cache Storage Location**
   - Option A: `~/.openclaw-audit/vt-cache/` (separate from OpenClaw)
   - Option B: `~/.openclaw/audit-cache/` (integrated)
   - **Recommendation:** Option A (avoid touching OpenClaw dirs)

2. **API Key Distribution**
   - Should we provide a shared community API key for hobbyists?
   - Risk: quota shared across all users, could be exhausted quickly
   - **Recommendation:** Users bring their own keys (free to register)

3. **Premium API Support**
   - Should we design for premium tier (if users upgrade)?
   - Premium offers: unlimited quota, YARA rules, more sandboxes
   - **Recommendation:** Design extensible, add premium features in Phase 4

4. **Behavioral Analysis Depth**
   - How much sandbox data to show? (Full dumps can be 100+ KB)
   - **Recommendation:** Summary by default, `--vt-detailed` flag for full

5. **MITRE ATT&CK Compliance**
   - Should we generate ATT&CK Navigator JSON for import?
   - **Recommendation:** Yes, Phase 3 feature for compliance teams

### For Product Direction

6. **Commercial Offering?**
   - If we offer hosted SaaS (future), how do we handle VT API costs?
   - **Recommendation:** User brings API key, or premium tier includes VT Premium

7. **Community Threat Feed**
   - Should we build our own IOC feed from VT + Koi + Snyk research?
   - **Recommendation:** Yes, Phase 3 — aggregate multiple sources

8. **Skill Reputation System**
   - Should we assign trust scores to skills (VT + community + our analysis)?
   - **Recommendation:** Phase 4 — "OpenClaw Skill Trust Score"

---

## Appendix: VirusTotal API Reference

### Endpoints Used

**File Hash Lookup:**
```http
GET https://www.virustotal.com/api/v3/files/{hash}
Headers:
  x-apikey: YOUR_API_KEY
```

**Behavioral Report:**
```http
GET https://www.virustotal.com/api/v3/files/{hash}/behaviours
```

**Community Votes:**
```http
GET https://www.virustotal.com/api/v3/files/{hash}/votes
```

**Community Comments:**
```http
GET https://www.virustotal.com/api/v3/files/{hash}/comments
```

### Rate Limits

- **Free Tier:** 4 requests/minute, 500/day
- **Quota Reset:** Daily at 00:00 UTC
- **HTTP 429:** Quota exceeded (retry after reset)

### Authentication

```bash
# Environment variable (recommended)
export VIRUSTOTAL_API_KEY="abc123..."

# Request header
x-apikey: abc123...
```

---

## References

- [VirusTotal API v3 Documentation](https://docs.virustotal.com/reference/overview)
- [Public vs Premium API Limits](https://docs.virustotal.com/reference/public-vs-premium-api)
- [File Behavior Reports](https://docs.virustotal.com/reference/file-behaviour-summary)
- [Koi Security: ClawHavoc Campaign](https://koi.ai/research/clawhavoc)
- [Snyk: ClawHub Campaign Analysis](https://snyk.io/blog/clawhub-campaign)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)

---

**Next Steps:**
1. Review this design doc with main agent
2. Get approval on architecture + API strategy
3. Implement Phase 1 (Hash Lookup MVP)
4. Test with 50-skill deployment
5. Iterate based on quota usage + user feedback

---

*Design document completed by Najm Security Design Sub-Agent*  
*Date: February 9, 2026*
