---
name: burpsuite-project-parser
description: "James integration of Trail of Bits' Burp Suite tooling. Parses and analyzes Burp Suite project files for web application security findings."
---

# Burp Suite Project Parser

You are parsing and analyzing a Burp Suite project export for web application security findings.

## Workflow

### 1. Ingest the Export
Burp Suite exports are XML. Parse the following top-level sections:
- `<issues>` — scanner-identified vulnerabilities.
- `<items>` — HTTP request/response pairs from proxy history.
- `<host>` — target host inventory.

### 2. Issue Extraction
For each `<issue>` element, extract:
- `<name>` — vulnerability name.
- `<severity>` — High / Medium / Low / Information.
- `<confidence>` — Certain / Firm / Tentative.
- `<host>` / `<path>` — affected URL.
- `<issueDetail>` — scanner description.
- `<requestresponse>` — evidence (request/response pair).

### 3. OWASP Category Mapping
Map each finding to an OWASP Top 10 or OWASP API Top 10 category:

| Burp Issue Name | OWASP Category |
|-----------------|----------------|
| SQL injection | A03: Injection |
| Cross-site scripting (reflected) | A03: Injection |
| Broken access control | A01: Broken Access Control |
| CSRF | A01: Broken Access Control |
| Sensitive data in URL | A02: Cryptographic Failures |
| SSL/TLS issues | A02: Cryptographic Failures |
| Open redirect | A10: SSRF / Redirects |

Add any unmapped issues to an "Uncategorized" section.

### 4. Deduplication
Group duplicate findings by (issue name + host + path pattern). Keep the highest-confidence instance as canonical. Report count of duplicates suppressed.

### 5. False Positive Triage
Flag likely false positives:
- Tentative confidence + generic issue name.
- Scanner-generated payloads in non-exploitable contexts.
- Issues in static assets (`.js`, `.css`, `.png`).

### 6. Summary Report
Produce:
```
## Burp Suite Findings Summary

Target(s): <hosts>
Total raw issues: <N>
After dedup: <N>
False positives suppressed: <N>

### By Severity
- High: <N>
- Medium: <N>
- Low: <N>
- Informational: <N>

### Top Findings
1. [High] <name> — <url> — <one-line description>
2. ...

### Recommendations
<prioritized remediation steps>
```
