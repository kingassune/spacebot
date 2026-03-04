---
name: capability-analysis
description: "Maps James platform capabilities against MITRE ATT&CK, OWASP Top 10/ASVS, and NIST CSF frameworks to identify coverage gaps and generate prioritized remediation recommendations."
allowed-tools: ["shell", "file", "exec"]
---

# Capability Analysis

You are analyzing the coverage of the James security platform against industry frameworks. The goal is to produce an accurate coverage map, identify gaps, and prioritize new capability development.

## Reference Module

```
src/meta_agent/capability_analysis.rs — CapabilityAnalyzer
```

## MITRE ATT&CK Framework Mapping

### Coverage Map Generation

```bash
# Build current capability inventory
james meta capability-inventory \
  --include-skills \
  --include-plugins \
  --format json > meta/capabilities.json

# Map capabilities to ATT&CK techniques
james meta mitre-map \
  --capabilities meta/capabilities.json \
  --framework mitre-attack-v15 \
  --output meta/attack_coverage.json

# Generate ATT&CK Navigator layer
james meta attack-navigator-layer \
  --coverage meta/attack_coverage.json \
  --output meta/james_layer.json
# Import into https://mitre-attack.github.io/attack-navigator/
```

### Coverage by Tactic

Assess coverage for each ATT&CK tactic:

| Tactic | ATT&CK ID | James Skills | Coverage |
|---|---|---|---|
| Reconnaissance | TA0043 | apt-emulation, web-security | Partial |
| Resource Development | TA0042 | apt-emulation | Partial |
| Initial Access | TA0001 | apt-emulation, web-security, social-engineering | Good |
| Execution | TA0002 | apt-emulation, exploit-development | Good |
| Persistence | TA0003 | apt-emulation, incident-response | Good |
| Privilege Escalation | TA0004 | exploit-development, cloud-security | Partial |
| Defense Evasion | TA0005 | exploit-development, apt-emulation | Partial |
| Credential Access | TA0006 | apt-emulation, pentest | Partial |
| Discovery | TA0007 | network-security, cloud-security | Partial |
| Lateral Movement | TA0008 | apt-emulation, network-security | Good |
| Collection | TA0009 | apt-emulation | Partial |
| Command and Control | TA0011 | apt-emulation, threat-detection | Partial |
| Exfiltration | TA0010 | apt-emulation, threat-detection | Partial |
| Impact | TA0040 | incident-response, malware-analysis | Good |

```bash
# Identify uncovered techniques (high frequency, no coverage)
jq '[.tactics[] | .techniques[] | select(.coverage == 0 and .prevalence == "high")] | 
    sort_by(-.datasource_count) | .[0:20]' meta/attack_coverage.json

# Generate gap priority list
james meta gap-priority \
  --coverage meta/attack_coverage.json \
  --scoring "prevalence,datasource_availability,detection_difficulty" \
  --top 10 \
  --output meta/priority_gaps.json
```

## OWASP Coverage

### OWASP Top 10 (Web)

```bash
# Map web-security skill to OWASP Top 10
james meta owasp-map \
  --skill web-security \
  --version 2021 \
  --output meta/owasp_web_coverage.json
```

| OWASP ID | Category | James Skill | Coverage |
|---|---|---|---|
| A01:2021 | Broken Access Control | web-security | Full |
| A02:2021 | Cryptographic Failures | web-security, contract-audit | Full |
| A03:2021 | Injection | web-security | Full |
| A04:2021 | Insecure Design | scoping-and-reporting | Partial |
| A05:2021 | Security Misconfiguration | cloud-security, network-security | Full |
| A06:2021 | Vulnerable Components | contract-audit, network-security | Partial |
| A07:2021 | Auth Failures | web-security, wallet-security | Full |
| A08:2021 | Software Integrity Failures | contract-audit, malware-analysis | Partial |
| A09:2021 | Security Logging Failures | siem-integration, threat-detection | Partial |
| A10:2021 | SSRF | web-security | Full |

### OWASP ASVS (Application Security Verification Standard)

```bash
# Generate ASVS gap report
james meta asvs-gap \
  --level 2 \
  --current-skills meta/capabilities.json \
  --output meta/asvs_gaps.json

# Identify unverified ASVS requirements
jq '.requirements[] | select(.covered == false) | {id, description, level}' meta/asvs_gaps.json
```

### OWASP Smart Contract Top 10

| SC Rank | Category | James Skill | Coverage |
|---|---|---|---|
| SC01 | Reentrancy | contract-audit | Full |
| SC02 | Integer Overflow | contract-audit | Full |
| SC03 | Timestamp Dependence | contract-audit | Partial |
| SC04 | Access Control | contract-audit | Full |
| SC05 | Front Running | defi-security | Full |
| SC06 | Denial of Service | contract-audit | Partial |
| SC07 | Logic Errors | contract-audit | Partial |
| SC08 | Unsafe External Calls | contract-audit, bridge-audit | Full |
| SC09 | Bad Randomness | consensus-analysis | Partial |
| SC10 | Short Address | contract-audit | Full |

## NIST CSF Gap Analysis

### CSF Function Coverage

```bash
# Generate NIST CSF coverage report
james meta nist-csf-map \
  --capabilities meta/capabilities.json \
  --csf-version 2.0 \
  --output meta/nist_csf_coverage.json
```

| Function | Category | James Coverage | Gap |
|---|---|---|---|
| GOVERN | Organizational Context | ⚠️ Partial | Policy templates needed |
| IDENTIFY | Asset Management | ✅ network-security | — |
| IDENTIFY | Risk Assessment | ✅ scoping-and-reporting | — |
| PROTECT | Access Control | ✅ web-security, cloud-security | — |
| PROTECT | Awareness Training | ✅ social-engineering | — |
| PROTECT | Data Security | ⚠️ Partial | DLP skill gap |
| DETECT | Anomalies and Events | ✅ threat-detection, siem-integration | — |
| DETECT | Continuous Monitoring | ✅ siem-integration | — |
| RESPOND | Incident Management | ✅ incident-response | — |
| RESPOND | Communications | ❌ Missing | Comms playbook needed |
| RECOVER | Recovery Planning | ⚠️ Partial | Recovery runbook gap |
| RECOVER | Improvements | ✅ self-extension | — |

```bash
# Quantify CSF maturity level per function
james meta csf-maturity \
  --coverage meta/nist_csf_coverage.json \
  --output meta/csf_maturity.json
# Returns maturity levels: 1 (Partial) → 4 (Adaptive)
```

## Coverage Report Generation

```bash
# Generate full coverage report (HTML)
james meta coverage-report \
  --frameworks "mitre-attack,owasp-top10,owasp-smart-contract,nist-csf" \
  --capabilities meta/capabilities.json \
  --format html \
  --output reports/capability_coverage_$(date +%Y%m%d).html

# Generate executive summary
james meta executive-summary \
  --coverage-report reports/capability_coverage_$(date +%Y%m%d).html \
  --format markdown \
  --output reports/executive_summary.md
```

## Remediation Priority Recommendations

```bash
# Generate prioritized skill development roadmap
james meta development-roadmap \
  --gaps meta/priority_gaps.json \
  --effort-scoring medium \
  --output meta/roadmap.json

# Top recommendations based on coverage impact vs. effort
jq '.recommendations | sort_by(-.impact_per_effort) | .[0:10]' meta/roadmap.json
```

Priority scoring factors:
- **Coverage impact:** How many gaps does this new skill close?
- **Threat prevalence:** How frequently is this technique used in real attacks?
- **Detection difficulty:** How hard is it to detect without dedicated tooling?
- **Implementation effort:** Estimated development time (S/M/L/XL).

## Output Checklist

- [ ] Capability inventory generated from all skills and plugins
- [ ] ATT&CK coverage map produced and Navigator layer exported
- [ ] OWASP Top 10 and ASVS coverage assessed
- [ ] NIST CSF function coverage mapped
- [ ] Top 10 priority gaps identified and scored
- [ ] Full coverage report generated in HTML
- [ ] Executive summary produced
- [ ] Development roadmap with prioritized recommendations delivered
