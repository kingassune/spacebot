---
name: cross-domain
description: "Cross-domain security analysis combining red team, blue team, blockchain, and pentest findings into unified risk scoring, attack path to detection gap correlation, and executive reporting."
allowed-tools: ["shell", "file", "exec"]
---

# Cross-Domain Security Analysis

You are aggregating and correlating security findings across all James platform domains — red team, blue team, blockchain, and penetration testing — to produce a unified risk picture and prioritized remediation roadmap.

## Reference Module

```
src/meta_agent/cross_domain.rs — CrossDomainAnalyzer
```

## Unified Findings Aggregation

### Findings Import

```bash
# Import findings from all active engagement reports
james meta cross-domain import \
  --source red-team --engagement-id $RT_ID \
  --source blue-team --engagement-id $BT_ID \
  --source blockchain --engagement-id $BC_ID \
  --source pentest --engagement-id $PT_ID \
  --output meta/unified_findings.json

# Normalize finding schema across domains
james meta normalize-findings \
  --input meta/unified_findings.json \
  --schema meta/finding_schema.json \
  --output meta/normalized_findings.json
```

### Unified Finding Schema

Every finding, regardless of domain, is normalized to:

```json
{
  "id": "FIND-001",
  "domain": "red-team | blue-team | blockchain | pentest",
  "title": "Finding title",
  "severity": "Critical | High | Medium | Low | Informational",
  "cvss_score": 9.1,
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
  "mitre_techniques": ["T1059.001", "T1021.001"],
  "cve_ids": [],
  "affected_assets": ["10.0.0.1", "api.example.com"],
  "remediation": "Patch description or control recommendation",
  "detection_coverage": "detected | not-detected | unknown",
  "evidence": "Log references, screenshots, proof of concept"
}
```

## Cross-Domain Correlation

### Attack Path to Detection Gap Mapping

The most valuable cross-domain analysis: map what the red team did to what the blue team detected (or missed).

```bash
# Correlate red team techniques with detection coverage
james meta correlate-attack-detect \
  --red-team meta/normalized_findings.json \
  --blue-team meta/detection_coverage.json \
  --output meta/attack_detect_gaps.json

# Show techniques that were executed but not detected
jq '[.correlations[] | select(.executed == true and .detected == false)] | 
    sort_by(-.cvss_score)' meta/attack_detect_gaps.json
```

### Attack Path Visualization

```bash
# Generate attack path diagram (DOT format)
james meta attack-path-graph \
  --findings meta/normalized_findings.json \
  --output meta/attack_paths.dot

# Render to SVG
dot -Tsvg meta/attack_paths.dot -o reports/attack_paths.svg

# Identify critical attack paths (paths reaching Tier 0 assets)
james meta critical-paths \
  --graph meta/attack_paths.dot \
  --tier0-assets "$AD_DOMAIN_CONTROLLER,$PROD_DB" \
  --output meta/critical_paths.json
```

### Blockchain + Traditional Security Correlation

For organizations with both on-chain and off-chain infrastructure:

```bash
# Find admin keys stored on compromised hosts
james meta correlate \
  --pentest-finding "admin credentials on compromised host" \
  --blockchain-finding "privileged contract deployer key" \
  --output meta/blockchain_host_correlation.json

# Assess bridge admin key exposure via social engineering vectors
james meta correlate \
  --social-eng-finding "phishing success rate" \
  --blockchain-finding "multisig threshold" \
  --question "How many signers could be phished to reach threshold?"
```

## Risk Scoring Across Domains

### Composite Risk Score

```bash
# Calculate composite risk score per asset
james meta risk-score \
  --findings meta/normalized_findings.json \
  --assets meta/asset_inventory.json \
  --model cvss-weighted \
  --output meta/risk_scores.json

# Generate risk heatmap by business unit
james meta risk-heatmap \
  --risk-scores meta/risk_scores.json \
  --group-by business_unit \
  --output reports/risk_heatmap.html
```

### Risk Scoring Model

```
Composite Risk = (CVSS Base Score × Exploitability Weight × Asset Criticality) / Detection Coverage Factor

Where:
  Exploitability Weight = 1.5 if exploited by red team, 1.0 if theoretical
  Asset Criticality     = 2.0 for Tier 0, 1.5 for Tier 1, 1.0 for Tier 2
  Detection Coverage    = 0.5 if detected in <1hr, 1.0 if detected >1hr, 2.0 if not detected
```

### Prioritized Remediation Matrix

```bash
# Generate remediation priority matrix
james meta remediation-matrix \
  --risk-scores meta/risk_scores.json \
  --effort-estimates meta/effort_estimates.json \
  --output meta/remediation_matrix.json

# Top-N remediations by risk/effort ratio
jq '.remediations | sort_by(-.risk_per_effort) | .[0:15]' meta/remediation_matrix.json
```

## Executive Summary Generation

### Summary Structure

```bash
# Generate full executive summary
james meta executive-summary \
  --findings meta/normalized_findings.json \
  --risk-scores meta/risk_scores.json \
  --attack-paths meta/critical_paths.json \
  --detection-gaps meta/attack_detect_gaps.json \
  --format pdf \
  --audience executive \
  --output reports/executive_summary_$(date +%Y%m%d).pdf
```

The executive summary includes:

1. **Overall Risk Rating** — single risk score with color coding (Critical/High/Medium/Low)
2. **Key Findings Table** — top 10 findings by risk score across all domains
3. **Critical Attack Path** — one or two narrative attack paths in plain language
4. **Detection Effectiveness** — % of red team techniques detected vs. missed
5. **Domain Breakdown** — risk summary per domain (red team, blockchain, pentest, cloud)
6. **Remediation Roadmap** — top 10 actions with effort and risk reduction estimates
7. **Trend Analysis** — comparison against previous assessment if available

### Technical Report Generation

```bash
# Generate full technical report
james meta technical-report \
  --findings meta/normalized_findings.json \
  --include-evidence \
  --include-poc \
  --format html \
  --output reports/technical_report_$(date +%Y%m%d).html

# Generate per-domain appendices
james meta domain-appendix \
  --domain red-team \
  --findings meta/normalized_findings.json \
  --output reports/appendix_red_team.html
```

## Continuous Cross-Domain Monitoring

```bash
# Set up cross-domain correlation alerts
james meta monitor \
  --correlate red-team:siem-detection \
  --alert-on undetected_critical \
  --notify security-team@company.com \
  --interval 1h

# Track remediation progress
james meta remediation-tracker \
  --baseline reports/technical_report_20240101.html \
  --current reports/technical_report_$(date +%Y%m%d).html \
  --output meta/remediation_progress.json
```

## Output Checklist

- [ ] Findings imported and normalized from all domains
- [ ] Attack path to detection gap correlation completed
- [ ] Critical attack paths (reaching Tier 0 assets) identified
- [ ] Composite risk scores calculated per asset and business unit
- [ ] Remediation priority matrix generated
- [ ] Executive summary produced in PDF
- [ ] Full technical report generated with evidence
- [ ] Remediation progress tracking initialized
- [ ] Cross-domain correlation alerts configured
