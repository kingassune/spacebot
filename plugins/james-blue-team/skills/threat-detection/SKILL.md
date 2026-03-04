---
name: threat-detection
description: "Threat detection covering SIGMA rule creation, YARA rule authoring for malware families, anomaly detection baseline establishment, and IOC correlation and enrichment."
allowed-tools: ["shell", "file", "exec"]
---

# Threat Detection

You are building and tuning threat detection capabilities for a security operations center. All detection content is deployed only in authorized environments.

## SIGMA Rule Creation Workflow

Reference module: `src/blue_team/detection.rs — SigmaRuleEngine`

### SIGMA Rule Structure

```yaml
title: Suspicious PowerShell Encoded Command Execution
id: a2a279c8-1e56-4d7d-9a4b-b1e3e3f7d0b0
status: experimental
description: Detects PowerShell execution with base64-encoded command via -EncodedCommand flag
references:
  - https://attack.mitre.org/techniques/T1059/001/
author: James Security
date: 2024/01/15
tags:
  - attack.execution
  - attack.t1059.001
  - attack.defense_evasion
  - attack.t1027
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\powershell.exe'
    CommandLine|contains:
      - ' -EncodedCommand '
      - ' -enc '
      - ' -ec '
  condition: selection
falsepositives:
  - Legitimate software using encoded commands (e.g., SCCM, some installers)
  - Security tools running encoded scan commands
level: medium
```

### Rule Creation Process

```bash
# Generate SIGMA rule from IOC
james security detect sigma-from-ioc \
  --technique T1059.001 \
  --log-source windows \
  --output rules/sigma/

# Validate rule syntax
sigma check rules/sigma/new_rule.yml

# Convert to SIEM query (Splunk)
sigma convert -t splunk rules/sigma/new_rule.yml

# Convert to Elastic KQL
sigma convert -t elasticsearch-dsl rules/sigma/new_rule.yml

# Test against log sample
sigma test rules/sigma/new_rule.yml --backend splunk --test-data samples/win_process.json
```

### Rule Quality Criteria

- [ ] Each rule targets a specific ATT&CK technique (tag with MITRE ID).
- [ ] False positive section documents known benign triggers.
- [ ] Log source specified (product + category).
- [ ] Rule tested against representative log samples before deployment.
- [ ] Rule assigned appropriate level: informational / low / medium / high / critical.

## YARA Rule Authoring

### YARA Rule Structure

```yara
rule APT29_SUNBURST_Dropper {
    meta:
        description = "Detects SUNBURST backdoor dropper used by APT29 in SolarWinds campaign"
        author = "James Security"
        date = "2024-01-15"
        reference = "https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain.html"
        hash = "d0d626deb3f9484e649294a8dfa814c5568f846d5aa02d4cdad5d041a29d5600"
        mitre_attack = "T1195.002"
    strings:
        $mz = { 4D 5A }
        $s1 = "SolarWinds.Orion.Core.BusinessLayer" wide ascii
        $s2 = "appsettings" nocase
        $suspicious_api1 = "GetTempPath" ascii
        $suspicious_api2 = "CreateThread" ascii
        $sleep_pattern = { 48 8B 05 ?? ?? ?? ?? 48 85 C0 74 }
    condition:
        $mz at 0 and
        all of ($s*) and
        2 of ($suspicious_api*) and
        $sleep_pattern
}
```

### YARA Development Workflow

```bash
# Test rule against sample directory
yara -r rules/apt29_sunburst.yar samples/

# Test for false positives against clean baseline
yara -r rules/apt29_sunburst.yar /usr/bin/ /usr/lib/ 2>/dev/null | wc -l

# Optimize rule for performance (avoid slow patterns)
yarAnalyzer rules/ --performance

# Validate rule syntax
yara rules/apt29_sunburst.yar /dev/null && echo "Syntax OK"

# Submit to VirusTotal Intelligence (if authorized)
vt yara-retrohunt rules/apt29_sunburst.yar --days 30
```

### Rule Quality Criteria

- [ ] At least one string condition is specific enough to minimize false positives.
- [ ] Rule tested against a clean baseline before production deployment.
- [ ] Rule tested against target malware family samples.
- [ ] Meta section includes reference, author, date, and MITRE ATT&CK technique.
- [ ] Performance-heavy rules (regex, wide strings) tested for scan speed.

## Anomaly Detection Baseline Establishment

Reference module: `src/blue_team/detection.rs — AnomalyDetector`

### Baseline Data Collection

```bash
# Establish process creation baseline (30-day window)
james security detect baseline \
  --data-source process_creation \
  --window 30d \
  --output baselines/process_baseline.json

# Establish network connection baseline
james security detect baseline \
  --data-source network_connections \
  --window 30d \
  --output baselines/network_baseline.json

# Establish authentication baseline
james security detect baseline \
  --data-source authentication \
  --window 30d \
  --output baselines/auth_baseline.json
```

### Anomaly Detection Metrics

| Signal | Baseline Metric | Alert Threshold |
|---|---|---|
| Failed logins per account | Mean + 3σ per hour | >10 failures / 5 min |
| New process parent-child pairs | Observed pairs | First-time pair involving sensitive process |
| External connection volume | Mean bytes/hr per host | >3σ above baseline |
| DNS query rate per host | Mean queries/hr | >5× baseline |
| Privileged account logins | Normal hours + source IPs | Login outside normal hours or from new IP |
| Lateral movement (SMB/RDP) | Observed connection graph | New connection between hosts not previously connected |

### Behavioral Detection Rules

```bash
# Detect new admin account creation
james security detect rule \
  --template new_admin_account \
  --threshold 1 \
  --window 1h

# Detect process injection indicators
james security detect rule \
  --template process_injection \
  --signals "CreateRemoteThread,VirtualAllocEx,WriteProcessMemory"

# Detect DNS beaconing
james security detect rule \
  --template dns_beaconing \
  --interval-variance 0.05 \
  --min-queries 50
```

## IOC Correlation and Enrichment

Reference module: `src/blue_team/threat_intel.rs — IocCorrelator`

### IOC Ingestion and Normalization

```bash
# Import IOCs from MISP feed
james security intel import-misp \
  --url https://misp.internal/events/restSearch \
  --key $MISP_API_KEY \
  --type ip,domain,hash

# Import from STIX/TAXII feed
james security intel import-taxii \
  --discovery-url https://taxii.threatintel.com/discovery \
  --collection "malware-iocs"

# Import from CSV
james security intel import-csv \
  --file iocs.csv \
  --columns "type,value,confidence,tlp"
```

### IOC Enrichment Pipeline

```bash
# Enrich IP addresses
james security intel enrich-ip 1.2.3.4 \
  --sources virustotal,shodan,abuseipdb,greynoise

# Enrich domain
james security intel enrich-domain evil.example.com \
  --sources virustotal,urlscan,whois

# Enrich file hash
james security intel enrich-hash d41d8cd98f00b204e9800998ecf8427e \
  --sources virustotal,malwarebazaar,hybridanalysis
```

### Correlation Queries

```bash
# Find hosts communicating with known-bad IPs
james security detect correlate \
  --ioc-type ip \
  --data-source network_logs \
  --window 7d

# Find hosts with known-bad file hashes
james security detect correlate \
  --ioc-type hash \
  --data-source endpoint_logs \
  --window 30d
```

## Output Checklist

- [ ] SIGMA rules created for target ATT&CK techniques
- [ ] YARA rules authored for relevant malware families
- [ ] Rules tested against samples and clean baseline
- [ ] Behavioral baselines established for key signals
- [ ] IOC feeds integrated and enrichment pipeline active
- [ ] Correlation rules deployed to SIEM
- [ ] False positive rate measured and acceptable (<5% per rule)
- [ ] Detection coverage mapped to ATT&CK matrix
