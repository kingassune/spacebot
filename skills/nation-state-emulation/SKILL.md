---
name: nation-state-emulation
description: "Comprehensive nation-state adversary emulation skill for authorized red team engagements. References MITRE ATT&CK, Lockheed Martin Cyber Kill Chain, and detection evasion scoring."
---

# Nation-State Adversary Emulation

You are emulating the tactics, techniques, and procedures (TTPs) of an advanced nation-state threat actor in an authorized red team engagement. All activity is strictly simulation-only within a documented, authorized scope.

## Pre-Engagement Requirements

- Verify written authorization from asset owner before proceeding.
- Confirm Rules of Engagement (ROE) and out-of-scope systems.
- Identify the deconfliction contact for blue team coordination.
- Document the threat actor profile to emulate (e.g., APT28, APT29, Lazarus, Sandworm).

## Workflow

### 1. Threat Actor Profile Selection

Select a threat actor profile from the James kill chain module:

```
james security red-team apt-profiles
```

Confirm the profile covers:
- Nation-state sponsor and objective (espionage / sabotage / financial).
- MITRE ATT&CK groups and associated techniques.
- Known tooling (Cobalt Strike, Mimikatz, custom implants).
- Historical campaign patterns.

### 2. Kill Chain Planning (Lockheed Martin Model)

Map the emulation to all seven kill chain phases:

| Phase | Description | Key ATT&CK Tactics |
|---|---|---|
| Reconnaissance | Target profiling, OSINT | TA0043 Reconnaissance |
| Weaponization | Payload development offline | TA0042 Resource Development |
| Delivery | Spearphishing / watering hole | TA0001 Initial Access |
| Exploitation | Vulnerability exploitation | TA0002 Execution |
| Installation | Malware / backdoor persistence | TA0003 Persistence |
| Command & Control | HTTPS/DNS C2 channels | TA0011 Command and Control |
| Actions on Objectives | Data theft / sabotage | TA0010 Exfiltration |

### 3. ATT&CK Technique Selection

For each kill chain phase, select 2–3 techniques appropriate to the emulated actor:

**Initial Access:**
- T1566.001 — Spearphishing Attachment (macro-enabled document)
- T1190 — Exploit Public-Facing Application
- T1195.002 — Compromise Software Supply Chain

**Execution:**
- T1059.001 — PowerShell
- T1059.003 — Windows Command Shell
- T1204.002 — Malicious File

**Persistence:**
- T1547.001 — Registry Run Keys / Startup Folder
- T1053.005 — Scheduled Task/Job

**Credential Access:**
- T1003.001 — LSASS Memory (Mimikatz)
- T1552.001 — Credentials In Files

**Lateral Movement:**
- T1021.001 — Remote Desktop Protocol
- T1550.002 — Pass the Hash

**Exfiltration:**
- T1041 — Exfiltration Over C2 Channel
- T1048.003 — Exfiltration Over Unencrypted Protocol

### 4. Detection Evasion Scoring

Before executing each technique, score its stealth profile:

- **Process Evasion:** Process hollowing, DLL injection, reflective loading.
- **AV/EDR Bypass:** AMSI patching, ETW blinding, direct syscalls.
- **Network Evasion:** Domain fronting, DNS-over-HTTPS C2, protocol mimicry.
- **Signature Evasion:** Payload obfuscation, packing, in-memory execution only.
- **Anti-Forensics:** Timestomping, log clearing, volume shadow deletion.

Score each technique 1–10 for detection likelihood. Prefer techniques scoring ≤4 during stealth phases.

### 5. Execution

Execute each phase in sequence. For each technique:

1. Record the ATT&CK technique ID and phase.
2. Note any IOCs generated (registry keys, file drops, network connections).
3. Record detection events from blue team.
4. Adjust technique selection if detection rate exceeds threshold.

### 6. Purple Team Integration

After each phase, share IOCs with the blue team deconfliction contact:
- Share technique IDs (not implementation details).
- Allow blue team to validate their detection rules.
- Document detection gaps for the gap analysis report.

### 7. Assessment and Reporting

Generate the kill chain report:
```
james security red-team kill-chain-report --engagement-id <id>
```

Report must include:
- Kill chain phases executed and success rate.
- Techniques used and detection rates.
- IOCs generated.
- Dwell time (time from initial access to objective).
- Blue team detection coverage percentage.
- Recommended remediation actions.

## Reference ATT&CK Groups

| Group | Sponsor | Focus | Key Techniques |
|---|---|---|---|
| APT28 (Fancy Bear) | Russia | Espionage | T1566.001, T1059.005, T1003.001 |
| APT29 (Cozy Bear) | Russia | Espionage | T1195.002, T1071.001, T1027 |
| Lazarus | North Korea | Financial / Sabotage | T1566.001, T1486, T1059.001 |
| Sandworm | Russia | Sabotage | T1486, T1561.002, T1195.001 |
| APT41 | China | Espionage + Criminal | T1190, T1059.001, T1078 |
| Kimsuky | North Korea | Espionage | T1566.001, T1005, T1041 |

## Output Checklist

- [ ] Threat actor profile documented
- [ ] Kill chain phases planned with ATT&CK technique mapping
- [ ] Evasion score computed per technique
- [ ] Engagement executed within authorized scope
- [ ] IOCs recorded and shared with deconfliction contact
- [ ] Detection gaps identified and scored
- [ ] Final kill chain report generated
- [ ] Remediation recommendations provided
