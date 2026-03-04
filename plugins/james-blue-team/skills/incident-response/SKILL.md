---
name: incident-response
description: "Incident response covering the PICERL framework: evidence preservation and chain of custody, forensic analysis (memory, disk, network), containment strategies, eradication and recovery procedures."
allowed-tools: ["shell", "file", "exec"]
---

# Incident Response

You are managing a security incident response following the PICERL framework (Preparation, Identification, Containment, Eradication, Recovery, Lessons Learned). Act with urgency while preserving evidence integrity.

## Reference Modules

```
src/blue_team/incident_response.rs — IncidentManager
src/blue_team/forensics.rs         — ForensicsCollector
```

## Phase 1: Preparation

Before an incident occurs:

- Verify IR playbooks are current and accessible offline.
- Confirm forensic workstation is ready (write blockers, imaging tools, large-capacity storage).
- Ensure IR team contacts and escalation path are documented.
- Confirm legal and communications teams are identified for notification requirements.
- Verify backup integrity and recovery time objectives.

## Phase 2: Identification

### Initial Triage

```bash
# Assess scope of affected systems
james security ir triage \
  --alert-source $SIEM_ALERT_ID \
  --output triage/initial_scope.json

# Determine incident severity
james security ir severity-assess \
  --systems-affected $COUNT \
  --data-classification $LEVEL \
  --business-impact $DESCRIPTION
```

**Severity Classification:**

| Severity | Definition | Response SLA |
|---|---|---|
| P1 Critical | Active breach, ransomware, data exfiltration in progress | Immediate — all hands |
| P2 High | Confirmed compromise, lateral movement detected | 1 hour |
| P3 Medium | Suspicious activity, potential compromise | 4 hours |
| P4 Low | Single IOC match, no confirmed compromise | 24 hours |

### Incident Declaration

- Assign Incident Commander.
- Open incident channel (Slack/Teams) and record all actions with timestamps.
- Initiate legal hold if data breach is suspected.
- Notify stakeholders per communication plan.

## Phase 3: Evidence Preservation and Chain of Custody

**Critical:** Preserve evidence before containment where possible. Containment actions can destroy volatile evidence.

### Memory Acquisition

```bash
# Linux memory acquisition (LiME kernel module)
sudo insmod lime-$(uname -r).ko "path=/media/forensics/mem_$(hostname)_$(date +%Y%m%d_%H%M%S).lime format=lime"

# Windows memory acquisition (Magnet RAM Capture or WinPmem)
winpmem_mini_x64.exe -o E:\forensics\mem_$env:COMPUTERNAME_$(Get-Date -Format yyyyMMdd_HHmmss).aff4

# Verify integrity immediately
sha256sum /media/forensics/mem_*.lime | tee /media/forensics/mem_hashes.txt
```

### Disk Imaging

```bash
# Create forensic disk image (write blocker required)
dcfldd if=/dev/sdb of=/media/forensics/disk_$(hostname)_$(date +%Y%m%d).dd \
  hash=sha256 hashlog=/media/forensics/disk_hash.txt \
  bs=4096 conv=noerror,sync

# Verify image integrity
sha256sum /media/forensics/disk_*.dd

# Mount read-only for analysis
mount -o ro,loop /media/forensics/disk.dd /mnt/evidence
```

### Chain of Custody Documentation

Every evidence item requires:

```
Evidence Item: [unique ID]
Description: [disk image / memory dump / log archive]
Acquisition Date/Time: [UTC timestamp]
Acquired By: [analyst name and badge]
Hash (SHA-256): [hash value]
Storage Location: [physical location + access controls]
Transfer Log: [every person who accessed the evidence]
```

```bash
# Log evidence in chain of custody system
james security ir evidence-log \
  --item-id $EVIDENCE_ID \
  --type disk_image \
  --hash $SHA256 \
  --acquired-by $ANALYST \
  --location "/secure/evidence/$CASE_ID/"
```

## Phase 4: Forensic Analysis

### Memory Forensics

```bash
# Determine OS profile (Volatility 3)
vol3 -f mem.lime windows.info
vol3 -f mem.lime linux.banner

# Process list (spot hidden/injected processes)
vol3 -f mem.lime windows.pslist
vol3 -f mem.lime windows.pstree
vol3 -f mem.lime windows.malfind  # Injected code detection

# Network connections at time of dump
vol3 -f mem.lime windows.netstat

# Recover encryption keys
vol3 -f mem.lime windows.hashdump
vol3 -f mem.lime windows.lsadump

# Detect rootkit hooks
vol3 -f mem.lime windows.ssdt
vol3 -f mem.lime windows.callbacks
```

### Disk Forensics

```bash
# Timeline analysis (file system)
fls -r -m / /mnt/evidence > bodyfile.txt
mactime -b bodyfile.txt -d > timeline.csv

# Recover deleted files
photorec /log /d /media/forensics/recovered /mnt/evidence

# Browser artifacts
autopsy --forensic-image /media/forensics/disk.dd

# Windows event logs (offline parsing)
evtx_dump /mnt/evidence/Windows/System32/winevt/Logs/*.evtx \
  | jq 'select(.Event.System.EventID == 4624 or .Event.System.EventID == 4625)'

# Prefetch analysis (execution artifacts)
python3 prefetch_parser.py /mnt/evidence/Windows/Prefetch/
```

### Network Forensics

```bash
# Parse PCAP for suspicious traffic
tcpdump -r capture.pcap 'not (port 80 or port 443)' -w suspicious.pcap

# Zeek analysis
zeek -r capture.pcap local "Log::default_rotation_interval=24hrs"
cat zeek_logs/conn.log | zeek-cut id.orig_h id.resp_h id.resp_p proto duration bytes

# Detect beaconing
james security ir detect-beaconing \
  --pcap capture.pcap \
  --output beaconing_candidates.json

# Extract files from PCAP
tcpflow -r capture.pcap -o extracted_files/
```

## Phase 5: Containment

### Immediate Containment Options

| Action | Impact | Use When |
|---|---|---|
| Network isolation (VLAN/FW rule) | High — disrupts operations | Active lateral movement or exfiltration |
| Account disable | Medium — blocks user | Compromised credentials confirmed |
| Endpoint quarantine (EDR) | Medium — isolates one host | Single-host compromise |
| DNS sinkhole | Low — blocks C2 comms | Known C2 domains identified |
| Password reset | Low | Credential compromise suspected |

```bash
# Isolate host via EDR
james security ir isolate-host --hostname $AFFECTED_HOST --reason "Active compromise"

# Block C2 IPs/domains at firewall
james security ir block-ioc \
  --type ip \
  --value 1.2.3.4 \
  --reason "Confirmed C2 infrastructure" \
  --expiry 30d

# Disable compromised account
james security ir disable-account \
  --account $UPN \
  --reason "Credential compromise confirmed" \
  --notify-manager
```

## Phase 6: Eradication

```bash
# Remove persistence mechanisms
# Registry run keys
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v SuspiciousEntry /f

# Scheduled tasks
schtasks /delete /tn "SuspiciousTask" /f

# Malware file removal (after imaging)
rm -f /path/to/malware

# Rotate all credentials that may have been exposed
james security ir credential-rotation \
  --scope affected_systems \
  --include service_accounts,admin_accounts
```

## Phase 7: Recovery

- Restore systems from known-good backups taken before the incident window.
- Verify backup integrity before restoring (hash comparison).
- Rebuild compromised systems from clean images where possible.
- Confirm eradication before returning to production.
- Implement emergency detections to catch re-infection immediately.

## Phase 8: Lessons Learned

```bash
# Generate incident timeline
james security ir timeline --case-id $CASE_ID --output timeline.html

# Generate incident report
james security ir report \
  --case-id $CASE_ID \
  --format pdf \
  --include timeline,findings,containment,recommendations
```

Report must include:
- Incident timeline (detection time, dwell time, containment time, recovery time)
- Root cause analysis
- Detection failures (what should have caught this earlier)
- Remediation actions taken
- Recommended control improvements
- Lessons learned and owner assignments

## Output Checklist

- [ ] Incident severity classified and commander assigned
- [ ] Evidence preserved before containment
- [ ] Chain of custody documented for all evidence items
- [ ] Memory and disk forensics completed
- [ ] Network forensics completed
- [ ] Containment actions taken and documented
- [ ] Eradication confirmed (persistence mechanisms removed, credentials rotated)
- [ ] Systems recovered from clean backups
- [ ] Post-incident report generated with lessons learned
