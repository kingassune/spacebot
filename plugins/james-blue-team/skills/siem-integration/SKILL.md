---
name: siem-integration
description: "SIEM/SOAR integration covering Splunk SPL query generation, Elastic KQL query authoring, Azure Sentinel KQL queries, alert correlation rules, and automated response playbook design."
allowed-tools: ["shell", "file", "exec"]
---

# SIEM/SOAR Integration

You are building detection content and automated response capabilities for a SIEM/SOAR platform. All queries and playbooks are deployed only in authorized production or staging environments.

## Reference Module

```
src/blue_team/siem_soar.rs — SiemIntegration
```

## Splunk SPL Query Generation

### Query Templates

**Detect Brute Force Login Attempts:**

```spl
index=windows sourcetype="WinEventLog:Security" EventCode=4625
| bucket _time span=5m
| stats count AS failed_logins, dc(src_ip) AS unique_ips BY _time, TargetUserName
| where failed_logins > 10
| sort -failed_logins
| table _time, TargetUserName, failed_logins, unique_ips
```

**Detect PowerShell Encoded Commands:**

```spl
index=windows sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational"
  OR sourcetype="WinEventLog:Security" EventCode=4688
  (CommandLine="*-EncodedCommand*" OR CommandLine="*-enc *" OR CommandLine="*-ec *")
| eval decoded=base64decode(replace(CommandLine, ".*(?:-EncodedCommand|-enc|-ec) ([A-Za-z0-9+/=]+).*", "\1"))
| table _time, host, user, CommandLine, decoded
| sort -_time
```

**Detect Lateral Movement via PsExec/WMI:**

```spl
index=windows sourcetype="WinEventLog:Security"
  (EventCode=4624 LogonType=3) OR (EventCode=7045 ServiceName="PSEXESVC")
| eval is_lateral=if(EventCode=4624 AND src_ip!="127.0.0.1" AND NOT match(src_ip, "^10\."), 1, 0)
| search is_lateral=1
| stats count BY _time, src_ip, dest_host, user
| where count > 3
```

**Detect DNS Beaconing:**

```spl
index=dns
| eval domain=lower(query)
| stats count AS query_count, dc(_time) AS time_windows,
        avg(eval(round(_time/60)*60)) AS avg_interval
    BY src_ip, domain
| where query_count > 50 AND time_windows > 20
| eval beacon_score=round((1 - stddev(eval(round(_time/60)*60)) / avg_interval) * 100, 1)
| where beacon_score > 85
| sort -beacon_score
```

### SPL Query Best Practices

```bash
# Generate SPL query from SIGMA rule
sigma convert -t splunk rules/sigma/suspicious_powershell.yml

# Test query against sample data
james security siem test-splunk-query \
  --query 'index=windows EventCode=4625 | stats count BY src_ip' \
  --sample-data samples/windows_auth.json

# Estimate query performance
| tstats count WHERE index=windows BY _time span=1h  # Preferred over raw search
```

## Elastic KQL Query Authoring

### KQL Query Templates

**Detect Mimikatz LSASS Access:**

```kql
process.name: "lsass.exe" AND
event.type: "access" AND
winlog.event_data.GrantedAccess: (
  "0x1fffff" OR "0x1010" OR "0x143a" OR "0x1410"
) AND NOT
  process.parent.name: ("wininit.exe" OR "lsm.exe")
```

**Detect Suspicious Scheduled Task Creation:**

```kql
event.code: "4698" AND
winlog.event_data.TaskContent: (*cmd.exe* OR *powershell.exe* OR *mshta.exe* OR *wscript.exe* OR *cscript.exe* OR *regsvr32.exe* OR *rundll32.exe*)
```

**Detect Base64-Encoded Payload in Process Args:**

```kql
(process.name: ("powershell.exe" OR "pwsh.exe") AND
process.args: (*-enc* OR *-EncodedCommand* OR *-ec*)) OR
(process.args: (*JAB* OR *SQEX* OR *aQBm* OR *TVqQ*))
```

**Detect Suspicious Parent-Child Process Relationships:**

```kql
process.parent.name: ("winword.exe" OR "excel.exe" OR "outlook.exe" OR "powerpnt.exe") AND
process.name: (
  "cmd.exe" OR "powershell.exe" OR "wscript.exe" OR "cscript.exe" OR
  "mshta.exe" OR "regsvr32.exe" OR "rundll32.exe" OR "certutil.exe"
)
```

### EQL (Event Query Language) for Sequences

```eql
/* Detect credential dumping followed by lateral movement within 30 minutes */
sequence by host.name with maxspan=30m
  [process where process.name == "lsass.exe" and event.type == "access"]
  [network where destination.port in (445, 3389, 5985, 5986)]
```

```bash
# Convert SIGMA to Elastic
sigma convert -t elasticsearch-dsl rules/sigma/credential_dumping.yml

# Validate KQL syntax
james security siem validate-kql \
  --query 'process.name: "powershell.exe" AND process.args: *-enc*' \
  --platform elasticsearch
```

## Azure Sentinel KQL Queries

### Sentinel KQL Templates

**Detect Impossible Travel:**

```kql
SigninLogs
| where ResultType == 0  // Successful sign-in
| project TimeGenerated, UserPrincipalName, IPAddress, Location, AppDisplayName
| sort by UserPrincipalName, TimeGenerated asc
| extend PrevTime = prev(TimeGenerated, 1),
         PrevIP = prev(IPAddress, 1),
         PrevLocation = prev(Location, 1)
| where UserPrincipalName == prev(UserPrincipalName, 1)
| extend TimeDelta = datetime_diff('minute', TimeGenerated, PrevTime)
| where TimeDelta between (1 .. 120)
  and Location != PrevLocation
  and IPAddress != PrevIP
| project TimeGenerated, UserPrincipalName, Location, PrevLocation,
          IPAddress, PrevIP, TimeDelta, AppDisplayName
```

**Detect Mass File Deletion (Ransomware Indicator):**

```kql
DeviceFileEvents
| where ActionType == "FileDeleted"
| summarize DeleteCount = count(), FileTypes = make_set(tolower(FileName)) by DeviceName, bin(Timestamp, 5m)
| where DeleteCount > 100
| order by DeleteCount desc
```

**Detect Suspicious OAuth Application Consent:**

```kql
AuditLogs
| where OperationName == "Consent to application"
| extend TargetApp = tostring(TargetResources[0].displayName)
| extend ConsentedBy = tostring(InitiatedBy.user.userPrincipalName)
| extend Permissions = tostring(AdditionalDetails)
| where Permissions has_any ("Mail.Read", "Files.ReadWrite.All", "Directory.ReadWrite.All")
| project TimeGenerated, ConsentedBy, TargetApp, Permissions
```

```bash
# Deploy Sentinel analytics rule
james security siem deploy-sentinel-rule \
  --query-file sentinel_rules/impossible_travel.kql \
  --workspace-id $SENTINEL_WORKSPACE_ID \
  --alert-threshold 1 \
  --frequency 5m
```

## Alert Correlation Rules

### Multi-Stage Attack Detection

```bash
# Create correlation rule: brute force followed by successful login
james security siem correlation-rule create \
  --name "Brute Force to Successful Login" \
  --stage1 "EventCode=4625 count>10 window=5m groupby=src_ip" \
  --stage2 "EventCode=4624 same.src_ip window=60m" \
  --severity high \
  --mitre T1110,T1078

# Create correlation rule: lateral movement chain
james security siem correlation-rule create \
  --name "Lateral Movement Chain" \
  --stage1 "process=mimikatz OR LSASS_access" \
  --stage2 "SMB_connection_to_new_host within=30m same.src_host" \
  --stage3 "new_process_creation on=stage2.dest_host within=15m" \
  --severity critical
```

## Automated Response Playbook Design

### Playbook: Compromised Account Response

```yaml
name: Compromised Account Response
trigger:
  alert_name: "Brute Force to Successful Login"
  severity: high

steps:
  - name: Enrich user context
    action: lookup_user
    params:
      source: active_directory
      field: TargetUserName

  - name: Check recent activity
    action: query_siem
    params:
      query: "user={TargetUserName} last=7d | stats count BY action"

  - name: Disable account
    action: disable_ad_account
    params:
      user: "{TargetUserName}"
      reason: "Auto-disabled: Brute force compromise indicator"
    requires_approval: true
    approvers: ["security-team@company.com"]

  - name: Revoke sessions
    action: revoke_azure_sessions
    params:
      user: "{UserPrincipalName}"

  - name: Notify SOC
    action: send_alert
    params:
      channel: "#soc-alerts"
      message: "Account {TargetUserName} disabled: brute force indicator. Case: {case_id}"

  - name: Create incident ticket
    action: create_jira_ticket
    params:
      project: SEC
      type: Incident
      priority: High
      summary: "Potential account compromise: {TargetUserName}"
```

```bash
# Deploy playbook to SOAR platform
james security siem deploy-playbook \
  --file playbooks/compromised_account.yaml \
  --platform palo_alto_xsoar \
  --environment production

# Test playbook with synthetic alert
james security siem test-playbook \
  --playbook compromised_account \
  --synthetic-alert '{"TargetUserName": "testuser", "src_ip": "1.2.3.4"}'
```

## Output Checklist

- [ ] SPL queries created and tested for target use cases
- [ ] Elastic KQL queries validated and deployed
- [ ] Azure Sentinel KQL rules deployed and alerting
- [ ] Multi-stage correlation rules configured
- [ ] False positive rate measured per rule (target <5%)
- [ ] Automated response playbooks designed and tested
- [ ] Playbooks reviewed for accuracy — no destructive action without approval
- [ ] Detection coverage mapped to ATT&CK matrix
- [ ] SIEM performance impact assessed (query execution time)
