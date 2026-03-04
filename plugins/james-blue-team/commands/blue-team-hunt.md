# /blue-team-hunt

Orchestrates a threat hunting operation across all blue team detection capabilities.

## Usage

```
/blue-team-hunt [--hypothesis <hypothesis>] [--data-source <source>] [--window <window>]
```

## Parameters

- `--hypothesis`: Hunting hypothesis or ATT&CK technique to hunt for (e.g., T1059.001, "lateral-movement", "ransomware")
- `--data-source`: Data source to hunt in (siem, endpoint, network, all) [default: all]
- `--window`: Time window for the hunt (e.g., 7d, 30d, 90d) [default: 7d]

## Workflow

1. **Hypothesis formation** — define ATT&CK technique or threat scenario to hunt
2. **Baseline review** (`threat-detection` skill) — compare current activity against established baselines
3. **IOC correlation** — cross-reference known IOCs against logs and endpoint telemetry
4. **SIGMA/YARA sweep** — run detection rules across historical data
5. **Anomaly analysis** — review statistical outliers in process, network, and auth data
6. **SIEM query execution** (`siem-integration` skill) — run targeted SPL/KQL queries
7. **Findings triage** — classify hits as true positives, false positives, or requires investigation
8. **Incident escalation** (`incident-response` skill) — escalate confirmed threats
9. **Hunt report** — document findings, new detections added, and coverage improvements

## Examples

```
/blue-team-hunt --hypothesis T1059.001 --data-source endpoint --window 30d
/blue-team-hunt --hypothesis lateral-movement --data-source all --window 7d
/blue-team-hunt --hypothesis ransomware --data-source siem --window 90d
```

## Output

- Hunt timeline with analyst actions logged
- True positive findings with IOC inventory
- New SIGMA/YARA rules generated from hunt findings
- Detection gap recommendations
- ATT&CK coverage improvement summary
