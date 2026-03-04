# /red-team-engage

Orchestrates a full advanced red team engagement using APT emulation, exploit development, and social engineering skills.

## Usage

```
/red-team-engage <target> --threat-actor <actor> [--scope <scope>] [--roe <roe-file>]
```

## Parameters

- `target`: Organization name, domain, or IP range (must be in scope)
- `--threat-actor`: Threat actor profile to emulate (APT28, APT29, Lazarus, Sandworm, APT41, etc.)
- `--scope`: Engagement scope (full, network, application, physical, social) [default: full]
- `--roe`: Path to Rules of Engagement document [required for full scope]

## Workflow

1. **Authorization verification** — validate ROE document and scope boundaries
2. **Threat actor profiling** (`apt-emulation` skill) — select and configure threat actor TTPs
3. **Reconnaissance** — OSINT, infrastructure mapping, employee enumeration
4. **Initial access** — phishing, exploitation, or valid credentials per actor profile
5. **Lateral movement and persistence** — kill chain execution with ATT&CK mapping
6. **Social engineering** (`social-engineering` skill, if in scope) — phishing/vishing campaigns
7. **Exploit development** (`exploit-development` skill, if zero-days in scope) — custom payload development
8. **Objective completion** — simulated data exfiltration or sabotage within scope
9. **Purple team debrief** — share IOCs, detection gaps, remediation priorities

## Examples

```
/red-team-engage acmecorp.com --threat-actor APT29 --scope full --roe /path/to/roe.pdf
/red-team-engage 10.0.0.0/8 --threat-actor Lazarus --scope network
/red-team-engage acmecorp.com --threat-actor APT28 --scope social
```

## Output

- Engagement timeline with ATT&CK technique log
- Detection rate per kill chain phase
- Dwell time from initial access to objective
- IOC inventory (hashes, registry keys, network indicators)
- Detection gap analysis with blue team recommendations
- Executive summary with risk rating
