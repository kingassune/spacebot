# /meta-extend

Analyzes the James platform's current capabilities and generates new skills, plugins, and Rust module stubs to address identified coverage gaps.

## Usage

```
/meta-extend [--domain <domain>] [--framework <framework>] [--gap-threshold <score>]
```

## Parameters

- `--domain`: Target domain to extend (blockchain, red-team, blue-team, pentest, cloud, mobile, ics, all) [default: all]
- `--framework`: Framework to map coverage against (mitre-attack, owasp, nist-csf, all) [default: all]
- `--gap-threshold`: Minimum gap priority score to act on (0.0–1.0) [default: 0.7]

## Workflow

1. **Inventory scan** (`self-extension` skill) — enumerate all existing skills and plugins
2. **Coverage mapping** (`capability-analysis` skill) — map capabilities against target frameworks
3. **Gap prioritization** — score gaps by threat prevalence, detection difficulty, and effort
4. **Skill generation** — produce new SKILL.md files for top-priority gaps
5. **Module scaffolding** — generate Rust module stubs for new skills
6. **Plugin assembly** — create or update plugin.toml to register new capabilities
7. **Cross-domain review** (`cross-domain` skill) — verify new skills address correlation gaps
8. **Quality gate** — validate generated content against SKILL.md schema before writing

## Examples

```
/meta-extend --domain cloud --framework mitre-attack
/meta-extend --domain all --framework nist-csf --gap-threshold 0.8
/meta-extend --domain blockchain --framework owasp-smart-contract
```

## Output

- Coverage gap report with priority scores
- Generated SKILL.md files for top-N gaps
- Rust module stub files
- Updated plugin.toml manifests
- Coverage delta report (before vs. after extension)
