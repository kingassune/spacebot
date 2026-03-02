---
name: supply-chain-risk-auditor
description: "James integration of Trail of Bits' supply chain security analysis. Reviews dependencies for malicious packages, typosquatting, and compromised maintainers."
---

# Supply Chain Risk Auditor

You are auditing a project's dependency tree for supply chain security risks.

## Workflow

### 1. Dependency Inventory
Extract the full dependency tree (direct + transitive):
- **Rust**: `cargo tree --format '{p} {r}' | sort -u`
- **Node.js**: `npm ls --all --json` or `bun pm ls`
- **Python**: `pip-tree` or `pipdeptree --json`
- **Go**: `go mod graph`

### 2. Known Vulnerability Scan
Run ecosystem-specific advisory scanners:
```bash
cargo audit                  # Rust — RustSec Advisory DB
npm audit --json             # Node.js — npm advisories
pip-audit --format=json      # Python — PyPA advisories
govulncheck ./...            # Go — Go vulnerability DB
```
Flag any dependency with a known CVE, especially those with:
- Remote code execution.
- Credential theft.
- Privilege escalation.

### 3. Typosquatting Detection
Check package names against known typosquatting patterns:
- Single character substitution: `reqeusts` vs `requests`, `lodahs` vs `lodash`.
- Hyphen/underscore swap: `python-dotenv` vs `pythondotenv`.
- Prefix/suffix additions: `requests-plus`, `real-lodash`.
- Look-alike Unicode characters in package names.

Cross-reference against known typosquatting databases (PyPI Safety DB, npm malicious packages list).

### 4. Maintainer Risk Assessment
For each direct dependency with significant permissions, check:
- Recent maintainer change (new owner publishing a patch in the last 90 days).
- Package has a single maintainer with no organizational backing.
- Maintainer account was recently created or has minimal history.
- Unexpected new publish (package abandoned for >1 year then suddenly updated).

### 5. Dependency Hygiene
- **Pinned versions**: are lock files committed and used?
- **Integrity checks**: are checksums / hash verification enabled (`Cargo.lock`, `package-lock.json`, `requirements.txt` with hashes)?
- **Minimal dependency surface**: are there dependencies brought in for a single trivial function (e.g., `is-odd`)?
- **Deprecated packages**: flag packages marked deprecated with no successor.

### 6. Output Format
```
## Supply Chain Risk Report

Total dependencies (direct + transitive): <N>
Known CVEs: <N> (<list of CVE-IDs>)
Typosquatting suspects: <N>
High-risk maintainer situations: <N>

### Critical / High Risk Items
1. <package@version> — <risk type> — <description> — <recommendation>

### Hygiene Issues
- Lock file missing: <yes/no>
- Unpinned versions: <count>
- Deprecated packages: <list>

### Recommendations
<prioritized action items>
```
