---
name: static-analysis
description: "James integration of Trail of Bits' static analysis workflow. Orchestrates multiple static analysis tools and synthesizes findings."
---

# Static Analysis Workflow

You are orchestrating multiple static analysis tools and synthesizing their findings into a unified report.

## Workflow

### 1. Tool Selection by Language/Ecosystem

**Rust**
```bash
cargo audit          # Known CVEs in dependencies
cargo clippy -- -D warnings  # Lint + common bugs
cargo geiger         # Unsafe code inventory
semgrep --config=auto src/  # Pattern-based rules
```

**JavaScript / TypeScript**
```bash
npm audit            # Known CVEs
eslint --ext .ts,.js src/
semgrep --config=auto src/
```

**Python**
```bash
pip-audit            # Known CVEs
bandit -r src/       # Security-focused lint
semgrep --config=auto src/
```

**C / C++**
```bash
cppcheck --enable=all src/
clang-tidy src/
semgrep --config=auto src/
```

**Solidity**
```bash
slither .            # Solidity static analysis
semgrep --config=auto contracts/
```

**Multi-language**
```bash
semgrep --config=p/default  # OWASP Top 10 rules
codeql database create ...  # For deep dataflow analysis
```

### 2. Running the Tools
For each tool:
1. Run with maximum sensitivity (enable all checks / all rules).
2. Capture output in a structured format (JSON where available).
3. Note tool version and rule set used.

### 3. Synthesis and Deduplication
After collecting all tool outputs:
- Group findings by: (file, approximate line range, vulnerability class).
- If two tools report the same issue, keep both as corroboration but count as one finding.
- Assign unified severity: `Critical > High > Medium > Low > Informational`.
- Map to CWE where possible.

### 4. False Positive Triage
- Mark as FP: tool-generated test files, vendored code not in scope, clearly unreachable code paths.
- Mark as "Needs Manual Verification": low-confidence, tentative, or context-dependent findings.
- Mark as Confirmed: high-confidence or multi-tool corroboration.

### 5. Output Report
```
## Static Analysis Report

Date: <date>
Tools run: <list with versions>
Files analyzed: <N>
Total raw findings: <N>
After dedup/FP: <N>

### Findings by Severity
- Critical: <N>
- High: <N>
- Medium: <N>
- Low: <N>
- Informational: <N>

### Confirmed Findings
<numbered list with: severity, tool, file:line, description, CWE, recommendation>

### Needs Manual Verification
<list>

### False Positives Suppressed
<count and reason>
```
