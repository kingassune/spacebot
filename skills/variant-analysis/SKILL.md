---
name: variant-analysis
description: "James integration of Trail of Bits' variant analysis methodology. Finds related vulnerabilities after a root cause is identified."
---

# Variant Analysis

You are performing variant analysis: after identifying a root cause vulnerability, find all related instances of the same pattern.

## Workflow

### 1. Root Cause Abstraction
Given a confirmed vulnerability:
- Identify the **vulnerability class** (e.g., integer overflow, use-after-free, missing auth check).
- Identify the **root cause pattern**: what specific code construct causes the issue.
- Express the pattern abstractly: "function X called with Y without checking Z".

### 2. Pattern Generalization
Generalize the pattern to find variants:

**Same function, different callers**
- Find every call site of the vulnerable function.
- Check if each call site has the same missing check.

**Equivalent functions**
- Identify other functions in the codebase that perform the same operation.
- Apply the same check to each.

**Same pattern, different types**
- If the issue is with type T, check all similar types.
- If the issue is with operation O, check all operations in the same class.

**Incomplete fix variants**
- Check if a previous fix addressed only one call site but not others.
- Check if the fix introduced a bypass (e.g., off-by-one, edge case).

### 3. Automated Search
Depending on the pattern:

**Grep-based**:
```bash
# Find all call sites of the vulnerable function
grep -rn "vulnerable_function(" src/
# Find similar patterns
grep -rn "similar_pattern" src/
```

**Semgrep-based**:
Write a Semgrep rule (use `semgrep-rule-creator` skill) and run across the entire codebase.

**CodeQL-based**:
Write a CodeQL query for dataflow from source to sink matching the root cause.

### 4. Triage Each Candidate
For each candidate found:
- **Confirmed variant**: same root cause, exploitable.
- **Similar but safe**: same pattern, but mitigated by context.
- **False positive**: pattern match but not the same issue.

### 5. Output Format
```
## Variant Analysis Report

Root cause: <description>
Original finding: <location>
Search method: <grep/semgrep/codeql/manual>
Candidates found: <N>

### Confirmed Variants
1. <location> — <description of how it matches the root cause>

### Similar but Safe
1. <location> — <why it is mitigated>

### Incomplete Fix
<if the original fix was incomplete, describe what was missed>

### Recommendations
- Fix all confirmed variants together with the original.
- Add regression test covering each variant.
- Consider adding a Semgrep rule to prevent reintroduction.
```
