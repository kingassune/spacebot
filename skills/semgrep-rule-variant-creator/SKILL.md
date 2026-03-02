---
name: semgrep-rule-variant-creator
description: "James integration of Trail of Bits' Semgrep variant analysis tooling. Extends existing Semgrep rules to detect variant vulnerabilities."
---

# Semgrep Rule Variant Creator

You are extending an existing Semgrep rule to detect variant vulnerabilities of the same root cause.

## Workflow

### 1. Analyze the Original Rule
Given an existing Semgrep rule:
- Identify what exact code pattern it detects.
- Identify the root cause (e.g., unsanitized input reaches a sink).
- List the specific APIs / functions it matches.

### 2. Generate Variant Hypotheses
For each original pattern, consider variants along these axes:

**Equivalent API variants**
- Different function names that do the same thing (e.g., `exec` vs `execSync` vs `execFile`).
- Method chaining that achieves the same result.
- Aliased imports (`from os import system as run`).

**Structural variants**
- Indirect call through a variable (`let f = dangerousFunc; f(...)`).
- Call through a wrapper function.
- Async variant of the same sink (`await dangerousFuncAsync(...)`).

**Context variants**
- Same sink reached from a different source (user input via different route).
- Same source flowing to a different sink of the same class.
- Bypassing the sanitizer through a different code path.

**Language-specific variants**
- Template literal vs string concatenation vs format string.
- List/dict spreading that injects values.
- Decorator or middleware that modifies the data before the sink.

### 3. Write Variant Rules
For each variant:
1. Write a minimal code example exhibiting the variant.
2. Write the Semgrep rule using the structure from `semgrep-rule-creator`.
3. Add a unique ID: `<original-id>-variant-<N>`.
4. Reference the original rule in metadata.

```yaml
metadata:
  original-rule: <original-id>
  variant-of: <description of how this differs>
```

### 4. Consolidation
Where possible, merge variants into the original rule using `pattern-either`:
```yaml
pattern-either:
  - pattern: original_pattern(...)
  - pattern: variant_pattern_1(...)
  - pattern: variant_pattern_2(...)
```

### 5. Test Coverage
For each variant rule, add test cases confirming:
- The variant is caught.
- The original safe pattern is not flagged.
- The fix for the original also fixes this variant (if applicable).

### 6. Output
Produce a set of `.yaml` files: one per variant rule (or a consolidated rule), plus a summary of variants found and their relationship to the original.
