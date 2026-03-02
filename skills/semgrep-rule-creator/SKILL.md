---
name: semgrep-rule-creator
description: "James integration of Trail of Bits' Semgrep rule authoring methodology. Creates custom Semgrep rules for detecting specific vulnerability patterns."
---

# Semgrep Rule Creator

You are writing a custom Semgrep rule to detect a specific vulnerability pattern.

## Workflow

### 1. Define the Target Pattern
Before writing the rule:
- Describe the vulnerability in one sentence.
- Write a minimal code example that exhibits the vulnerable pattern.
- Write a minimal code example that is safe (the fix).

### 2. Rule Structure
Every Semgrep rule has this YAML structure:
```yaml
rules:
  - id: <unique-kebab-case-id>
    languages: [<language>]
    severity: ERROR  # ERROR, WARNING, or INFO
    message: >
      <Human-readable description of the finding and how to fix it.>
    metadata:
      category: security
      cwe: "CWE-<number>: <name>"
      confidence: HIGH  # HIGH, MEDIUM, LOW
      likelihood: MEDIUM
      impact: HIGH
      subcategory: [vuln]  # vuln, audit
      references:
        - https://example.com
    patterns:  # or pattern, pattern-either, pattern-not, etc.
      - pattern: |
          <vulnerable pattern>
```

### 3. Pattern Syntax Reference

**Metavariables**: `$VAR`, `$FUNC`, `$ARG` — match any expression.
**Ellipsis**: `...` — match zero or more statements/arguments.
**Type annotations**: `$VAR: int` — match with type constraint (typed languages).

**Combining patterns**:
- `pattern`: single pattern match.
- `patterns`: all must match (AND).
- `pattern-either`: any must match (OR).
- `pattern-not`: exclude matches.
- `pattern-inside`: match only within a containing pattern.
- `pattern-not-inside`: exclude matches inside a containing pattern.

**Taint tracking** (for data-flow):
```yaml
mode: taint
pattern-sources:
  - pattern: request.GET.get(...)
pattern-sinks:
  - pattern: os.system(...)
pattern-sanitizers:
  - pattern: shlex.quote(...)
```

### 4. Testing the Rule
Create test files:
- `test_vuln.py` (or appropriate extension): code that **should** match — add `# ruleid: <id>`.
- `test_ok.py`: code that **should not** match — add `# ok: <id>`.

Run: `semgrep --test --config rule.yaml test_vuln.py test_ok.py`

### 5. Common Pitfalls
- Too broad: use `pattern-not` or `pattern-not-inside` to reduce false positives.
- Too narrow: use `pattern-either` to cover variant call styles.
- Forgetting imports: use `pattern-inside` scoped to the file if the import matters.
- Missing ellipsis: `func(...)` matches any number of args; `func($A)` matches exactly one.

### 6. Output
Produce the complete `.yaml` rule file content, ready to run with `semgrep --config <rule>.yaml <target>`.
