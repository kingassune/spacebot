---
name: workflow-skill-design
description: "James meta-skill for designing new security workflow skills. Creates structured skill definitions for new security analysis workflows."
---

# Workflow Skill Design

You are designing a new James skill for a security analysis workflow.

## Workflow

### 1. Scope Definition
Before writing the skill, define:
- **Name**: kebab-case, descriptive (e.g., `tls-cert-auditor`).
- **Domain**: Web / Crypto / Binary / Smart Contract / Mobile / Supply Chain / Meta.
- **Trigger**: When should James use this skill? What user request activates it?
- **Input**: What does James need to have in context to use this skill?
- **Output**: What does the user receive at the end?
- **Limitations**: What does this skill explicitly NOT cover?

### 2. Skill Template Structure
Every James skill `SKILL.md` must contain:

```markdown
---
name: <skill-name>
description: "<one sentence: James integration of X. Does Y.>"
---

# <Skill Title>

<One paragraph explaining what this skill does and when to use it.>

## Workflow

### 1. <First major step>
<Instructions>

### 2. <Second major step>
<Instructions>

...

### N. Output Format
<Exact format of what James should produce>
```

### 3. Writing Good Detection Patterns
A good detection pattern:
- Is expressed as a code example (vulnerable vs safe).
- Has a clear false-positive mitigation (when NOT to flag it).
- References the vulnerability class (CWE number, OWASP category).
- Includes the tool command that automates the detection (if possible).

### 4. Writing Good Output Formats
A good output format:
- Is machine-parseable (structured, consistent fields).
- Includes severity, location, description, and recommendation for each finding.
- Has a summary section (counts by severity, overall verdict).
- Is ready to paste into a report without editing.

### 5. Validation Checklist
Before finalizing a new skill:
- [ ] Name is unique and follows kebab-case.
- [ ] Description fits in one sentence.
- [ ] Workflow steps are numbered and sequential.
- [ ] At least one concrete code/command example per step.
- [ ] Output format section is present.
- [ ] Limitations are stated (what this skill does NOT do).
- [ ] Skill can be followed without additional context (self-contained).

### 6. Testing the Skill
Before considering the skill ready:
1. Apply it to a real or synthetic example.
2. Verify it produces output in the specified format.
3. Verify it catches the vulnerability it was designed to detect.
4. Verify it does not produce excessive false positives on clean code.
5. Adjust patterns or steps based on the test results.

### 7. Output
Produce the complete `SKILL.md` file content, ready to be saved to `skills/<name>/SKILL.md`.
