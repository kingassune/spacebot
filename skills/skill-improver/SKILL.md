---
name: skill-improver
description: "James meta-skill for iterative skill refinement. Reviews and improves existing James skills based on usage feedback and new techniques."
---

# Skill Improver

You are reviewing and improving an existing James skill based on usage feedback, new techniques, or gaps identified during use.

## Workflow

### 1. Skill Assessment
Read the existing skill's `SKILL.md` and assess:
- **Coverage**: Does it cover all the main cases for its stated purpose?
- **Accuracy**: Are the instructions technically correct and up to date?
- **Clarity**: Are the steps clear and unambiguous?
- **Actionability**: Can James follow the instructions without additional context?
- **False positive rate**: Do the detection patterns produce too many false positives?
- **False negative rate**: Are there important cases the skill misses?

### 2. Gap Analysis
Identify gaps by reviewing:
- Usage feedback: what findings did the skill miss? What produced noise?
- New CVEs or vulnerability research published since the skill was written.
- New tool versions with changed output formats.
- New language features or framework versions that introduce new patterns.
- Edge cases encountered in real engagements.

### 3. Improvement Categories

**Add missing detection patterns**
- New variant of an existing vulnerability class.
- New API or framework that needs coverage.
- Language-specific footgun not previously covered.

**Remove or refine noisy patterns**
- Detection pattern that produces too many false positives.
- Over-broad condition that flags safe code.

**Update tool commands**
- CLI flags that have changed.
- New recommended tool replacing an old one.
- Output format changes requiring new parsing logic.

**Improve workflow structure**
- Steps that should be reordered for efficiency.
- Missing triage or false-positive-filtering step.
- Missing output format section.

**Add examples**
- Concrete code examples for patterns that are abstract.
- Real-world exploit scenarios to motivate each detection pattern.

### 4. Improvement Protocol
For each improvement:
1. Document **what** is being changed and **why**.
2. Show the **before** and **after** for changed content.
3. Add a test case (vulnerable example + safe example) for each new detection pattern.

### 5. Output
Produce:
1. A summary of gaps found and improvements made.
2. The updated `SKILL.md` content (full replacement, not a patch).
3. A changelog entry: `YYYY-MM-DD: <summary of changes>`.
