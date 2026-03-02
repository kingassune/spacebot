---
name: differential-review
description: "James integration of Trail of Bits' differential security review methodology. Compares code diffs to identify security regressions and new vulnerability introduction."
---

# Differential Security Review

You are performing a security-focused review of a code diff to identify regressions and newly introduced vulnerabilities.

## Workflow

### 1. Diff Ingestion
- Accept a git diff (`git diff base..head`) or a PR diff.
- Identify all changed files and categorize them:
  - Security-sensitive (auth, crypto, input handling, permissions, secrets).
  - Business logic (financial calculations, state transitions).
  - Infrastructure / config (Docker, CI/CD, env files).
  - Tests / documentation (lower priority).

### 2. Security-Sensitive Change Detection
For each changed file, scan for:

**Authentication / Authorization Changes**
- Any modification to auth middleware, session handling, token validation.
- Removal or relaxation of access control checks.
- New endpoints added without auth guards.

**Cryptographic Changes**
- Algorithm changes (especially downgrades: AES-256 → AES-128, SHA-256 → MD5).
- Key length reductions.
- Removal of signature verification.
- Hardcoded keys or IVs.

**Input Handling**
- New unsanitized inputs passed to SQL, shell, XML, HTML, LDAP.
- Removal of existing validation logic.
- New deserialization of untrusted data.

**Dependency Changes**
- New dependencies added (`Cargo.toml`, `package.json`, `requirements.txt`).
- Version bumps (check changelog for known CVEs).
- Removal of security-relevant dependencies (e.g. removing a sanitizer).

**Configuration Changes**
- Security headers removed or weakened.
- CORS policy broadened.
- TLS version downgraded.
- Debug mode enabled.

### 3. Regression Check
For each security fix present in the base:
- Verify the fix is not reverted in the diff.
- Check if refactoring re-introduces the same pattern the fix addressed.

### 4. Output Format
For each concern found:
```
[SEVERITY: Critical/High/Medium/Low]
File: <path>
Lines: <line range>
Change Type: New Vulnerability / Regression / Suspicious Change
Description: <what changed and why it's concerning>
Recommendation: <what to do>
```

### 5. Summary
- Count of security-relevant changes reviewed.
- Count of concerns raised by severity.
- Verdict: **Approve** / **Request Changes** / **Block** (Critical issues).
