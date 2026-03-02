---
name: testing-handbook-skills
description: "James integration of Trail of Bits' Testing Handbook methodology. Applies structured security testing workflows from the Testing Handbook."
---

# Testing Handbook Skills

You are applying Trail of Bits' Testing Handbook structured security testing methodology.

## Workflow

### 1. Select Testing Domain

**Web Application Testing**
Follow the Trail of Bits web testing workflow:
1. Enumerate all endpoints (authenticated + unauthenticated).
2. Test authentication: brute force protection, session fixation, JWT weaknesses.
3. Test authorization: horizontal/vertical privilege escalation, IDOR.
4. Test injection: SQLi, XSS, XXE, SSTI, command injection.
5. Test business logic: race conditions, negative values, skipped steps.
6. Test transport security: TLS config, HSTS, cookie flags.

**Blockchain / Smart Contract Testing**
Follow the Trail of Bits blockchain testing workflow:
1. Run automated tools: Slither, Echidna, Medusa, Manticore.
2. Manual review: reentrancy, arithmetic, access control, oracle.
3. Invariant testing: write Echidna properties for all economic invariants.
4. Formal verification candidates: identify functions amenable to SMT solving.

**Cryptographic Protocol Testing**
Follow the Trail of Bits cryptography testing workflow:
1. Protocol specification review: map spec to implementation, find deviations.
2. Key management: generation (entropy), storage, rotation, destruction.
3. Algorithm choices: key lengths, modes of operation, padding.
4. Side channels: timing, cache, power (where applicable).
5. Protocol flaws: replay, reflection, downgrade, man-in-the-middle.

### 2. Test Case Design
For each test area:
- Write a **precondition** (what state is required).
- Write the **test steps** (exact actions).
- Write the **expected result** (what a secure system does).
- Write the **failure indicator** (what indicates a vulnerability).

### 3. Evidence Collection
For each finding:
- Capture request/response or transaction hash.
- Record exact reproduction steps.
- Calculate CVSS score or DeFi risk score.
- Draft proof-of-concept exploit or test case.

### 4. Reporting
Produce findings in Trail of Bits report format:
```
**ID**: TOB-<PROJECT>-<NUM>
**Title**: <Short descriptive title>
**Severity**: Critical / High / Medium / Low / Informational
**Difficulty**: High / Medium / Low  (to exploit)
**Type**: <vulnerability class>
**Target**: <file/contract/endpoint>

**Description**
<Detailed technical description>

**Exploit Scenario**
<Step-by-step attack narrative>

**Recommendation**
<Specific remediation advice>

**References**
<Links to relevant standards, advisories, or documentation>
```
