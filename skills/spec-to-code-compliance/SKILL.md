---
name: spec-to-code-compliance
description: "James integration of Trail of Bits' specification compliance review. Compares implementation against protocol specifications to find deviations."
---

# Spec-to-Code Compliance Review

You are comparing an implementation against its protocol specification to find deviations.

## Workflow

### 1. Obtain the Specification
Identify and retrieve the authoritative specification:
- IETF RFC (e.g., RFC 7519 for JWT, RFC 8446 for TLS 1.3).
- NIST standard (e.g., FIPS 197 for AES, SP 800-38A for block cipher modes).
- EIP / ERC for Ethereum standards.
- Project-specific design document or whitepaper.

Note the specific version or revision of the spec being implemented.

### 2. Extract Normative Requirements
From the specification, extract all normative requirements (MUST, SHALL, MUST NOT, SHALL NOT, SHOULD, SHOULD NOT, MAY):

| Req ID | Requirement Text | Keyword | Section |
|--------|-----------------|---------|---------|
| R-001 | The server MUST reject tokens with exp in the past | MUST | §4.1.4 |
| R-002 | Implementations SHOULD validate iss claim | SHOULD | §4.1.1 |

### 3. Map Requirements to Code
For each requirement, locate the corresponding implementation:
- Find the function/module that should implement it.
- Assess compliance: **Compliant / Partial / Non-Compliant / Not Found**.
- Note the file and line range.

### 4. Deviation Analysis
For each non-compliant or partially compliant requirement:
- **Type of deviation**:
  - Missing check (requirement not implemented at all).
  - Incorrect implementation (implemented but wrong).
  - Off-by-one / boundary error.
  - Spec ambiguity leading to unsafe interpretation.
- **Security impact**: Does this deviation create a vulnerability?
- **RFC keywords matter**: MUST violations are bugs; SHOULD violations are risks.

### 5. RFC / Standard Compliance Verification Examples

**JWT (RFC 7519)**
```
MUST verify signature before processing claims.
MUST reject if exp has passed.
MUST reject if nbf is in the future.
MUST reject unknown critical header params (crit).
SHOULD validate iss and aud claims.
```

**TLS (RFC 8446)**
```
MUST NOT negotiate below TLS 1.3 (if spec requires 1.3+).
MUST validate certificate chain to a trust anchor.
MUST reject expired certificates.
```

**ERC-20**
```
MUST emit Transfer event on token transfers (including mints/burns).
MUST emit Approval event on approve.
transfer to address(0) behavior: check if spec defines it.
```

### 6. Output Format
```
## Spec-to-Code Compliance Report

Specification: <name + version/RFC number>
Implementation: <file/module under review>

### Compliance Summary
- Total requirements: <N>
- Compliant: <N>
- Partial: <N>
- Non-Compliant: <N>
- Not Found: <N>

### Non-Compliant Findings
[HIGH/MEDIUM/LOW] R-<ID>: <requirement text>
  Status: Non-Compliant / Partial
  Location: <file:line>
  Deviation: <what the code does instead>
  Security impact: <yes/no — description>
  Recommendation: <fix>
```
