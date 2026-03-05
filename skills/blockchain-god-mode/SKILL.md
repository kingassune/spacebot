---
name: blockchain-god-mode
description: "Comprehensive blockchain security audit combining smart contract analysis, formal verification, DeFi risk, cross-chain bridge security, ZK circuit auditing, and consensus attack modelling."
allowed-tools:
  - Bash
  - Read
  - Grep
  - Glob
  - WebFetch
---

# Blockchain God-Mode Security Audit

You are performing a comprehensive, nation-state-grade blockchain security audit. Your job is to leave no stone unturned across every layer of the stack.

## Scope

This skill covers:

1. **Smart Contract Vulnerability Detection** — reentrancy, tx.origin abuse, delegatecall storage collisions, integer overflow/underflow, access control flaws, flash loan attack surfaces, oracle manipulation, MEV/sandwich attack vectors.
2. **Formal Verification** — property-based invariant checking (no-reentrancy, no-overflow, access-control), using Certora Prover, Halmos, or Echidna as appropriate.
3. **Cross-Chain Bridge Security** — message replay, signature forgery, validator collusion, unbounded mint, missing nonce checks, exit window bypass.
4. **ZK Circuit Auditing** — under-constrained inputs, trusted setup weaknesses, Fiat-Shamir weaknesses, nullifier reuse, missing range checks.
5. **DeFi Protocol Risk** — flash loan exploitability, oracle dependency, sandwich attack surfaces, impermanent loss exploitation, governance attacks, rug pull vectors.
6. **Wallet & Approval Chain Security** — unlimited approvals, address poisoning, signature malleability, entropy assessment.
7. **Gas Optimisation Analysis** — identify gas-wasting patterns and their security implications (e.g., unbounded loops).
8. **Consensus Mechanism Attack Modelling** — 51% attacks, long-range attacks, nothing-at-stake, selfish mining, eclipse attacks.

## Workflow

### Phase 1: Static Analysis

```bash
# Run Slither on the contract
slither . --json slither-results.json

# Run Semgrep with Solidity rules
semgrep --config "p/solidity" --json > semgrep-results.json

# Check for known vulnerability patterns
grep -rn "tx.origin\|selfdestruct\|delegatecall\|assembly\|ecrecover" contracts/
```

### Phase 2: Formal Verification

```bash
# Run Echidna for property-based fuzzing
echidna-test contracts/Target.sol --contract Target --config echidna.yaml

# Run Halmos for symbolic execution
halmos --contract Target --function check_

# Run Certora Prover (if configured)
certoraRun contracts/Target.sol --verify Target:specs/Target.spec
```

### Phase 3: DeFi Risk Assessment

Analyse the contract for:
- Price oracle dependencies (check for TWAP vs. spot price usage)
- Flash loan entry points (look for single-transaction state changes)
- Reentrancy paths (trace external calls before state updates)
- MEV-extractable value (identify sandwich-able swap operations)

### Phase 4: Bridge Security (if applicable)

```bash
# Check for message replay protection
grep -n "nonce\|messageId\|executed\[" contracts/Bridge*.sol

# Verify signature validation
grep -n "ecrecover\|_verify\|require.*signer" contracts/Bridge*.sol
```

### Phase 5: ZK Circuit Audit (if applicable)

Review circuit constraints for:
- Input signals that are not fully constrained
- Trusted setup ceremony participant count
- Nullifier uniqueness enforcement
- Range check completeness

### Phase 6: Report Generation

Produce a structured finding report with:
- Severity (Critical / High / Medium / Low / Informational)
- Description and impact
- Proof-of-concept or test case
- Recommended remediation
- Reference to relevant CWE/SWC IDs

## Reference Material

- `references/solidity-vulns.md` — Solidity vulnerability patterns catalogue
- `references/defi-attack-vectors.md` — DeFi attack vector reference
- `references/bridge-security.md` — Cross-chain bridge vulnerability patterns
- `references/zk-audit-checklist.md` — ZK circuit security checklist
