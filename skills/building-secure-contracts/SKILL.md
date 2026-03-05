---
name: building-secure-contracts
description: "James integration of Trail of Bits' secure contract development methodology. Guides auditing of Solidity/Vyper smart contracts for common vulnerability classes."
allowed-tools:
  - Bash
  - Read
  - Grep
  - Glob
---

# Building Secure Contracts

You are performing a smart contract security audit using Trail of Bits' methodology.

## Workflow

### 1. Initial Triage
- Identify the contract language (Solidity version, Vyper version).
- Map all external entry points: public/external functions, fallback, receive.
- Note all state variables and their visibility.

### 2. Vulnerability Checklist

**Reentrancy**
- Check all external calls (`.call`, `.transfer`, `.send`, interface calls).
- Verify checks-effects-interactions pattern is followed.
- Look for cross-function and cross-contract reentrancy paths.
- Check for read-only reentrancy in view functions used in state-changing logic.

**Integer Overflow / Underflow**
- For Solidity <0.8.0: verify SafeMath usage or manual bounds checks on every arithmetic op.
- For Solidity ≥0.8.0: verify unchecked blocks are audited for intentional overflow.
- Check casting between uint sizes (e.g. uint256 → uint128 truncation).

**Access Control**
- Verify all privileged functions have appropriate modifiers (onlyOwner, roles).
- Check for missing access control on initialization functions.
- Review role assignment and revocation logic.
- Look for tx.origin used for authorization (use msg.sender instead).

**Oracle Manipulation**
- Identify price oracle sources (Uniswap spot, Chainlink, TWAP).
- Flag any use of spot price from AMM without TWAP or circuit-breaker.
- Check for flash-loan-exploitable price reads within the same transaction.

**Flash Loan Attacks**
- Identify functions that change state based on token balances.
- Check for atomicity assumptions (single-block state changes).
- Verify no single-transaction manipulation of collateral ratios or price feeds.

**Additional Checks**
- Front-running: are sensitive operations sandwich-attackable?
- Denial of service: can an attacker block progress via gas griefing or forced revert?
- Signature replay: are EIP-712 signatures validated with nonce and chain ID?
- Upgradability: if proxy pattern used, verify storage slot conflicts and initializer guards.
- Timestamp dependence: `block.timestamp` used for randomness or critical deadlines?

### 3. Output Format
Produce findings as:
```
[SEVERITY: Critical/High/Medium/Low/Informational]
Title: <short title>
Location: <file:line or function name>
Description: <what the issue is>
Impact: <what an attacker can do>
Recommendation: <how to fix>
```

### 4. Summary Report
After all findings, produce:
- Total count by severity.
- Top 3 most critical findings.
- Overall contract security posture (Insecure / Needs Work / Acceptable / Strong).
