---
name: blockchain-formal-verification
description: "Formal verification and invariant testing skill for smart contracts. Covers Solidity assert/require extraction, Echidna/Medusa invariant campaigns, state machine modeling, and temporal property checking."
---

# Blockchain Formal Verification

You are applying formal verification and invariant testing techniques to smart contract source code to mathematically prove or disprove security properties.

## Pre-Verification Requirements

- Obtain the full contract source code (Solidity/Vyper preferred).
- Identify the primary contract name and all inherited contracts.
- Determine the ERC standard (ERC-20, ERC-721, ERC-1155, or custom).
- List critical invariants from the protocol specification or audit scope.

## Workflow

### 1. Assertion and Require Extraction

Extract all safety checks declared in the contract:

```bash
grep -n "assert\|require\|revert" Contract.sol
```

For each extracted statement:
- Classify as: balance check, access control, arithmetic bound, state transition guard.
- Note which functions contain them.
- Identify functions that lack expected guards.

### 2. State Machine Modeling

Map all state-modifying functions and their transitions:

1. List all `state` variables (enums, booleans, counters).
2. For each function: identify preconditions (require), state changes, postconditions.
3. Draw the state transition graph.
4. Identify unreachable states and invalid transition paths.

Key patterns to check:
- Pause/unpause state consistency.
- Ownership transfer atomicity.
- Reentrancy lock state transitions.

### 3. Invariant Property Specification

Define invariants to verify using Echidna/Medusa naming convention:

```solidity
// Balance conservation
function echidna_total_supply_conserved() external view returns (bool) {
    uint256 sum = 0;
    for (address addr in holders) { sum += balances[addr]; }
    return sum == totalSupply;
}

// No unauthorized minting
function echidna_supply_only_increases_on_mint() external view returns (bool) {
    return totalSupply <= MAX_SUPPLY;
}

// Ownership integrity
function echidna_owner_not_zero() external view returns (bool) {
    return owner != address(0);
}
```

### 4. Invariant Fuzzing Campaign (Echidna)

Configure and run the invariant campaign:

```yaml
# echidna.yaml
testLimit: 100000
corpusDir: "corpus/"
testMode: "property"
coverage: true
seed: 12345
```

```bash
echidna-test Contract.sol --config echidna.yaml --contract ContractTest
```

Analyze results:
- **Passing properties:** Confirm they hold at the configured test limit.
- **Broken properties:** Examine the minimized call sequence (corpus entry).
- **Coverage report:** Ensure all branches are exercised (`echidna-cov`).

### 5. Temporal Property Checking

Check temporal properties (always/eventually):

**Safety properties (must always hold):**
- `G(balance[x] >= 0)` — balance never negative.
- `G(allowance[x][y] <= balance[x])` — allowance cannot exceed balance.
- `G(locked → !locked || msg.sender == owner)` — reentrancy lock respected.

**Liveness properties (must eventually hold):**
- `F(paused → unpaused)` — contract can always be unpaused.
- `F(pending_withdrawal → withdrawal_complete)` — withdrawals always finalize.

Use Certora Prover CVL syntax for temporal rules when available:

```cvl
rule balanceNeverNegative {
    env e; address user;
    require balanceOf(user) >= 0;
    method f; calldataarg args;
    f(e, args);
    assert balanceOf(user) >= 0;
}
```

### 6. ERC Standard Compliance Verification

Verify compliance with the relevant ERC standard:

**ERC-20 Required Functions:**
- `transfer(address, uint256) returns (bool)`
- `transferFrom(address, address, uint256) returns (bool)`
- `approve(address, uint256) returns (bool)`
- `allowance(address, address) returns (uint256)`
- `balanceOf(address) returns (uint256)`
- `totalSupply() returns (uint256)`

Check for non-standard behaviors:
- Fee-on-transfer (breaks ERC-20 assumptions in integrations).
- Rebasing supply (breaks accounting in lending protocols).
- Missing return values (silent failures in older contracts).

**ERC-721 Additional Checks:**
- `safeTransferFrom` must call `onERC721Received` on contracts.
- `approve` must check `ownerOf(tokenId) == msg.sender`.
- `setApprovalForAll` must emit `ApprovalForAll` event.

### 7. Vulnerability Pattern Matching

Cross-reference findings with known vulnerability classes:

| Pattern | Severity | Invariant to Check |
|---|---|---|
| Integer overflow (pre-0.8) | Critical | `unchecked { a + b } >= a` |
| Reentrancy | Critical | `locked` guard around state changes |
| Approval race | High | `increaseAllowance` pattern exists |
| Flash loan price oracle | High | Time-weighted price used |
| Centralization risk | Medium | Owner key is multi-sig |
| Infinite approval | High | `type(uint256).max` approval pattern |

### 8. Report Generation

Generate the formal verification report:

```
james security blockchain verify --contract Contract.sol --name MyToken
```

Report sections:
1. **Executive Summary** — Properties verified, violations found, risk score.
2. **Invariant Test Results** — Each property with pass/fail and counter-example.
3. **ERC Compliance** — Missing functions, non-standard behaviors.
4. **State Machine Analysis** — Invalid state transitions identified.
5. **Temporal Properties** — Always/eventually properties checked.
6. **Remediation Recommendations** — Ordered by severity.

## Output Checklist

- [ ] Assertions and require statements extracted and categorized
- [ ] State machine diagram constructed
- [ ] Invariant properties defined using Echidna naming convention
- [ ] Echidna/Medusa campaign run at sufficient test limit (≥10,000)
- [ ] Coverage report reviewed (target ≥80%)
- [ ] Temporal properties specified and checked
- [ ] ERC standard compliance verified
- [ ] Vulnerability patterns cross-referenced
- [ ] Final verification report generated with remediation recommendations
