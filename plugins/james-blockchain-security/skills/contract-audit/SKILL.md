---
name: contract-audit
description: "Comprehensive smart contract audit skill for Solidity, Rust (Solana/CosmWasm), and Move contracts. Covers reentrancy, access control, arithmetic, flash loans, oracle manipulation, bridge vulnerabilities, MEV, and ZK circuit weaknesses."
allowed-tools: ["shell", "file", "exec"]
---

# Smart Contract Audit

You are performing a comprehensive smart contract security audit within an authorized engagement. All analysis targets contracts explicitly in scope per the signed engagement agreement.

## Pre-Audit Setup

### 1. Scope Definition

Confirm the following before beginning:

- List of in-scope contract addresses or repository paths.
- Target blockchain and EVM compatibility (Ethereum, Polygon, Arbitrum, Solana, Cosmos, etc.).
- Known contract roles: owner, admin, pauser, minter, upgrader.
- Audit focus areas: full audit, specific module, upgrade review, or emergency triage.

### 2. Codebase Enumeration

```bash
# Enumerate Solidity contracts
find . -name "*.sol" | sort

# Check Solana Rust programs
find . -name "*.rs" -path "*/programs/*" | sort

# Check CosmWasm contracts
find . -name "*.rs" -path "*/contracts/*" | sort

# Check Move modules
find . -name "*.move" | sort
```

Run static analysis tooling appropriate to the target language:

```bash
# Solidity — Slither
slither . --print human-summary

# Solidity — Mythril
myth analyze contracts/Target.sol --execution-timeout 120

# Solidity — Semgrep
semgrep --config p/solidity .

# Rust/Solana — Cargo Audit
cargo audit

# Cargo Clippy (lints)
cargo clippy -- -D warnings
```

### 3. Dependency Analysis

- Review all imported libraries (OpenZeppelin, Solmate, Anchor, CosmWasm std).
- Cross-reference dependency versions against known CVE databases.
- Flag any unaudited or pinned-to-commit dependencies.

## Vulnerability Categories

### Reentrancy

Check all external calls followed by state changes:

- **Classic reentrancy:** ETH transfer before balance update (`call.value()` before `balances[msg.sender] = 0`).
- **Cross-function reentrancy:** Attacker re-enters a different function that shares state.
- **Read-only reentrancy:** View function called during a reentrant context returns stale state used by another protocol.
- **Cross-contract reentrancy:** State shared between two contracts exploited via a callback.

```bash
# Slither reentrancy detector
slither . --detect reentrancy-eth,reentrancy-no-eth,reentrancy-benign
```

Remediation: Apply checks-effects-interactions pattern. Use `ReentrancyGuard` (`nonReentrant` modifier) from OpenZeppelin.

### Access Control

- Identify privileged functions: `onlyOwner`, `onlyRole`, `onlyAdmin`.
- Verify `Ownable2Step` is used instead of single-step `transferOwnership`.
- Check for missing access modifiers on state-changing functions.
- Review `DEFAULT_ADMIN_ROLE` assignments in OpenZeppelin `AccessControl`.
- Verify timelocks on critical parameter changes (fee updates, oracle changes, upgrades).

```bash
slither . --detect unprotected-upgrade,missing-zero-check,suicidal
```

### Arithmetic Overflow / Underflow

- Solidity ≥0.8: Built-in overflow checks. Verify `unchecked {}` blocks are justified.
- Solidity <0.8: Confirm SafeMath is used consistently.
- Rust/Solana: Check `checked_add`, `checked_sub`, `saturating_*` usage.
- Identify precision loss in division before multiplication.

### Flash Loan Attacks

- Identify all price-sensitive operations exploitable within a single transaction.
- Map flash loan entry points (Aave, dYdX, Balancer, Uniswap).
- Assess whether state changes are isolated from flash-borrowed liquidity.
- Check for spot-price reliance (vs. TWAP) in lending, liquidation, or minting logic.

### Oracle Manipulation

- Identify all price feed integrations (Chainlink, Pyth, Band, Uniswap TWAP, custom).
- Verify Chainlink feeds check `answeredInRound >= roundId` (staleness) and `answer > 0`.
- Confirm TWAP windows are long enough (≥30 min) to resist manipulation.
- Assess impact of a 1-block oracle deviation on liquidation thresholds.

### Bridge Vulnerabilities

- Verify `ecrecover` return value is checked for the zero address.
- Confirm nonce uniqueness and replay protection on cross-chain messages.
- Check mint/burn authority — can any account mint without a corresponding lock?
- Review validator/relayer set update authority and threshold.

### MEV / Sandwich Attacks

- Identify slippage parameters on all AMM interactions — are they user-controlled or hardcoded?
- Flag `deadline` parameters that default to `block.timestamp` (useless protection).
- Review commit-reveal schemes for front-running resistance.
- Assess liquidation functions for sandwich profitability.

### ZK Circuit Weaknesses

- Verify all public inputs are properly constrained.
- Check for under-constrained intermediate signals that allow witness manipulation.
- Confirm nullifier uniqueness is enforced on-chain, not just in the circuit.
- Review the trusted setup ceremony (Groth16 toxic waste disposal).

## Analysis Workflow

```
src/blockchain_security/contract_analysis.rs
```

The `ContractAnalyzer` struct pattern-matches against the vulnerability taxonomy above:

1. Parse AST (Solidity via `solc --ast-json`, Rust via `syn`).
2. Run pattern matchers for each vulnerability category.
3. Score findings by severity (Critical / High / Medium / Low / Informational).
4. Assign CVSS v3.1 base scores.
5. Generate structured finding objects.

## Reporting Format

Each finding must include:

| Field | Description |
|---|---|
| ID | AUDIT-XXX sequential identifier |
| Severity | Critical / High / Medium / Low / Informational |
| CVSS v3.1 | Base score and vector string |
| Title | Short descriptive title |
| Location | File name and line numbers |
| Description | Technical explanation with root cause |
| Impact | What an attacker can achieve |
| Proof of Concept | Exploit code or step-by-step reproduction |
| Remediation | Specific code fix with example |
| References | CWE ID, SWC Registry ID, related advisories |

## Output Checklist

- [ ] Scope confirmed and documented
- [ ] All contracts enumerated and language-appropriate tooling run
- [ ] Dependencies audited
- [ ] Reentrancy paths mapped
- [ ] Access control matrix reviewed
- [ ] Arithmetic operations validated
- [ ] Oracle integrations assessed
- [ ] Flash loan attack surfaces identified
- [ ] MEV exposure quantified
- [ ] Bridge and cross-chain logic reviewed (if applicable)
- [ ] ZK circuit constraints verified (if applicable)
- [ ] All findings assigned CVSS scores
- [ ] Remediation guidance provided for every finding
- [ ] Final audit report generated
