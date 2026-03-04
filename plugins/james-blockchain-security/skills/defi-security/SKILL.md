---
name: defi-security
description: "DeFi protocol security analysis covering flash loans, oracle risk, liquidity pool security, impermanent loss, and MEV/sandwich attack vectors."
allowed-tools: ["shell", "file", "exec"]
---

# DeFi Protocol Security Analysis

You are performing a DeFi protocol security assessment within an authorized engagement. All analysis is strictly within documented scope.

## Pre-Assessment Setup

- Confirm protocol type: AMM, lending, yield aggregator, options, perpetuals, stablecoin, bridge.
- Document all smart contracts in scope and their roles.
- Map external dependencies: oracles, price feeds, liquidity sources, governance contracts.
- Identify economic invariants the protocol must maintain (e.g., total debt ≤ total collateral × LTV).

## Flash Loan Attack Vectors

### Attack Surface Identification

Flash loans allow borrowing arbitrary amounts within a single transaction. Assess every function that:

- Reads a token balance and uses it for a price or ratio calculation.
- Checks collateral value before allowing a withdrawal or mint.
- Relies on `token.balanceOf(address(this))` as an invariant.
- Performs a liquidation based on a collateral ratio computed in the same block.

### Flash Loan Simulation

```bash
# Reference module
src/blockchain_security/defi.rs — FlashLoanSimulator

# Foundry fork test against mainnet state
forge test --match-test testFlashLoanAttack --fork-url $RPC_URL -vvv

# Check for Balancer, Aave v2/v3, Uniswap v3 flash loan entry points
grep -r "flashLoan\|flashSwap\|flash_borrow" contracts/
```

### Checklist

- [ ] No spot price reads inside flash-borrowable execution paths.
- [ ] All price-sensitive functions use TWAP or validated Chainlink feeds.
- [ ] Reentrancy guards present on all lending entry points.
- [ ] Borrow-then-liquidate-same-account scenarios impossible.

## Oracle Risk Assessment

### Price Manipulation Detection

```bash
# Check for spot price reliance (Uniswap v2 getReserves pattern)
grep -n "getReserves\|token0\.balanceOf\|token1\.balanceOf" contracts/

# Chainlink staleness check pattern
grep -n "latestRoundData\|answeredInRound\|updatedAt" contracts/

# TWAP window assessment
grep -n "observe\|consult\|period\|twapPeriod" contracts/
```

### Oracle Risk Matrix

| Oracle Type | Manipulation Cost | Recommended Use |
|---|---|---|
| Uniswap v2 spot | Very Low | Never for pricing |
| Uniswap v3 TWAP <5 min | Low | Low-value decisions only |
| Uniswap v3 TWAP ≥30 min | Medium | Acceptable with circuit breakers |
| Chainlink (standard) | High | Preferred; verify staleness |
| Pyth (on-demand) | High | Acceptable; verify confidence interval |
| Chronicle | High | Acceptable; verify update threshold |

### Chainlink Validation Pattern

Verify every `latestRoundData()` call implements:

```solidity
(uint80 roundId, int256 answer, , uint256 updatedAt, uint80 answeredInRound) = feed.latestRoundData();
require(answeredInRound >= roundId, "Stale price");
require(answer > 0, "Negative price");
require(block.timestamp - updatedAt <= MAX_ORACLE_DELAY, "Oracle timeout");
```

## Impermanent Loss Analysis

- Calculate IL exposure for the LP token pair across ±50%, ±80%, and ±99% price deviations.
- Assess protocol fee APR vs. expected IL for realistic market conditions.
- Identify whether LP positions are used as collateral — IL amplifies liquidation risk.
- Review concentrated liquidity positions (Uniswap v3) for out-of-range scenarios that eliminate fee income.

## Liquidity Pool Security

### Sandwich Attack Assessment

```bash
# Look for hardcoded or zero slippage
grep -n "amountOutMinimum.*0\|minOut.*0\|slippage.*0" contracts/

# Check deadline parameters
grep -n "deadline.*block.timestamp\|deadline.*type(uint" contracts/
```

Sandwich attack conditions:
1. Slippage tolerance is high (>0.5% for large trades).
2. Transaction is pending in mempool (not using private RPC).
3. `deadline` is `block.timestamp` or far in the future.

### MEV Extraction Analysis

- Review liquidation functions for MEV profitability (high profit → bot competition → gas wars).
- Assess arbitrage opportunities created by delayed oracle updates.
- Identify JIT (Just-In-Time) liquidity injection risk in concentrated AMM pools.
- Evaluate whether governance votes are front-runnable.

```bash
# Check for protected liquidation patterns
grep -n "liquidate\|seize\|repayBorrow" contracts/

# Flashbots/MEV protection
grep -rn "flashbots\|private.*rpc\|protect\|commitReveal" contracts/ docs/
```

### Donation / Inflation Attacks

For pools using `balanceOf` as the accounting source (e.g., ERC-4626 vaults):

- Check if an attacker can donate tokens before first deposit to inflate the share price.
- Verify vault uses virtual shares/assets offset (OpenZeppelin v5 pattern).
- Test for zero-share rounding that burns depositor funds.

## Protocol-Specific Checks

### Lending Protocols

- Confirm liquidation threshold < collateral factor (no bad debt accumulation at threshold).
- Verify interest rate model parameters (kink, slope) cannot create insolvency.
- Check for donation attacks on reserve accrual calculations.

### Stablecoins

- Verify redemption mechanism maintains peg under worst-case collateral drop.
- Assess liquidity runway if collateral price gaps down 30% in one block.
- For algorithmic stablecoins: identify death spiral conditions.

### Yield Aggregators

- Check harvesting functions for flash loan manipulation of reward token prices.
- Verify strategy migration paths cannot be used to drain vaults.
- Assess fee-on-transfer token compatibility.

## Output Checklist

- [ ] Protocol type and external dependencies documented
- [ ] Flash loan attack surfaces enumerated and tested
- [ ] All oracle integrations assessed for manipulation cost
- [ ] Chainlink staleness/validity checks verified
- [ ] Slippage and deadline parameters reviewed
- [ ] MEV extraction scenarios mapped
- [ ] Donation/inflation attack vectors checked
- [ ] Economic invariants verified under stress scenarios
- [ ] Findings assigned CVSS scores with remediation guidance
