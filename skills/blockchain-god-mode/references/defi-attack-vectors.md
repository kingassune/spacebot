# DeFi Attack Vectors Reference

A comprehensive reference for DeFi-specific attack vectors, including flash loans,
oracle manipulation, sandwich attacks, MEV, and liquidity exploitation.

---

## Flash Loan Attacks

### Mechanism
Flash loans allow borrowing any amount of tokens within a single transaction with
zero collateral, as long as the borrowed amount is returned before the transaction
ends. This gives attackers temporary access to capital measured in billions of USD.

### Attack Patterns

**Price Oracle Manipulation via Flash Loan:**
1. Borrow large amount of Token A via flash loan.
2. Swap Token A for Token B on the target DEX, inflating Token B's spot price.
3. Use the inflated price to borrow/drain from a lending protocol that uses this
   DEX as its price oracle.
4. Repay flash loan; attacker profits from the drained funds.

**Historic Examples:**
- bZx attacks (2020) — ~$1M drained via Uniswap spot price oracle manipulation
- Pancake Bunny (2021) — ~$45M via BNB price manipulation
- Mango Markets (2022) — ~$117M via oracle manipulation (not flash loan, but similar)

### Detection Indicators
```solidity
// Red flags:
IERC20(token).balanceOf(address(this)) // Spot balance checks
IUniswapV2Pair(pair).getReserves()     // Spot price from AMM
```

### Mitigation
- Use time-weighted average prices (TWAP) with sufficient window (≥ 30 min for most protocols)
- Use Chainlink price feeds as primary oracle
- Add sanity checks: reject if price deviates > X% from TWAP
- Implement flashloan-resistant reentrancy guards

---

## Oracle Manipulation

### Uniswap V2 Spot Price Vulnerability
Uniswap V2's `getReserves()` returns instantaneous reserves. A single large swap
can move the price significantly within a block.

```solidity
// Vulnerable oracle:
(uint112 reserve0, uint112 reserve1,) = pair.getReserves();
uint price = reserve1 / reserve0; // Manipulable!
```

### TWAP Implementation (Uniswap V2)
```solidity
// Secure: use cumulative prices with time-weighting
uint price0CumulativeLast = pair.price0CumulativeLast();
uint32 blockTimestampLast = pair.blockTimestampLast();
// ... observe over multiple blocks
```

### Chainlink Price Feed Usage
```solidity
AggregatorV3Interface priceFeed = AggregatorV3Interface(feedAddress);
(, int256 price, , uint256 updatedAt, ) = priceFeed.latestRoundData();
require(block.timestamp - updatedAt <= MAX_STALENESS, "Stale price");
require(price > 0, "Invalid price");
```

---

## Sandwich Attacks (MEV)

### Mechanism
1. Attacker monitors the public mempool for pending swap transactions.
2. Attacker submits a front-run transaction with higher gas (buying before victim).
3. Victim's swap executes at a worse price due to the attacker's purchase.
4. Attacker back-runs with a sell at the inflated price, capturing the spread.

### Profit Estimation
For a victim swap of `Δx` tokens with slippage tolerance `s`:
```
Attacker profit ≈ Δx × s × (1 - fee)²
```

### Mitigation
- Set tight slippage tolerance (0.1–0.5% for liquid pools)
- Use Flashbots Protect or MEV Blocker for private mempool submission
- Use DEX aggregators with MEV protection (1inch Fusion, CoW Protocol)
- Implement commit-reveal for large trades

---

## Impermanent Loss Exploitation

### Mechanism
LPs in AMMs suffer impermanent loss when the price of pooled assets diverges.
Attackers can exploit this by:
1. Taking large directional positions before known price-moving events.
2. Using governance to drain concentrated liquidity positions.

### Formula
For a price ratio change `r = P_final / P_initial`:
```
IL = 2√r / (1 + r) - 1
```
At 2× price change: IL ≈ 5.7%
At 4× price change: IL ≈ 20%

---

## Governance Attacks

### Flash Loan Governance Attack
1. Acquire large voting power via flash loan (borrow governance tokens).
2. Create and immediately pass a malicious governance proposal.
3. Execute the proposal in the same transaction.
4. Repay the flash loan.

**Mitigation:** Require a time-lock between proposal creation and execution (≥ 2 days).
Snapshot voting power at proposal creation time, not execution time.

### Vote Buying (Economic Attack)
Offer token holders a small bribe to vote for a malicious proposal. The bribe
cost may be less than the attacker's expected profit.

**Mitigation:** Optimistic governance with veto mechanisms, on-chain identity.

---

## Rug Pull Vectors

### Admin Key Rug Pull
Developer retains `onlyOwner` functions that can:
- Drain the treasury
- Pause trading indefinitely
- Mint unlimited tokens

**Detection:**
```bash
# Search for dangerous owner functions
grep -rn "onlyOwner" contracts/ | grep -E "withdraw|drain|mint|pause"
```

### Liquidity Removal
Project team removes liquidity from the AMM pool, collapsing the token price.

**Mitigation:** Time-locked liquidity, LP token vesting contracts.

### Proxy Upgrade Attack
Owner upgrades a proxy to a malicious implementation that drains user funds.

**Mitigation:** Time-locked upgrades, multi-sig ownership, community veto.

---

## Token Inflation / Rebase Attacks

Rebasing tokens (e.g., Ampleforth, stETH) change balances externally. Protocols
that cache token balances without accounting for rebases may undercount or overcount
user positions.

```solidity
// Vulnerable: caches balance at deposit time
mapping(address => uint256) deposited;
function deposit(uint256 amount) external {
    token.transferFrom(msg.sender, address(this), amount);
    deposited[msg.sender] += amount; // Does not account for rebases
}
```

**Mitigation:** Use share-based accounting (like ERC-4626 vault shares).

---

## Interest Rate Manipulation

Lending protocols that compute interest rates based on current utilisation can be
manipulated: a flash loan that temporarily increases utilisation spikes the interest
rate, disadvantaging borrowers in the same block.

**Mitigation:** Smooth interest rate updates (e.g., Aave V3's rate strategy).
