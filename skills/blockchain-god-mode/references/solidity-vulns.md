# Solidity Vulnerability Patterns

A comprehensive reference for known Solidity smart contract vulnerability patterns,
mapped to SWC Registry IDs where applicable.

---

## SWC-107 — Reentrancy

**Severity:** Critical

**Description:** An external call is made before state is updated, allowing the callee
to re-enter the calling contract and drain funds or corrupt state.

**Vulnerable pattern:**
```solidity
function withdraw(uint256 amount) external {
    require(balances[msg.sender] >= amount);
    (bool ok, ) = msg.sender.call{value: amount}(""); // External call BEFORE state update
    require(ok);
    balances[msg.sender] -= amount; // State update AFTER call — reentrancy window
}
```

**Secure pattern:**
```solidity
function withdraw(uint256 amount) external nonReentrant {
    require(balances[msg.sender] >= amount);
    balances[msg.sender] -= amount; // State update BEFORE call
    (bool ok, ) = msg.sender.call{value: amount}("");
    require(ok);
}
```

**Detection:** Look for `.call{value:}`, `.transfer()`, or `.send()` before state updates.

---

## SWC-115 — tx.origin Authentication

**Severity:** High

**Description:** Using `tx.origin` for authentication allows phishing attacks where a
malicious contract calls the victim contract on behalf of the legitimate user.

**Vulnerable pattern:**
```solidity
function transferOwnership(address newOwner) external {
    require(tx.origin == owner); // Vulnerable: uses tx.origin
    owner = newOwner;
}
```

**Secure pattern:**
```solidity
function transferOwnership(address newOwner) external {
    require(msg.sender == owner); // Correct: uses msg.sender
    owner = newOwner;
}
```

---

## SWC-112 — Delegatecall to Untrusted Callee

**Severity:** Critical

**Description:** `delegatecall` to a user-controlled or upgradeable address executes
code in the context of the calling contract, allowing arbitrary storage writes.

**Vulnerable pattern:**
```solidity
function execute(address target, bytes calldata data) external {
    target.delegatecall(data); // Arbitrary code execution in this contract's context
}
```

**Mitigation:** Whitelist `delegatecall` targets and validate implementation addresses
in upgradeability proxies.

---

## SWC-124 — Write to Arbitrary Storage Location

**Severity:** Critical

**Description:** Storage collisions between proxy and implementation contracts allow
attackers to overwrite admin slots or critical state variables.

**Mitigation:** Use EIP-1967 standardised storage slots (`keccak256("eip1967.proxy.implementation") - 1`).

---

## SWC-101 — Integer Overflow and Underflow

**Severity:** High (pre-Solidity 0.8.x)

**Description:** Arithmetic operations wrap around without reverting in Solidity < 0.8.

**Mitigation:** Use Solidity ≥ 0.8 (built-in overflow checks) or OpenZeppelin `SafeMath`.

---

## SWC-105 — Unprotected Ether Withdrawal

**Severity:** Critical

**Description:** A withdrawal function lacks access controls, allowing any caller to
drain contract funds.

**Detection:** Search for `transfer(` or `.call{value:}(` without `onlyOwner` or equivalent guard.

---

## SWC-116 — Block Values as a Proxy for Time

**Severity:** Medium

**Description:** `block.timestamp` can be manipulated by miners within a ~15-second window.
Do not use it for randomness or precise time-locks.

---

## SWC-120 — Weak Sources of Randomness from Chain Attributes

**Severity:** High

**Description:** Using `block.hash`, `block.timestamp`, or `blockhash()` as randomness
sources is predictable and manipulable by validators.

**Mitigation:** Use Chainlink VRF or commit-reveal schemes.

---

## SWC-103 — Floating Pragma

**Severity:** Low

**Description:** Contracts compiled with a floating pragma (`^0.8.0`) may behave
differently across compiler versions.

**Mitigation:** Pin the pragma to a specific version.

---

## Access Control Patterns

### Missing Access Control on Critical Functions
```solidity
// Vulnerable: no access control
function setOwner(address newOwner) external {
    owner = newOwner;
}

// Secure
function setOwner(address newOwner) external onlyOwner {
    owner = newOwner;
}
```

### Role-Based Access Control (OpenZeppelin)
```solidity
bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");

function mint(address to, uint256 amount) external {
    require(hasRole(MINTER_ROLE, msg.sender), "Not minter");
    _mint(to, amount);
}
```

---

## Flash Loan Attack Surface

Flash loans allow borrowing large amounts of tokens within a single transaction.
Contracts are vulnerable when:
1. They use spot prices from AMMs as oracle values.
2. They update state based on token balances within the same transaction.
3. Governance votes can be manipulated within a single block.

**Mitigation:** Use TWAP oracles, add time-locks to governance, and validate token
balances against expected invariants.

---

## Oracle Manipulation

**Price Oracle Sources (risk ranking, highest risk first):**
1. Uniswap V2 spot price — trivially manipulable
2. Uniswap V3 slot0 — manipulable within a block
3. Uniswap V3 TWAP (1-hour) — expensive to manipulate
4. Chainlink price feeds — most robust for most use cases
5. Maker OSM (Oracle Security Module) — 1-hour delay, very robust

---

## MEV Attack Vectors

### Sandwich Attack
1. Attacker sees victim's swap transaction in the mempool.
2. Attacker front-runs with a buy, driving up the price.
3. Victim's swap executes at a worse price.
4. Attacker back-runs with a sell, capturing the profit.

**Mitigation:** Slippage tolerance, private mempools (Flashbots Protect), DEX aggregators.

### Front-Running
Any transaction that reveals information (e.g., revealing a secret in a commit-reveal
scheme) is front-runnable. Use Flashbots or off-chain signing where possible.
