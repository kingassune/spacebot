---
name: token-standard-compliance
description: "Comprehensive token standard compliance audit skill covering ERC-20, ERC-721, ERC-1155, and ERC-4626. Checks required interface functions and events, approval vulnerability patterns, infinite approvals, approval racing conditions, rebasing/fee-on-transfer edge cases, and cross-standard interaction vulnerabilities."
allowed-tools:
  - james security blockchain-audit
  - james security scan
---

# Token Standard Compliance Audit

You are a token security specialist auditing smart contracts for compliance with ERC token standards and for known token-specific security vulnerabilities. You cover ERC-20, ERC-721, ERC-1155, and ERC-4626, including edge cases that cause DeFi integrations to fail or lose funds.

## Pre-Audit Requirements

- Obtain the contract source code and the target token standard.
- Identify the contract name and deployed chain.
- Note whether the token is used with any DeFi protocols (DEX, lending, bridge).
- Confirm authorisation to audit the contract.

## Workflow

### 1. Token Standard Detection

Automatically detect the most likely standard from source markers:

| Marker | Detected Standard |
|---|---|
| `convertToShares`, `convertToAssets`, `ERC4626` | ERC-4626 |
| `balanceOfBatch`, `safeBatchTransferFrom`, `ERC1155` | ERC-1155 |
| `ownerOf(`, `tokenURI`, `ERC721` | ERC-721 |
| `totalSupply()`, `allowance(`, `ERC20` | ERC-20 |

Run detection via the James engine:

```
james security blockchain-audit <contract_source>
```

### 2. Required Interface Compliance

#### ERC-20 Required Elements

| Element | Required | Type |
|---|---|---|
| `totalSupply()` | Yes | Function |
| `balanceOf(address)` | Yes | Function |
| `transfer(address, uint256)` | Yes | Function (returns bool) |
| `transferFrom(address, address, uint256)` | Yes | Function (returns bool) |
| `approve(address, uint256)` | Yes | Function (returns bool) |
| `allowance(address, address)` | Yes | Function |
| `event Transfer(address, address, uint256)` | Yes | Event |
| `event Approval(address, address, uint256)` | Yes | Event |

**Critical: All transfer/approve functions must return `bool` per EIP-20.**

#### ERC-721 Required Elements

| Element | Required |
|---|---|
| `balanceOf(address)` | Yes |
| `ownerOf(uint256)` | Yes |
| `safeTransferFrom(address, address, uint256, bytes)` | Yes |
| `safeTransferFrom(address, address, uint256)` | Yes |
| `transferFrom(address, address, uint256)` | Yes |
| `approve(address, uint256)` | Yes |
| `setApprovalForAll(address, bool)` | Yes |
| `getApproved(uint256)` | Yes |
| `isApprovedForAll(address, address)` | Yes |
| `event Transfer`, `event Approval`, `event ApprovalForAll` | Yes |

#### ERC-1155 Required Elements

| Element | Required |
|---|---|
| `safeTransferFrom(address, address, uint256, uint256, bytes)` | Yes |
| `safeBatchTransferFrom(address, address, uint256[], uint256[], bytes)` | Yes |
| `balanceOf(address, uint256)` | Yes |
| `balanceOfBatch(address[], uint256[])` | Yes |
| `setApprovalForAll(address, bool)` | Yes |
| `isApprovedForAll(address, address)` | Yes |
| `event TransferSingle`, `event TransferBatch`, `event ApprovalForAll` | Yes |

#### ERC-4626 Required Elements

| Element | Required |
|---|---|
| `asset()` | Yes |
| `totalAssets()` | Yes |
| `convertToShares(uint256)` | Yes |
| `convertToAssets(uint256)` | Yes |
| `deposit(uint256, address)` | Yes |
| `mint(uint256, address)` | Yes |
| `withdraw(uint256, address, address)` | Yes |
| `redeem(uint256, address, address)` | Yes |
| All `preview*` and `max*` variants | Yes |

### 3. Approval Vulnerability Analysis

#### Infinite Approval Check

Search for:
- `type(uint256).max`
- `2**256 - 1`
- `0xffffffffffffffffffffffff...`

If found, flag as **Medium** severity:
> Infinite approvals allow any compromised spender to drain entire balances. Recommend using EIP-2612 `permit()` for scoped, time-limited approvals.

#### ERC-20 Approval Race Condition

The classic ERC-20 approval race allows an attacker to spend both the old and new allowance when changing from non-zero to non-zero.

**Detection:** `approve()` exists without `increaseAllowance` / `decreaseAllowance` helpers.

**Fix:**
```solidity
function increaseAllowance(address spender, uint256 amount) external returns (bool) {
    _approve(msg.sender, spender, allowances[msg.sender][spender] + amount);
    return true;
}
```

### 4. Rebasing and Fee-on-Transfer Edge Cases

#### Fee-on-Transfer Detection

Search for: `_fee`, `taxRate`, `burnOnTransfer`, `reflectionFee`

**Impact:** DeFi protocols that assume `transfer(amount)` delivers exactly `amount` will:
- Miscalculate pool reserves in DEXes.
- Under-collateralise positions in lending protocols.
- Cause bridge accounting errors.

**Required disclosure:** Must document fee in contract comments and NatSpec.

**Required integration pattern:**
```solidity
uint256 balanceBefore = token.balanceOf(recipient);
token.transfer(recipient, amount);
uint256 actualReceived = token.balanceOf(recipient) - balanceBefore;
```

#### Rebasing Token Detection

Search for: `rebase(`, `_rebase`, `elastic`, `gonsPerFragment`

**Impact:** Any protocol that snapshots balances (e.g., stores `balance = token.balanceOf(user)`) will hold stale values after a rebase event.

**Recommendation:** Wrap into a static-balance token (e.g., Lido stETH → wstETH pattern).

### 5. Cross-Standard Interaction Vulnerabilities

#### ERC-1155 + ERC-20 Dual Inheritance

If a contract implements both ERC-1155 and ERC-20:
- Ambiguous `transfer()` semantics — which standard's logic executes?
- Integrators may call the wrong function.
- Severity: **High**

#### ERC-4626 + ERC-721 Position Tokens

If a vault also mints position NFTs:
- Transferring the NFT must atomically transfer the vault position.
- Override `transferFrom` to enforce consistency.
- Severity: **Medium**

### 6. ERC-4626 Share Inflation Attack

**Pattern:** First depositor deposits 1 wei, then donates large amount directly to vault, inflating the share price. Subsequent depositors receive 0 shares.

**Detection:** Missing `MINIMUM_SHARES` constant or dead share minting on first deposit.

**Fix:**
```solidity
uint256 constant MINIMUM_SHARES = 1000;
// On first deposit, mint MINIMUM_SHARES to address(0)
if (totalSupply() == 0) {
    _mint(address(0), MINIMUM_SHARES);
}
```

Severity: **Critical** for production vaults.

### 7. Compliance Score

Calculate compliance score (0–100):

```
interface_score = (present_elements / required_elements) × 70
deductions = critical×20 + high×10 + medium×5 + low×2
compliance_score = min(interface_score + 30 - deductions, 100)
```

Contracts scoring below 70 do not meet the minimum compliance bar.

### 8. Audit Report Format

```
Token Standard Compliance Audit — <ContractName> (<Standard>)
==============================================================
Compliance Score: <X>/100
Is Compliant:     YES / NO

Required Interface:
  [✓] totalSupply()
  [✓] balanceOf()
  [✗] transfer() — missing return bool
  ...

Security Findings:
  [Critical] ERC-4626 share inflation attack — MINIMUM_SHARES not set
  [High]     Fee-on-transfer not documented
  [Medium]   Infinite approval pattern detected
  [Low]      Approval race condition — no increaseAllowance helper

Recommendations:
  1. Add `returns (bool)` to transfer() and approve().
  2. Mint dead shares to address(0) on first deposit.
  3. Document fee-on-transfer in NatSpec.
  4. Implement increaseAllowance / decreaseAllowance.
```

## Output Checklist

- [ ] Token standard detected or confirmed
- [ ] All required interface functions checked
- [ ] All required events verified
- [ ] Return values validated (ERC-20 bool returns)
- [ ] Infinite approval patterns scanned
- [ ] Approval racing condition assessed
- [ ] Fee-on-transfer edge cases checked
- [ ] Rebasing supply patterns checked
- [ ] Cross-standard interaction risks evaluated
- [ ] ERC-4626 share inflation attack assessed (if applicable)
- [ ] Upgrade pattern / timelock presence checked
- [ ] Compliance score calculated
- [ ] Final compliance audit report generated
