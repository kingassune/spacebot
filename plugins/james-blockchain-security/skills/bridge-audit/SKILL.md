---
name: bridge-audit
description: "Cross-chain bridge security audit covering message verification, nonce management, ecrecover patterns, mint authority, and per-bridge-type checklists for Lock-and-Mint, Burn-and-Mint, Liquidity, and AMB bridges."
allowed-tools: ["shell", "file", "exec"]
---

# Cross-Chain Bridge Security Audit

You are auditing a cross-chain bridge within an authorized engagement. Bridge vulnerabilities have historically led to the largest DeFi exploits (Ronin $625M, Wormhole $320M, Nomad $190M). Treat every finding as high impact.

## Pre-Audit Setup

- Identify bridge architecture: Lock-and-Mint, Burn-and-Mint, Liquidity Network, or Arbitrary Message Bridge (AMB).
- Map all chains involved and per-chain contract addresses.
- Document the validator/relayer set, their signing authority, and threshold (e.g., 5-of-9 multisig).
- Confirm which contracts hold user funds and the total TVL (sets severity baseline).

## Message Verification Weaknesses

### Signature Validation

The most critical bridge vulnerability class. Every cross-chain message must be cryptographically verified.

```bash
# Search for ecrecover usage
grep -rn "ecrecover\|recover\|ECDSA.recover" contracts/

# Check for zero-address validation after ecrecover
grep -A5 "ecrecover\|ECDSA.recover" contracts/ | grep -n "require\|revert\|== address(0)"
```

**Critical checks:**

- `ecrecover` returns `address(0)` on failure — verify the return value is always compared to a non-zero expected signer.
- Signatures must be bound to: chain ID, contract address, nonce, and payload hash. Missing any element enables replay.
- Verify `ECDSA.recover` (OpenZeppelin) is used instead of raw `ecrecover` to prevent malleable signature attacks.
- Check for `v` parameter handling — accept only `v = 27` or `v = 28`; reject `v ∈ {0, 1}`.

### Validator Set Integrity

```bash
# Find validator/guardian set management
grep -rn "setGuardians\|updateValidators\|setRelayer\|addSigner\|removeSigner" contracts/

# Check threshold logic
grep -rn "threshold\|quorum\|requiredSignatures\|_minSignatures" contracts/
```

- Verify threshold is strictly greater than `(n/3)` for BFT or `(n/2)` for majority schemes.
- Confirm validator set updates require the same threshold as message verification.
- Check for single-admin override that can bypass threshold (Ronin root cause).
- Verify validator key rotation does not create a replay window with old signatures.

## Nonce Management and Replay Attacks

### Nonce Implementation Review

```bash
# Find nonce tracking
grep -rn "nonce\|sequence\|messageId\|transferId" contracts/

# Check cross-chain nonce storage
grep -rn "mapping.*nonce\|processedMessages\|usedNonces" contracts/
```

**Checklist:**

- [ ] Every message has a globally unique identifier (chain ID + nonce or content hash).
- [ ] Processed message IDs are stored in a mapping and checked before execution.
- [ ] Nonce increments are atomic — no re-entrancy possible between nonce check and increment.
- [ ] Nonce namespace is per-source-chain (nonce 5 on Chain A ≠ nonce 5 on Chain B).
- [ ] No `nonce = 0` default that could collide with uninitialized storage.

### Replay Attack Vectors

- Send same message to same chain after contract upgrade.
- Send source chain message to a different destination chain.
- Resend a failed message after state reset.
- Reuse signatures from a previous validator set after rotation.

## Per-Bridge-Type Checklists

### Lock-and-Mint Bridges

Assets are locked on source chain; wrapped tokens minted on destination.

- [ ] Mint function is gated behind verified cross-chain message — no direct minting path.
- [ ] Total minted supply on destination cannot exceed locked supply on source.
- [ ] Unlock/burn function verifies the corresponding burn on the destination chain.
- [ ] Pausing mechanism: can deposits be paused independently from withdrawals?
- [ ] Fee accounting: fees cannot be extracted by replaying fee-bearing messages.

```bash
# Check mint authority
grep -rn "mint\|_mint\|safeMint" contracts/ | grep -v "test\|mock"

# Verify mint is gated
grep -B10 "_mint\|safeMint" contracts/ | grep -n "onlyBridge\|onlyRelayer\|require.*verified"
```

### Burn-and-Mint Bridges

Assets are burned on source chain; native tokens released on destination.

- [ ] Burn is irreversible — verify no `unburn` or recovery path.
- [ ] Destination release verifies burn proof (merkle proof or validator signatures).
- [ ] Native asset supply accounting remains consistent across chains.

### Liquidity Network Bridges

Liquidity pools on both chains; rebalancing via relayers.

- [ ] Liquidity pool cannot be drained by a single large transfer without rebalancing.
- [ ] LP withdrawal timing cannot be exploited to steal pending user funds.
- [ ] Relayer incentive mechanism cannot be gamed to extract LP funds.

### Arbitrary Message Bridges (AMB)

General cross-chain message passing (LayerZero, Wormhole, Axelar, Hyperlane).

```bash
# Check lzReceive / _nonblockingLzReceive implementation
grep -rn "lzReceive\|_nonblockingLzReceive\|handle\|execute" contracts/

# Check trusted remote configuration
grep -rn "trustedRemote\|setTrustedRemote\|setRemote\|setPeer" contracts/
```

- [ ] Trusted remote addresses are set for every expected source chain — no wildcard.
- [ ] Message executor validates source chain AND source address.
- [ ] Failed message handling does not leave funds locked forever.
- [ ] Gas estimation on destination is correct — insufficient gas must not leave state partially updated.

## Mint Authority and Access Control

```bash
# Map all privileged roles
slither . --print human-summary 2>/dev/null | grep -A20 "roles\|Access"

# Check upgradeability
grep -rn "upgradeTo\|upgradeToAndCall\|_authorizeUpgrade\|UUPSUpgradeable\|TransparentUpgradeableProxy" contracts/
```

- Identify who can call mint, burn, pause, upgrade, and updateValidators.
- Verify these roles are assigned to timelocked governance contracts, not EOAs.
- Check that upgrade proxy admin is not the same address as the contract owner.
- Assess the multisig threshold for each privileged operation.

## Reference Module

```
src/blockchain_security/bridge.rs — BridgeAuditor
```

## Output Checklist

- [ ] Bridge architecture documented
- [ ] Validator set and threshold verified
- [ ] All `ecrecover` calls checked for zero-address validation
- [ ] Signature binding (chain ID, contract, nonce, payload) verified
- [ ] Nonce uniqueness and replay protection confirmed
- [ ] Per-bridge-type checklist completed
- [ ] Mint authority mapped and timelocked
- [ ] Upgradeability review completed
- [ ] All findings CVSS-scored with remediation guidance
