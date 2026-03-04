# Cross-Chain Bridge Security Reference

A structured reference for cross-chain bridge vulnerability patterns, covering
architectural risks, known attack classes, and mitigation strategies.

---

## Bridge Architecture Types

| Type | Description | Risk Profile |
|------|-------------|--------------|
| Lock-and-Mint | Lock tokens on source chain, mint wrapped tokens on dest | High: unbounded mint risk |
| Burn-and-Mint | Burn on source, mint on dest | High: coordination failures |
| Liquidity Pool | LP provides native tokens on each chain | Medium: LP imbalance risk |
| Optimistic | Fraud-proof window before finality | Medium: challenge period attacks |
| ZK Bridge | ZK proof of source chain state | Low: most secure, but circuit bugs possible |
| Message Passing | Arbitrary message relay (LayerZero, Wormhole, etc.) | High: validator set trust |

---

## Attack Class 1: Signature Forgery

**Description:** The bridge relies on validator signatures to authorise cross-chain
messages. If the signature verification is incomplete, attackers can forge messages.

**Root Cause:** `ecrecover` returns `address(0)` on invalid signatures. If the contract
does not check for this, an attacker can pass a zero signature and impersonate a validator.

**Vulnerable pattern:**
```solidity
function processMessage(bytes calldata message, bytes calldata sig) external {
    address signer = recoverSigner(message, sig);
    require(validatorSet[signer], "Not validator"); // Passes if address(0) is in validatorSet!
}
```

**Mitigation:**
```solidity
address signer = recoverSigner(message, sig);
require(signer != address(0), "Invalid signature");
require(validatorSet[signer], "Not validator");
```

---

## Attack Class 2: Message Replay

**Description:** A message that has already been processed is replayed on the same
or a different chain, causing double-spending or duplicate minting.

**Historic Example:** Nomad bridge hack (2022, ~$190M) — the initial root was set to `0x00`,
meaning any message was considered "proven". Any observer could replay valid messages.

**Detection:**
```bash
grep -n "processed\[msgId\]\|executed\[hash\]\|nonces\[" contracts/Bridge*.sol
```

**Mitigation:**
```solidity
mapping(bytes32 => bool) public processedMessages;

function processMessage(bytes32 msgId, ...) external {
    require(!processedMessages[msgId], "Already processed");
    processedMessages[msgId] = true;
    // ... process
}
```

---

## Attack Class 3: Validator Set Collusion

**Description:** Bridges secured by a small multisig or a small validator set are
vulnerable to collusion. If a threshold of validators are compromised or bribed,
they can authorise arbitrary withdrawals.

**Historic Examples:**
- Ronin Network hack (2022, ~$625M) — 5-of-9 multisig, attacker obtained 5 keys
- Harmony Horizon hack (2022, ~$100M) — 2-of-5 multisig compromised

**Mitigation:**
- Require a large, diverse validator set (≥ 20 validators minimum)
- Use hardware security modules (HSMs) for validator key storage
- Implement rate limiting: cap daily withdrawal volume
- Require governance timelock for large withdrawals
- Prefer ZK validity proofs over trusted relayers

---

## Attack Class 4: Unbounded Minting

**Description:** The bridge's mint function has no cap or rate limit, allowing an
attacker who controls the minting authority to create unlimited tokens.

**Vulnerable pattern:**
```solidity
function mintWrapped(address recipient, uint256 amount) external onlyRelayer {
    wrappedToken.mint(recipient, amount); // No cap, no rate limit
}
```

**Mitigation:**
- Implement a daily mint cap
- Require multi-party authorisation for large mints
- Monitor and alert on unusual mint volumes

---

## Attack Class 5: Missing Finality Checks

**Description:** The bridge processes messages before the source chain transaction
has achieved finality, allowing chain reorganisations to invalidate the source event
while the destination-side action has already occurred.

**Mitigation:**
- Require a minimum number of block confirmations:
  - Ethereum: 12–32 blocks
  - Polygon: 128+ blocks (due to reorg risk)
  - BSC: 15+ blocks
- For Proof-of-Stake chains, wait for finality checkpoints

---

## Attack Class 6: Front-Running Bridge Relayers

**Description:** If relayer reward logic is predictable, MEV bots can front-run
relayers to capture fees without providing the liveness guarantee.

**Mitigation:** Use commit-reveal for relayer selection, or use a relayer auction mechanism.

---

## Protocol-Specific Findings

### LayerZero
- Verify `trustedRemote` is correctly set for each chain pair
- Ensure `_lzReceive` is protected against reentrancy
- Check `nonce` ordering enforcement

### Wormhole
- Validate guardian signatures against the guardian set
- Ensure VAA (Verified Action Approval) sequence numbers are checked
- Protect against duplicate VAA replays with `isTransferCompleted`

### Axelar / Hyperlane
- Verify the validator set threshold is sufficiently high
- Check that the message routing is correctly scoped to authorised senders

---

## Bridge Security Checklist

- [ ] Replay protection: every message has a unique ID checked against a "processed" mapping
- [ ] Signature validation: `ecrecover` result checked against address(0) and against validator set
- [ ] Threshold: minimum M-of-N validators required (M > N/2)
- [ ] Rate limiting: daily withdrawal/mint caps enforced
- [ ] Finality checks: source-chain confirmation count validated
- [ ] Upgrade timelock: contract upgrades require ≥ 48-hour timelock
- [ ] Emergency pause: circuit breaker can halt the bridge
- [ ] Monitoring: alerts on anomalous volume spikes
- [ ] Validator key management: HSMs or MPC key management in use
- [ ] Audit trail: all bridge events emitted and indexable
