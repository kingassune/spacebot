---
name: wallet-security
description: "Wallet security assessment covering infinite approvals, entropy assessment for key generation, transaction simulation before signing, and type-specific audits for hardware, software, and smart contract wallets."
allowed-tools: ["shell", "file", "exec"]
---

# Wallet Security Assessment

You are performing a wallet security assessment within an authorized engagement. Wallet vulnerabilities directly expose user funds; treat every finding with appropriate severity.

## Scope and Setup

- Identify wallet type(s) in scope: hardware, software (browser extension, mobile, desktop), or smart contract wallet (Safe, Argent, Kernel).
- Document the wallet's key derivation path (BIP-32/BIP-44 path, HD wallet structure).
- Confirm whether seed phrase or private key storage is in scope.
- Map all external integrations: RPC endpoints, dApp connectors (WalletConnect, MetaMask snap), signing APIs.

## Infinite Approval Detection

Token approvals that set `amount = type(uint256).max` (infinite) expose users to total loss if the approved contract is compromised.

### Detection

```bash
# Scan frontend code for infinite approvals
grep -rn "MaxUint256\|ethers.constants.MaxUint256\|2\*\*256\-1\|type(uint256).max\|UNLIMITED" src/ frontend/ lib/

# Check ERC-20 approve calls — are amounts exact?
grep -rn "\.approve\|approveMax\|increaseAllowance" src/ | grep -v "test"

# ERC-2612 permit() — check deadline and amount
grep -rn "permit\|signTypedData.*Permit" src/
```

### Assessment Criteria

- [ ] All approval amounts are exact (equal to the immediate transaction amount) unless explicitly user-configured.
- [ ] EIP-2612 `permit()` calls use short deadlines (≤1 hour) and exact amounts.
- [ ] Approval revocation UI is present and discoverable.
- [ ] `SafeERC20.safeApprove` or `forceApprove` used for tokens that require approval reset to zero first.
- [ ] Users are warned before approving unaudited contracts.

### Remediation

Replace infinite approvals with exact amounts:

```typescript
// Bad: infinite approval
await token.approve(spender, ethers.constants.MaxUint256);

// Good: exact amount
await token.approve(spender, amountNeeded);
```

## Entropy Assessment for Key Generation

Poor entropy during key generation is catastrophic and irreversible.

```bash
# Check RNG source in wallet codebase
grep -rn "Math.random\|Date.now\|new Date\|crypto.getRandomValues\|randomBytes\|getEntropy" src/

# Flag insecure RNG
grep -rn "Math.random()" src/ --include="*.ts" --include="*.js" --include="*.rs"

# Check mnemonic generation
grep -rn "generateMnemonic\|entropyToMnemonic\|mnemonicToSeed" src/
```

### Entropy Requirements

| Operation | Minimum Entropy | Acceptable Source |
|---|---|---|
| 12-word mnemonic | 128 bits | `crypto.getRandomValues` / OS CSPRNG |
| 24-word mnemonic | 256 bits | `crypto.getRandomValues` / OS CSPRNG |
| Private key | 256 bits | `crypto.randomBytes` (Node) / `OsRng` (Rust) |
| Nonce / salt | 96–128 bits | Same as above |

### Checklist

- [ ] `Math.random()` never used for cryptographic material.
- [ ] Entropy source is `window.crypto.getRandomValues` (browser), `crypto.randomBytes` (Node), or OS CSPRNG.
- [ ] Mnemonic generation uses BIP-39 compliant 128-bit or 256-bit entropy.
- [ ] Deterministic key derivation follows BIP-32/BIP-44/BIP-84 standards.
- [ ] No entropy reuse between wallets or sessions.

## Transaction Simulation Before Signing

Blind signing — approving a transaction without knowing its effects — is a leading cause of user fund loss.

### Simulation Assessment

```bash
# Check for simulation integration
grep -rn "simulate\|eth_call\|tenderly\|blowfish\|pocket_universe\|fire_extension" src/ manifest.json

# Check decoded calldata rendering
grep -rn "decodeFunction\|parseTransaction\|decodedInput\|4byte" src/
```

### Requirements

- [ ] Every transaction is simulated via `eth_call` or Tenderly/Alchemy simulation API before presenting to user.
- [ ] Simulation results show: token balance changes, NFT movements, approval grants.
- [ ] Simulation failures are surfaced as warnings, not silently ignored.
- [ ] ABI decoding is attempted for all calldata — unknown function selectors are flagged.
- [ ] EIP-712 structured data is decoded and displayed in human-readable form.
- [ ] `eth_signTypedData_v4` domains are validated against the connected chain and contract address.

## Type-Specific Audit Guidance

### Hardware Wallets (Ledger, Trezor, GridPlus Lattice)

- Verify the device firmware version and check against known vulnerability advisories.
- Confirm the companion app (Ledger Live, Trezor Suite) is from the official source — check code signing.
- Assess display: does the hardware device show the correct recipient address and amount? Test with a long address.
- Review USB/Bluetooth attack surface — test pairing and session hijacking.
- Check for supply chain tampering indicators (holographic seals, device serial verification).

### Software Wallets (Browser Extension, Mobile, Desktop)

```bash
# Check extension manifest for overly broad permissions
cat manifest.json | jq '.permissions, .host_permissions'

# Check content script injection scope
cat manifest.json | jq '.content_scripts[].matches'

# Scan for XSS in extension UI
grep -rn "innerHTML\|dangerouslySetInnerHTML\|eval(" src/
```

- [ ] Extension permissions are minimal — no `<all_urls>` unless required.
- [ ] Content scripts do not inject into sensitive pages (bank sites, other wallets).
- [ ] Seed phrase / private key never written to `localStorage` or `sessionStorage`.
- [ ] Seed phrase encrypted at rest with user-derived key (PBKDF2/scrypt/Argon2).
- [ ] Auto-lock timer implemented and enforced.
- [ ] Clipboard operations do not leave seed phrase/private key in clipboard.

### Smart Contract Wallets (Safe, Argent, Kernel, Biconomy)

```bash
# Check module and guard registry
grep -rn "enableModule\|addOwner\|changeThreshold\|setFallbackHandler" contracts/

# Check signature validation
grep -rn "isValidSignature\|checkSignatures\|_checkSignature" contracts/
```

- [ ] Module whitelisting: only audited modules enabled.
- [ ] Social recovery mechanism requires threshold approval — cannot be triggered by a single guardian.
- [ ] Delegate call targets in modules are restricted to known-safe contracts.
- [ ] Fallback handler is audited and does not expose arbitrary external calls.
- [ ] ERC-4337 paymaster validation correctly enforces sponsorship limits.

## Reference Module

```
src/blockchain_security/wallet.rs — WalletSecurityAssessor
```

## Output Checklist

- [ ] Wallet type and architecture documented
- [ ] Infinite approval patterns identified and remediation provided
- [ ] Entropy source audited and verified as CSPRNG
- [ ] Transaction simulation capability assessed
- [ ] Type-specific checklist completed
- [ ] All findings assigned CVSS scores
- [ ] Remediation guidance provided for every finding
