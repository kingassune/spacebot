---
name: zk-audit
description: "Zero-knowledge proof system audit covering trusted setup ceremony validation, under-constrained circuits and soundness issues, nullifier uniqueness enforcement, and system-specific vulnerabilities for Groth16, PLONK, STARK, Halo2, and Bulletproofs."
allowed-tools: ["shell", "file", "exec"]
---

# Zero-Knowledge Proof System Audit

You are auditing a zero-knowledge proof system within an authorized engagement. ZK vulnerabilities can break soundness (accept false proofs) or zero-knowledge (leak private inputs) — both are critical severity.

## Pre-Audit Setup

- Identify ZK proving system: Groth16, PLONK, FFLONK, Marlin, STARK, Halo2, Bulletproofs, Nova, or custom.
- Document all circuits in scope: file names, language (Circom, Halo2, Noir, Cairo, Leo, zkASM).
- Identify the trusted setup parameters (if required) and ceremony records.
- Map public inputs vs. private inputs (witnesses) for each circuit.
- Confirm on-chain verifier contract addresses and their deployment hashes.

## Trusted Setup Weaknesses

### Ceremony Validation (Groth16, PLONK/FFLONK, Marlin)

Trusted setups require "toxic waste" to be destroyed. If any participant retains toxic waste, they can generate fake proofs.

```bash
# Download ceremony transcript and verify
b2sum ptau/hermez_final.ptau

# Verify against known-good hashes (Powers of Tau)
# https://github.com/iden3/snarkjs#powers-of-tau

# Verify circuit-specific contribution
snarkjs powersoftau verify ptau/hermez_final.ptau
snarkjs zkey verify circuit.r1cs ptau/hermez_final.ptau circuit_final.zkey
```

**Checklist:**

- [ ] Powers of Tau file hash matches publicly documented ceremony transcript.
- [ ] Circuit-specific `zkey` was generated from the verified PTAU file.
- [ ] Phase 2 ceremony had ≥1 honest participant (verifiable from transcript).
- [ ] `zkey export verificationkey` output matches deployed verifier contract's embedded key.
- [ ] No single entity performed all ceremony contributions.

### Verifier Contract Key Matching

```bash
# Extract embedded verification key from deployed contract
cast call $VERIFIER_ADDRESS "verifyingKey()(uint256[2],uint256[2][2],uint256[2])" --rpc-url $RPC_URL

# Compare against snarkjs exported key
snarkjs zkey export verificationkey circuit_final.zkey verification_key.json
```

## Under-Constrained Circuits

Under-constrained circuits are the most common ZK vulnerability — a signal that has no constraint can take any value, allowing a malicious prover to produce valid proofs for false statements.

### Circom Specific

```bash
# Run symbolic analysis
circom circuit.circom --r1cs --wasm --sym

# Use circomspect for constraint analysis
circomspect circuit.circom

# Check constraint count vs signal count
snarkjs r1cs info circuit.r1cs
# Constraints must equal or exceed (signals - public inputs - outputs - 1)
```

**Common under-constrained patterns:**

| Pattern | Vulnerability |
|---|---|
| `signal output x;` with no `<==` | Unconstrained output — prover sets freely |
| `component.in <-- expr;` without `<== ` | Assignment without constraint |
| Range check missing on user input | Bit decomposition bypass |
| `IsZero` result not constrained | Prover can claim any value is zero |
| Selector in multiplexer not boolean-checked | Selector can be non-binary |

### Halo2 Specific

```bash
# Look for cells that are assigned but never constrained
grep -rn "assign_advice\|assign_fixed" src/ | grep -v "create_gate\|lookup"

# Verify lookup arguments cover the full input range
grep -rn "lookup\|range_check\|TableColumn" src/
```

### Soundness Issues

- **Honest-verifier zero knowledge only:** Some systems are only ZK against honest verifiers — verify the protocol uses non-interactive ZK (Fiat-Shamir).
- **Weak Fiat-Shamir:** Hash function used in transcript must include all prior messages; missing any element enables grinding attacks.
- **Malleability:** Can a valid proof be transformed into another valid proof for a different statement?

## Nullifier Uniqueness Enforcement

Nullifiers prevent double-spending in ZK applications (Tornado Cash, Zcash, Aztec).

### Assessment

```bash
# Find nullifier storage on-chain
grep -rn "nullifierHash\|_nullifiers\|usedNullifiers\|spent" contracts/

# Verify nullifier is checked before state change
grep -B5 -A10 "nullifier" contracts/ | grep -n "require\|revert\|mapping"

# Check nullifier hash preimage binding
grep -rn "nullifier.*=.*hash\|Poseidon\|MiMC\|pedersen" circuits/ contracts/
```

**Checklist:**

- [ ] Nullifier hashes stored in a contract-level mapping.
- [ ] Nullifier check occurs before any state change (checks-effects pattern).
- [ ] Nullifier is deterministically derived from the secret note: `nullifier = H(secret, path_index)`.
- [ ] Nullifier binding: same secret cannot produce two different nullifiers.
- [ ] Circuit enforces that the nullifier matches the commitment in the Merkle tree.

## System-Specific Vulnerabilities

### Groth16

- **Non-subgroup points:** Verify that the verifier checks points are on the correct subgroup (or uses a pairing that implicitly checks). Missing subgroup checks allow forgery.
- **Malleable proofs:** Groth16 proofs can be randomized; if the protocol requires proof uniqueness, this is a vulnerability.
- **Trusted setup dependency:** All of the above ceremony checks apply. There is no transparent variant.

```bash
# Check subgroup membership validation in verifier
grep -n "isOnCurve\|checkOnCurve\|isInSubgroup\|subgroupCheck" contracts/
```

### PLONK / FFLONK

- **Fiat-Shamir transcript completeness:** Verify all polynomials and commitments are hashed into the transcript before being used as challenges.
- **KZG commitment scheme:** Verify SRS (Structured Reference String) matches the ceremony output.
- **Custom gates:** Each custom gate constraint must be verified to correctly encode the intended computation.

### STARKs (StarkEx, StarkNet Cairo)

- **FRI soundness:** Verify the FRI folding parameter `ρ` (rate) provides adequate soundness bits (≥80 for ZK rollups, ≥128 for financial applications).
- **Grinding resistance:** Check that the proof-of-work nonce in Fiat-Shamir is enforced on-chain.
- **Cairo integer overflow:** Cairo's `felt` type is modular arithmetic over a prime field — verify range checks for values that represent real-world quantities.

```bash
# Check range checks in Cairo contracts
grep -rn "assert_nn\|assert_le\|assert_in_range\|is_nn" contracts/ src/
```

### Halo2

- **Lookup argument completeness:** Ensure all witness values that must be range-checked are included in lookup tables.
- **Permutation argument:** Verify that copy constraints correctly link cells that must share a value.
- **Circuit floor planner:** Confirm region assignments don't create accidental unconstrained cells.

### Bulletproofs

- **Range proof soundness:** Verify the range bound (e.g., 0 to 2⁶⁴) is enforced by the verifier.
- **Inner product argument:** Check that the verifier regenerates the vector commitment and does not accept a prover-supplied value.
- **No trusted setup — but:** Verify the group generator is a nothing-up-my-sleeve point (hash-to-curve from a public string).

## Reference Module

```
src/blockchain_security/zk.rs — ZkAuditor
```

## Output Checklist

- [ ] ZK system type identified and ceremony validation performed
- [ ] Under-constrained signals identified via static analysis
- [ ] Nullifier uniqueness enforcement verified on-chain
- [ ] System-specific vulnerability class reviewed
- [ ] Fiat-Shamir transcript completeness verified
- [ ] Verifier contract deployment hash matches expected key
- [ ] All findings assigned CVSS scores
- [ ] Remediation guidance specific to the ZK system provided
