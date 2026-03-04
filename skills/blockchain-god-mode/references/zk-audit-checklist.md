# ZK Circuit Security Checklist

A comprehensive checklist for auditing zero-knowledge proof systems and circuits,
covering Groth16, PLONK, Halo2, STARKs, and general ZK protocol security.

---

## 1. Circuit Constraint Completeness

### Under-Constrained Inputs
**Risk:** Signals that are not fully constrained allow multiple valid witnesses for
the same public input, potentially enabling proof forgery.

- [ ] Every private input signal has at least one constraint that binds it
- [ ] Every intermediate signal is properly constrained
- [ ] The number of constraints is proportional to the computation complexity
- [ ] Run automated tools to detect under-constrained signals (e.g., `circomspect`)

**Detection:**
```bash
# Circom: check for unconstrained signals
circomspect circuit.circom
```

### Missing Range Checks
**Risk:** Without explicit range constraints, a prover may provide out-of-bounds
values that satisfy the arithmetic constraint but violate semantic correctness.

- [ ] All integer inputs are range-checked to their expected bit width
- [ ] Comparison operations use proper bit-decomposition gadgets
- [ ] Range checks are applied to all user-supplied signals

---

## 2. Trusted Setup Security (Groth16, PLONK with KZG)

### Ceremony Participants
- [ ] Minimum 10+ independent participants (more is better)
- [ ] Participants represent diverse jurisdictions and organisations
- [ ] Ceremony transcript is publicly verifiable
- [ ] Transcript is stored on a permanent, immutable medium (e.g., IPFS/Filecoin)
- [ ] Powers of tau are appropriate for the circuit size

### Toxic Waste Destruction
- [ ] Participants attest to deleting their randomness after contribution
- [ ] Hardware destruction or air-gapped machines used for key generation
- [ ] At least one participant is provably honest for soundness

### Universal vs. Per-Circuit Setup
- [ ] Groth16: per-circuit trusted setup (higher risk if circuit changes)
- [ ] PLONK/Marlin: universal setup (shared across circuits — better)
- [ ] STARKs: no trusted setup (preferred when performance allows)
- [ ] Halo2: no trusted setup required

---

## 3. Soundness Properties

### Fiat-Shamir Transform (for non-interactive proofs)
**Risk:** If the hash function used in the Fiat-Shamir transform is weak, malleable,
or insufficiently binding, the non-interactive proof may be forgeable.

- [ ] Use a collision-resistant hash function (SHA-256, Poseidon, Keccak)
- [ ] Include all public inputs and circuit commitments in the transcript
- [ ] Verify that the Fiat-Shamir heuristic is applied correctly per the protocol spec

### Malleability
- [ ] Proofs are not malleable (attackers cannot modify a valid proof to another valid proof)
- [ ] Public input is validated on-chain before proof verification
- [ ] Verifier checks the proof against the correct verification key

---

## 4. Nullifier Security (Privacy Protocols)

### Nullifier Uniqueness
**Risk:** Allowing a nullifier to be used more than once enables double-spending.

- [ ] Nullifiers are stored in an on-chain or committed set
- [ ] Double-spend check is performed before accepting a proof
- [ ] Nullifier hash function is collision-resistant

### Nullifier Linkability
**Risk:** If nullifier construction reveals the user's identity or links transactions,
it defeats the privacy guarantee.

- [ ] Nullifier is derived deterministically from private inputs only
- [ ] Nullifier does not leak sender identity to chain observers

---

## 5. Verification Key Integrity

- [ ] Verification key is derived from the correct circuit
- [ ] Verification key is committed on-chain and cannot be silently changed
- [ ] Contract upgrade cannot replace the verification key without a timelock/multisig
- [ ] Verification key matches the published ceremony output

---

## 6. On-Chain Verifier Security

- [ ] Verifier contract is generated from the canonical circuit (not hand-written)
- [ ] Verifier rejects proofs with `pairing check failed`; does not silently pass
- [ ] Verifier input validation: public inputs are length-checked
- [ ] Gas limit attack: verifier cannot be griefed by malformed input causing OOG
- [ ] Reentrancy: verifier state updates happen before external calls

---

## 7. ZK Protocol-Specific Checks

### Groth16
- [ ] Per-circuit toxic waste ceremony completed
- [ ] `α`, `β`, `γ`, `δ` parameters are from the ceremony (not test vectors)
- [ ] Circuit has not changed since the ceremony

### PLONK / Turbo-PLONK
- [ ] Universal SRS (structured reference string) is from a reputable ceremony
- [ ] Custom gates are correctly constrained
- [ ] Lookup arguments (Plookup) tables are properly bounded

### Halo2
- [ ] Permutation arguments correctly bind column relationships
- [ ] Region layout does not leave unconstrained cells
- [ ] Lookup tables have correct membership proofs

### STARKs (Polygon zkEVM, StarkNet Cairo)
- [ ] FRI protocol parameters (blowup factor, query count) meet security target
- [ ] Merkle tree implementation is collision-resistant
- [ ] Cairo programs correctly encode the intended computation

### Circom Circuits
- [ ] All `signal input` variables are constrained
- [ ] Template instantiation does not share signals across independent uses
- [ ] `<--` (assignment) always accompanied by `===` (constraint)

---

## 8. Integration Security

- [ ] On-chain contract validates all public inputs before calling `verifyProof`
- [ ] Proof submission is replay-protected (include nullifier or commitment)
- [ ] Contract does not trust the prover-supplied verification key
- [ ] Circuit ID is committed to prevent proof reuse across circuits

---

## Recommended Tools

| Tool | Purpose |
|------|---------|
| `circomspect` | Static analysis for Circom circuits |
| `halo2-analyzer` | Detect under-constrained cells in Halo2 |
| `ecne` | Formal under-constraint detection for R1CS |
| `picus` | Symbolic analysis for Circom |
| `snarkjs` | Groth16 and PLONK proof generation and verification |
| `powersoftau` | Verify trusted setup ceremony transcripts |
