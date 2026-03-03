//! Zero-knowledge proof system security analysis.

use std::collections::HashSet;

/// ZK proof system classification.
#[derive(Debug, Clone, PartialEq)]
pub enum ZkSystem {
    Groth16,
    Plonk,
    Stark,
    Halo2,
    Nova,
    Marlin,
    Bulletproofs,
    Fflonk,
}

/// Vulnerability classes specific to ZK proof systems.
#[derive(Debug, Clone, PartialEq)]
pub enum ZkVulnerability {
    SoundnessError,
    CompletenessError,
    TrustedSetupCompromise,
    WitnessLeakage,
    CircuitUnderConstrained,
    FiatShamirWeakness,
    NullifierReuse,
    MissingRangeCheck,
}

/// Static metadata describing a ZK circuit.
#[derive(Debug, Clone)]
pub struct ZkCircuitInfo {
    pub system: ZkSystem,
    pub constraint_count: u64,
    pub input_count: u32,
    pub output_count: u32,
    pub has_trusted_setup: bool,
    pub setup_participants: u32,
}

/// Comprehensive ZK audit result.
#[derive(Debug, Clone)]
pub struct ZkAuditResult {
    pub system: ZkSystem,
    pub vulnerabilities: Vec<ZkVulnerability>,
    pub soundness_ok: bool,
    pub completeness_ok: bool,
    pub security_level_bits: u32,
    pub findings: Vec<String>,
}

/// Proof bytes alongside public inputs and a verification-key fingerprint.
#[derive(Debug, Clone)]
pub struct ProofData {
    pub proof_bytes: Vec<u8>,
    pub public_inputs: Vec<String>,
    pub verification_key_hash: String,
}

/// Analyse a ZK circuit and return an audit result.
pub fn analyze_zk_circuit(circuit_info: &ZkCircuitInfo) -> ZkAuditResult {
    let mut vulnerabilities = Vec::new();
    let mut findings = Vec::new();

    // Under-constrained circuit
    if circuit_info.constraint_count == 0 {
        vulnerabilities.push(ZkVulnerability::CircuitUnderConstrained);
        findings.push("Circuit has zero constraints; any witness satisfies the proof.".into());
    }

    // Weak trusted setup
    if circuit_info.has_trusted_setup && circuit_info.setup_participants < 10 {
        vulnerabilities.push(ZkVulnerability::TrustedSetupCompromise);
        findings.push(format!(
            "Trusted setup ceremony had only {} participant(s); a threshold of ≥10 is recommended.",
            circuit_info.setup_participants,
        ));
    }

    // System-specific checks
    match circuit_info.system {
        ZkSystem::Groth16 => {
            if circuit_info.has_trusted_setup {
                findings.push(
                    "Groth16 requires a per-circuit trusted setup; verify ceremony integrity."
                        .into(),
                );
            }
        }
        ZkSystem::Stark => {
            // STARKs are transparent – no trusted setup risk
        }
        ZkSystem::Halo2 => {
            if circuit_info.constraint_count > 0 && circuit_info.input_count == 0 {
                vulnerabilities.push(ZkVulnerability::MissingRangeCheck);
                findings
                    .push("Halo2 circuit has no public inputs; range checks may be absent.".into());
            }
        }
        ZkSystem::Bulletproofs => {
            if circuit_info.constraint_count > 1_000_000 {
                findings
                    .push("Bulletproofs verification is O(n); large circuits will be slow.".into());
            }
        }
        _ => {}
    }

    let security_level_bits = match circuit_info.system {
        ZkSystem::Groth16 | ZkSystem::Plonk | ZkSystem::Fflonk | ZkSystem::Marlin => 128,
        ZkSystem::Stark => 128,
        ZkSystem::Halo2 | ZkSystem::Nova => 128,
        ZkSystem::Bulletproofs => 128,
    };

    let soundness_ok = !vulnerabilities.contains(&ZkVulnerability::SoundnessError)
        && !vulnerabilities.contains(&ZkVulnerability::CircuitUnderConstrained);
    let completeness_ok = !vulnerabilities.contains(&ZkVulnerability::CompletenessError);

    ZkAuditResult {
        system: circuit_info.system.clone(),
        vulnerabilities,
        soundness_ok,
        completeness_ok,
        security_level_bits,
        findings,
    }
}

/// Return Ok(true) if the proof bytes are non-empty (basic structural check).
pub fn verify_proof(proof: &ProofData) -> anyhow::Result<bool> {
    Ok(!proof.proof_bytes.is_empty())
}

/// Return true if all nullifiers in the list are unique.
pub fn check_nullifier_uniqueness(nullifiers: &[String]) -> bool {
    let set: HashSet<&String> = nullifiers.iter().collect();
    set.len() == nullifiers.len()
}

/// Return a human-readable assessment of a trusted setup's security.
pub fn assess_trusted_setup(participants: u32, is_mpc: bool) -> String {
    if !is_mpc {
        return "Single-party trusted setup: the operator knows the toxic waste. Do not use in production.".into();
    }
    if participants == 0 {
        return "No participants recorded; setup integrity cannot be verified.".into();
    }
    if participants < 10 {
        format!(
            "MPC setup with {} participant(s) is weak; at least one participant must be honest. Recommend ≥10.",
            participants,
        )
    } else if participants < 50 {
        format!(
            "MPC setup with {} participant(s) is acceptable; consider a larger ceremony for higher assurance.",
            participants,
        )
    } else {
        format!(
            "MPC setup with {} participant(s) provides strong security guarantees.",
            participants,
        )
    }
}
