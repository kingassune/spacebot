//! Consensus mechanism security analysis framework.

/// Consensus algorithm classification.
#[derive(Debug, Clone, PartialEq)]
pub enum ConsensusType {
    ProofOfWork,
    ProofOfStake,
    DelegatedPoS,
    Bft,
    Pbft,
    Tendermint,
    HotStuff,
    Nakamoto,
    Avalanche,
    HybridPoW,
}

/// Known attack vectors against consensus protocols.
#[derive(Debug, Clone, PartialEq)]
pub enum ConsensusAttack {
    LongRangeAttack,
    NothingAtStake,
    GrindingAttack,
    SelfishMining,
    EclipseAttack,
    SybilAttack,
    ValidatorBribery,
    TimeBanditAttack,
    FinalityDelay,
    ValidatorSlashing,
}

/// On-chain metadata for a single validator.
#[derive(Debug, Clone)]
pub struct ValidatorInfo {
    pub address: String,
    pub stake_amount: u64,
    pub uptime_percent: f64,
    pub slashing_history: Vec<String>,
}

/// Aggregated consensus-layer security analysis.
#[derive(Debug, Clone)]
pub struct ConsensusAnalysis {
    pub consensus_type: ConsensusType,
    pub total_validators: u32,
    pub total_stake: u64,
    pub finality_time_secs: u64,
    pub attack_threshold_percent: f64,
    pub vulnerabilities: Vec<ConsensusAttack>,
}

/// Finality model and safe confirmation parameters.
#[derive(Debug, Clone)]
pub struct FinalityAnalysis {
    pub is_probabilistic: bool,
    pub finality_blocks: u32,
    pub reorg_risk: String,
    pub safe_confirmation_blocks: u32,
}

/// Analyse a consensus mechanism and enumerate relevant vulnerabilities.
pub fn analyze_consensus(
    consensus_type: &ConsensusType,
    validator_count: u32,
) -> ConsensusAnalysis {
    let (finality_time_secs, vulnerabilities): (u64, Vec<ConsensusAttack>) = match consensus_type {
        ConsensusType::ProofOfWork | ConsensusType::Nakamoto => (
            3600,
            vec![
                ConsensusAttack::SelfishMining,
                ConsensusAttack::EclipseAttack,
                ConsensusAttack::SybilAttack,
                ConsensusAttack::TimeBanditAttack,
            ],
        ),
        ConsensusType::ProofOfStake => (
            64,
            vec![
                ConsensusAttack::LongRangeAttack,
                ConsensusAttack::NothingAtStake,
                ConsensusAttack::ValidatorBribery,
                ConsensusAttack::GrindingAttack,
            ],
        ),
        ConsensusType::DelegatedPoS => (
            3,
            vec![
                ConsensusAttack::ValidatorBribery,
                ConsensusAttack::SybilAttack,
                ConsensusAttack::FinalityDelay,
            ],
        ),
        ConsensusType::Bft | ConsensusType::Pbft => (
            2,
            vec![
                ConsensusAttack::ValidatorBribery,
                ConsensusAttack::FinalityDelay,
                ConsensusAttack::ValidatorSlashing,
            ],
        ),
        ConsensusType::Tendermint | ConsensusType::HotStuff => (
            6,
            vec![
                ConsensusAttack::FinalityDelay,
                ConsensusAttack::ValidatorSlashing,
                ConsensusAttack::ValidatorBribery,
            ],
        ),
        ConsensusType::Avalanche => (
            1,
            vec![ConsensusAttack::SybilAttack, ConsensusAttack::EclipseAttack],
        ),
        ConsensusType::HybridPoW => (
            1800,
            vec![
                ConsensusAttack::SelfishMining,
                ConsensusAttack::NothingAtStake,
                ConsensusAttack::TimeBanditAttack,
            ],
        ),
    };

    ConsensusAnalysis {
        consensus_type: consensus_type.clone(),
        total_validators: validator_count,
        total_stake: 0,
        finality_time_secs,
        attack_threshold_percent: calculate_attack_threshold(consensus_type),
        vulnerabilities,
    }
}

/// Return the finality model and safe-confirmation parameters for a consensus type.
pub fn assess_finality(consensus_type: &ConsensusType) -> FinalityAnalysis {
    match consensus_type {
        ConsensusType::ProofOfWork | ConsensusType::Nakamoto => FinalityAnalysis {
            is_probabilistic: true,
            finality_blocks: 6,
            reorg_risk: "High – reorgs possible up to ~6 blocks under 51 % attack.".into(),
            safe_confirmation_blocks: 12,
        },
        ConsensusType::ProofOfStake => FinalityAnalysis {
            is_probabilistic: false,
            finality_blocks: 2,
            reorg_risk: "Low – single-slot finality (ETH Casper) after 2 epochs.".into(),
            safe_confirmation_blocks: 3,
        },
        ConsensusType::DelegatedPoS => FinalityAnalysis {
            is_probabilistic: false,
            finality_blocks: 1,
            reorg_risk: "Medium – depends on delegate set honesty.".into(),
            safe_confirmation_blocks: 3,
        },
        ConsensusType::Bft
        | ConsensusType::Pbft
        | ConsensusType::Tendermint
        | ConsensusType::HotStuff => FinalityAnalysis {
            is_probabilistic: false,
            finality_blocks: 1,
            reorg_risk: "Very low – instant finality; no reorgs after commit.".into(),
            safe_confirmation_blocks: 1,
        },
        ConsensusType::Avalanche => FinalityAnalysis {
            is_probabilistic: false,
            finality_blocks: 1,
            reorg_risk: "Low – probabilistic finality converges in <2 s.".into(),
            safe_confirmation_blocks: 2,
        },
        ConsensusType::HybridPoW => FinalityAnalysis {
            is_probabilistic: true,
            finality_blocks: 6,
            reorg_risk: "Medium – PoW component introduces probabilistic finality.".into(),
            safe_confirmation_blocks: 10,
        },
    }
}

/// Assess the security posture of a validator set and return a risk summary.
pub fn assess_validator_security(validators: &[ValidatorInfo]) -> String {
    if validators.is_empty() {
        return "No validator data available.".into();
    }

    let avg_uptime =
        validators.iter().map(|v| v.uptime_percent).sum::<f64>() / validators.len() as f64;
    let slashed_count = validators
        .iter()
        .filter(|v| !v.slashing_history.is_empty())
        .count();

    let risk = if avg_uptime < 90.0 || slashed_count > validators.len() / 4 {
        "HIGH"
    } else if avg_uptime < 97.0 || slashed_count > 0 {
        "MEDIUM"
    } else {
        "LOW"
    };

    format!(
        "Validator security risk: {} | Avg uptime: {:.1}% | Slashed validators: {}/{}",
        risk,
        avg_uptime,
        slashed_count,
        validators.len(),
    )
}

/// Return the percentage of stake (or hash power) an attacker needs to compromise finality.
pub fn calculate_attack_threshold(consensus_type: &ConsensusType) -> f64 {
    match consensus_type {
        ConsensusType::ProofOfWork | ConsensusType::Nakamoto | ConsensusType::HybridPoW => 51.0,
        ConsensusType::ProofOfStake | ConsensusType::DelegatedPoS => 33.4,
        ConsensusType::Bft
        | ConsensusType::Pbft
        | ConsensusType::Tendermint
        | ConsensusType::HotStuff => 33.4,
        ConsensusType::Avalanche => 51.0,
    }
}
