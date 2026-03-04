//! Red team simulation framework for authorized security assessments.
//!
//! Provides structured methodologies for authorized penetration testing
//! and adversary emulation exercises. All operations are strictly
//! simulation-only and must only be used within a documented, authorised
//! engagement scope.

pub mod adversary_profiles;
pub mod apt_emulation;
pub mod c2;
pub mod campaign;
pub mod evasion;
pub mod exfiltration;
pub mod exploitation;
pub mod kill_chain;
pub mod lateral_movement;
pub mod nation_state;
pub mod persistence;
pub mod recon;
pub mod supply_chain;

pub use adversary_profiles::{
    AdversaryProfile, CampaignPhases, MitreTechnique, all_profiles, find_profile,
};
pub use campaign::{Campaign, CampaignPhase, CampaignResult, RulesOfEngagement};
pub use nation_state::{
    C2InfrastructureType, EmulationSummary, EvasionTechnique, NationStateEmulator,
};

use crate::red_team::{
    apt_emulation::{AptGroup, AptProfile, EmulationResult, EngagementScope},
    c2::{C2Config, C2Session},
    exfiltration::{ExfilConfig, ExfilResult},
    exploitation::{ExploitConfig, ExploitResult},
    lateral_movement::{LateralMovementConfig, LateralMovementResult},
    persistence::{PersistenceConfig, PersistenceResult},
    recon::{ReconConfig, ReconResult},
};

/// Orchestrates all red team simulation modules for an authorized engagement.
#[derive(Debug, Clone)]
pub struct RedTeamEngine {
    pub engagement_id: String,
    pub operator: String,
}

impl RedTeamEngine {
    /// Creates a new engine instance for an authorized engagement.
    pub fn new(engagement_id: impl Into<String>, operator: impl Into<String>) -> Self {
        Self {
            engagement_id: engagement_id.into(),
            operator: operator.into(),
        }
    }

    /// Runs reconnaissance against the target defined in `config`.
    pub async fn run_recon(&self, config: &ReconConfig) -> anyhow::Result<ReconResult> {
        recon::run_recon(config).await
    }

    /// Simulates exploitation of a vulnerability.
    pub async fn exploit(&self, config: &ExploitConfig) -> anyhow::Result<ExploitResult> {
        exploitation::exploit_vulnerability(config).await
    }

    /// Simulates lateral movement through the target network.
    pub async fn lateral_move(
        &self,
        config: &LateralMovementConfig,
    ) -> anyhow::Result<LateralMovementResult> {
        lateral_movement::execute_lateral_movement(config).await
    }

    /// Simulates establishing persistence on a host.
    pub async fn establish_persistence(
        &self,
        config: &PersistenceConfig,
    ) -> anyhow::Result<PersistenceResult> {
        persistence::establish_persistence(config).await
    }

    /// Simulates data exfiltration.
    pub async fn exfiltrate(
        &self,
        config: &ExfilConfig,
        data: &[u8],
    ) -> anyhow::Result<ExfilResult> {
        exfiltration::stage_exfiltration(config, data).await
    }

    /// Initialises the C2 listener.
    pub async fn init_c2(&self, config: &C2Config) -> anyhow::Result<()> {
        c2::initialize_c2(config).await
    }

    /// Lists active C2 sessions.
    pub async fn list_c2_sessions(&self, config: &C2Config) -> anyhow::Result<Vec<C2Session>> {
        c2::list_sessions(config).await
    }

    /// Loads a threat actor profile and emulates their TTPs.
    pub async fn emulate_apt(
        &self,
        group: &AptGroup,
        scope: &EngagementScope,
    ) -> anyhow::Result<EmulationResult> {
        let profile: AptProfile = apt_emulation::load_apt_profile(group);
        apt_emulation::emulate_apt(group, &profile, scope).await
    }

    /// Plan and simulate a Cyber Kill Chain execution.
    pub fn plan_kill_chain(
        &self,
        config: &kill_chain::KillChainConfig,
    ) -> kill_chain::KillChainExecution {
        kill_chain::plan_kill_chain(config)
    }

    /// Select an evasion technique chain and test it against the defender stack.
    pub fn test_evasion(&self, config: &evasion::EvasionConfig) -> evasion::EvasionResult {
        let chain = evasion::select_evasion_chain(config);
        evasion::test_evasion(&chain, config)
    }

    /// Assess supply chain risk for a target organization.
    pub fn assess_supply_chain(
        &self,
        config: &supply_chain::SupplyChainConfig,
    ) -> supply_chain::SupplyChainResult {
        supply_chain::assess_supply_chain_risk(config)
    }
}
