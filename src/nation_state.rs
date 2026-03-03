//! Nation-state adversary emulation and campaign simulation framework.
//!
//! Provides structured methodologies for authorised nation-state threat emulation,
//! infrastructure modelling, operational tradecraft, supply chain attack simulation,
//! cyber-physical impact assessment, and influence operations research.
//!
//! All modules are strictly simulation-only and must only be used within a
//! documented, authorised engagement scope.

pub mod campaign;
pub mod cyber_physical;
pub mod influence_ops;
pub mod infrastructure;
pub mod supply_chain;
pub mod tradecraft;

use campaign::{CampaignObjective, CampaignStatus, NationStateCampaign};
use infrastructure::AttackInfrastructure;
use tradecraft::{OpsecLevel, Tradecraft};

/// Top-level engine that orchestrates all nation-state simulation submodules.
#[derive(Debug, Clone)]
pub struct NationStateEngine {
    /// Active campaigns managed by this engine.
    pub campaigns: Vec<NationStateCampaign>,
    /// Attack infrastructure managed by this engine.
    pub infrastructure: Vec<AttackInfrastructure>,
    /// Default tradecraft configuration.
    pub tradecraft: Tradecraft,
}

impl NationStateEngine {
    /// Create a new engine with default Maximum opsec tradecraft.
    pub fn new() -> Self {
        Self {
            campaigns: Vec::new(),
            infrastructure: Vec::new(),
            tradecraft: Tradecraft::new(OpsecLevel::Maximum),
        }
    }

    /// Create and register a new nation-state campaign.
    pub fn create_campaign(
        &mut self,
        apt_group: impl Into<String>,
        objectives: Vec<CampaignObjective>,
        duration_days: u64,
    ) -> &NationStateCampaign {
        let id = format!("campaign-{}", uuid::Uuid::new_v4());
        let mut campaign = NationStateCampaign::new(id, apt_group, objectives, duration_days);
        campaign.plan_campaign();
        self.campaigns.push(campaign);
        self.campaigns.last().unwrap()
    }

    /// Register an infrastructure set with the engine.
    pub fn add_infrastructure(&mut self, infra: AttackInfrastructure) {
        self.infrastructure.push(infra);
    }

    /// Return the count of active campaigns.
    pub fn active_campaign_count(&self) -> usize {
        self.campaigns
            .iter()
            .filter(|c| c.status == CampaignStatus::Active)
            .count()
    }

    /// Summarise all campaigns managed by this engine.
    pub fn summarize(&self) -> String {
        let total = self.campaigns.len();
        let active = self.active_campaign_count();
        let attribution_risk = self.tradecraft.assess_attribution_risk();

        format!(
            "NationStateEngine: {total} campaigns ({active} active), \
             {} infrastructure sets, attribution risk: {:.1}%",
            self.infrastructure.len(),
            attribution_risk * 100.0
        )
    }
}

impl Default for NationStateEngine {
    fn default() -> Self {
        Self::new()
    }
}
