//! Integration and orchestration layer for cross-engine security workflows.

pub mod campaign;
pub mod deconfliction;
pub mod pipeline;
pub mod purple_team;

pub use campaign::{Campaign, CampaignConfig, CampaignPhase, CampaignResult, CampaignState};
pub use deconfliction::{Deconfliction, DeconflictionConfig};
pub use pipeline::{PipelineConfig, PipelineResult, SecurityPipeline};
pub use purple_team::{PurpleTeamConfig, PurpleTeamResult, PurpleTeamRunner};

/// Top-level orchestrator that wires all security engines together.
#[derive(Debug, Clone)]
pub struct JamesOrchestrator {
    pub engagement_id: String,
    pub operator: String,
}

impl JamesOrchestrator {
    pub fn new(engagement_id: impl Into<String>, operator: impl Into<String>) -> Self {
        Self {
            engagement_id: engagement_id.into(),
            operator: operator.into(),
        }
    }

    /// Run a full end-to-end security pipeline engagement.
    pub async fn run_pipeline(&self, config: &PipelineConfig) -> anyhow::Result<PipelineResult> {
        let pipeline = SecurityPipeline::new(self.engagement_id.clone());
        pipeline.run_full_engagement(config).await
    }

    /// Run a purple team assessment.
    pub async fn run_purple_team(
        &self,
        config: &PurpleTeamConfig,
    ) -> anyhow::Result<PurpleTeamResult> {
        let runner = PurpleTeamRunner::new(self.engagement_id.clone());
        runner.run(config).await
    }

    /// Start a multi-phase adversary campaign.
    pub fn start_campaign(&self, config: CampaignConfig) -> Campaign {
        Campaign::new(config)
    }
}
