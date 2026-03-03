//! Nation-state campaign lifecycle management.

use chrono::{DateTime, Utc};

/// Objective of a nation-state campaign.
#[derive(Debug, Clone, PartialEq)]
pub enum CampaignObjective {
    /// Espionage — steal intelligence and secrets.
    Espionage,
    /// Sabotage — disrupt or destroy target capabilities.
    Sabotage,
    /// Influence — shape opinion, policy, or behaviour.
    Influence,
    /// Financial theft — steal money or cryptocurrency.
    FinancialTheft,
    /// Intellectual property theft.
    IntellectualPropertyTheft,
    /// Disruption of critical infrastructure.
    InfrastructureDisruption,
}

/// Phase of a nation-state campaign following the MITRE ATT&CK lifecycle.
#[derive(Debug, Clone, PartialEq)]
pub enum CampaignPhase {
    /// Passive and active intelligence gathering.
    Reconnaissance,
    /// Gaining a foothold in the target environment.
    InitialAccess,
    /// Establishing persistent, stealthy presence.
    Establishment,
    /// Mapping the internal network and systems.
    InternalRecon,
    /// Moving across systems within the target environment.
    LateralMovement,
    /// Identifying and staging data for exfiltration.
    Collection,
    /// Moving data out of the target environment.
    Exfiltration,
    /// Executing destructive or disruptive objectives.
    ImpactOps,
}

/// Operational status of a campaign.
#[derive(Debug, Clone, PartialEq)]
pub enum CampaignStatus {
    /// Campaign is being planned, not yet active.
    Planning,
    /// Campaign is actively running.
    Active,
    /// Campaign is temporarily paused.
    Paused,
    /// Campaign has achieved its objectives and concluded.
    Completed,
    /// Campaign has been detected and infrastructure burned.
    Burned,
}

/// A nation-state adversary campaign with full lifecycle management.
#[derive(Debug, Clone)]
pub struct NationStateCampaign {
    /// Unique identifier for this campaign.
    pub campaign_id: String,
    /// APT group or threat actor name.
    pub apt_group: String,
    /// Strategic objectives for this campaign.
    pub objectives: Vec<CampaignObjective>,
    /// Ordered phases the campaign will execute.
    pub phases: Vec<CampaignPhase>,
    /// Planned duration in days.
    pub duration_days: u64,
    /// Current operational status.
    pub status: CampaignStatus,
    /// Timestamp when the campaign was created.
    pub created_at: DateTime<Utc>,
}

impl NationStateCampaign {
    /// Create a new campaign in the Planning status.
    pub fn new(
        campaign_id: impl Into<String>,
        apt_group: impl Into<String>,
        objectives: Vec<CampaignObjective>,
        duration_days: u64,
    ) -> Self {
        Self {
            campaign_id: campaign_id.into(),
            apt_group: apt_group.into(),
            objectives,
            phases: Vec::new(),
            duration_days,
            status: CampaignStatus::Planning,
            created_at: Utc::now(),
        }
    }

    /// Plan the campaign by selecting appropriate phases for its objectives.
    pub fn plan_campaign(&mut self) {
        self.phases = plan_phases_for_objectives(&self.objectives);
        self.status = CampaignStatus::Planning;
    }

    /// Advance the campaign to the next phase.
    ///
    /// Returns `Some(&CampaignPhase)` for the new current phase, or `None` if
    /// the campaign has completed all phases.
    pub fn advance_phase(&mut self) -> Option<&CampaignPhase> {
        if self.status == CampaignStatus::Planning {
            self.status = CampaignStatus::Active;
        }
        self.phases.first()
    }

    /// Estimate the current risk of operational detection (0.0–1.0).
    ///
    /// Higher scores indicate greater likelihood of detection.
    pub fn assess_detection_risk(&self) -> f64 {
        let base_risk: f64 = match self.status {
            CampaignStatus::Planning => 0.05,
            CampaignStatus::Active => 0.35,
            CampaignStatus::Paused => 0.15,
            CampaignStatus::Completed => 0.20,
            CampaignStatus::Burned => 1.0,
        };

        if self.phases.is_empty() {
            return base_risk;
        }

        let phase_modifier: f64 =
            self.phases.iter().map(phase_detection_risk).sum::<f64>() / self.phases.len() as f64;

        (base_risk + phase_modifier * 0.4).min(1.0)
    }

    /// Generate a human-readable campaign report.
    pub fn generate_campaign_report(&self) -> String {
        let objective_list: Vec<String> =
            self.objectives.iter().map(|o| format!("{o:?}")).collect();
        let phase_list: Vec<String> = self.phases.iter().map(|p| format!("{p:?}")).collect();

        format!(
            "=== Nation-State Campaign Report ===\n\
             ID:           {}\n\
             APT Group:    {}\n\
             Status:       {:?}\n\
             Duration:     {} days\n\
             Objectives:   {}\n\
             Phases:       {}\n\
             Detection Risk: {:.1}%\n\
             Created:      {}",
            self.campaign_id,
            self.apt_group,
            self.status,
            self.duration_days,
            objective_list.join(", "),
            phase_list.join(" → "),
            self.assess_detection_risk() * 100.0,
            self.created_at.format("%Y-%m-%d %H:%M:%S UTC"),
        )
    }
}

/// Select campaign phases appropriate for the given objectives.
fn plan_phases_for_objectives(objectives: &[CampaignObjective]) -> Vec<CampaignPhase> {
    let mut phases = vec![
        CampaignPhase::Reconnaissance,
        CampaignPhase::InitialAccess,
        CampaignPhase::Establishment,
        CampaignPhase::InternalRecon,
    ];

    let needs_lateral = objectives.iter().any(|o| {
        matches!(
            o,
            CampaignObjective::Espionage
                | CampaignObjective::FinancialTheft
                | CampaignObjective::IntellectualPropertyTheft
        )
    });

    if needs_lateral {
        phases.push(CampaignPhase::LateralMovement);
        phases.push(CampaignPhase::Collection);
        phases.push(CampaignPhase::Exfiltration);
    }

    let needs_impact = objectives.iter().any(|o| {
        matches!(
            o,
            CampaignObjective::Sabotage | CampaignObjective::InfrastructureDisruption
        )
    });

    if needs_impact {
        phases.push(CampaignPhase::ImpactOps);
    }

    phases
}

/// Estimate detection risk contribution for a single campaign phase.
fn phase_detection_risk(phase: &CampaignPhase) -> f64 {
    match phase {
        CampaignPhase::Reconnaissance => 0.10,
        CampaignPhase::InitialAccess => 0.40,
        CampaignPhase::Establishment => 0.30,
        CampaignPhase::InternalRecon => 0.25,
        CampaignPhase::LateralMovement => 0.50,
        CampaignPhase::Collection => 0.45,
        CampaignPhase::Exfiltration => 0.60,
        CampaignPhase::ImpactOps => 0.80,
    }
}
