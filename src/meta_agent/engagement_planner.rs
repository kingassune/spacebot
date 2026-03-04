//! Automated engagement planning for multi-phase security operations.
//!
//! Covers multi-phase engagement planning (recon → exploit → persist → exfil),
//! rules of engagement enforcement, automated scope validation,
//! kill chain stage management, and blue team deconfliction.

use serde::{Deserialize, Serialize};

// — Engagement phase types —

/// Ordered phases of a security engagement following the kill chain model.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EngagementPhase {
    /// Open-source and technical reconnaissance.
    Recon,
    /// Initial access and exploitation.
    Exploit,
    /// Persistence mechanisms and lateral movement.
    Persist,
    /// Data staging and simulated exfiltration.
    ExfilSimulation,
    /// Cleanup and evidence removal simulation.
    Cleanup,
}

impl std::fmt::Display for EngagementPhase {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            Self::Recon => "Reconnaissance",
            Self::Exploit => "Exploitation",
            Self::Persist => "Persistence",
            Self::ExfilSimulation => "Exfiltration Simulation",
            Self::Cleanup => "Cleanup",
        };
        formatter.write_str(label)
    }
}

/// Status of a single engagement phase.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PhaseStatus {
    Pending,
    Active,
    Complete,
    Skipped,
    Blocked,
}

// — Rules of engagement —

/// Defines what is and is not permitted during an engagement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RulesOfEngagement {
    /// Systems explicitly in scope (CIDR ranges, hostnames, or contract addresses).
    pub in_scope: Vec<String>,
    /// Systems explicitly out of scope.
    pub out_of_scope: Vec<String>,
    /// Permitted attack categories.
    pub permitted_techniques: Vec<String>,
    /// Explicitly prohibited techniques.
    pub prohibited_techniques: Vec<String>,
    /// Maximum acceptable impact level: "None", "Low", "Medium", "High".
    pub max_impact_level: String,
    /// Whether destructive actions are allowed.
    pub allow_destructive: bool,
    /// Whether social engineering is in scope.
    pub allow_social_engineering: bool,
    /// Engagement start time (ISO 8601).
    pub start_time: String,
    /// Engagement end time (ISO 8601).
    pub end_time: String,
    /// Emergency contact for immediate engagement halt.
    pub emergency_contact: String,
    /// Blue team deconfliction contact.
    pub deconfliction_contact: String,
}

impl Default for RulesOfEngagement {
    fn default() -> Self {
        Self {
            in_scope: Vec::new(),
            out_of_scope: Vec::new(),
            permitted_techniques: Vec::new(),
            prohibited_techniques: Vec::new(),
            max_impact_level: "Medium".to_string(),
            allow_destructive: false,
            allow_social_engineering: false,
            start_time: String::new(),
            end_time: String::new(),
            emergency_contact: String::new(),
            deconfliction_contact: String::new(),
        }
    }
}

/// Outcome of validating a target against the rules of engagement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopeValidationResult {
    /// Target that was validated.
    pub target: String,
    /// Whether the target is within scope.
    pub in_scope: bool,
    /// Reason for the decision.
    pub reason: String,
}

// — Phase plan types —

/// A single planned action within an engagement phase.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlannedAction {
    /// Short action identifier.
    pub id: String,
    /// Human-readable description.
    pub description: String,
    /// ATT&CK technique ID (if applicable).
    pub technique_id: Option<String>,
    /// Estimated impact level: "None", "Low", "Medium", "High".
    pub impact_level: String,
    /// Whether blue team should be notified before this action.
    pub notify_blue_team: bool,
    /// Prerequisite action IDs.
    pub prerequisites: Vec<String>,
}

/// Plan for a single engagement phase.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhasePlan {
    /// Which phase this plan covers.
    pub phase: EngagementPhase,
    /// Current status of this phase.
    pub status: PhaseStatus,
    /// Planned actions for this phase.
    pub actions: Vec<PlannedAction>,
    /// Objectives to achieve before phase is considered complete.
    pub success_criteria: Vec<String>,
    /// Estimated duration in hours.
    pub estimated_duration_hours: f32,
}

// — Full engagement plan —

/// Configuration for generating an engagement plan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngagementPlanConfig {
    /// Unique engagement identifier.
    pub engagement_id: String,
    /// Target name or identifier.
    pub target_name: String,
    /// Target description.
    pub target_description: String,
    /// Threat actor profile to emulate (optional).
    pub emulate_actor: Option<String>,
    /// Phases to include in the plan.
    pub phases: Vec<EngagementPhase>,
    /// Rules of engagement for this engagement.
    pub rules_of_engagement: RulesOfEngagement,
    /// Engagement objectives.
    pub objectives: Vec<String>,
}

impl Default for EngagementPlanConfig {
    fn default() -> Self {
        Self {
            engagement_id: uuid_placeholder(),
            target_name: String::new(),
            target_description: String::new(),
            emulate_actor: None,
            phases: vec![
                EngagementPhase::Recon,
                EngagementPhase::Exploit,
                EngagementPhase::Persist,
                EngagementPhase::ExfilSimulation,
                EngagementPhase::Cleanup,
            ],
            rules_of_engagement: RulesOfEngagement::default(),
            objectives: Vec::new(),
        }
    }
}

/// A fully planned multi-phase security engagement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngagementPlan {
    /// Engagement identifier.
    pub engagement_id: String,
    /// Target information.
    pub target_name: String,
    /// Configuration used to generate this plan.
    pub config: EngagementPlanConfig,
    /// Phase plans in execution order.
    pub phase_plans: Vec<PhasePlan>,
    /// Whether this plan has passed RoE validation.
    pub roe_validated: bool,
    /// Deconfliction log entries.
    pub deconfliction_log: Vec<String>,
    /// Risk summary.
    pub risk_summary: String,
}

// — Deconfliction event —

/// A deconfliction event shared with the blue team.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeconflictionEvent {
    /// Engagement this event belongs to.
    pub engagement_id: String,
    /// Phase the action occurs in.
    pub phase: EngagementPhase,
    /// Source IP or system identifier.
    pub source: String,
    /// Target IP or system identifier.
    pub target: String,
    /// Action description.
    pub action_description: String,
    /// ATT&CK technique ID.
    pub technique_id: String,
    /// Expected detection artefacts.
    pub expected_artefacts: Vec<String>,
    /// Timestamp (ISO 8601).
    pub timestamp: String,
}

// — Engagement planner —

/// Plans and manages multi-phase security engagements.
#[derive(Debug, Clone)]
pub struct EngagementPlanner {
    /// Active engagement plans.
    pub active_plans: Vec<EngagementPlan>,
    /// Deconfliction events sent to blue team.
    pub deconfliction_events: Vec<DeconflictionEvent>,
}

impl EngagementPlanner {
    /// Create a new planner with no active engagements.
    pub fn new() -> Self {
        Self {
            active_plans: Vec::new(),
            deconfliction_events: Vec::new(),
        }
    }

    /// Validate a target against the given rules of engagement.
    pub fn validate_scope(
        &self,
        target: &str,
        roe: &RulesOfEngagement,
    ) -> ScopeValidationResult {
        // Check explicit out-of-scope list first.
        if roe.out_of_scope.iter().any(|entry| target.contains(entry.as_str())) {
            return ScopeValidationResult {
                target: target.to_string(),
                in_scope: false,
                reason: format!("Target '{target}' matches an out-of-scope entry."),
            };
        }

        // If an in-scope list is provided, the target must match.
        if !roe.in_scope.is_empty()
            && !roe.in_scope.iter().any(|entry| target.contains(entry.as_str()))
        {
            return ScopeValidationResult {
                target: target.to_string(),
                in_scope: false,
                reason: format!("Target '{target}' is not in the in-scope list."),
            };
        }

        ScopeValidationResult {
            target: target.to_string(),
            in_scope: true,
            reason: "Target is within the authorised scope.".to_string(),
        }
    }

    /// Generate a full engagement plan from the supplied configuration.
    pub fn generate_plan(&mut self, config: EngagementPlanConfig) -> EngagementPlan {
        let roe_validated = !config.rules_of_engagement.in_scope.is_empty()
            && !config.rules_of_engagement.emergency_contact.is_empty();

        let phase_plans: Vec<PhasePlan> = config
            .phases
            .iter()
            .map(|phase| build_default_phase_plan(phase))
            .collect();

        let risk_summary = format!(
            "Engagement '{}' covers {} phase(s) targeting '{}'. \
             Destructive actions: {}. Max impact: {}.",
            config.engagement_id,
            config.phases.len(),
            config.target_name,
            if config.rules_of_engagement.allow_destructive { "YES" } else { "NO" },
            config.rules_of_engagement.max_impact_level,
        );

        let plan = EngagementPlan {
            engagement_id: config.engagement_id.clone(),
            target_name: config.target_name.clone(),
            config,
            phase_plans,
            roe_validated,
            deconfliction_log: Vec::new(),
            risk_summary,
        };

        self.active_plans.push(plan.clone());
        plan
    }

    /// Record a deconfliction event and add it to the engagement log.
    pub fn record_deconfliction(&mut self, event: DeconflictionEvent) {
        let log_entry = format!(
            "[{}] Phase={} | {} → {} | {} ({})",
            event.timestamp,
            event.phase,
            event.source,
            event.target,
            event.action_description,
            event.technique_id,
        );

        // Update the matching engagement's log.
        if let Some(plan) = self
            .active_plans
            .iter_mut()
            .find(|plan| plan.engagement_id == event.engagement_id)
        {
            plan.deconfliction_log.push(log_entry);
        }

        self.deconfliction_events.push(event);
    }

    /// Advance a phase to the next status in its lifecycle.
    pub fn advance_phase(
        &mut self,
        engagement_id: &str,
        phase: &EngagementPhase,
    ) -> Option<PhaseStatus> {
        let plan = self
            .active_plans
            .iter_mut()
            .find(|plan| plan.engagement_id == engagement_id)?;

        let phase_plan = plan
            .phase_plans
            .iter_mut()
            .find(|phase_plan| &phase_plan.phase == phase)?;

        let next_status = match phase_plan.status {
            PhaseStatus::Pending => PhaseStatus::Active,
            PhaseStatus::Active => PhaseStatus::Complete,
            PhaseStatus::Complete | PhaseStatus::Skipped | PhaseStatus::Blocked => {
                return Some(phase_plan.status.clone());
            }
        };

        phase_plan.status = next_status.clone();
        Some(next_status)
    }

    /// Return the active plan for the given engagement ID.
    pub fn get_plan(&self, engagement_id: &str) -> Option<&EngagementPlan> {
        self.active_plans
            .iter()
            .find(|plan| plan.engagement_id == engagement_id)
    }
}

impl Default for EngagementPlanner {
    fn default() -> Self {
        Self::new()
    }
}

// — Internal helpers —

fn build_default_phase_plan(phase: &EngagementPhase) -> PhasePlan {
    let (actions, criteria, hours) = match phase {
        EngagementPhase::Recon => (
            vec![
                PlannedAction {
                    id: "recon-01".to_string(),
                    description: "Passive OSINT — DNS, WHOIS, certificates".to_string(),
                    technique_id: Some("T1596".to_string()),
                    impact_level: "None".to_string(),
                    notify_blue_team: false,
                    prerequisites: Vec::new(),
                },
                PlannedAction {
                    id: "recon-02".to_string(),
                    description: "Active port scan of in-scope targets".to_string(),
                    technique_id: Some("T1046".to_string()),
                    impact_level: "Low".to_string(),
                    notify_blue_team: true,
                    prerequisites: vec!["recon-01".to_string()],
                },
            ],
            vec!["Attack surface map documented".to_string()],
            4.0_f32,
        ),
        EngagementPhase::Exploit => (
            vec![
                PlannedAction {
                    id: "exploit-01".to_string(),
                    description: "Spearphishing simulation (no payload delivery)".to_string(),
                    technique_id: Some("T1566.001".to_string()),
                    impact_level: "Low".to_string(),
                    notify_blue_team: true,
                    prerequisites: vec!["recon-02".to_string()],
                },
                PlannedAction {
                    id: "exploit-02".to_string(),
                    description: "Exploit public-facing application vulnerability".to_string(),
                    technique_id: Some("T1190".to_string()),
                    impact_level: "Medium".to_string(),
                    notify_blue_team: true,
                    prerequisites: vec!["exploit-01".to_string()],
                },
            ],
            vec!["Initial access obtained to at least one in-scope system".to_string()],
            8.0_f32,
        ),
        EngagementPhase::Persist => (
            vec![
                PlannedAction {
                    id: "persist-01".to_string(),
                    description: "Establish persistence via scheduled task".to_string(),
                    technique_id: Some("T1053.005".to_string()),
                    impact_level: "Medium".to_string(),
                    notify_blue_team: true,
                    prerequisites: vec!["exploit-02".to_string()],
                },
                PlannedAction {
                    id: "persist-02".to_string(),
                    description: "Lateral movement via pass-the-hash".to_string(),
                    technique_id: Some("T1550.002".to_string()),
                    impact_level: "Medium".to_string(),
                    notify_blue_team: true,
                    prerequisites: vec!["persist-01".to_string()],
                },
            ],
            vec![
                "Persistence mechanism documented".to_string(),
                "Lateral movement to secondary host achieved".to_string(),
            ],
            6.0_f32,
        ),
        EngagementPhase::ExfilSimulation => (
            vec![
                PlannedAction {
                    id: "exfil-01".to_string(),
                    description: "Stage simulated data for exfiltration (canary files only)".to_string(),
                    technique_id: Some("T1074".to_string()),
                    impact_level: "Low".to_string(),
                    notify_blue_team: true,
                    prerequisites: vec!["persist-02".to_string()],
                },
                PlannedAction {
                    id: "exfil-02".to_string(),
                    description: "Simulate exfiltration over HTTPS C2 channel (no real data)".to_string(),
                    technique_id: Some("T1041".to_string()),
                    impact_level: "Low".to_string(),
                    notify_blue_team: true,
                    prerequisites: vec!["exfil-01".to_string()],
                },
            ],
            vec!["Exfiltration path demonstrated and documented".to_string()],
            2.0_f32,
        ),
        EngagementPhase::Cleanup => (
            vec![
                PlannedAction {
                    id: "cleanup-01".to_string(),
                    description: "Remove all artefacts and persistence mechanisms".to_string(),
                    technique_id: Some("T1070".to_string()),
                    impact_level: "None".to_string(),
                    notify_blue_team: true,
                    prerequisites: Vec::new(),
                },
            ],
            vec!["All artefacts removed and confirmed with blue team".to_string()],
            2.0_f32,
        ),
    };

    PhasePlan {
        phase: phase.clone(),
        status: PhaseStatus::Pending,
        actions,
        success_criteria: criteria,
        estimated_duration_hours: hours,
    }
}

/// Returns a deterministic placeholder UUID string.
/// In production, use a real UUID library.
fn uuid_placeholder() -> String {
    "00000000-0000-0000-0000-000000000000".to_string()
}
