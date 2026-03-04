//! Multi-phase adversary campaign orchestration for authorised red team exercises.
//!
//! Provides structured campaign planning and simulation following the MITRE ATT&CK
//! framework lifecycle. All campaign execution is strictly simulation-only and must
//! be used exclusively within a documented, authorised engagement scope.

use crate::red_team::adversary_profiles::AdversaryProfile;

/// Rules of engagement that bound what a campaign simulation may attempt.
#[derive(Debug, Clone)]
pub struct RulesOfEngagement {
    /// Systems explicitly in scope.
    pub in_scope_systems: Vec<String>,
    /// Systems explicitly excluded from simulation.
    pub out_of_scope_systems: Vec<String>,
    /// Maximum noise/detection footprint allowed (0 = silent, 10 = noisy).
    pub max_noise_level: u8,
    /// Whether destructive techniques are permitted.
    pub destructive_allowed: bool,
    /// Whether data exfiltration simulation is permitted.
    pub exfiltration_allowed: bool,
    /// Campaign operator contact for emergency stop.
    pub emergency_contact: String,
}

impl Default for RulesOfEngagement {
    fn default() -> Self {
        Self {
            in_scope_systems: Vec::new(),
            out_of_scope_systems: Vec::new(),
            max_noise_level: 3,
            destructive_allowed: false,
            exfiltration_allowed: false,
            emergency_contact: "security@example.com".to_string(),
        }
    }
}

/// The status of a campaign phase execution.
#[derive(Debug, Clone, PartialEq)]
pub enum PhaseStatus {
    /// Phase has not yet started.
    Pending,
    /// Phase is currently executing.
    InProgress,
    /// Phase completed successfully.
    Completed,
    /// Phase was skipped (out of scope or not applicable).
    Skipped,
    /// Phase failed or was blocked.
    Blocked,
}

/// A single phase in the campaign execution lifecycle.
#[derive(Debug, Clone)]
pub struct CampaignPhase {
    /// Phase name (e.g., `"Initial Access"`).
    pub name: String,
    /// MITRE ATT&CK tactic this phase maps to.
    pub mitre_tactic: String,
    /// Techniques to be simulated in this phase.
    pub techniques: Vec<String>,
    /// Current execution status.
    pub status: PhaseStatus,
    /// Observations recorded during execution.
    pub observations: Vec<String>,
    /// Artefacts produced (IOCs, files, network indicators).
    pub artefacts: Vec<String>,
}

impl CampaignPhase {
    /// Create a new pending phase.
    pub fn new(name: impl Into<String>, mitre_tactic: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            mitre_tactic: mitre_tactic.into(),
            techniques: Vec::new(),
            status: PhaseStatus::Pending,
            observations: Vec::new(),
            artefacts: Vec::new(),
        }
    }

    /// Mark the phase as completed with a set of observations.
    pub fn complete(&mut self, observations: Vec<String>, artefacts: Vec<String>) {
        self.status = PhaseStatus::Completed;
        self.observations = observations;
        self.artefacts = artefacts;
    }

    /// Mark the phase as blocked with a reason.
    pub fn block(&mut self, reason: impl Into<String>) {
        self.status = PhaseStatus::Blocked;
        self.observations.push(reason.into());
    }
}

/// The aggregate result of running all campaign phases.
#[derive(Debug, Clone)]
pub struct CampaignResult {
    pub campaign_id: String,
    pub adversary_name: String,
    pub phases_completed: usize,
    pub phases_blocked: usize,
    pub phases_skipped: usize,
    pub total_phases: usize,
    pub key_findings: Vec<String>,
    pub recommended_mitigations: Vec<String>,
    pub risk_summary: String,
}

/// A multi-phase adversary campaign simulation.
#[derive(Debug, Clone)]
pub struct Campaign {
    /// Unique identifier for this campaign.
    pub id: String,
    /// Ordered list of campaign phases.
    pub phases: Vec<CampaignPhase>,
    /// Adversary profile being emulated.
    pub adversary: AdversaryProfile,
    /// Campaign objectives (e.g., `"exfiltrate PII"`, `"achieve domain admin"`).
    pub objectives: Vec<String>,
    /// Bounding rules of engagement.
    pub rules_of_engagement: RulesOfEngagement,
}

impl Campaign {
    /// Create a new campaign for the given adversary profile and objectives.
    pub fn new(
        adversary: AdversaryProfile,
        objectives: Vec<String>,
        rules_of_engagement: RulesOfEngagement,
    ) -> Self {
        let id = uuid::Uuid::new_v4().to_string();
        let phases = build_phases_from_profile(&adversary);
        Self {
            id,
            phases,
            adversary,
            objectives,
            rules_of_engagement,
        }
    }

    /// Run all campaign phases in sequence and return a summarised result.
    ///
    /// Each phase is evaluated against the rules of engagement before execution.
    /// Phases that violate the ROE are automatically skipped.
    pub fn run(&mut self) -> CampaignResult {
        let total_phases = self.phases.len();

        for phase in &mut self.phases {
            if phase.status != PhaseStatus::Pending {
                continue;
            }

            // Check ROE constraints.
            if !self.rules_of_engagement.exfiltration_allowed
                && phase.mitre_tactic == "Exfiltration"
            {
                phase.status = PhaseStatus::Skipped;
                continue;
            }

            if !self.rules_of_engagement.destructive_allowed && phase.mitre_tactic == "Impact" {
                phase.status = PhaseStatus::Skipped;
                continue;
            }

            // Simulate phase execution.
            phase.status = PhaseStatus::InProgress;
            let observations = vec![format!(
                "Simulated {} phase using {} technique(s).",
                phase.name,
                phase.techniques.len()
            )];
            let artefacts = phase
                .techniques
                .iter()
                .map(|t| format!("IOC:{}", t))
                .collect();
            phase.complete(observations, artefacts);
        }

        self.build_result(total_phases)
    }

    fn build_result(&self, total_phases: usize) -> CampaignResult {
        let phases_completed = self
            .phases
            .iter()
            .filter(|p| p.status == PhaseStatus::Completed)
            .count();
        let phases_blocked = self
            .phases
            .iter()
            .filter(|p| p.status == PhaseStatus::Blocked)
            .count();
        let phases_skipped = self
            .phases
            .iter()
            .filter(|p| p.status == PhaseStatus::Skipped)
            .count();

        let key_findings: Vec<String> = self
            .phases
            .iter()
            .filter(|p| p.status == PhaseStatus::Completed)
            .flat_map(|p| p.observations.clone())
            .collect();

        let recommended_mitigations = vec![
            "Implement network segmentation to limit lateral movement.".to_string(),
            "Deploy EDR solutions with behavioural detections enabled.".to_string(),
            "Enforce MFA on all privileged accounts.".to_string(),
            "Enable enhanced audit logging across all systems.".to_string(),
        ];

        let risk_summary = format!(
            "Campaign '{}' against {} emulating {}: {}/{} phases completed, {} blocked, {} skipped.",
            self.id,
            self.rules_of_engagement
                .in_scope_systems
                .first()
                .cloned()
                .unwrap_or_else(|| "target".to_string()),
            self.adversary.name,
            phases_completed,
            total_phases,
            phases_blocked,
            phases_skipped,
        );

        CampaignResult {
            campaign_id: self.id.clone(),
            adversary_name: self.adversary.name.clone(),
            phases_completed,
            phases_blocked,
            phases_skipped,
            total_phases,
            key_findings,
            recommended_mitigations,
            risk_summary,
        }
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn build_phases_from_profile(adversary: &AdversaryProfile) -> Vec<CampaignPhase> {
    let phase_defs: &[(&str, &str)] = &[
        ("Initial Access", "Initial Access"),
        ("Execution", "Execution"),
        ("Persistence", "Persistence"),
        ("Privilege Escalation", "Privilege Escalation"),
        ("Defense Evasion", "Defense Evasion"),
        ("Credential Access", "Credential Access"),
        ("Lateral Movement", "Lateral Movement"),
        ("Collection", "Collection"),
        ("Exfiltration", "Exfiltration"),
        ("Impact", "Impact"),
    ];

    phase_defs
        .iter()
        .map(|(name, tactic)| {
            let mut phase = CampaignPhase::new(*name, *tactic);
            // Populate techniques from adversary profile TTPs.
            phase.techniques = adversary
                .typical_ttps
                .all_techniques()
                .into_iter()
                .filter(|t| t.tactic == *tactic)
                .map(|t| t.id.clone())
                .collect();
            phase
        })
        .collect()
}
