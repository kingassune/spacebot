//! Multi-phase security operation campaign management.
//!
//! Provides checkpoint-based campaign execution with rollback support
//! for coordinated multi-engine security assessments.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Current state of a campaign.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CampaignState {
    /// Campaign has not yet started.
    Pending,
    /// Campaign is actively running.
    Running,
    /// Campaign completed all phases successfully.
    Completed,
    /// Campaign was paused at a checkpoint.
    Paused,
    /// Campaign was rolled back to a previous checkpoint.
    RolledBack,
    /// Campaign failed and was aborted.
    Failed(String),
}

/// A discrete phase within a campaign.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CampaignPhase {
    Reconnaissance,
    InitialAccess,
    Execution,
    Persistence,
    PrivilegeEscalation,
    LateralMovement,
    Collection,
    Exfiltration,
    Impact,
    Detection,
    Response,
}

impl CampaignPhase {
    /// Human-readable label.
    pub fn label(&self) -> &'static str {
        match self {
            CampaignPhase::Reconnaissance => "Reconnaissance",
            CampaignPhase::InitialAccess => "Initial Access",
            CampaignPhase::Execution => "Execution",
            CampaignPhase::Persistence => "Persistence",
            CampaignPhase::PrivilegeEscalation => "Privilege Escalation",
            CampaignPhase::LateralMovement => "Lateral Movement",
            CampaignPhase::Collection => "Collection",
            CampaignPhase::Exfiltration => "Exfiltration",
            CampaignPhase::Impact => "Impact",
            CampaignPhase::Detection => "Detection Coverage",
            CampaignPhase::Response => "Incident Response",
        }
    }
}

/// A saved checkpoint that can be used for rollback.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Checkpoint {
    /// Phase this checkpoint was saved after.
    pub after_phase: CampaignPhase,
    /// Timestamp of the checkpoint.
    pub saved_at: DateTime<Utc>,
    /// State snapshot description.
    pub description: String,
}

/// Configuration for a multi-phase security campaign.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignConfig {
    /// Campaign name.
    pub name: String,
    /// Target organisation or environment.
    pub target: String,
    /// Operator or team name.
    pub operator: String,
    /// Ordered phases to execute.
    pub phases: Vec<CampaignPhase>,
    /// Whether to save a checkpoint after each phase.
    pub checkpoint_on_phase_complete: bool,
    /// Maximum total duration in hours (0 = unlimited).
    pub max_duration_hours: u32,
}

impl Default for CampaignConfig {
    fn default() -> Self {
        Self {
            name: "Campaign Alpha".to_string(),
            target: "undefined".to_string(),
            operator: "james".to_string(),
            phases: vec![
                CampaignPhase::Reconnaissance,
                CampaignPhase::InitialAccess,
                CampaignPhase::Execution,
                CampaignPhase::Persistence,
                CampaignPhase::LateralMovement,
                CampaignPhase::Exfiltration,
                CampaignPhase::Detection,
            ],
            checkpoint_on_phase_complete: true,
            max_duration_hours: 72,
        }
    }
}

/// Result for a single completed phase.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhaseResult {
    /// Phase that was executed.
    pub phase: CampaignPhase,
    /// Whether the phase succeeded.
    pub success: bool,
    /// Summary of what was accomplished.
    pub summary: String,
    /// Number of findings produced.
    pub findings_count: usize,
    /// Execution duration in seconds.
    pub duration_secs: u64,
}

/// Result of a completed or failed campaign.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignResult {
    /// Campaign configuration.
    pub config: CampaignConfig,
    /// Per-phase results.
    pub phase_results: Vec<PhaseResult>,
    /// Final campaign state.
    pub final_state: CampaignState,
    /// Total findings across all phases.
    pub total_findings: usize,
    /// Executive summary.
    pub executive_summary: String,
    /// Checkpoints saved during execution.
    pub checkpoints: Vec<Checkpoint>,
}

/// An active campaign that can be advanced phase by phase.
#[derive(Debug, Clone)]
pub struct Campaign {
    /// Campaign configuration.
    pub config: CampaignConfig,
    /// Current state.
    pub state: CampaignState,
    /// Completed phase results.
    pub completed_phases: Vec<PhaseResult>,
    /// Saved checkpoints.
    pub checkpoints: Vec<Checkpoint>,
    /// Index of the next phase to execute.
    pub current_phase_index: usize,
    /// Campaign start time.
    pub started_at: DateTime<Utc>,
}

impl Campaign {
    /// Create a new campaign from configuration.
    pub fn new(config: CampaignConfig) -> Self {
        Self {
            config,
            state: CampaignState::Pending,
            completed_phases: Vec::new(),
            checkpoints: Vec::new(),
            current_phase_index: 0,
            started_at: Utc::now(),
        }
    }

    /// Start the campaign.
    pub fn start(&mut self) {
        self.state = CampaignState::Running;
        self.started_at = Utc::now();
    }

    /// Advance to the next phase with a simulated result.
    pub fn advance_phase(&mut self) {
        if self.current_phase_index >= self.config.phases.len() {
            return;
        }
        let phase = self.config.phases[self.current_phase_index].clone();
        let result = PhaseResult {
            phase: phase.clone(),
            success: true,
            summary: format!("{} phase completed successfully.", phase.label()),
            findings_count: 2,
            duration_secs: 300,
        };

        if self.config.checkpoint_on_phase_complete {
            self.checkpoints.push(Checkpoint {
                after_phase: phase,
                saved_at: Utc::now(),
                description: format!(
                    "Checkpoint after phase {}",
                    self.current_phase_index + 1
                ),
            });
        }

        self.completed_phases.push(result);
        self.current_phase_index += 1;

        if self.current_phase_index >= self.config.phases.len() {
            self.state = CampaignState::Completed;
        }
    }

    /// Roll back to the most recent checkpoint.
    pub fn rollback(&mut self) -> Option<&Checkpoint> {
        if let Some(checkpoint) = self.checkpoints.last() {
            let phase = &checkpoint.after_phase;
            let rollback_index = self
                .config
                .phases
                .iter()
                .position(|p| p == phase)
                .unwrap_or(0);
            self.current_phase_index = rollback_index;
            self.completed_phases.truncate(rollback_index);
            self.state = CampaignState::RolledBack;
            self.checkpoints.last()
        } else {
            None
        }
    }

    /// Finalise and return the campaign result.
    pub fn finalise(self) -> CampaignResult {
        let total_findings: usize = self
            .completed_phases
            .iter()
            .map(|r| r.findings_count)
            .sum();
        let summary = format!(
            "Campaign '{}' against '{}' — {} phases completed, {} total findings.",
            self.config.name,
            self.config.target,
            self.completed_phases.len(),
            total_findings
        );
        CampaignResult {
            config: self.config,
            phase_results: self.completed_phases,
            final_state: self.state,
            total_findings,
            executive_summary: summary,
            checkpoints: self.checkpoints,
        }
    }
}
