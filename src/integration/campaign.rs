//! Multi-phase adversary campaign management.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Configuration for a multi-phase adversary campaign.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignConfig {
    /// Human-readable campaign name.
    pub name: String,
    /// Target organization or environment.
    pub target: String,
    /// Operator or red team name.
    pub operator: String,
    /// Ordered phases to execute.
    pub phases: Vec<CampaignPhase>,
    /// Maximum total duration in days.
    pub max_duration_days: u32,
}

impl Default for CampaignConfig {
    fn default() -> Self {
        Self {
            name: "Campaign Alpha".to_string(),
            target: "undefined".to_string(),
            operator: "unknown".to_string(),
            phases: CampaignPhase::default_sequence(),
            max_duration_days: 30,
        }
    }
}

/// A discrete phase of an adversary campaign aligned to the kill chain.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CampaignPhase {
    /// Initial access and foothold establishment.
    InitialAccess,
    /// Execution and post-exploitation.
    Execution,
    /// Persistence mechanisms.
    Persistence,
    /// Privilege escalation.
    PrivilegeEscalation,
    /// Defense evasion techniques.
    DefenseEvasion,
    /// Credential harvesting.
    CredentialAccess,
    /// Internal network discovery.
    Discovery,
    /// Lateral movement through the network.
    LateralMovement,
    /// Data collection and staging.
    Collection,
    /// Command and control communication.
    CommandAndControl,
    /// Data exfiltration.
    Exfiltration,
    /// Impact and effects on objective.
    Impact,
}

impl CampaignPhase {
    pub fn default_sequence() -> Vec<Self> {
        vec![
            Self::InitialAccess,
            Self::Execution,
            Self::Persistence,
            Self::PrivilegeEscalation,
            Self::DefenseEvasion,
            Self::CredentialAccess,
            Self::Discovery,
            Self::LateralMovement,
            Self::Collection,
            Self::CommandAndControl,
            Self::Exfiltration,
        ]
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::InitialAccess => "Initial Access",
            Self::Execution => "Execution",
            Self::Persistence => "Persistence",
            Self::PrivilegeEscalation => "Privilege Escalation",
            Self::DefenseEvasion => "Defense Evasion",
            Self::CredentialAccess => "Credential Access",
            Self::Discovery => "Discovery",
            Self::LateralMovement => "Lateral Movement",
            Self::Collection => "Collection",
            Self::CommandAndControl => "Command and Control",
            Self::Exfiltration => "Exfiltration",
            Self::Impact => "Impact",
        }
    }
}

/// Runtime state of the campaign.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CampaignState {
    /// Campaign has been configured but not started.
    Planned,
    /// Campaign is actively executing a phase.
    Active,
    /// Campaign is temporarily suspended.
    Paused,
    /// Campaign completed all phases successfully.
    Completed,
    /// Campaign was aborted due to out-of-scope detection or operator decision.
    Aborted,
}

/// Result of executing a single campaign phase.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhaseExecutionResult {
    pub phase: CampaignPhase,
    pub success: bool,
    pub techniques_used: Vec<String>,
    pub hosts_compromised: u32,
    pub detection_events: u32,
    pub notes: String,
    pub executed_at: DateTime<Utc>,
}

/// Aggregated results of a complete campaign.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignResult {
    pub campaign_name: String,
    pub target: String,
    pub state: CampaignState,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub phase_results: Vec<PhaseExecutionResult>,
    pub total_techniques: usize,
    pub total_hosts_compromised: u32,
    pub total_detection_events: u32,
    pub objective_achieved: bool,
    pub executive_summary: String,
}

/// Tracks and orchestrates a multi-phase adversary campaign.
#[derive(Debug, Clone)]
pub struct Campaign {
    pub config: CampaignConfig,
    pub state: CampaignState,
    pub phase_results: Vec<PhaseExecutionResult>,
    pub started_at: Option<DateTime<Utc>>,
}

impl Campaign {
    pub fn new(config: CampaignConfig) -> Self {
        Self {
            config,
            state: CampaignState::Planned,
            phase_results: Vec::new(),
            started_at: None,
        }
    }

    /// Start the campaign, transitioning from Planned → Active.
    pub fn start(&mut self) {
        self.state = CampaignState::Active;
        self.started_at = Some(Utc::now());
    }

    /// Pause an active campaign.
    pub fn pause(&mut self) {
        if self.state == CampaignState::Active {
            self.state = CampaignState::Paused;
        }
    }

    /// Resume a paused campaign.
    pub fn resume(&mut self) {
        if self.state == CampaignState::Paused {
            self.state = CampaignState::Active;
        }
    }

    /// Abort the campaign with a reason.
    pub fn abort(&mut self, reason: &str) {
        self.state = CampaignState::Aborted;
        self.phase_results.push(PhaseExecutionResult {
            phase: CampaignPhase::Impact,
            success: false,
            techniques_used: Vec::new(),
            hosts_compromised: 0,
            detection_events: 0,
            notes: format!("Campaign aborted: {reason}"),
            executed_at: Utc::now(),
        });
    }

    /// Execute the next pending phase and record the result.
    pub async fn execute_next_phase(&mut self) -> anyhow::Result<Option<PhaseExecutionResult>> {
        if self.state != CampaignState::Active {
            return Ok(None);
        }
        let completed_count = self.phase_results.len();
        let next_phase = self.config.phases.get(completed_count).cloned();

        let Some(phase) = next_phase else {
            self.state = CampaignState::Completed;
            return Ok(None);
        };

        let result = execute_phase(&phase, &self.config.target).await;
        self.phase_results.push(result.clone());

        if completed_count + 1 >= self.config.phases.len() {
            self.state = CampaignState::Completed;
        }

        Ok(Some(result))
    }

    /// Compile a final campaign report.
    pub fn finalize(&self) -> CampaignResult {
        let total_techniques: usize = self
            .phase_results
            .iter()
            .map(|r| r.techniques_used.len())
            .sum();
        let total_hosts = self.phase_results.iter().map(|r| r.hosts_compromised).sum();
        let total_detections = self.phase_results.iter().map(|r| r.detection_events).sum();
        let objective_achieved =
            self.state == CampaignState::Completed && self.phase_results.iter().all(|r| r.success);

        let summary = format!(
            "Campaign '{}' against '{}' — state: {:?}. {} phases executed, {} techniques used, {} hosts compromised, {} detection events.",
            self.config.name,
            self.config.target,
            self.state,
            self.phase_results.len(),
            total_techniques,
            total_hosts,
            total_detections,
        );

        CampaignResult {
            campaign_name: self.config.name.clone(),
            target: self.config.target.clone(),
            state: self.state.clone(),
            started_at: self.started_at.unwrap_or_else(Utc::now),
            completed_at: if matches!(
                self.state,
                CampaignState::Completed | CampaignState::Aborted
            ) {
                Some(Utc::now())
            } else {
                None
            },
            phase_results: self.phase_results.clone(),
            total_techniques,
            total_hosts_compromised: total_hosts,
            total_detection_events: total_detections,
            objective_achieved,
            executive_summary: summary,
        }
    }
}

/// Simulate execution of a campaign phase and return structured results.
async fn execute_phase(phase: &CampaignPhase, target: &str) -> PhaseExecutionResult {
    let (techniques, hosts, detections, notes) = match phase {
        CampaignPhase::InitialAccess => (
            vec!["T1566.001 Spearphishing".to_string()],
            1,
            0,
            format!("Initial foothold established on {target}"),
        ),
        CampaignPhase::Execution => (
            vec!["T1059.001 PowerShell".to_string()],
            1,
            0,
            "Payload executed via PowerShell".to_string(),
        ),
        CampaignPhase::Persistence => (
            vec!["T1547.001 Registry Run Keys".to_string()],
            1,
            0,
            "Persistence established via registry".to_string(),
        ),
        CampaignPhase::PrivilegeEscalation => (
            vec!["T1068 Exploitation for Privilege Escalation".to_string()],
            1,
            1,
            "Privileges escalated to SYSTEM".to_string(),
        ),
        CampaignPhase::DefenseEvasion => (
            vec!["T1562.001 Disable Windows Defender".to_string()],
            1,
            0,
            "AV disabled on target host".to_string(),
        ),
        CampaignPhase::CredentialAccess => (
            vec!["T1003.001 LSASS Memory Dump".to_string()],
            1,
            1,
            "Credentials harvested from LSASS".to_string(),
        ),
        CampaignPhase::Discovery => (
            vec!["T1018 Remote System Discovery".to_string()],
            0,
            0,
            "Internal network mapped".to_string(),
        ),
        CampaignPhase::LateralMovement => (
            vec!["T1021.001 RDP Lateral Movement".to_string()],
            2,
            1,
            "Moved to 2 additional hosts via RDP".to_string(),
        ),
        CampaignPhase::Collection => (
            vec!["T1005 Data from Local System".to_string()],
            0,
            0,
            "Sensitive files staged for exfiltration".to_string(),
        ),
        CampaignPhase::CommandAndControl => (
            vec!["T1071.001 Web Protocols C2".to_string()],
            0,
            0,
            "C2 channel established over HTTPS".to_string(),
        ),
        CampaignPhase::Exfiltration => (
            vec!["T1041 Exfiltration Over C2".to_string()],
            0,
            1,
            "Data exfiltrated to operator infrastructure".to_string(),
        ),
        CampaignPhase::Impact => (
            vec!["T1486 Data Encrypted for Impact".to_string()],
            0,
            2,
            "Impact phase simulated".to_string(),
        ),
    };

    PhaseExecutionResult {
        phase: phase.clone(),
        success: true,
        techniques_used: techniques,
        hosts_compromised: hosts,
        detection_events: detections,
        notes,
        executed_at: Utc::now(),
    }
}
