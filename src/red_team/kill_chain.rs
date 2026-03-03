//! Full Lockheed Martin Cyber Kill Chain + MITRE ATT&CK integration.

use serde::{Deserialize, Serialize};

/// The seven phases of the Lockheed Martin Cyber Kill Chain.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum KillChainPhase {
    /// Target identification and profiling.
    Reconnaissance,
    /// Weaponizing a deliverable payload.
    Weaponization,
    /// Delivering the weaponized payload.
    Delivery,
    /// Exploiting a vulnerability on the target.
    Exploitation,
    /// Installing malware or backdoors.
    Installation,
    /// Establishing a C2 channel.
    CommandAndControl,
    /// Achieving the mission objectives.
    ActionsOnObjectives,
}

impl KillChainPhase {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Reconnaissance => "Reconnaissance",
            Self::Weaponization => "Weaponization",
            Self::Delivery => "Delivery",
            Self::Exploitation => "Exploitation",
            Self::Installation => "Installation",
            Self::CommandAndControl => "Command & Control",
            Self::ActionsOnObjectives => "Actions on Objectives",
        }
    }

    /// Return the default ATT&CK tactic that maps to this kill chain phase.
    pub fn mitre_tactic(&self) -> &'static str {
        match self {
            Self::Reconnaissance => "Reconnaissance",
            Self::Weaponization => "Resource Development",
            Self::Delivery => "Initial Access",
            Self::Exploitation => "Execution",
            Self::Installation => "Persistence",
            Self::CommandAndControl => "Command and Control",
            Self::ActionsOnObjectives => "Exfiltration",
        }
    }
}

/// Configuration for a kill chain simulation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KillChainConfig {
    /// Target organization or environment.
    pub target: String,
    /// ATT&CK group or campaign name to emulate.
    pub threat_actor: String,
    /// Phases to execute (subset of the full chain).
    pub phases: Vec<KillChainPhase>,
    /// Whether to skip phases that would cause detection.
    pub stealth_mode: bool,
    /// Authorized technique IDs (empty = all allowed).
    pub authorized_techniques: Vec<String>,
}

impl Default for KillChainConfig {
    fn default() -> Self {
        Self {
            target: "undefined".to_string(),
            threat_actor: "generic".to_string(),
            phases: vec![
                KillChainPhase::Reconnaissance,
                KillChainPhase::Weaponization,
                KillChainPhase::Delivery,
                KillChainPhase::Exploitation,
                KillChainPhase::Installation,
                KillChainPhase::CommandAndControl,
                KillChainPhase::ActionsOnObjectives,
            ],
            stealth_mode: true,
            authorized_techniques: Vec::new(),
        }
    }
}

/// Result of executing a single kill chain phase.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhaseResult {
    pub phase: KillChainPhase,
    pub success: bool,
    pub techniques_executed: Vec<String>,
    pub iocs_generated: Vec<String>,
    pub detection_likelihood: f64,
    pub notes: String,
}

/// Aggregated execution record for a full kill chain run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KillChainExecution {
    pub target: String,
    pub threat_actor: String,
    pub phase_results: Vec<PhaseResult>,
    pub overall_success: bool,
    pub total_iocs: usize,
    pub report: String,
}

/// Plan a kill chain execution by mapping the threat actor to ATT&CK techniques.
pub fn plan_kill_chain(config: &KillChainConfig) -> KillChainExecution {
    let phase_results: Vec<PhaseResult> = config
        .phases
        .iter()
        .map(|phase| plan_phase(phase, config))
        .collect();

    let overall_success = phase_results.iter().all(|r| r.success);
    let total_iocs: usize = phase_results.iter().map(|r| r.iocs_generated.len()).sum();
    let report = generate_kill_chain_report(config, &phase_results);

    KillChainExecution {
        target: config.target.clone(),
        threat_actor: config.threat_actor.clone(),
        phase_results,
        overall_success,
        total_iocs,
        report,
    }
}

/// Execute a single kill chain phase.
pub fn execute_phase(phase: &KillChainPhase, config: &KillChainConfig) -> PhaseResult {
    plan_phase(phase, config)
}

/// Assess overall kill chain progress and identify gaps.
pub fn assess_progress(execution: &KillChainExecution) -> String {
    let completed = execution.phase_results.iter().filter(|r| r.success).count();
    let total = execution.phase_results.len();
    let pct = if total > 0 {
        (completed as f64 / total as f64) * 100.0
    } else {
        0.0
    };

    let failed_phases: Vec<&str> = execution
        .phase_results
        .iter()
        .filter(|r| !r.success)
        .map(|r| r.phase.label())
        .collect();

    if failed_phases.is_empty() {
        format!(
            "Kill chain {:.0}% complete ({}/{} phases). All phases successful.",
            pct, completed, total
        )
    } else {
        format!(
            "Kill chain {:.0}% complete ({}/{} phases). Blocked at: {}.",
            pct,
            completed,
            total,
            failed_phases.join(", ")
        )
    }
}

/// Generate a structured kill chain report.
pub fn generate_kill_chain_report(
    config: &KillChainConfig,
    phase_results: &[PhaseResult],
) -> String {
    let mut report = format!(
        "Kill Chain Report — {} against {}\n\
         Threat Actor: {}\n\
         ================================================\n\n",
        config.threat_actor, config.target, config.threat_actor
    );

    for result in phase_results {
        let status = if result.success { "✓" } else { "✗" };
        report.push_str(&format!(
            "[{status}] {}\n  MITRE Tactic: {}\n  Techniques: {}\n  Detection likelihood: {:.0}%\n  {}\n\n",
            result.phase.label(),
            result.phase.mitre_tactic(),
            result.techniques_executed.join(", "),
            result.detection_likelihood * 100.0,
            result.notes,
        ));
    }
    report
}

// — Internal helpers —

fn plan_phase(phase: &KillChainPhase, config: &KillChainConfig) -> PhaseResult {
    let (techniques, iocs, detection, notes) = match phase {
        KillChainPhase::Reconnaissance => (
            vec![
                "T1595.001 Active Scanning".to_string(),
                "T1589 Gather Identity Information".to_string(),
            ],
            vec!["DNS lookups from scanner IP".to_string()],
            if config.stealth_mode { 0.1 } else { 0.4 },
            "OSINT and passive recon completed".to_string(),
        ),
        KillChainPhase::Weaponization => (
            vec!["T1587.001 Malware Development".to_string()],
            vec![],
            0.0,
            "Payload compiled offline; no network activity".to_string(),
        ),
        KillChainPhase::Delivery => (
            vec!["T1566.001 Spearphishing Attachment".to_string()],
            vec!["Email with macro-enabled attachment".to_string()],
            if config.stealth_mode { 0.2 } else { 0.5 },
            "Phishing email delivered to target".to_string(),
        ),
        KillChainPhase::Exploitation => (
            vec![
                "T1059.001 PowerShell".to_string(),
                "T1204.002 User Execution".to_string(),
            ],
            vec!["powershell.exe spawned by winword.exe".to_string()],
            if config.stealth_mode { 0.3 } else { 0.7 },
            "Macro payload executed in target environment".to_string(),
        ),
        KillChainPhase::Installation => (
            vec!["T1547.001 Registry Run Keys".to_string()],
            vec![
                "Registry modification: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
                    .to_string(),
            ],
            if config.stealth_mode { 0.2 } else { 0.5 },
            "Persistence established via registry run key".to_string(),
        ),
        KillChainPhase::CommandAndControl => (
            vec!["T1071.001 Web Protocols".to_string()],
            vec!["HTTPS beacon to C2 every 60s".to_string()],
            if config.stealth_mode { 0.15 } else { 0.4 },
            "HTTPS C2 channel established with jitter".to_string(),
        ),
        KillChainPhase::ActionsOnObjectives => (
            vec!["T1041 Exfiltration Over C2".to_string()],
            vec!["Large encrypted upload to C2".to_string()],
            if config.stealth_mode { 0.25 } else { 0.6 },
            "Target data staged and exfiltrated".to_string(),
        ),
    };

    PhaseResult {
        phase: phase.clone(),
        success: true,
        techniques_executed: techniques,
        iocs_generated: iocs,
        detection_likelihood: detection,
        notes,
    }
}
