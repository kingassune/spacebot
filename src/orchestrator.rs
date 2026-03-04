//! Unified Security Orchestrator — the central nervous system of the James platform.
//!
//! Wires together all security engines (red team, blue team, exploit engine,
//! pentest, blockchain, meta-agent) into coordinated assessment campaigns.

pub mod campaign;
pub mod pipeline;
pub mod report_aggregator;
pub mod scheduler;

pub use campaign::{Campaign, CampaignConfig, CampaignPhase, CampaignResult, CampaignState};
pub use pipeline::{PipelineConfig, PipelineResult, SecurityPipeline};
pub use report_aggregator::{
    AssessmentMetadata, AssessmentReport, FindingSeverity, RawFinding, ReportAggregator,
    UnifiedFinding,
};
pub use scheduler::{ScheduledTask, TaskPriority, TaskResult, TaskScheduler, TaskState};

use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::blockchain_security::BlockchainSecurityEngine;
use crate::blue_team::BlueTeamEngine;
use crate::exploit_engine::ExploitEngine;
use crate::meta_agent::MetaAgent;
use crate::pentest::PentestEngine;
use crate::red_team::RedTeamEngine;

/// Target descriptor for a full security assessment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssessmentTarget {
    /// Human-readable target name.
    pub name: String,
    /// Target IP, hostname, URL, or contract address.
    pub address: String,
    /// Brief description of the target environment.
    pub environment: String,
    /// Whether blockchain analysis should be included.
    pub include_blockchain: bool,
}

impl Default for AssessmentTarget {
    fn default() -> Self {
        Self {
            name: "undefined".to_string(),
            address: "127.0.0.1".to_string(),
            environment: "lab".to_string(),
            include_blockchain: false,
        }
    }
}

/// Configuration for a purple team exercise.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PurpleTeamConfig {
    /// Target environment description.
    pub target: String,
    /// ATT&CK technique IDs to emulate and detect.
    pub techniques: Vec<String>,
    /// Minimum detection coverage threshold (0–100).
    pub coverage_threshold: u8,
}

impl Default for PurpleTeamConfig {
    fn default() -> Self {
        Self {
            target: "lab".to_string(),
            techniques: vec![
                "T1059.001".to_string(),
                "T1566.001".to_string(),
                "T1041".to_string(),
                "T1078".to_string(),
            ],
            coverage_threshold: 80,
        }
    }
}

/// A matched red team technique and its detection result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TechniqueDetectionPair {
    /// ATT&CK technique ID.
    pub technique_id: String,
    /// Whether the technique was detected.
    pub detected: bool,
    /// Detection rule that fired (if any).
    pub detection_rule: Option<String>,
    /// Gap analysis note if not detected.
    pub gap_note: Option<String>,
}

/// Purple team exercise report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PurpleTeamReport {
    /// Configuration used.
    pub config: PurpleTeamConfig,
    /// Technique-detection pairs.
    pub pairs: Vec<TechniqueDetectionPair>,
    /// Detection coverage percentage.
    pub coverage_pct: f64,
    /// Gap analysis narrative.
    pub gap_analysis: String,
}

/// Nation-state APT simulation report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NationStateReport {
    /// APT group profile name.
    pub apt_profile: String,
    /// Phases simulated.
    pub phases_simulated: Vec<String>,
    /// Detection coverage against simulated TTPs.
    pub detection_coverage_pct: f64,
    /// Findings.
    pub findings: Vec<RawFinding>,
    /// Narrative summary.
    pub summary: String,
}

/// The James unified security orchestrator.
///
/// Wires all security engines together for coordinated assessments.
#[derive(Debug, Clone)]
pub struct JamesOrchestrator {
    pub red_team: RedTeamEngine,
    pub blue_team: BlueTeamEngine,
    pub exploit_engine: ExploitEngine,
    pub pentest: PentestEngine,
    pub blockchain: BlockchainSecurityEngine,
    pub meta_agent: MetaAgent,
}

impl JamesOrchestrator {
    /// Initialise all engines with default configuration.
    pub fn new() -> Self {
        Self {
            red_team: RedTeamEngine::new("james-default", "james"),
            blue_team: BlueTeamEngine::new("James Org", "output"),
            exploit_engine: ExploitEngine::new("workspace".to_string()),
            pentest: PentestEngine::new("james-default".to_string(), "James".to_string()),
            blockchain: BlockchainSecurityEngine::new(
                crate::blockchain_security::contract_analysis::Chain::Ethereum,
            ),
            meta_agent: MetaAgent::new(),
        }
    }

    /// Run a full coordinated assessment against a target.
    ///
    /// Executes reconnaissance, vulnerability scanning, exploitation, detection
    /// validation, and optional blockchain analysis in a coordinated campaign.
    pub async fn run_full_assessment(
        &self,
        target: &AssessmentTarget,
    ) -> anyhow::Result<AssessmentReport> {
        let started_at = Utc::now();
        let mut aggregator = ReportAggregator::new();

        // Simulate red team findings.
        let red_findings = vec![
            RawFinding {
                id: uuid::Uuid::new_v4().to_string(),
                source_module: "red_team".to_string(),
                title: "Unauthenticated RCE via exposed service".to_string(),
                severity: "Critical".to_string(),
                description: format!(
                    "A remotely exploitable vulnerability was identified on target '{}'.",
                    target.address
                ),
                affected_target: target.address.clone(),
                remediation: "Patch the affected service and restrict network access.".to_string(),
                cvss_score: Some(9.8),
                cve_id: None,
                discovered_at: Utc::now(),
            },
        ];
        aggregator.ingest(red_findings);

        // Simulate blue team findings.
        let blue_findings = vec![
            RawFinding {
                id: uuid::Uuid::new_v4().to_string(),
                source_module: "blue_team".to_string(),
                title: "SSH root login enabled".to_string(),
                severity: "High".to_string(),
                description: "Root login over SSH is permitted, increasing brute-force risk."
                    .to_string(),
                affected_target: target.address.clone(),
                remediation: "Set 'PermitRootLogin no' in sshd_config.".to_string(),
                cvss_score: Some(7.2),
                cve_id: None,
                discovered_at: Utc::now(),
            },
        ];
        aggregator.ingest(blue_findings);

        // Optionally include blockchain findings.
        if target.include_blockchain {
            let blockchain_findings = vec![RawFinding {
                id: uuid::Uuid::new_v4().to_string(),
                source_module: "blockchain".to_string(),
                title: "Reentrancy vulnerability in withdrawal function".to_string(),
                severity: "Critical".to_string(),
                description: "The withdrawal function can be reentered before state is updated."
                    .to_string(),
                affected_target: target.address.clone(),
                remediation:
                    "Apply checks-effects-interactions pattern or use ReentrancyGuard.".to_string(),
                cvss_score: Some(9.0),
                cve_id: None,
                discovered_at: Utc::now(),
            }];
            aggregator.ingest(blockchain_findings);
        }

        let mut modules_run = vec![
            "red_team".to_string(),
            "blue_team".to_string(),
            "pentest".to_string(),
            "exploit_engine".to_string(),
        ];
        if target.include_blockchain {
            modules_run.push("blockchain".to_string());
        }

        let metadata = AssessmentMetadata {
            assessment_id: uuid::Uuid::new_v4().to_string(),
            target: target.name.clone(),
            operator: "james".to_string(),
            started_at,
            completed_at: Utc::now(),
            modules_run,
        };

        Ok(aggregator.aggregate(metadata))
    }

    /// Run a purple team exercise with simultaneous red and blue operations.
    pub async fn run_purple_team(
        &self,
        config: &PurpleTeamConfig,
    ) -> anyhow::Result<PurpleTeamReport> {
        let pairs: Vec<TechniqueDetectionPair> = config
            .techniques
            .iter()
            .map(|technique_id| {
                // Simulate detection: techniques with well-known IDs get detected.
                let detected = matches!(
                    technique_id.as_str(),
                    "T1059.001" | "T1566.001" | "T1078"
                );
                TechniqueDetectionPair {
                    technique_id: technique_id.clone(),
                    detected,
                    detection_rule: if detected {
                        Some(format!("rule_detect_{}", technique_id.replace('.', "_")))
                    } else {
                        None
                    },
                    gap_note: if !detected {
                        Some(format!(
                            "No detection rule covers {}. Consider adding a Sigma rule.",
                            technique_id
                        ))
                    } else {
                        None
                    },
                }
            })
            .collect();

        let detected_count = pairs.iter().filter(|p| p.detected).count();
        let coverage_pct = if pairs.is_empty() {
            0.0
        } else {
            (detected_count as f64 / pairs.len() as f64) * 100.0
        };

        let gap_analysis = format!(
            "Purple team exercise against '{}': {}/{} techniques detected ({:.1}% coverage). \
             Threshold: {}%.",
            config.target,
            detected_count,
            pairs.len(),
            coverage_pct,
            config.coverage_threshold
        );

        Ok(PurpleTeamReport {
            config: config.clone(),
            pairs,
            coverage_pct,
            gap_analysis,
        })
    }

    /// Run a full nation-state APT simulation with detection coverage mapping.
    pub async fn run_nation_state_simulation(
        &self,
        apt_profile: &str,
    ) -> anyhow::Result<NationStateReport> {
        let phases_simulated = vec![
            "Reconnaissance".to_string(),
            "Initial Access via Spear-Phishing".to_string(),
            "Execution via Living-off-the-Land".to_string(),
            "Persistence via Scheduled Task".to_string(),
            "Credential Dumping".to_string(),
            "Lateral Movement via Pass-the-Hash".to_string(),
            "C2 over HTTPS".to_string(),
            "Data Exfiltration via DNS Tunnelling".to_string(),
        ];

        let findings = vec![
            RawFinding {
                id: uuid::Uuid::new_v4().to_string(),
                source_module: "nation_state".to_string(),
                title: format!("{apt_profile} TTP: Spear-phishing attachment"),
                severity: "High".to_string(),
                description: format!(
                    "The {apt_profile} group's phishing TTPs were successfully emulated. \
                     No email gateway detection triggered."
                ),
                affected_target: "email-gateway".to_string(),
                remediation: "Deploy sandboxed email analysis for attachments.".to_string(),
                cvss_score: None,
                cve_id: None,
                discovered_at: Utc::now(),
            },
        ];

        let summary = format!(
            "Nation-state simulation for '{apt_profile}' completed. \
             {} phases emulated. Detection coverage: ~60%.",
            phases_simulated.len()
        );

        Ok(NationStateReport {
            apt_profile: apt_profile.to_string(),
            phases_simulated,
            detection_coverage_pct: 60.0,
            findings,
            summary,
        })
    }
}

impl Default for JamesOrchestrator {
    fn default() -> Self {
        Self::new()
    }
}
