//! Blue team defensive operations framework.

pub mod detection;
pub mod forensics;
pub mod hardening;
pub mod incident_response;
pub mod malware_analysis;
pub mod monitoring;
pub mod siem_soar;
pub mod threat_hunting;
pub mod threat_intel;

use incident_response::Severity;

/// Central orchestration handle for blue team capabilities.
///
/// Holds configuration and delegates to the sub-modules for detection,
/// forensics, threat hunting, threat intelligence, malware analysis, and
/// SIEM/SOAR integration.
#[derive(Debug, Clone)]
pub struct BlueTeamEngine {
    pub org_name: String,
    pub default_severity: Severity,
    pub output_dir: String,
}

impl BlueTeamEngine {
    /// Create a new engine with the given organisation name and output directory.
    pub fn new(org_name: &str, output_dir: &str) -> Self {
        Self {
            org_name: org_name.to_string(),
            default_severity: Severity::Medium,
            output_dir: output_dir.to_string(),
        }
    }

    /// Build a default incident response playbook for the configured severity.
    pub fn default_ir_playbook(&self) -> incident_response::IrPlaybook {
        incident_response::generate_ir_playbook(&self.default_severity)
    }

    /// Open a new forensics case under this engine's output directory.
    pub fn new_forensics_case(&self, case_id: &str, examiner: &str) -> forensics::ForensicsCase {
        let config = forensics::ForensicsConfig {
            case_id: case_id.to_string(),
            examiner: examiner.to_string(),
            evidence_sources: Vec::new(),
            output_dir: self.output_dir.clone(),
        };
        forensics::ForensicsCase::new(config)
    }
}
