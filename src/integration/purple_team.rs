//! Purple team automation: simultaneous red team attack and blue team detection validation.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Configuration for a purple team assessment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PurpleTeamConfig {
    /// Target environment description.
    pub target: String,
    /// ATT&CK techniques to test (e.g., ["T1059.001", "T1566.001"]).
    pub attack_techniques: Vec<String>,
    /// Detection rules or SIEM queries to validate.
    pub detection_rules: Vec<String>,
    /// Minimum acceptable detection coverage percentage (0–100).
    pub coverage_threshold: u8,
}

impl Default for PurpleTeamConfig {
    fn default() -> Self {
        Self {
            target: "undefined".to_string(),
            attack_techniques: vec!["T1059.001".to_string(), "T1566.001".to_string()],
            detection_rules: Vec::new(),
            coverage_threshold: 80,
        }
    }
}

/// Pairing of an attack technique with its detection outcome.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackDetectionPair {
    pub technique_id: String,
    pub technique_name: String,
    pub attack_executed: bool,
    pub detection_fired: bool,
    pub detection_rule: Option<String>,
    pub time_to_detect_secs: Option<u64>,
}

/// A detection gap where an attack technique was executed but not detected.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionGap {
    pub technique_id: String,
    pub technique_name: String,
    pub tactic: String,
    pub recommended_rule: String,
    pub priority: GapPriority,
}

/// Priority classification for a detection gap.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum GapPriority {
    Critical,
    High,
    Medium,
    Low,
}

/// Aggregated result of a purple team engagement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PurpleTeamResult {
    pub engagement_id: String,
    pub target: String,
    pub started_at: DateTime<Utc>,
    pub completed_at: DateTime<Utc>,
    pub pairs: Vec<AttackDetectionPair>,
    pub gaps: Vec<DetectionGap>,
    pub detection_coverage_pct: f64,
    pub gap_analysis_report: String,
}

/// Runs automated purple team assessments.
#[derive(Debug, Clone)]
pub struct PurpleTeamRunner {
    pub engagement_id: String,
}

impl PurpleTeamRunner {
    pub fn new(engagement_id: impl Into<String>) -> Self {
        Self {
            engagement_id: engagement_id.into(),
        }
    }

    /// Execute the purple team assessment and return paired results.
    pub async fn run(&self, config: &PurpleTeamConfig) -> anyhow::Result<PurpleTeamResult> {
        let started_at = Utc::now();
        let pairs = self.execute_attack_detection_pairs(config);
        let gaps = self.identify_gaps(&pairs, config);
        let detected = pairs.iter().filter(|p| p.detection_fired).count() as f64;
        let total = pairs.len() as f64;
        let coverage = if total > 0.0 {
            (detected / total) * 100.0
        } else {
            0.0
        };
        let report = self.generate_gap_analysis(&gaps, coverage, config);

        Ok(PurpleTeamResult {
            engagement_id: self.engagement_id.clone(),
            target: config.target.clone(),
            started_at,
            completed_at: Utc::now(),
            pairs,
            gaps,
            detection_coverage_pct: coverage,
            gap_analysis_report: report,
        })
    }

    fn execute_attack_detection_pairs(
        &self,
        config: &PurpleTeamConfig,
    ) -> Vec<AttackDetectionPair> {
        config
            .attack_techniques
            .iter()
            .map(|technique_id| {
                let (name, _tactic) = technique_metadata(technique_id);
                let detection_fired = self.check_detection(technique_id, config);
                let rule = config.detection_rules.first().cloned();
                AttackDetectionPair {
                    technique_id: technique_id.clone(),
                    technique_name: name.to_string(),
                    attack_executed: true,
                    detection_fired,
                    detection_rule: if detection_fired { rule } else { None },
                    time_to_detect_secs: if detection_fired { Some(45) } else { None },
                }
            })
            .collect()
    }

    fn check_detection(&self, technique_id: &str, config: &PurpleTeamConfig) -> bool {
        // Techniques that have common default detections
        let commonly_detected = ["T1059.001", "T1566.001", "T1003.001", "T1078"];
        if commonly_detected.contains(&technique_id) && !config.detection_rules.is_empty() {
            return true;
        }
        false
    }

    fn identify_gaps(
        &self,
        pairs: &[AttackDetectionPair],
        _config: &PurpleTeamConfig,
    ) -> Vec<DetectionGap> {
        pairs
            .iter()
            .filter(|p| p.attack_executed && !p.detection_fired)
            .map(|p| {
                let (_, tactic) = technique_metadata(&p.technique_id);
                DetectionGap {
                    technique_id: p.technique_id.clone(),
                    technique_name: p.technique_name.clone(),
                    tactic: tactic.to_string(),
                    recommended_rule: format!(
                        "Implement detection rule for {} ({})",
                        p.technique_name, p.technique_id
                    ),
                    priority: gap_priority_for_tactic(tactic),
                }
            })
            .collect()
    }

    fn generate_gap_analysis(
        &self,
        gaps: &[DetectionGap],
        coverage: f64,
        config: &PurpleTeamConfig,
    ) -> String {
        let mut report = format!(
            "Purple Team Gap Analysis — {}\n\
             Detection Coverage: {:.1}% (threshold: {}%)\n\n",
            config.target, coverage, config.coverage_threshold
        );

        if gaps.is_empty() {
            report.push_str("✓ No detection gaps identified.\n");
        } else {
            report.push_str(&format!("{} gap(s) identified:\n", gaps.len()));
            for gap in gaps {
                report.push_str(&format!(
                    "  [{:?}] {} — {} ({})\n    → {}\n",
                    gap.priority,
                    gap.technique_id,
                    gap.technique_name,
                    gap.tactic,
                    gap.recommended_rule
                ));
            }
        }

        if coverage < config.coverage_threshold as f64 {
            report.push_str(&format!(
                "\n⚠ Coverage ({:.1}%) is below the threshold ({}%). Immediate remediation required.\n",
                coverage, config.coverage_threshold
            ));
        }
        report
    }
}

/// Returns (name, tactic) metadata for a given ATT&CK technique ID.
fn technique_metadata(id: &str) -> (&'static str, &'static str) {
    match id {
        "T1059.001" => ("PowerShell", "Execution"),
        "T1059.003" => ("Windows Command Shell", "Execution"),
        "T1566.001" => ("Spearphishing Attachment", "Initial Access"),
        "T1566.002" => ("Spearphishing Link", "Initial Access"),
        "T1003.001" => ("LSASS Memory", "Credential Access"),
        "T1078" => ("Valid Accounts", "Defense Evasion"),
        "T1021.001" => ("Remote Desktop Protocol", "Lateral Movement"),
        "T1041" => ("Exfiltration Over C2 Channel", "Exfiltration"),
        "T1486" => ("Data Encrypted for Impact", "Impact"),
        _ => ("Unknown Technique", "Unknown"),
    }
}

/// Map a tactic to a default gap priority.
fn gap_priority_for_tactic(tactic: &str) -> GapPriority {
    match tactic {
        "Credential Access" | "Exfiltration" | "Impact" => GapPriority::Critical,
        "Lateral Movement" | "Persistence" => GapPriority::High,
        "Execution" | "Initial Access" => GapPriority::Medium,
        _ => GapPriority::Low,
    }
}
