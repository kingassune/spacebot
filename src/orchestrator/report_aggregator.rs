//! Report aggregator for merging and deduplicating findings across all modules.
//!
//! Merges findings from red team, blue team, pentest, exploit engine, and
//! blockchain security into a unified assessment report with deduplication.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Severity level for a deduplicated finding.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum FindingSeverity {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

impl FindingSeverity {
    /// Parse from a string (case-insensitive).
    pub fn parse(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "critical" => FindingSeverity::Critical,
            "high" => FindingSeverity::High,
            "medium" | "moderate" => FindingSeverity::Medium,
            "low" => FindingSeverity::Low,
            _ => FindingSeverity::Informational,
        }
    }
}

/// A raw finding contributed by a security module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawFinding {
    /// Unique identifier from the source module.
    pub id: String,
    /// Source module name (e.g. "red_team", "blockchain").
    pub source_module: String,
    /// Short title.
    pub title: String,
    /// Severity string as reported by the module.
    pub severity: String,
    /// Detailed description.
    pub description: String,
    /// Affected target or asset.
    pub affected_target: String,
    /// Recommended remediation.
    pub remediation: String,
    /// Optional CVSS score.
    pub cvss_score: Option<f32>,
    /// Optional CVE identifier.
    pub cve_id: Option<String>,
    /// Timestamp when the finding was produced.
    pub discovered_at: DateTime<Utc>,
}

/// A deduplicated, enriched finding in the unified report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnifiedFinding {
    /// Unique identifier in the aggregated report.
    pub id: String,
    /// Normalised severity.
    pub severity: FindingSeverity,
    /// Short title.
    pub title: String,
    /// Description (may be synthesised from multiple sources).
    pub description: String,
    /// Affected target.
    pub affected_target: String,
    /// Remediation guidance.
    pub remediation: String,
    /// Source modules that contributed this finding.
    pub source_modules: Vec<String>,
    /// Original raw finding IDs that were merged into this entry.
    pub merged_from: Vec<String>,
    /// CVSS score (highest across merged findings).
    pub cvss_score: Option<f32>,
    /// CVE identifier if any merged finding had one.
    pub cve_id: Option<String>,
    /// Timestamp of the earliest discovery.
    pub first_discovered_at: DateTime<Utc>,
}

/// Metadata about an assessment used in the report header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssessmentMetadata {
    /// Unique assessment identifier.
    pub assessment_id: String,
    /// Target organisation or environment.
    pub target: String,
    /// Operator or team name.
    pub operator: String,
    /// Assessment start timestamp.
    pub started_at: DateTime<Utc>,
    /// Assessment end timestamp.
    pub completed_at: DateTime<Utc>,
    /// Modules that contributed to this assessment.
    pub modules_run: Vec<String>,
}

/// Full unified assessment report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssessmentReport {
    /// Assessment metadata.
    pub metadata: AssessmentMetadata,
    /// Deduplicated, severity-sorted findings.
    pub findings: Vec<UnifiedFinding>,
    /// Total finding counts by severity.
    pub severity_counts: HashMap<String, usize>,
    /// Executive summary text.
    pub executive_summary: String,
    /// Prioritised remediation recommendations.
    pub remediation_plan: Vec<String>,
}

impl AssessmentReport {
    /// Return findings filtered by minimum severity.
    pub fn findings_at_or_above(&self, min_severity: &FindingSeverity) -> Vec<&UnifiedFinding> {
        self.findings
            .iter()
            .filter(|f| &f.severity >= min_severity)
            .collect()
    }

    /// Return findings from a specific source module.
    pub fn findings_from_module(&self, module: &str) -> Vec<&UnifiedFinding> {
        self.findings
            .iter()
            .filter(|f| f.source_modules.iter().any(|m| m == module))
            .collect()
    }
}

/// Aggregates and deduplicates findings from multiple modules.
#[derive(Debug, Clone, Default)]
pub struct ReportAggregator {
    raw_findings: Vec<RawFinding>,
}

impl ReportAggregator {
    /// Create a new empty aggregator.
    pub fn new() -> Self {
        Self::default()
    }

    /// Ingest raw findings from a source module.
    pub fn ingest(&mut self, findings: Vec<RawFinding>) {
        self.raw_findings.extend(findings);
    }

    /// Deduplicate by title+target similarity, then build the unified report.
    pub fn aggregate(&self, metadata: AssessmentMetadata) -> AssessmentReport {
        // Group findings by normalised title key.
        let mut groups: HashMap<String, Vec<&RawFinding>> = HashMap::new();
        for finding in &self.raw_findings {
            let key = normalise_title_key(&finding.title, &finding.affected_target);
            groups.entry(key).or_default().push(finding);
        }

        let mut unified: Vec<UnifiedFinding> = groups
            .into_values()
            .map(|group| merge_group(&group))
            .collect();

        // Sort by severity descending.
        unified.sort_by(|a, b| b.severity.cmp(&a.severity));

        // Count by severity.
        let mut severity_counts: HashMap<String, usize> = HashMap::new();
        for f in &unified {
            *severity_counts
                .entry(format!("{:?}", f.severity))
                .or_default() += 1;
        }

        let critical = severity_counts.get("Critical").copied().unwrap_or(0);
        let high = severity_counts.get("High").copied().unwrap_or(0);

        let executive_summary = format!(
            "Assessment '{}' against '{}' completed. {} unique findings identified ({} Critical, {} High). \
             Modules executed: {}.",
            metadata.assessment_id,
            metadata.target,
            unified.len(),
            critical,
            high,
            metadata.modules_run.join(", ")
        );

        let remediation_plan: Vec<String> = unified
            .iter()
            .filter(|f| f.severity >= FindingSeverity::High)
            .map(|f| format!("[{:?}] {} — {}", f.severity, f.title, f.remediation))
            .collect();

        AssessmentReport {
            metadata,
            findings: unified,
            severity_counts,
            executive_summary,
            remediation_plan,
        }
    }

    /// Total number of raw findings ingested.
    pub fn raw_count(&self) -> usize {
        self.raw_findings.len()
    }
}

/// Normalise a finding title and target into a deduplication key.
fn normalise_title_key(title: &str, target: &str) -> String {
    format!(
        "{}::{}",
        title.to_lowercase().trim().replace(' ', "-"),
        target.to_lowercase().trim()
    )
}

/// Merge a group of related raw findings into a single unified finding.
fn merge_group(group: &[&RawFinding]) -> UnifiedFinding {
    let primary = group[0];
    let source_modules: Vec<String> = {
        let mut modules: Vec<String> = group.iter().map(|f| f.source_module.clone()).collect();
        modules.dedup();
        modules
    };
    let merged_from: Vec<String> = group.iter().map(|f| f.id.clone()).collect();
    let highest_cvss = group
        .iter()
        .filter_map(|f| f.cvss_score)
        .fold(None::<f32>, |acc, s| Some(acc.map_or(s, |a: f32| a.max(s))));
    let cve_id = group.iter().find_map(|f| f.cve_id.clone());
    let earliest = group
        .iter()
        .map(|f| f.discovered_at)
        .min()
        .unwrap_or_else(Utc::now);
    let severity = group
        .iter()
        .map(|f| FindingSeverity::parse(&f.severity))
        .max()
        .unwrap_or(FindingSeverity::Informational);

    UnifiedFinding {
        id: format!("JAMES-{}", uuid::Uuid::new_v4().simple()),
        severity,
        title: primary.title.clone(),
        description: primary.description.clone(),
        affected_target: primary.affected_target.clone(),
        remediation: primary.remediation.clone(),
        source_modules,
        merged_from,
        cvss_score: highest_cvss,
        cve_id,
        first_discovered_at: earliest,
    }
}
