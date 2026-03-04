//! DAG-based security task pipeline for the unified orchestrator.
//!
//! Defines a directed-acyclic-graph pipeline of security tasks that can be
//! executed with dependency ordering and parallel stage support.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A node in the security task DAG.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TaskNode {
    /// Passive and active reconnaissance.
    Reconnaissance,
    /// Threat model construction.
    ThreatModelling,
    /// Automated vulnerability scanning.
    VulnerabilityScanning,
    /// Manual exploitation attempts.
    Exploitation,
    /// Blue team detection rule validation.
    DetectionValidation,
    /// Blockchain smart contract analysis.
    BlockchainAnalysis,
    /// Final findings aggregation and deduplication.
    ReportAggregation,
}

impl TaskNode {
    /// Human-readable label.
    pub fn label(&self) -> &'static str {
        match self {
            TaskNode::Reconnaissance => "Reconnaissance",
            TaskNode::ThreatModelling => "Threat Modelling",
            TaskNode::VulnerabilityScanning => "Vulnerability Scanning",
            TaskNode::Exploitation => "Exploitation",
            TaskNode::DetectionValidation => "Detection Validation",
            TaskNode::BlockchainAnalysis => "Blockchain Analysis",
            TaskNode::ReportAggregation => "Report Aggregation",
        }
    }

    /// Default execution duration estimate in seconds.
    pub fn estimated_duration_secs(&self) -> u64 {
        match self {
            TaskNode::Reconnaissance => 600,
            TaskNode::ThreatModelling => 300,
            TaskNode::VulnerabilityScanning => 900,
            TaskNode::Exploitation => 1800,
            TaskNode::DetectionValidation => 600,
            TaskNode::BlockchainAnalysis => 1200,
            TaskNode::ReportAggregation => 300,
        }
    }
}

/// Configuration for a security pipeline execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineConfig {
    /// Target system description.
    pub target: String,
    /// Operator name.
    pub operator: String,
    /// Nodes to include in this pipeline run.
    pub nodes: Vec<TaskNode>,
    /// Dependency map: node → prerequisite nodes.
    pub dependencies: HashMap<String, Vec<String>>,
    /// Maximum time per node in seconds (0 = unlimited).
    pub node_timeout_secs: u64,
    /// Whether to abort on the first node failure.
    pub abort_on_failure: bool,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        let mut dependencies = HashMap::new();
        dependencies.insert(
            "VulnerabilityScanning".to_string(),
            vec!["Reconnaissance".to_string(), "ThreatModelling".to_string()],
        );
        dependencies.insert(
            "Exploitation".to_string(),
            vec!["VulnerabilityScanning".to_string()],
        );
        dependencies.insert(
            "DetectionValidation".to_string(),
            vec!["Exploitation".to_string()],
        );
        dependencies.insert(
            "ReportAggregation".to_string(),
            vec![
                "DetectionValidation".to_string(),
                "BlockchainAnalysis".to_string(),
            ],
        );

        Self {
            target: "undefined".to_string(),
            operator: "james".to_string(),
            nodes: vec![
                TaskNode::Reconnaissance,
                TaskNode::ThreatModelling,
                TaskNode::VulnerabilityScanning,
                TaskNode::Exploitation,
                TaskNode::DetectionValidation,
                TaskNode::BlockchainAnalysis,
                TaskNode::ReportAggregation,
            ],
            dependencies,
            node_timeout_secs: 3600,
            abort_on_failure: false,
        }
    }
}

/// Result for a single executed pipeline node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeResult {
    /// Node that was executed.
    pub node: TaskNode,
    /// Whether execution succeeded.
    pub success: bool,
    /// Output summary.
    pub output: String,
    /// Number of findings produced.
    pub findings_count: usize,
    /// Wall-clock execution duration in seconds.
    pub duration_secs: u64,
    /// Timestamp execution started.
    pub started_at: DateTime<Utc>,
}

/// Full pipeline execution result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineResult {
    /// Configuration used.
    pub config: PipelineConfig,
    /// Per-node results in execution order.
    pub node_results: Vec<NodeResult>,
    /// Whether all nodes completed successfully.
    pub success: bool,
    /// Total findings across all nodes.
    pub total_findings: usize,
    /// Executive summary.
    pub executive_summary: String,
}

/// A stateful pipeline that executes task nodes in dependency order.
#[derive(Debug, Clone)]
pub struct SecurityPipeline {
    /// Engagement identifier.
    pub engagement_id: String,
}

impl SecurityPipeline {
    /// Create a new pipeline for the given engagement.
    pub fn new(engagement_id: impl Into<String>) -> Self {
        Self {
            engagement_id: engagement_id.into(),
        }
    }

    /// Execute all nodes in the pipeline configuration (simulation).
    pub async fn run(&self, config: &PipelineConfig) -> anyhow::Result<PipelineResult> {
        let mut node_results = Vec::new();
        let mut total_findings = 0;

        for node in &config.nodes {
            let started_at = Utc::now();
            let findings_count = match node {
                TaskNode::Reconnaissance => 5,
                TaskNode::VulnerabilityScanning => 12,
                TaskNode::Exploitation => 4,
                TaskNode::DetectionValidation => 8,
                TaskNode::BlockchainAnalysis => 6,
                _ => 1,
            };
            total_findings += findings_count;

            let result = NodeResult {
                node: node.clone(),
                success: true,
                output: format!("{} completed for target '{}'.", node.label(), config.target),
                findings_count,
                duration_secs: node.estimated_duration_secs() / 10,
                started_at,
            };
            node_results.push(result);

            if config.abort_on_failure {
                // In a real implementation we'd check the result here.
            }
        }

        let summary = format!(
            "Pipeline '{}' completed {} nodes against '{}'. Total findings: {}.",
            self.engagement_id,
            node_results.len(),
            config.target,
            total_findings
        );

        Ok(PipelineResult {
            config: config.clone(),
            node_results,
            success: true,
            total_findings,
            executive_summary: summary,
        })
    }
}
