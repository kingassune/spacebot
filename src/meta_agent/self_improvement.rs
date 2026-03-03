//! Self-improvement cycle management for security skills.

use chrono::{DateTime, Utc};

/// Outcome of a task execution for tracking purposes.
#[derive(Debug, Clone, PartialEq)]
pub enum TaskOutcomeKind {
    Success,
    Failure,
    Partial,
}

/// Recorded result of a task execution.
#[derive(Debug, Clone)]
pub struct TaskOutcome {
    pub task_id: String,
    pub kind: TaskOutcomeKind,
    pub score: f64,
    pub error: Option<String>,
    pub recorded_at: DateTime<Utc>,
}

/// A concrete suggestion for improving performance or coverage.
#[derive(Debug, Clone)]
pub struct ImprovementSuggestion {
    pub id: String,
    pub description: String,
    pub target_task_pattern: String,
    pub expected_impact: f64,
    pub parameter_changes: Vec<(String, String)>,
}

/// Tracks outcomes and derives improvement plans.
#[derive(Debug, Clone)]
pub struct SelfImprover {
    outcomes: Vec<TaskOutcome>,
}

impl SelfImprover {
    pub fn new() -> Self {
        Self {
            outcomes: Vec::new(),
        }
    }

    /// Record the outcome of a completed task.
    pub fn record_outcome(&mut self, task_id: &str, outcome: &TaskOutcome) {
        let mut stored = outcome.clone();
        stored.task_id = task_id.to_string();
        self.outcomes.push(stored);
    }

    /// Analyze recorded outcomes for recurring failure patterns.
    pub fn analyze_patterns(&self) -> Vec<ImprovementSuggestion> {
        let mut suggestions = Vec::new();

        let failures: Vec<&TaskOutcome> = self
            .outcomes
            .iter()
            .filter(|o| o.kind == TaskOutcomeKind::Failure)
            .collect();

        if failures.len() >= 3 {
            suggestions.push(ImprovementSuggestion {
                id: format!("pattern-{}", Utc::now().timestamp()),
                description: format!(
                    "Recurring failures detected ({} failures out of {} outcomes). Consider tuning parameters.",
                    failures.len(),
                    self.outcomes.len()
                ),
                target_task_pattern: "all".to_string(),
                expected_impact: 0.20,
                parameter_changes: vec![
                    ("max_retries".to_string(), "3".to_string()),
                    ("timeout_secs".to_string(), "120".to_string()),
                ],
            });
        }

        let avg_score: f64 = if self.outcomes.is_empty() {
            0.0
        } else {
            self.outcomes.iter().map(|o| o.score).sum::<f64>() / self.outcomes.len() as f64
        };

        if avg_score < 0.7 && !self.outcomes.is_empty() {
            suggestions.push(ImprovementSuggestion {
                id: format!("score-{}", Utc::now().timestamp()),
                description: format!(
                    "Average task score {avg_score:.2} is below 0.70. Review prompts and tool configurations."
                ),
                target_task_pattern: "low-score".to_string(),
                expected_impact: 0.15,
                parameter_changes: vec![
                    ("temperature".to_string(), "0.2".to_string()),
                ],
            });
        }

        suggestions
    }

    /// Apply a suggestion by logging its parameter changes.
    pub fn apply_suggestion(&self, suggestion: &ImprovementSuggestion) -> anyhow::Result<()> {
        anyhow::ensure!(
            !suggestion.parameter_changes.is_empty(),
            "suggestion has no parameter changes to apply"
        );
        // In a full system this would write to a config store.
        // Here we validate and return Ok to indicate intent was processed.
        Ok(())
    }
}

impl Default for SelfImprover {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum ImprovementCategory {
    Accuracy,
    Coverage,
    Performance,
    Documentation,
    Testing,
    Integration,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CycleStatus {
    Review,
    Implementing,
    Testing,
    Deployed,
    Cancelled,
}

#[derive(Debug, Clone)]
pub struct QualityMetrics {
    pub skill_name: String,
    pub success_rate: f64,
    pub false_positive_rate: f64,
    pub coverage_score: f64,
    pub performance_score: f64,
    pub last_evaluated: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct Improvement {
    pub description: String,
    pub expected_impact: f64,
    pub effort_level: String,
    pub category: ImprovementCategory,
}

#[derive(Debug, Clone)]
pub struct ImprovementCycle {
    pub cycle_id: String,
    pub skill_name: String,
    pub started_at: DateTime<Utc>,
    pub metrics_before: QualityMetrics,
    pub improvements_proposed: Vec<Improvement>,
    pub status: CycleStatus,
}

pub fn evaluate_skill_quality(skill_name: &str, success_rate: f64, fp_rate: f64) -> QualityMetrics {
    // Coverage and performance are derived from the provided rates.
    let coverage_score = (success_rate * 0.8).min(1.0);
    let performance_score = ((1.0 - fp_rate) * 0.9).min(1.0);
    QualityMetrics {
        skill_name: skill_name.to_string(),
        success_rate,
        false_positive_rate: fp_rate,
        coverage_score,
        performance_score,
        last_evaluated: Utc::now(),
    }
}

pub fn propose_improvements(metrics: &QualityMetrics) -> Vec<Improvement> {
    let mut improvements = Vec::new();

    if metrics.success_rate < 0.8 {
        improvements.push(Improvement {
            description: format!(
                "Improve detection logic for '{}': success rate {:.0}% is below threshold",
                metrics.skill_name,
                metrics.success_rate * 100.0
            ),
            expected_impact: 0.15,
            effort_level: "medium".to_string(),
            category: ImprovementCategory::Accuracy,
        });
    }

    if metrics.false_positive_rate > 0.1 {
        improvements.push(Improvement {
            description: format!(
                "Reduce false positives for '{}': FP rate {:.0}% exceeds 10%",
                metrics.skill_name,
                metrics.false_positive_rate * 100.0
            ),
            expected_impact: 0.20,
            effort_level: "high".to_string(),
            category: ImprovementCategory::Accuracy,
        });
    }

    if metrics.coverage_score < 0.7 {
        improvements.push(Improvement {
            description: format!(
                "Expand coverage for '{}': coverage score {:.0}% is below 70%",
                metrics.skill_name,
                metrics.coverage_score * 100.0
            ),
            expected_impact: 0.25,
            effort_level: "high".to_string(),
            category: ImprovementCategory::Coverage,
        });
    }

    improvements
}

pub fn start_improvement_cycle(skill_name: String, metrics: QualityMetrics) -> ImprovementCycle {
    let proposals = propose_improvements(&metrics);
    ImprovementCycle {
        cycle_id: format!("{}-{}", skill_name, Utc::now().timestamp()),
        skill_name,
        started_at: Utc::now(),
        metrics_before: metrics,
        improvements_proposed: proposals,
        status: CycleStatus::Review,
    }
}

pub fn advance_cycle(cycle: &mut ImprovementCycle) {
    cycle.status = match cycle.status {
        CycleStatus::Review => CycleStatus::Implementing,
        CycleStatus::Implementing => CycleStatus::Testing,
        CycleStatus::Testing => CycleStatus::Deployed,
        CycleStatus::Deployed | CycleStatus::Cancelled => return,
    };
}
