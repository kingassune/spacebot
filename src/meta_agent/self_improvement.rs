//! Self-improvement cycle management for security skills.

use chrono::{DateTime, Utc};

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
