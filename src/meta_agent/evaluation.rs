//! Evaluation criteria and scoring for security agents.

use chrono::Utc;

#[derive(Debug, Clone)]
pub struct EvaluationCriteria {
    pub name: String,
    pub description: String,
    pub weight: f64,
    pub min_score: f64,
    pub max_score: f64,
}

#[derive(Debug, Clone)]
pub struct EvaluationResult {
    pub criteria_name: String,
    pub score: f64,
    pub passed: bool,
    pub feedback: String,
}

#[derive(Debug, Clone)]
pub struct AgentEvaluation {
    pub agent_id: String,
    pub evaluated_at: chrono::DateTime<chrono::Utc>,
    pub criteria_results: Vec<EvaluationResult>,
    pub overall_score: f64,
    pub passed: bool,
}

pub fn evaluate_agent(
    agent_id: &str,
    criteria: &[EvaluationCriteria],
    scores: &[f64],
) -> AgentEvaluation {
    let criteria_results: Vec<EvaluationResult> = criteria
        .iter()
        .zip(scores.iter().chain(std::iter::repeat(&0.0)))
        .map(|(c, &score)| {
            let clamped = score.clamp(c.min_score, c.max_score);
            let passed = clamped >= (c.min_score + (c.max_score - c.min_score) * 0.6);
            EvaluationResult {
                criteria_name: c.name.clone(),
                score: clamped,
                passed,
                feedback: if passed {
                    format!("{}: score {:.2} meets requirements", c.name, clamped)
                } else {
                    format!(
                        "{}: score {:.2} is below the passing threshold",
                        c.name, clamped
                    )
                },
            }
        })
        .collect();

    let total_weight: f64 = criteria.iter().map(|c| c.weight).sum();
    let weighted_sum: f64 = criteria
        .iter()
        .zip(criteria_results.iter())
        .map(|(c, r)| {
            let range = c.max_score - c.min_score;
            let normalized = if range > 0.0 {
                (r.score - c.min_score) / range
            } else {
                0.0
            };
            normalized * c.weight
        })
        .sum();

    let overall_score = if total_weight > 0.0 {
        weighted_sum / total_weight
    } else {
        0.0
    };

    let passed = criteria_results.iter().all(|r| r.passed);

    AgentEvaluation {
        agent_id: agent_id.to_string(),
        evaluated_at: Utc::now(),
        criteria_results,
        overall_score,
        passed,
    }
}

pub fn default_security_criteria() -> Vec<EvaluationCriteria> {
    vec![
        EvaluationCriteria {
            name: "Detection Accuracy".to_string(),
            description: "Correctness of threat detections".to_string(),
            weight: 0.35,
            min_score: 0.0,
            max_score: 1.0,
        },
        EvaluationCriteria {
            name: "False Positive Rate".to_string(),
            description: "Rate of incorrect positive alerts".to_string(),
            weight: 0.25,
            min_score: 0.0,
            max_score: 1.0,
        },
        EvaluationCriteria {
            name: "Response Time".to_string(),
            description: "Speed of detection and response".to_string(),
            weight: 0.20,
            min_score: 0.0,
            max_score: 1.0,
        },
        EvaluationCriteria {
            name: "Coverage".to_string(),
            description: "Breadth of threat coverage".to_string(),
            weight: 0.20,
            min_score: 0.0,
            max_score: 1.0,
        },
    ]
}
