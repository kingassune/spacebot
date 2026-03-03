//! Learning engine for platform self-improvement from engagement results.

use std::collections::HashMap;

/// A recorded result from a completed security engagement.
#[derive(Debug, Clone)]
pub struct EngagementResult {
    /// Unique identifier for the engagement.
    pub engagement_id: String,
    /// Type of engagement (e.g. "red_team", "blockchain_audit").
    pub engagement_type: String,
    /// Target system or organisation.
    pub target: String,
    /// Whether the engagement achieved its primary objective.
    pub success: bool,
    /// Techniques employed, keyed by name.
    pub techniques_used: Vec<String>,
    /// Number of detections triggered by defensive tooling.
    pub detections_triggered: u32,
}

/// A correlation between a technique and a detection event.
#[derive(Debug, Clone)]
pub struct DetectionCorrelation {
    /// Technique that triggered the detection.
    pub technique: String,
    /// Number of times this technique triggered a detection.
    pub detection_count: u32,
    /// Number of times this technique was used in total.
    pub usage_count: u32,
    /// Detection rate (0.0–1.0).
    pub detection_rate: f64,
}

/// Recommendation produced by the learning engine.
#[derive(Debug, Clone)]
pub struct ImprovementRecommendation {
    /// Short title.
    pub title: String,
    /// Detailed description.
    pub description: String,
    /// Confidence in this recommendation (0.0–1.0).
    pub confidence: f64,
    /// Engagement types this applies to.
    pub applies_to: Vec<String>,
}

/// Learning engine that tracks technique effectiveness and detection correlations.
#[derive(Debug, Clone)]
pub struct LearningEngine {
    /// History of engagement results.
    pub engagement_history: Vec<EngagementResult>,
    /// Effectiveness scores per technique (0.0–1.0).
    pub technique_effectiveness: HashMap<String, f64>,
    /// Detection correlations per technique.
    pub detection_correlations: Vec<DetectionCorrelation>,
}

impl LearningEngine {
    /// Create a new empty learning engine.
    pub fn new() -> Self {
        Self {
            engagement_history: Vec::new(),
            technique_effectiveness: HashMap::new(),
            detection_correlations: Vec::new(),
        }
    }

    /// Record an engagement result and update internal models.
    pub fn record_engagement(&mut self, result: EngagementResult) {
        self.update_technique_scores_from_result(&result);
        self.update_detection_correlations(&result);
        self.engagement_history.push(result);
    }

    /// Analyse the effectiveness of all tracked techniques.
    ///
    /// Returns a sorted list of `(technique, effectiveness_score)` pairs.
    pub fn analyze_effectiveness(&self) -> Vec<(String, f64)> {
        let mut scores: Vec<(String, f64)> = self
            .technique_effectiveness
            .iter()
            .map(|(k, v)| (k.clone(), *v))
            .collect();
        scores.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        scores
    }

    /// Recommend improvements based on engagement history and detection data.
    pub fn recommend_improvements(&self) -> Vec<ImprovementRecommendation> {
        let mut recommendations = Vec::new();

        for correlation in &self.detection_correlations {
            if correlation.detection_rate > 0.5 {
                recommendations.push(ImprovementRecommendation {
                    title: format!("Reduce detection rate for '{}'", correlation.technique),
                    description: format!(
                        "Technique '{}' was detected {:.0}% of the time ({}/{} uses). \
                         Consider evasion modifications or alternative techniques.",
                        correlation.technique,
                        correlation.detection_rate * 100.0,
                        correlation.detection_count,
                        correlation.usage_count
                    ),
                    confidence: correlation.detection_rate,
                    applies_to: vec!["red_team".to_string(), "pentest".to_string()],
                });
            }
        }

        for (technique, score) in self
            .analyze_effectiveness()
            .into_iter()
            .filter(|(_, s)| *s > 0.8)
            .take(3)
        {
            recommendations.push(ImprovementRecommendation {
                title: format!("Promote high-performing technique: '{technique}'"),
                description: format!(
                    "Technique '{technique}' has an effectiveness score of {score:.2}. \
                     Prioritise this technique in future engagements."
                ),
                confidence: score,
                applies_to: vec!["general".to_string()],
            });
        }

        recommendations
    }

    /// Update effectiveness scores for all techniques used in an engagement result.
    pub fn update_technique_scores(&mut self, result: &EngagementResult) {
        self.update_technique_scores_from_result(result);
    }

    /// Generate a lessons-learned report from engagement history.
    pub fn generate_lessons_learned(&self) -> String {
        let total = self.engagement_history.len();
        let successful = self.engagement_history.iter().filter(|r| r.success).count();
        let techniques_tracked = self.technique_effectiveness.len();

        let top_techniques: Vec<String> = self
            .analyze_effectiveness()
            .into_iter()
            .take(5)
            .map(|(t, s)| format!("{t} ({:.0}%)", s * 100.0))
            .collect();

        format!(
            "=== Lessons Learned Report ===\n\
             Engagements recorded: {total}\n\
             Success rate:         {:.1}%\n\
             Techniques tracked:   {techniques_tracked}\n\n\
             Top techniques:\n  {}\n\n\
             Detection correlations: {}",
            if total == 0 {
                0.0
            } else {
                successful as f64 / total as f64 * 100.0
            },
            top_techniques.join("\n  "),
            self.detection_correlations.len()
        )
    }

    /// Internal: update technique effectiveness from a result.
    fn update_technique_scores_from_result(&mut self, result: &EngagementResult) {
        for technique in &result.techniques_used {
            let entry = self
                .technique_effectiveness
                .entry(technique.clone())
                .or_insert(0.5);
            if result.success {
                *entry = (*entry * 0.9 + 0.1).min(1.0);
            } else {
                *entry = (*entry * 0.9).max(0.0);
            }
        }
    }

    /// Internal: update detection correlations from a result.
    fn update_detection_correlations(&mut self, result: &EngagementResult) {
        for technique in &result.techniques_used {
            if let Some(correlation) = self
                .detection_correlations
                .iter_mut()
                .find(|c| c.technique == *technique)
            {
                correlation.usage_count += 1;
                if result.detections_triggered > 0 {
                    correlation.detection_count += 1;
                }
                correlation.detection_rate =
                    correlation.detection_count as f64 / correlation.usage_count as f64;
            } else {
                let detected = if result.detections_triggered > 0 {
                    1
                } else {
                    0
                };
                self.detection_correlations.push(DetectionCorrelation {
                    technique: technique.clone(),
                    detection_count: detected,
                    usage_count: 1,
                    detection_rate: detected as f64,
                });
            }
        }
    }
}

impl Default for LearningEngine {
    fn default() -> Self {
        Self::new()
    }
}
