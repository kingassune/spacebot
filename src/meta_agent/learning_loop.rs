//! Continuous learning from engagement outcomes.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Configuration for the learning loop.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LearningConfig {
    /// Minimum confidence threshold to promote a lesson to the knowledge base (0.0–1.0).
    pub confidence_threshold: f64,
    /// Maximum number of lessons to retain in the active knowledge base.
    pub max_lessons: usize,
    /// Whether to automatically apply lessons as recommendations.
    pub auto_apply: bool,
}

impl Default for LearningConfig {
    fn default() -> Self {
        Self {
            confidence_threshold: 0.6,
            max_lessons: 200,
            auto_apply: true,
        }
    }
}

/// A recorded outcome from a completed engagement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngagementOutcome {
    pub engagement_id: String,
    pub engagement_type: String,
    pub target: String,
    pub success: bool,
    pub techniques_used: Vec<String>,
    pub detections_triggered: u32,
    pub objective_achieved: bool,
    pub operator_notes: String,
    pub recorded_at: DateTime<Utc>,
}

/// A lesson extracted from one or more engagement outcomes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LessonLearned {
    pub id: String,
    pub title: String,
    pub description: String,
    pub applies_to: Vec<String>,
    pub confidence: f64,
    pub source_engagements: Vec<String>,
    pub created_at: DateTime<Utc>,
}

/// Aggregated knowledge base of lessons learned.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnowledgeBase {
    pub lessons: Vec<LessonLearned>,
    pub last_updated: Option<DateTime<Utc>>,
    pub total_outcomes_processed: usize,
}

impl KnowledgeBase {
    pub fn new() -> Self {
        Self {
            lessons: Vec::new(),
            last_updated: None,
            total_outcomes_processed: 0,
        }
    }

    /// Find lessons relevant to a given engagement type.
    pub fn lessons_for(&self, engagement_type: &str) -> Vec<&LessonLearned> {
        self.lessons
            .iter()
            .filter(|l| l.applies_to.iter().any(|t| t == engagement_type))
            .collect()
    }
}

impl Default for KnowledgeBase {
    fn default() -> Self {
        Self::new()
    }
}

/// Metrics about the learning loop performance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LearningMetrics {
    pub outcomes_processed: usize,
    pub lessons_generated: usize,
    pub knowledge_base_size: usize,
    pub average_confidence: f64,
    pub coverage_by_domain: Vec<(String, usize)>,
}

/// Record a new engagement outcome and trigger lesson extraction.
pub fn record_outcome(kb: &mut KnowledgeBase, outcome: EngagementOutcome, config: &LearningConfig) {
    kb.total_outcomes_processed += 1;
    let new_lessons = extract_lessons(&[outcome]);
    for lesson in new_lessons {
        if lesson.confidence >= config.confidence_threshold {
            update_knowledge_base(kb, lesson, config);
        }
    }
    kb.last_updated = Some(Utc::now());
}

/// Extract structured lessons from a batch of engagement outcomes.
pub fn extract_lessons(outcomes: &[EngagementOutcome]) -> Vec<LessonLearned> {
    let mut lessons = Vec::new();

    // Lesson: techniques that frequently trigger detections.
    let detected_techniques: Vec<String> = outcomes
        .iter()
        .filter(|o| o.detections_triggered > 0)
        .flat_map(|o| o.techniques_used.clone())
        .collect();

    if !detected_techniques.is_empty() {
        lessons.push(LessonLearned {
            id: format!("lesson-detect-{}", uuid::Uuid::new_v4()),
            title: "Detection-triggering techniques identified".to_string(),
            description: format!(
                "Techniques {} triggered SIEM/EDR detections across {} engagements. Consider evasion alternatives.",
                detected_techniques.join(", "),
                outcomes.len()
            ),
            applies_to: vec!["red_team".to_string(), "pentest".to_string()],
            confidence: (outcomes.iter().filter(|o| o.detections_triggered > 0).count() as f64
                / outcomes.len().max(1) as f64),
            source_engagements: outcomes.iter().map(|o| o.engagement_id.clone()).collect(),
            created_at: Utc::now(),
        });
    }

    // Lesson: successful technique patterns.
    let successful: Vec<&EngagementOutcome> = outcomes
        .iter()
        .filter(|o| o.success && o.objective_achieved)
        .collect();

    if !successful.is_empty() {
        let common_techniques: Vec<String> = successful
            .iter()
            .flat_map(|o| o.techniques_used.iter().cloned())
            .collect();

        lessons.push(LessonLearned {
            id: format!("lesson-success-{}", uuid::Uuid::new_v4()),
            title: "Effective technique chain identified".to_string(),
            description: format!(
                "Technique chain [{techniques}] achieved objectives in {count} engagement(s).",
                techniques = common_techniques.join(", "),
                count = successful.len()
            ),
            applies_to: vec![successful[0].engagement_type.clone(), "general".to_string()],
            confidence: successful.len() as f64 / outcomes.len().max(1) as f64,
            source_engagements: successful.iter().map(|o| o.engagement_id.clone()).collect(),
            created_at: Utc::now(),
        });
    }

    lessons
}

/// Add or update a lesson in the knowledge base.
pub fn update_knowledge_base(
    kb: &mut KnowledgeBase,
    lesson: LessonLearned,
    config: &LearningConfig,
) {
    // Deduplicate: update confidence if a lesson with similar title exists.
    if let Some(existing) = kb.lessons.iter_mut().find(|l| l.title == lesson.title) {
        existing.confidence = (existing.confidence + lesson.confidence) / 2.0;
        existing
            .source_engagements
            .extend(lesson.source_engagements);
        return;
    }

    kb.lessons.push(lesson);

    // Trim to max_lessons, removing lowest-confidence lessons first.
    if kb.lessons.len() > config.max_lessons {
        kb.lessons
            .sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap());
        kb.lessons.truncate(config.max_lessons);
    }
}

/// Generate improvement recommendations from the knowledge base.
pub fn recommend_improvements(kb: &KnowledgeBase, engagement_type: &str) -> Vec<String> {
    let relevant = kb.lessons_for(engagement_type);

    if relevant.is_empty() {
        return vec![format!(
            "No lessons available for '{engagement_type}'. Run more engagements to build the knowledge base."
        )];
    }

    relevant
        .iter()
        .filter(|l| l.confidence >= 0.5)
        .map(|l| {
            format!(
                "[{:.0}% confidence] {}: {}",
                l.confidence * 100.0,
                l.title,
                l.description
            )
        })
        .collect()
}

/// Compute learning metrics for the current knowledge base.
pub fn compute_metrics(kb: &KnowledgeBase) -> LearningMetrics {
    let avg_confidence = if kb.lessons.is_empty() {
        0.0
    } else {
        kb.lessons.iter().map(|l| l.confidence).sum::<f64>() / kb.lessons.len() as f64
    };

    let mut domain_counts: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    for lesson in &kb.lessons {
        for domain in &lesson.applies_to {
            *domain_counts.entry(domain.clone()).or_insert(0) += 1;
        }
    }

    let coverage_by_domain: Vec<(String, usize)> = domain_counts.into_iter().collect();

    LearningMetrics {
        outcomes_processed: kb.total_outcomes_processed,
        lessons_generated: kb.lessons.len(),
        knowledge_base_size: kb.lessons.len(),
        average_confidence: avg_confidence,
        coverage_by_domain,
    }
}
