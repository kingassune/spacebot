//! Operational security tradecraft for nation-state operations.

/// Operational security level governing tradecraft stringency.
#[derive(Debug, Clone, PartialEq)]
pub enum OpsecLevel {
    /// Minimal precautions — acceptable for low-risk environments.
    Minimal,
    /// Standard baseline opsec for most operations.
    Standard,
    /// Enhanced measures for high-value targets.
    Enhanced,
    /// Maximum measures for the most sensitive operations.
    Maximum,
    /// Active denial and deception to mislead attribution.
    DenialAndDeception,
}

/// A single operational security rule or procedure.
#[derive(Debug, Clone)]
pub struct OpsecRule {
    /// Short identifier for the rule.
    pub id: String,
    /// Human-readable rule description.
    pub description: String,
    /// The minimum opsec level that activates this rule.
    pub minimum_level: OpsecLevel,
    /// Whether this rule is currently enforced.
    pub enforced: bool,
}

/// Communication security plan for an operation.
#[derive(Debug, Clone)]
pub struct CommsPlan {
    /// Primary encrypted communication channel.
    pub primary_channel: String,
    /// Fallback channel if primary is compromised.
    pub fallback_channel: String,
    /// Duration in hours between scheduled check-ins.
    pub check_in_interval_hours: u64,
    /// Whether all communications must be encrypted end-to-end.
    pub require_encryption: bool,
}

impl Default for CommsPlan {
    fn default() -> Self {
        Self {
            primary_channel: "Signal".to_string(),
            fallback_channel: "Telegram".to_string(),
            check_in_interval_hours: 24,
            require_encryption: true,
        }
    }
}

/// A cover identity used to mask an operator's real identity.
#[derive(Debug, Clone)]
pub struct CoverIdentity {
    /// Alias or legend name.
    pub alias: String,
    /// Backstory / legend for the identity.
    pub legend: String,
    /// Online personas associated with this identity.
    pub personas: Vec<String>,
    /// Whether this identity has supporting documentation.
    pub documented: bool,
}

/// Tradecraft configuration for a nation-state operation.
#[derive(Debug, Clone)]
pub struct Tradecraft {
    /// Active operational security rules.
    pub opsec_rules: Vec<OpsecRule>,
    /// Communication security plan.
    pub communication_plan: CommsPlan,
    /// Cover identities available to operators.
    pub cover_identities: Vec<CoverIdentity>,
    /// Current opsec level.
    pub opsec_level: OpsecLevel,
}

impl Tradecraft {
    /// Create a new tradecraft configuration at the given opsec level.
    pub fn new(level: OpsecLevel) -> Self {
        let opsec_rules = default_rules_for_level(&level);
        Self {
            opsec_level: level,
            opsec_rules,
            communication_plan: CommsPlan::default(),
            cover_identities: Vec::new(),
        }
    }

    /// Apply tradecraft rules, activating all rules appropriate for the current level.
    pub fn apply_tradecraft(&mut self) {
        for rule in &mut self.opsec_rules {
            rule.enforced = opsec_level_rank(&self.opsec_level)
                >= opsec_level_rank(&rule.minimum_level);
        }
    }

    /// Evaluate and return a summary of the current opsec posture.
    pub fn evaluate_opsec_posture(&self) -> String {
        let enforced: Vec<&OpsecRule> = self.opsec_rules.iter().filter(|r| r.enforced).collect();
        let total = self.opsec_rules.len();
        let score = if total == 0 {
            0.0
        } else {
            enforced.len() as f64 / total as f64 * 100.0
        };

        format!(
            "Opsec Level: {:?}\nRules enforced: {}/{}\nPosture score: {:.1}%\nComms plan: {} → {} ({}h interval)\nCover identities: {}",
            self.opsec_level,
            enforced.len(),
            total,
            score,
            self.communication_plan.primary_channel,
            self.communication_plan.fallback_channel,
            self.communication_plan.check_in_interval_hours,
            self.cover_identities.len()
        )
    }

    /// Generate a cover story suitable for the given operational context.
    pub fn generate_cover_story(&self, context: &str) -> String {
        if let Some(identity) = self.cover_identities.first() {
            format!(
                "Cover story for context '{}': Operator presents as '{}'. Legend: {}",
                context, identity.alias, identity.legend
            )
        } else {
            format!(
                "No cover identities registered. Operating under {:?} opsec for context: {context}",
                self.opsec_level
            )
        }
    }

    /// Estimate the risk of attribution to the real operator (0.0–1.0).
    ///
    /// Returns 0.0 (no risk) to 1.0 (certain attribution).
    pub fn assess_attribution_risk(&self) -> f64 {
        let level_risk = match self.opsec_level {
            OpsecLevel::Minimal => 0.80,
            OpsecLevel::Standard => 0.50,
            OpsecLevel::Enhanced => 0.25,
            OpsecLevel::Maximum => 0.10,
            OpsecLevel::DenialAndDeception => 0.05,
        };

        let enforced_count = self.opsec_rules.iter().filter(|r| r.enforced).count();
        let rule_reduction = (enforced_count as f64 * 0.02).min(0.30);

        let identity_reduction = if self.cover_identities.is_empty() {
            0.0
        } else {
            0.10
        };

        (level_risk - rule_reduction - identity_reduction).max(0.0)
    }

    /// Recommend countermeasures to reduce attribution risk.
    pub fn recommend_countermeasures(&self) -> Vec<String> {
        let mut recommendations = Vec::new();

        if matches!(self.opsec_level, OpsecLevel::Minimal | OpsecLevel::Standard) {
            recommendations.push("Upgrade opsec level to Enhanced or Maximum.".to_string());
        }

        if self.cover_identities.is_empty() {
            recommendations
                .push("Register at least one documented cover identity.".to_string());
        }

        if !self.communication_plan.require_encryption {
            recommendations.push("Enable end-to-end encryption on all comms channels.".to_string());
        }

        let unenforced: Vec<&OpsecRule> =
            self.opsec_rules.iter().filter(|r| !r.enforced).collect();
        for rule in unenforced.iter().take(3) {
            recommendations.push(format!("Enforce rule: {}", rule.description));
        }

        if recommendations.is_empty() {
            recommendations.push("Tradecraft posture is strong. Continue monitoring.".to_string());
        }

        recommendations
    }
}

/// Return a numeric rank for an opsec level (higher = stricter).
fn opsec_level_rank(level: &OpsecLevel) -> usize {
    match level {
        OpsecLevel::Minimal => 1,
        OpsecLevel::Standard => 2,
        OpsecLevel::Enhanced => 3,
        OpsecLevel::Maximum => 4,
        OpsecLevel::DenialAndDeception => 5,
    }
}

/// Build a default set of opsec rules appropriate for the given level.
fn default_rules_for_level(level: &OpsecLevel) -> Vec<OpsecRule> {
    vec![
        OpsecRule {
            id: "OR-001".to_string(),
            description: "Use VPN for all external connections.".to_string(),
            minimum_level: OpsecLevel::Minimal,
            enforced: opsec_level_rank(level) >= 1,
        },
        OpsecRule {
            id: "OR-002".to_string(),
            description: "Route all C2 traffic through redirectors.".to_string(),
            minimum_level: OpsecLevel::Standard,
            enforced: opsec_level_rank(level) >= 2,
        },
        OpsecRule {
            id: "OR-003".to_string(),
            description: "Apply domain fronting on all C2 channels.".to_string(),
            minimum_level: OpsecLevel::Enhanced,
            enforced: opsec_level_rank(level) >= 3,
        },
        OpsecRule {
            id: "OR-004".to_string(),
            description: "Sanitise all tools and implants before deployment.".to_string(),
            minimum_level: OpsecLevel::Enhanced,
            enforced: opsec_level_rank(level) >= 3,
        },
        OpsecRule {
            id: "OR-005".to_string(),
            description: "Use documented cover identities for all external interactions.".to_string(),
            minimum_level: OpsecLevel::Maximum,
            enforced: opsec_level_rank(level) >= 4,
        },
        OpsecRule {
            id: "OR-006".to_string(),
            description: "Plant false-flag artefacts to misdirect attribution.".to_string(),
            minimum_level: OpsecLevel::DenialAndDeception,
            enforced: opsec_level_rank(level) >= 5,
        },
    ]
}
