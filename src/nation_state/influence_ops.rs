//! Information warfare and influence operations simulation.

/// Technique used in an influence operation.
#[derive(Debug, Clone, PartialEq)]
pub enum InfluenceTechnique {
    /// Deliberately false information presented as true.
    Disinformation,
    /// False information spread without deliberate intent.
    Misinformation,
    /// Biased information used to promote a cause.
    Propaganda,
    /// Coordinated inauthentic behaviour masquerading as grassroots.
    Astroturfing,
    /// Automated accounts amplifying content at scale.
    BotNetworks,
    /// AI-generated synthetic media to fake events.
    DeepfakeGeneration,
    /// Coordinated manipulation of social platform algorithms.
    SocialMediaManipulation,
    /// Placing stories with compliant media outlets.
    MediaPlanting,
    /// Stealing and selectively leaking sensitive documents.
    HackAndLeak,
}

/// Target platform for influence operations.
#[derive(Debug, Clone, PartialEq)]
pub enum Platform {
    /// Twitter/X.
    Twitter,
    /// Facebook.
    Facebook,
    /// Telegram.
    Telegram,
    /// Reddit.
    Reddit,
    /// YouTube.
    YouTube,
    /// TikTok.
    TikTok,
    /// Traditional news media.
    NewsMedia,
    /// Online forums and message boards.
    Forums,
}

/// Strategy for amplifying narrative spread.
#[derive(Debug, Clone)]
pub struct AmplificationStrategy {
    /// Platforms to target for amplification.
    pub target_platforms: Vec<Platform>,
    /// Estimated number of bot accounts available.
    pub bot_count: u64,
    /// Estimated organic reach multiplier.
    pub organic_reach_multiplier: f64,
    /// Whether coordinated inauthentic behaviour networks are used.
    pub use_cib_networks: bool,
}

/// Modelled spread of a narrative over time.
#[derive(Debug, Clone)]
pub struct NarrativeSpreadModel {
    /// Estimated total reach (number of unique users exposed).
    pub total_reach: u64,
    /// Estimated engagement rate (0.0–1.0).
    pub engagement_rate: f64,
    /// Estimated share rate (0.0–1.0).
    pub share_rate: f64,
    /// Estimated time for narrative to peak in hours.
    pub peak_hours: u64,
    /// Percentage of target audience that adopted the narrative.
    pub adoption_percent: f64,
}

/// Assessment of an influence operation's impact.
#[derive(Debug, Clone)]
pub struct InfluenceImpactAssessment {
    /// Estimated change in public opinion (percentage points, can be negative).
    pub opinion_shift_pct: f64,
    /// Whether the operation was attributed to a state actor.
    pub attributed: bool,
    /// Counter-narrative effectiveness score (0.0–1.0).
    pub counter_narrative_effectiveness: f64,
    /// Summary narrative of the impact.
    pub narrative: String,
}

/// A simulated information warfare / influence operation.
#[derive(Debug, Clone)]
pub struct InfluenceOperation {
    /// Human-readable name for the operation.
    pub operation_name: String,
    /// Description of the target audience.
    pub target_audience: String,
    /// Core narrative or message being promoted.
    pub narrative: String,
    /// Platforms to operate on.
    pub platforms: Vec<Platform>,
    /// Amplification strategy for spreading the narrative.
    pub amplification_strategy: AmplificationStrategy,
    /// Techniques employed in the operation.
    pub techniques: Vec<InfluenceTechnique>,
}

impl InfluenceOperation {
    /// Create a new influence operation.
    pub fn new(
        operation_name: impl Into<String>,
        target_audience: impl Into<String>,
        narrative: impl Into<String>,
        platforms: Vec<Platform>,
        techniques: Vec<InfluenceTechnique>,
    ) -> Self {
        let amplification_platforms = platforms.clone();
        Self {
            operation_name: operation_name.into(),
            target_audience: target_audience.into(),
            narrative: narrative.into(),
            platforms,
            amplification_strategy: AmplificationStrategy {
                target_platforms: amplification_platforms,
                bot_count: 500,
                organic_reach_multiplier: 2.5,
                use_cib_networks: false,
            },
            techniques,
        }
    }

    /// Plan the influence operation — validate configuration and return a summary.
    pub fn plan_influence_operation(&self) -> String {
        let technique_list: Vec<String> =
            self.techniques.iter().map(|t| format!("{t:?}")).collect();
        let platform_list: Vec<String> = self.platforms.iter().map(|p| format!("{p:?}")).collect();

        format!(
            "Influence Operation: {}\nTarget Audience: {}\nNarrative: {}\nPlatforms: {}\nTechniques: {}",
            self.operation_name,
            self.target_audience,
            self.narrative,
            platform_list.join(", "),
            technique_list.join(", ")
        )
    }

    /// Model how the narrative spreads across target platforms.
    pub fn model_narrative_spread(&self) -> NarrativeSpreadModel {
        let base_reach = self.amplification_strategy.bot_count * 50 * self.platforms.len() as u64;
        let multiplied_reach =
            (base_reach as f64 * self.amplification_strategy.organic_reach_multiplier) as u64;

        let engagement_rate = if self.amplification_strategy.use_cib_networks {
            0.15
        } else {
            0.08
        };

        let has_deepfake = self
            .techniques
            .contains(&InfluenceTechnique::DeepfakeGeneration);
        let share_rate = if has_deepfake { 0.12 } else { 0.06 };

        let peak_hours = match self.platforms.first() {
            Some(Platform::Twitter) => 6,
            Some(Platform::TikTok) => 12,
            Some(Platform::YouTube) => 48,
            _ => 24,
        };

        NarrativeSpreadModel {
            total_reach: multiplied_reach,
            engagement_rate,
            share_rate,
            peak_hours,
            adoption_percent: engagement_rate * 100.0 * 0.3,
        }
    }

    /// Assess the operational impact of the influence operation.
    pub fn assess_impact(&self) -> InfluenceImpactAssessment {
        let spread = self.model_narrative_spread();
        let opinion_shift = spread.adoption_percent * 0.5;

        let attributed = self
            .techniques
            .contains(&InfluenceTechnique::DeepfakeGeneration)
            || self.amplification_strategy.bot_count > 10_000;

        let counter_effectiveness = if attributed { 0.7 } else { 0.3 };

        InfluenceImpactAssessment {
            opinion_shift_pct: opinion_shift,
            attributed,
            counter_narrative_effectiveness: counter_effectiveness,
            narrative: format!(
                "Operation '{}' estimated to shift opinion by {:.1}% among target audience '{}'. {}",
                self.operation_name,
                opinion_shift,
                self.target_audience,
                if attributed {
                    "Operation is likely to be attributed."
                } else {
                    "Attribution risk is low."
                }
            ),
        }
    }

    /// Generate countermeasures against this influence operation.
    pub fn generate_countermeasures(&self) -> Vec<String> {
        let mut measures = vec![
            "Deploy automated bot detection and labelling on all platforms.".to_string(),
            "Establish rapid-response fact-checking partnerships with media.".to_string(),
            "Increase digital media literacy awareness campaigns.".to_string(),
        ];

        if self
            .techniques
            .contains(&InfluenceTechnique::DeepfakeGeneration)
        {
            measures.push(
                "Deploy AI deepfake detection tools for video content verification.".to_string(),
            );
        }

        if self.techniques.contains(&InfluenceTechnique::BotNetworks) {
            measures.push(
                "Use graph-based CIB detection to identify coordinated inauthentic networks."
                    .to_string(),
            );
        }

        if self.techniques.contains(&InfluenceTechnique::HackAndLeak) {
            measures.push(
                "Pre-brief media on potential hack-and-leak operations targeting key personnel."
                    .to_string(),
            );
        }

        measures
    }
}
