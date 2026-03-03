//! Meta-agent orchestration for complex multi-agent security workflows.

pub mod capability_analysis;
pub mod code_generation;
pub mod cross_domain;
pub mod evaluation;
pub mod feedback;
pub mod learning_loop;
pub mod orchestrator;
pub mod plugin_builder;
pub mod runtime_registry;
pub mod self_improvement;
pub mod skill_generator;
pub mod skill_router;
pub mod workflow;

pub use capability_analysis::{CapabilityAnalyzer, CapabilityReport, EngagementType};
pub use cross_domain::{CrossDomainCoordinator, EngagementPlan, EngagementResult, EngagementScope};
pub use plugin_builder::{PluginBuilder, PluginConfig};
pub use self_improvement::{ImprovementSuggestion, SelfImprover, TaskOutcome, TaskOutcomeKind};
pub use skill_generator::{GeneratedSkill, SecurityDomain, SkillGenerator};

/// Top-level meta-agent that coordinates self-extension and multi-domain orchestration.
#[derive(Debug, Clone)]
pub struct MetaAgent {
    pub orchestrator: orchestrator::MetaOrchestrator,
    pub skill_router: skill_router::SkillRouter,
    pub capability_map: capability_analysis::CapabilityMap,
    pub skill_generator: SkillGenerator,
    pub capability_analyzer: CapabilityAnalyzer,
    pub self_improver: SelfImprover,
    pub plugin_builder: PluginBuilder,
    pub cross_domain: CrossDomainCoordinator,
    pub skill_registry: runtime_registry::SkillRegistry,
    pub knowledge_base: learning_loop::KnowledgeBase,
}

impl MetaAgent {
    pub fn new() -> Self {
        let capability_map = capability_analysis::build_initial_capability_map();
        Self {
            orchestrator: orchestrator::MetaOrchestrator::new(),
            skill_router: skill_router::SkillRouter::new(),
            capability_analyzer: CapabilityAnalyzer::new(capability_map.clone()),
            capability_map,
            skill_generator: SkillGenerator::default(),
            self_improver: SelfImprover::new(),
            plugin_builder: PluginBuilder::new("plugins"),
            cross_domain: CrossDomainCoordinator::new(),
            skill_registry: runtime_registry::SkillRegistry::new(),
            knowledge_base: learning_loop::KnowledgeBase::new(),
        }
    }

    /// Generate a new skill module for the given description.
    pub fn generate_skill_module(
        &self,
        config: &code_generation::CodeGenConfig,
    ) -> code_generation::GenerationResult {
        code_generation::generate_skill_module(config)
    }

    /// Record an engagement outcome and update the knowledge base.
    pub fn record_outcome(
        &mut self,
        outcome: learning_loop::EngagementOutcome,
        config: &learning_loop::LearningConfig,
    ) {
        learning_loop::record_outcome(&mut self.knowledge_base, outcome, config);
    }

    /// Get improvement recommendations for an engagement type.
    pub fn recommend_improvements(&self, engagement_type: &str) -> Vec<String> {
        learning_loop::recommend_improvements(&self.knowledge_base, engagement_type)
    }
}

impl Default for MetaAgent {
    fn default() -> Self {
        Self::new()
    }
}
