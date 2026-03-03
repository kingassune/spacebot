//! Meta-agent orchestration for complex multi-agent security workflows.

pub mod capability_analysis;
pub mod cross_domain;
pub mod evaluation;
pub mod feedback;
pub mod orchestrator;
pub mod plugin_builder;
pub mod self_improvement;
pub mod skill_generator;
pub mod skill_router;
pub mod workflow;

/// Top-level meta-agent that coordinates self-extension and multi-domain orchestration.
#[derive(Debug, Clone)]
pub struct MetaAgent {
    pub orchestrator: orchestrator::MetaOrchestrator,
    pub skill_router: skill_router::SkillRouter,
    pub capability_map: capability_analysis::CapabilityMap,
}
