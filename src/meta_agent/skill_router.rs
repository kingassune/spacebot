//! Skill router for meta-agent security workflows.

use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct SkillRouter {
    pub routes: HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct RouteRequest {
    pub task_description: String,
    pub required_capabilities: Vec<String>,
    pub priority: u8,
}

#[derive(Debug, Clone)]
pub struct RouteResult {
    pub selected_skill: String,
    pub confidence: f64,
    pub fallback_skills: Vec<String>,
}

impl SkillRouter {
    pub fn new() -> Self {
        Self {
            routes: HashMap::new(),
        }
    }

    pub fn register_skill(&mut self, skill_name: String, domain: String) {
        self.routes.insert(domain, skill_name);
    }

    pub fn route(&self, request: &RouteRequest) -> RouteResult {
        let selected = request
            .required_capabilities
            .iter()
            .find_map(|cap| self.routes.get(cap).cloned())
            .unwrap_or_else(|| "default-skill".to_string());

        let fallback_skills: Vec<String> = self
            .routes
            .values()
            .filter(|s| **s != selected)
            .cloned()
            .collect();

        RouteResult {
            selected_skill: selected,
            confidence: 0.85,
            fallback_skills,
        }
    }
}

impl Default for SkillRouter {
    fn default() -> Self {
        Self::new()
    }
}
