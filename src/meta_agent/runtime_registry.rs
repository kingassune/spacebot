//! Dynamic skill/plugin registry at runtime.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A manifest describing a registered skill or plugin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginManifest {
    pub name: String,
    pub version: String,
    pub author: String,
    pub description: String,
    pub capabilities: Vec<String>,
    pub entry_point: String,
    pub schema_version: String,
}

impl PluginManifest {
    /// Validate that required fields are present and non-empty.
    pub fn is_valid(&self) -> bool {
        !self.name.is_empty()
            && !self.version.is_empty()
            && !self.entry_point.is_empty()
            && !self.capabilities.is_empty()
    }
}

/// A skill registered at runtime.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisteredSkill {
    pub id: String,
    pub manifest: PluginManifest,
    pub registered_at: DateTime<Utc>,
    pub enabled: bool,
    pub invocation_count: u64,
}

/// An event emitted by the registry when skill state changes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum RegistryEvent {
    /// A new skill was registered.
    Registered { skill_id: String },
    /// A skill was unregistered.
    Unregistered { skill_id: String },
    /// A skill was enabled or disabled.
    StatusChanged { skill_id: String, enabled: bool },
    /// A skill was invoked.
    Invoked { skill_id: String },
}

/// Dynamic skill and plugin registry.
#[derive(Debug, Clone)]
pub struct SkillRegistry {
    pub skills: Vec<RegisteredSkill>,
    pub event_log: Vec<RegistryEvent>,
}

impl SkillRegistry {
    pub fn new() -> Self {
        Self {
            skills: Vec::new(),
            event_log: Vec::new(),
        }
    }

    /// Register a new skill from its manifest.
    pub fn register_skill(&mut self, manifest: PluginManifest) -> Result<String, String> {
        validate_manifest(&manifest)?;

        let id = format!("{}-{}", manifest.name, manifest.version);
        if self.skills.iter().any(|s| s.id == id) {
            return Err(format!("Skill '{id}' is already registered."));
        }

        let skill = RegisteredSkill {
            id: id.clone(),
            manifest,
            registered_at: Utc::now(),
            enabled: true,
            invocation_count: 0,
        };
        self.skills.push(skill);
        self.event_log.push(RegistryEvent::Registered {
            skill_id: id.clone(),
        });
        Ok(id)
    }

    /// Unregister a skill by ID.
    pub fn unregister_skill(&mut self, skill_id: &str) -> Result<(), String> {
        let pos = self
            .skills
            .iter()
            .position(|s| s.id == skill_id)
            .ok_or_else(|| format!("Skill '{skill_id}' not found."))?;

        self.skills.remove(pos);
        self.event_log.push(RegistryEvent::Unregistered {
            skill_id: skill_id.to_string(),
        });
        Ok(())
    }

    /// Discover all enabled skills matching a capability.
    pub fn discover_skills(&self, capability: &str) -> Vec<&RegisteredSkill> {
        self.skills
            .iter()
            .filter(|s| {
                s.enabled
                    && s.manifest
                        .capabilities
                        .iter()
                        .any(|c| c.contains(capability))
            })
            .collect()
    }

    /// Record a skill invocation.
    pub fn record_invocation(&mut self, skill_id: &str) {
        if let Some(skill) = self.skills.iter_mut().find(|s| s.id == skill_id) {
            skill.invocation_count += 1;
            self.event_log.push(RegistryEvent::Invoked {
                skill_id: skill_id.to_string(),
            });
        }
    }

    /// Enable or disable a registered skill.
    pub fn set_enabled(&mut self, skill_id: &str, enabled: bool) -> Result<(), String> {
        let skill = self
            .skills
            .iter_mut()
            .find(|s| s.id == skill_id)
            .ok_or_else(|| format!("Skill '{skill_id}' not found."))?;

        skill.enabled = enabled;
        self.event_log.push(RegistryEvent::StatusChanged {
            skill_id: skill_id.to_string(),
            enabled,
        });
        Ok(())
    }

    /// Return all registered skill IDs.
    pub fn list_skills(&self) -> Vec<&str> {
        self.skills.iter().map(|s| s.id.as_str()).collect()
    }
}

impl Default for SkillRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Validate a plugin manifest.
pub fn validate_manifest(manifest: &PluginManifest) -> Result<(), String> {
    if manifest.name.is_empty() {
        return Err("Manifest 'name' must not be empty.".to_string());
    }
    if manifest.version.is_empty() {
        return Err("Manifest 'version' must not be empty.".to_string());
    }
    if manifest.entry_point.is_empty() {
        return Err("Manifest 'entry_point' must not be empty.".to_string());
    }
    if manifest.capabilities.is_empty() {
        return Err("Manifest must declare at least one capability.".to_string());
    }
    Ok(())
}
