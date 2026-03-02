//! Plugin builder for dynamic detection plugin creation from threat intelligence.

use chrono::{DateTime, Utc};
use std::collections::HashMap;

pub use crate::meta_agent::skill_generator::ThreatIntelReport;

#[derive(Debug, Clone)]
pub struct PluginManifest {
    pub name: String,
    pub version: String,
    pub description: String,
    pub capabilities: Vec<String>,
    pub dependencies: Vec<String>,
    pub entry_point: String,
    pub config_schema: HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct CompiledPlugin {
    pub manifest: PluginManifest,
    pub binary_hash: String,
    pub size_bytes: u64,
    pub compiled_at: DateTime<Utc>,
}

pub fn build_plugin_from_intel(intel: &ThreatIntelReport) -> anyhow::Result<PluginManifest> {
    let name = format!(
        "plugin-{}",
        intel.title.to_lowercase().replace(' ', "-")
    );

    let capabilities: Vec<String> = intel
        .techniques
        .iter()
        .map(|t| format!("detect:{t}"))
        .chain(intel.iocs.iter().map(|ioc| format!("block:{ioc}")))
        .collect();

    let mut config_schema = HashMap::new();
    config_schema.insert("log_level".to_string(), "string".to_string());
    config_schema.insert("alert_threshold".to_string(), "integer".to_string());
    if intel.threat_actor.is_some() {
        config_schema.insert("threat_actor".to_string(), "string".to_string());
    }

    Ok(PluginManifest {
        name: name.clone(),
        version: "0.1.0".to_string(),
        description: format!("Detection plugin derived from threat intel: {}", intel.title),
        capabilities,
        dependencies: vec!["siem-connector".to_string(), "ioc-feed".to_string()],
        entry_point: format!("{name}::run"),
        config_schema,
    })
}

pub fn compile_plugin(manifest: &PluginManifest) -> anyhow::Result<CompiledPlugin> {
    validate_plugin_manifest(manifest)?;
    let binary_hash = format!("{:x}", {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        manifest.name.hash(&mut hasher);
        manifest.version.hash(&mut hasher);
        hasher.finish()
    });
    Ok(CompiledPlugin {
        manifest: manifest.clone(),
        binary_hash,
        size_bytes: 1024 * 64,
        compiled_at: Utc::now(),
    })
}

pub fn validate_plugin_manifest(manifest: &PluginManifest) -> anyhow::Result<()> {
    anyhow::ensure!(!manifest.name.is_empty(), "plugin name must not be empty");
    anyhow::ensure!(!manifest.version.is_empty(), "plugin version must not be empty");
    Ok(())
}

pub fn generate_plugin_config_template(manifest: &PluginManifest) -> String {
    let fields: Vec<String> = manifest
        .config_schema
        .iter()
        .map(|(key, value_type)| format!("# {key} ({value_type})\n# {key} = \"\""))
        .collect();

    format!(
        "[plugin.{}]\nversion = \"{}\"\n\n# Configuration fields\n{}\n",
        manifest.name,
        manifest.version,
        fields.join("\n\n")
    )
}
