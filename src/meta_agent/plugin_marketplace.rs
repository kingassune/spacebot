//! Plugin marketplace for community-contributed security extensions.

use chrono::{DateTime, Utc};

/// Review status of a plugin submission.
#[derive(Debug, Clone, PartialEq)]
pub enum ReviewStatus {
    /// Submitted but not yet reviewed.
    Pending,
    /// Currently being reviewed by the security team.
    InReview,
    /// Reviewed and approved for use.
    Approved,
    /// Reviewed and rejected due to security or quality issues.
    Rejected,
    /// Previously approved but now deprecated.
    Deprecated,
}

/// A plugin available in the marketplace.
#[derive(Debug, Clone)]
pub struct Plugin {
    /// Unique plugin name.
    pub name: String,
    /// Semantic version string (e.g. "1.2.0").
    pub version: String,
    /// Name or handle of the plugin author.
    pub author: String,
    /// Security domain category (e.g. "blockchain", "red-team").
    pub category: String,
    /// Current review status.
    pub security_review_status: ReviewStatus,
    /// SHA-256 hash of the plugin code for integrity verification.
    pub code_hash: String,
    /// When this plugin was submitted to the marketplace.
    pub submitted_at: DateTime<Utc>,
}

impl Plugin {
    /// Return `true` if the plugin is safe to install (approved and not deprecated).
    pub fn is_installable(&self) -> bool {
        self.security_review_status == ReviewStatus::Approved
    }
}

/// Security audit finding for a plugin.
#[derive(Debug, Clone)]
pub struct PluginAuditFinding {
    /// Severity of the finding.
    pub severity: String,
    /// Description of the issue.
    pub description: String,
    /// Recommended remediation.
    pub recommendation: String,
}

/// Result of a plugin security audit.
#[derive(Debug, Clone)]
pub struct PluginAuditResult {
    /// Plugin audited.
    pub plugin_name: String,
    /// Whether the plugin passed the audit.
    pub passed: bool,
    /// Findings discovered during the audit.
    pub findings: Vec<PluginAuditFinding>,
    /// Overall risk score (0.0–10.0).
    pub risk_score: f64,
}

/// Community plugin marketplace for James security extensions.
#[derive(Debug, Clone)]
pub struct PluginMarketplace {
    /// All registered plugins.
    pub plugins: Vec<Plugin>,
    /// Installed plugin names.
    pub installed: Vec<String>,
}

impl PluginMarketplace {
    /// Create a new empty marketplace.
    pub fn new() -> Self {
        Self {
            plugins: Vec::new(),
            installed: Vec::new(),
        }
    }

    /// Register a new plugin submission.
    ///
    /// Returns `Err` if a plugin with the same name and version already exists.
    pub fn register_plugin(&mut self, plugin: Plugin) -> Result<(), String> {
        if self
            .plugins
            .iter()
            .any(|p| p.name == plugin.name && p.version == plugin.version)
        {
            return Err(format!(
                "Plugin '{} v{}' is already registered.",
                plugin.name, plugin.version
            ));
        }
        self.plugins.push(plugin);
        Ok(())
    }

    /// Verify a plugin's integrity by comparing its stored hash against the expected hash.
    ///
    /// Returns `Ok(())` if hashes match, or `Err(description)` if they differ.
    pub fn verify_plugin_integrity(
        &self,
        plugin_name: &str,
        expected_hash: &str,
    ) -> Result<(), String> {
        let plugin = self
            .plugins
            .iter()
            .find(|p| p.name == plugin_name)
            .ok_or_else(|| format!("Plugin '{plugin_name}' not found in marketplace."))?;

        if plugin.code_hash == expected_hash {
            Ok(())
        } else {
            Err(format!(
                "Integrity check failed for '{plugin_name}': hash mismatch. \
                 Expected '{expected_hash}', got '{}'.",
                plugin.code_hash
            ))
        }
    }

    /// Install an approved plugin.
    ///
    /// Returns `Err` if the plugin is not approved or cannot be found.
    pub fn install_plugin(&mut self, plugin_name: &str) -> Result<(), String> {
        let plugin = self
            .plugins
            .iter()
            .find(|p| p.name == plugin_name)
            .ok_or_else(|| format!("Plugin '{plugin_name}' not found."))?
            .clone();

        if !plugin.is_installable() {
            return Err(format!(
                "Plugin '{plugin_name}' cannot be installed — status is {:?}.",
                plugin.security_review_status
            ));
        }

        if self.installed.contains(&plugin_name.to_string()) {
            return Err(format!("Plugin '{plugin_name}' is already installed."));
        }

        self.installed.push(plugin_name.to_string());
        Ok(())
    }

    /// List all available (approved) plugins.
    pub fn list_available_plugins(&self) -> Vec<&Plugin> {
        self.plugins
            .iter()
            .filter(|p| p.security_review_status == ReviewStatus::Approved)
            .collect()
    }

    /// Perform a security audit on a plugin.
    pub fn security_audit_plugin(&self, plugin_name: &str) -> Result<PluginAuditResult, String> {
        let plugin = self
            .plugins
            .iter()
            .find(|p| p.name == plugin_name)
            .ok_or_else(|| format!("Plugin '{plugin_name}' not found."))?;

        let mut findings = Vec::new();

        if plugin.code_hash.is_empty() {
            findings.push(PluginAuditFinding {
                severity: "Critical".to_string(),
                description: "Plugin has no code hash — integrity cannot be verified.".to_string(),
                recommendation: "Require all plugins to include a SHA-256 hash of their source."
                    .to_string(),
            });
        }

        if plugin.author.is_empty() {
            findings.push(PluginAuditFinding {
                severity: "Medium".to_string(),
                description: "Plugin has no identified author.".to_string(),
                recommendation: "Require author attribution for all marketplace submissions."
                    .to_string(),
            });
        }

        let risk_score = findings
            .iter()
            .map(|f| {
                if f.severity == "Critical" {
                    4.0
                } else if f.severity == "High" {
                    2.5
                } else {
                    1.0
                }
            })
            .sum::<f64>()
            .min(10.0);

        Ok(PluginAuditResult {
            plugin_name: plugin_name.to_string(),
            passed: findings.is_empty(),
            findings,
            risk_score,
        })
    }
}

impl Default for PluginMarketplace {
    fn default() -> Self {
        Self::new()
    }
}
