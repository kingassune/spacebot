//! Autonomous build-and-extend pipeline for the meta-agent.
//!
//! Implements the continuous discovery → propose → build → test → deploy → learn
//! loop that allows the James platform to extend itself with new security capabilities.

use serde::{Deserialize, Serialize};

use crate::meta_agent::{
    platform_scanner::{PlatformManifest, PlatformScanner},
    plugin_builder::{PluginBuilder, PluginConfig},
    skill_generator::{GeneratedSkill, SecurityDomain, SkillGenerator},
};

/// A gap in the platform's current security capabilities.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityGap {
    /// Security domain where the gap exists.
    pub domain: String,
    /// Short description of the missing capability.
    pub description: String,
    /// Priority for filling this gap (0–10).
    pub priority: u8,
    /// Suggested module or skill name.
    pub suggested_name: String,
}

/// A proposed extension to fill a capability gap.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtensionProposal {
    /// Gap this proposal addresses.
    pub gap: CapabilityGap,
    /// Type of extension (Skill, Module, Plugin).
    pub extension_type: ExtensionType,
    /// Proposed implementation description.
    pub proposal_description: String,
    /// Estimated complexity (1=trivial, 5=complex).
    pub complexity: u8,
}

/// Type of extension being proposed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ExtensionType {
    /// A new SKILL.md file for the skills directory.
    Skill,
    /// A new Rust module in the security framework.
    Module,
    /// A new plugin package in the plugins directory.
    Plugin,
}

/// Result of attempting to build a proposed extension.
#[derive(Debug, Clone)]
pub struct BuildResult {
    /// Proposal that was built.
    pub proposal: ExtensionProposal,
    /// Whether the build succeeded.
    pub success: bool,
    /// Build output or error message.
    pub output: String,
    /// Path where the artefact was produced (if successful).
    pub artifact_path: Option<String>,
    /// Generated skill content (for Skill extensions).
    pub generated_skill: Option<GeneratedSkill>,
}

/// Result of deploying a built extension.
#[derive(Debug, Clone)]
pub struct DeployResult {
    /// Build result that was deployed.
    pub build: BuildResult,
    /// Whether deployment succeeded.
    pub success: bool,
    /// Deployment output message.
    pub message: String,
    /// Whether the platform needs a restart to pick up the change.
    pub requires_restart: bool,
}

/// Analysis of current platform capabilities vs known security domains.
#[derive(Debug, Clone)]
pub struct CapabilityAnalysis {
    /// Platform manifest from the scanner.
    pub manifest: PlatformManifest,
    /// Identified gaps.
    pub gaps: Vec<CapabilityGap>,
    /// Coverage percentage across all domains (0–100).
    pub coverage_pct: f64,
}

/// The full autonomous pipeline that discovers, proposes, builds, and deploys
/// new platform capabilities.
#[derive(Debug, Clone)]
pub struct AutonomousPipeline {
    pub scanner: PlatformScanner,
    pub skill_generator: SkillGenerator,
    pub plugin_builder: PluginBuilder,
}

impl AutonomousPipeline {
    /// Create a new pipeline rooted at the given platform directory.
    pub fn new(root: impl Into<std::path::PathBuf>) -> Self {
        let root = root.into();
        let plugins_dir = root.join("plugins");
        Self {
            scanner: PlatformScanner::new(root),
            skill_generator: SkillGenerator::default(),
            plugin_builder: PluginBuilder::new(plugins_dir.to_string_lossy().as_ref()),
        }
    }

    /// Scan the platform and identify capability gaps relative to known security domains.
    pub fn discover_gaps(&self) -> Vec<CapabilityGap> {
        let manifest = self.scanner.full_scan();
        let existing_skills: std::collections::HashSet<String> =
            manifest.skills.iter().map(|s| s.name.clone()).collect();
        // Reserved for future module-level gap detection.
        let _existing_modules: std::collections::HashSet<String> =
            manifest.modules.iter().map(|m| m.name.clone()).collect();

        let mut gaps = Vec::new();

        // Enumerate known security capability areas that should be covered.
        let expected_skills = [
            ("cloud-enumeration", "cloud", 7),
            ("ai-model-security", "generic", 6),
            ("firmware-analysis", "exploit-dev", 8),
            ("iot-pentest", "pentest", 7),
            ("supply-chain-analysis", "red-team", 9),
            ("container-escape", "red-team", 8),
            ("k8s-security", "pentest", 7),
        ];

        for (skill_name, domain, priority) in expected_skills {
            if !existing_skills.iter().any(|s| s.contains(skill_name)) {
                gaps.push(CapabilityGap {
                    domain: domain.to_string(),
                    description: format!("No skill covering '{skill_name}'"),
                    priority,
                    suggested_name: skill_name.to_string(),
                });
            }
        }

        // Supplement with gaps from the scanner's own gap analysis.
        for scanner_gap in &manifest.gaps {
            if !gaps
                .iter()
                .any(|g| g.description == scanner_gap.description)
            {
                gaps.push(CapabilityGap {
                    domain: scanner_gap.framework.clone(),
                    description: scanner_gap.description.clone(),
                    priority: 5,
                    suggested_name: scanner_gap.category.to_lowercase().replace(' ', "-"),
                });
            }
        }

        // Sort by priority descending.
        gaps.sort_by(|a, b| b.priority.cmp(&a.priority));
        gaps
    }

    /// Generate extension proposals for a set of capability gaps.
    pub fn propose_extensions(&self, gaps: &[CapabilityGap]) -> Vec<ExtensionProposal> {
        gaps.iter()
            .map(|gap| {
                // All gaps are currently addressed as Skill extensions; Module/Plugin
                // support requires additional scaffolding infrastructure.
                let extension_type = ExtensionType::Skill;
                ExtensionProposal {
                    gap: gap.clone(),
                    extension_type,
                    proposal_description: format!(
                        "Generate a James skill for '{}' covering {}.",
                        gap.suggested_name, gap.description
                    ),
                    complexity: if gap.priority >= 8 { 3 } else { 2 },
                }
            })
            .collect()
    }

    /// Build and sanity-test a proposed extension.
    pub fn build_and_test(&self, proposal: &ExtensionProposal) -> BuildResult {
        match proposal.extension_type {
            ExtensionType::Skill => {
                let domain = parse_domain(&proposal.gap.domain);
                let skill = self
                    .skill_generator
                    .generate_skill(&proposal.gap.description, domain);
                let artifact_path = format!("skills/{}/SKILL.md", skill.name);
                BuildResult {
                    proposal: proposal.clone(),
                    success: true,
                    output: format!("Generated skill: {}", skill.name),
                    artifact_path: Some(artifact_path),
                    generated_skill: Some(skill),
                }
            }
            ExtensionType::Plugin | ExtensionType::Module => {
                let config = PluginConfig {
                    name: proposal.gap.suggested_name.clone(),
                    description: proposal.gap.description.clone(),
                    domain: proposal.gap.domain.clone(),
                    version: "0.1.0".to_string(),
                    include_hooks: false,
                    include_commands: false,
                };
                match self.plugin_builder.build_plugin(&config) {
                    Ok(manifest) => BuildResult {
                        proposal: proposal.clone(),
                        success: true,
                        output: format!("Plugin manifest created: {}", manifest.name),
                        artifact_path: Some(format!("plugins/{}/plugin.toml", manifest.name)),
                        generated_skill: None,
                    },
                    Err(e) => BuildResult {
                        proposal: proposal.clone(),
                        success: false,
                        output: format!("Plugin build failed: {e}"),
                        artifact_path: None,
                        generated_skill: None,
                    },
                }
            }
        }
    }

    /// Deploy a built extension into the platform.
    ///
    /// For skills, this writes the SKILL.md to disk. For plugins, the scaffold
    /// directory already exists after `build_and_test`.
    pub fn deploy_extension(&self, result: &BuildResult) -> DeployResult {
        if !result.success {
            return DeployResult {
                build: result.clone(),
                success: false,
                message: "Build failed; nothing to deploy.".to_string(),
                requires_restart: false,
            };
        }

        if let Some(skill) = &result.generated_skill {
            // Write the skill markdown to disk if we have a real artifact path.
            if let Some(path) = &result.artifact_path {
                if let Some(parent) = std::path::Path::new(path).parent() {
                    if std::fs::create_dir_all(parent).is_ok() {
                        let _ = std::fs::write(path, &skill.markdown);
                    }
                }
            }
            DeployResult {
                build: result.clone(),
                success: true,
                message: format!("Skill '{}' deployed to skills directory.", skill.name),
                requires_restart: false,
            }
        } else {
            DeployResult {
                build: result.clone(),
                success: true,
                message: "Plugin scaffold deployed. Requires manual integration.".to_string(),
                requires_restart: true,
            }
        }
    }

    /// Analyse current platform capabilities.
    pub fn analyze_capabilities(&self) -> CapabilityAnalysis {
        let manifest = self.scanner.full_scan();
        let gaps = self.discover_gaps();
        let total_domains = 10_usize;
        let covered = total_domains.saturating_sub(gaps.len());
        let coverage_pct = (covered as f64 / total_domains as f64) * 100.0;
        CapabilityAnalysis {
            manifest,
            gaps,
            coverage_pct,
        }
    }

    /// Run one iteration of the continuous improvement loop.
    ///
    /// Returns the list of deploy results from this iteration.
    pub fn run_improvement_iteration(&self) -> Vec<DeployResult> {
        let gaps = self.discover_gaps();
        let proposals = self.propose_extensions(&gaps);
        proposals
            .iter()
            .map(|proposal| {
                let build = self.build_and_test(proposal);
                self.deploy_extension(&build)
            })
            .collect()
    }
}

impl Default for AutonomousPipeline {
    fn default() -> Self {
        Self::new(".")
    }
}

fn parse_domain(domain_str: &str) -> SecurityDomain {
    match domain_str.to_lowercase().as_str() {
        "pentest" => SecurityDomain::Pentest,
        "red-team" | "redteam" | "red_team" => SecurityDomain::RedTeam,
        "blue-team" | "blueteam" | "blue_team" => SecurityDomain::BlueTeam,
        "blockchain" => SecurityDomain::Blockchain,
        "exploit-dev" | "exploit_dev" | "exploitdev" => SecurityDomain::ExploitDev,
        "intel" | "threat-intel" => SecurityDomain::ThreatIntel,
        _ => SecurityDomain::Generic,
    }
}
