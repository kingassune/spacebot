//! Automated skill factory for the James meta-agent.
//!
//! Generates new skills following the Trail of Bits skill schema:
//! - SKILL.md with YAML frontmatter
//! - `references/` subdirectory with knowledge-base documents
//! - `tools/` subdirectory with Python analysis scripts
//!
//! Generated skills are validated against the schema before being
//! hot-reloaded into the platform's runtime skill registry.

use std::path::{Path, PathBuf};

/// Allowed tool types in a skill's YAML frontmatter.
#[derive(Debug, Clone, PartialEq)]
pub enum AllowedTool {
    Bash,
    Read,
    Write,
    Grep,
    Glob,
    WebFetch,
    TodoRead,
    TodoWrite,
}

impl AllowedTool {
    /// Returns the string representation used in SKILL.md frontmatter.
    pub fn as_str(&self) -> &'static str {
        match self {
            AllowedTool::Bash => "Bash",
            AllowedTool::Read => "Read",
            AllowedTool::Write => "Write",
            AllowedTool::Grep => "Grep",
            AllowedTool::Glob => "Glob",
            AllowedTool::WebFetch => "WebFetch",
            AllowedTool::TodoRead => "TodoRead",
            AllowedTool::TodoWrite => "TodoWrite",
        }
    }
}

/// Specification for a new skill to be generated.
#[derive(Debug, Clone)]
pub struct SkillSpec {
    /// Kebab-case skill name (e.g., `"solana-anchor-audit"`).
    pub name: String,
    /// One-sentence description for the SKILL.md frontmatter.
    pub description: String,
    /// Tools the skill is permitted to invoke.
    pub allowed_tools: Vec<AllowedTool>,
    /// Skill body — the main instructions and guidance in Markdown.
    pub body: String,
    /// Reference documents to create under `references/`.
    pub references: Vec<ReferenceDoc>,
    /// Python tool scripts to generate under `tools/`.
    pub tool_scripts: Vec<ToolScript>,
}

/// A reference knowledge-base document.
#[derive(Debug, Clone)]
pub struct ReferenceDoc {
    /// Filename (e.g., `"vulnerability-patterns.md"`).
    pub filename: String,
    /// Markdown content of the reference document.
    pub content: String,
}

/// A Python tool script to be placed in `tools/`.
#[derive(Debug, Clone)]
pub struct ToolScript {
    /// Script filename (e.g., `"analyze_bytecode.py"`).
    pub filename: String,
    /// Python source code.
    pub content: String,
}

/// Validation error when a skill spec fails schema checks.
#[derive(Debug, Clone)]
pub struct ValidationError {
    pub field: String,
    pub message: String,
}

/// Result of validating a skill spec.
#[derive(Debug, Clone)]
pub struct ValidationResult {
    pub valid: bool,
    pub errors: Vec<ValidationError>,
}

impl ValidationResult {
    pub fn ok() -> Self {
        Self {
            valid: true,
            errors: Vec::new(),
        }
    }
}

/// The skill factory that generates and validates Trail of Bits-style skills.
#[derive(Debug, Clone)]
pub struct SkillFactory {
    /// Root directory where skills are stored.
    pub skills_root: PathBuf,
}

impl SkillFactory {
    /// Create a new factory rooted at the given directory.
    pub fn new(skills_root: impl Into<PathBuf>) -> Self {
        Self {
            skills_root: skills_root.into(),
        }
    }

    /// Validate a skill spec against the Trail of Bits schema.
    pub fn validate(&self, spec: &SkillSpec) -> ValidationResult {
        let mut errors = Vec::new();

        if spec.name.is_empty() {
            errors.push(ValidationError {
                field: "name".to_string(),
                message: "Skill name must not be empty.".to_string(),
            });
        }

        if !spec
            .name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        {
            errors.push(ValidationError {
                field: "name".to_string(),
                message: "Skill name must be kebab-case (lowercase ASCII letters, digits, and hyphens only)."
                    .to_string(),
            });
        }

        if spec.description.is_empty() {
            errors.push(ValidationError {
                field: "description".to_string(),
                message: "Description must not be empty.".to_string(),
            });
        }

        if spec.allowed_tools.is_empty() {
            errors.push(ValidationError {
                field: "allowed_tools".to_string(),
                message: "At least one tool must be listed.".to_string(),
            });
        }

        if spec.body.is_empty() {
            errors.push(ValidationError {
                field: "body".to_string(),
                message: "Skill body must not be empty.".to_string(),
            });
        }

        ValidationResult {
            valid: errors.is_empty(),
            errors,
        }
    }

    /// Generate the SKILL.md content for the given spec.
    pub fn render_skill_md(&self, spec: &SkillSpec) -> String {
        let tools_list = spec
            .allowed_tools
            .iter()
            .map(|t| format!("  - {}", t.as_str()))
            .collect::<Vec<_>>()
            .join("\n");

        format!(
            "---\nname: {}\ndescription: \"{}\"\nallowed-tools:\n{}\n---\n\n{}",
            spec.name, spec.description, tools_list, spec.body
        )
    }

    /// Write the skill to disk under `skills_root/<name>/`.
    ///
    /// Creates:
    /// - `skills/<name>/SKILL.md`
    /// - `skills/<name>/references/<doc>.md` for each reference
    /// - `skills/<name>/tools/<script>.py` for each tool script
    pub fn write_skill(&self, spec: &SkillSpec) -> anyhow::Result<PathBuf> {
        let validation = self.validate(spec);
        if !validation.valid {
            let messages: Vec<String> = validation
                .errors
                .iter()
                .map(|e| format!("{}: {}", e.field, e.message))
                .collect();
            anyhow::bail!("Skill validation failed:\n{}", messages.join("\n"));
        }

        // The name was already validated to contain only [a-z0-9-] by `validate()`,
        // so it is safe to join directly. Validate reference and tool filenames
        // separately since they are not covered by the spec-level validation.
        for reference in &spec.references {
            if reference.filename.contains('/')
                || reference.filename.contains('\\')
                || reference.filename.contains("..")
            {
                anyhow::bail!(
                    "Reference filename '{}' must not contain path separators.",
                    reference.filename
                );
            }
        }
        for script in &spec.tool_scripts {
            if script.filename.contains('/')
                || script.filename.contains('\\')
                || script.filename.contains("..")
            {
                anyhow::bail!(
                    "Tool script filename '{}' must not contain path separators.",
                    script.filename
                );
            }
        }

        let skill_dir = self.skills_root.join(&spec.name);
        std::fs::create_dir_all(&skill_dir)?;

        // Write SKILL.md.
        let skill_md = self.render_skill_md(spec);
        std::fs::write(skill_dir.join("SKILL.md"), &skill_md)?;

        // Write reference documents.
        if !spec.references.is_empty() {
            let references_dir = skill_dir.join("references");
            std::fs::create_dir_all(&references_dir)?;
            for reference in &spec.references {
                std::fs::write(references_dir.join(&reference.filename), &reference.content)?;
            }
        }

        // Write tool scripts.
        if !spec.tool_scripts.is_empty() {
            let tools_dir = skill_dir.join("tools");
            std::fs::create_dir_all(&tools_dir)?;
            for script in &spec.tool_scripts {
                std::fs::write(tools_dir.join(&script.filename), &script.content)?;
            }
        }

        Ok(skill_dir)
    }

    /// List all skill names present under `skills_root`.
    pub fn list_skills(&self) -> anyhow::Result<Vec<String>> {
        let mut skills = Vec::new();
        let read_dir = std::fs::read_dir(&self.skills_root);
        if let Ok(entries) = read_dir {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() && path.join("SKILL.md").exists() {
                    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                        skills.push(name.to_string());
                    }
                }
            }
        }
        skills.sort();
        Ok(skills)
    }

    /// Check whether a skill with the given name already exists.
    pub fn skill_exists(&self, name: &str) -> bool {
        self.skills_root.join(name).join("SKILL.md").exists()
    }
}
