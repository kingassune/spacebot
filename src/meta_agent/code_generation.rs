//! Code generation for new skills and tools.

use serde::{Deserialize, Serialize};

/// Configuration for a code generation run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeGenConfig {
    /// Target programming language.
    pub language: String,
    /// Domain or security area for the generated module.
    pub domain: String,
    /// Brief description of the skill to generate.
    pub description: String,
    /// Whether to include unit test scaffolding.
    pub include_tests: bool,
    /// Whether to include documentation comments.
    pub include_docs: bool,
}

impl Default for CodeGenConfig {
    fn default() -> Self {
        Self {
            language: "rust".to_string(),
            domain: "security".to_string(),
            description: String::new(),
            include_tests: true,
            include_docs: true,
        }
    }
}

/// A code template used to scaffold a new module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeTemplate {
    pub name: String,
    pub language: String,
    pub template_body: String,
    pub placeholders: Vec<String>,
}

/// A generated code module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneratedModule {
    pub module_name: String,
    pub file_name: String,
    pub language: String,
    pub source_code: String,
    pub test_code: Option<String>,
}

/// Result of a code generation run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenerationResult {
    pub config: CodeGenConfig,
    pub modules: Vec<GeneratedModule>,
    pub success: bool,
    pub notes: String,
}

/// Generate a complete skill module from a description.
pub fn generate_skill_module(config: &CodeGenConfig) -> GenerationResult {
    let module_name = sanitize_name(&config.description);
    let source_code = render_skill_template(config, &module_name);
    let test_code = if config.include_tests {
        Some(render_test_template(&module_name))
    } else {
        None
    };

    let module = GeneratedModule {
        module_name: module_name.clone(),
        file_name: format!("{module_name}.rs"),
        language: config.language.clone(),
        source_code,
        test_code,
    };

    GenerationResult {
        config: config.clone(),
        modules: vec![module],
        success: true,
        notes: format!(
            "Generated skill module '{module_name}' for domain '{}'.",
            config.domain
        ),
    }
}

/// Generate a tool wrapper module.
pub fn generate_tool_wrapper(tool_name: &str, commands: &[&str]) -> GeneratedModule {
    let module_name = sanitize_name(tool_name);
    let mut source = format!(
        "//! Auto-generated tool wrapper for {tool_name}.\n\n\
         use anyhow::Result;\n\n\
         /// Wrapper for the `{tool_name}` external tool.\n\
         pub struct {camel}Wrapper;\n\n\
         impl {camel}Wrapper {{\n",
        camel = to_camel_case(tool_name)
    );

    for cmd in commands {
        let fn_name = sanitize_name(cmd);
        source.push_str(&format!(
            "    /// Run `{cmd}` command.\n\
             pub fn {fn_name}(&self, args: &[&str]) -> Result<String> {{\n\
             let output = std::process::Command::new(\"{tool_name}\")\n\
             .args(args)\n\
             .output()?;\n\
             Ok(String::from_utf8_lossy(&output.stdout).to_string())\n\
             }}\n\n"
        ));
    }

    source.push_str("}\n");

    GeneratedModule {
        module_name: module_name.clone(),
        file_name: format!("{module_name}_wrapper.rs"),
        language: "rust".to_string(),
        source_code: source,
        test_code: None,
    }
}

/// Scaffold a complete plugin directory structure.
pub fn scaffold_plugin(plugin_name: &str, domain: &str) -> Vec<GeneratedModule> {
    let name = sanitize_name(plugin_name);
    let manifest = format!(
        "---\nname: {name}\ndomain: {domain}\nversion: 0.1.0\ndescription: Auto-scaffolded plugin\ncapabilities:\n  - {domain}_analysis\n"
    );
    let main_module = GeneratedModule {
        module_name: name.clone(),
        file_name: "SKILL.md".to_string(),
        language: "markdown".to_string(),
        source_code: manifest,
        test_code: None,
    };

    let config = CodeGenConfig {
        domain: domain.to_string(),
        description: plugin_name.to_string(),
        ..Default::default()
    };
    let mut result = generate_skill_module(&config);
    result.modules.push(main_module);
    result.modules
}

// — Internal helpers —

fn sanitize_name(s: &str) -> String {
    s.to_lowercase()
        .replace([' ', '-'], "_")
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '_')
        .collect()
}

fn to_camel_case(s: &str) -> String {
    s.split(|c: char| !c.is_alphanumeric())
        .filter(|p| !p.is_empty())
        .map(|p| {
            let mut chars = p.chars();
            match chars.next() {
                None => String::new(),
                Some(first) => first.to_uppercase().to_string() + chars.as_str(),
            }
        })
        .collect()
}

fn render_skill_template(config: &CodeGenConfig, module_name: &str) -> String {
    let doc_comment = if config.include_docs {
        format!(
            "//! {} skill module for {}.\n\n",
            module_name, config.domain
        )
    } else {
        String::new()
    };

    format!(
        "{doc_comment}\
         use serde::{{Deserialize, Serialize}};\n\n\
         /// Configuration for the {module_name} skill.\n\
         #[derive(Debug, Clone, Serialize, Deserialize)]\n\
         pub struct {camel}Config {{\n\
         pub target: String,\n\
         }}\n\n\
         /// Result produced by the {module_name} skill.\n\
         #[derive(Debug, Clone, Serialize, Deserialize)]\n\
         pub struct {camel}Result {{\n\
         pub findings: Vec<String>,\n\
         pub score: f64,\n\
         }}\n\n\
         /// Run the {module_name} skill against the given config.\n\
         pub fn run(config: &{camel}Config) -> {camel}Result {{\n\
         {camel}Result {{\n\
         findings: vec![format!(\"Analyzed: {{}}\", config.target)],\n\
         score: 0.0,\n\
         }}\n\
         }}\n",
        camel = to_camel_case(module_name),
    )
}

fn render_test_template(module_name: &str) -> String {
    let camel = to_camel_case(module_name);
    format!(
        "#[cfg(test)]\nmod tests {{\n    use super::*;\n\n\
         #[test]\n    fn test_{module_name}_runs() {{\n\
         let config = {camel}Config {{ target: \"test\".to_string() }};\n\
         let result = run(&config);\n\
         assert!(!result.findings.is_empty());\n\
         }}\n}}\n"
    )
}
