//! Skill generation from vulnerability patterns and threat intelligence.

use std::collections::HashMap;

/// Security domain for skill generation targeting.
#[derive(Debug, Clone, PartialEq)]
pub enum SecurityDomain {
    Pentest,
    RedTeam,
    BlueTeam,
    Blockchain,
    ExploitDev,
    ThreatIntel,
    Generic,
}

/// A skill generated from a task description and domain context.
#[derive(Debug, Clone)]
pub struct GeneratedSkill {
    pub name: String,
    pub domain: SecurityDomain,
    pub description: String,
    pub markdown: String,
}

/// Generates SKILL.md files from task descriptions and domain context.
#[derive(Debug, Clone)]
pub struct SkillGenerator {
    pub default_domain: SecurityDomain,
}

impl SkillGenerator {
    pub fn new(default_domain: SecurityDomain) -> Self {
        Self { default_domain }
    }

    /// Analyze a task description and generate a SKILL.md for the given domain.
    pub fn generate_skill(&self, task: &str, domain: SecurityDomain) -> GeneratedSkill {
        let sanitised = task.to_lowercase().replace(' ', "-");
        let name = format!("{}-{}", domain_prefix(&domain), sanitised);
        let description = format!("Skill for: {task}");
        let markdown = build_skill_markdown(&name, &description, &domain, task);
        GeneratedSkill {
            name,
            domain,
            description,
            markdown,
        }
    }
}

impl Default for SkillGenerator {
    fn default() -> Self {
        Self::new(SecurityDomain::Generic)
    }
}

fn domain_prefix(domain: &SecurityDomain) -> &'static str {
    match domain {
        SecurityDomain::Pentest => "pentest",
        SecurityDomain::RedTeam => "redteam",
        SecurityDomain::BlueTeam => "blueteam",
        SecurityDomain::Blockchain => "blockchain",
        SecurityDomain::ExploitDev => "exploit",
        SecurityDomain::ThreatIntel => "intel",
        SecurityDomain::Generic => "skill",
    }
}

fn build_skill_markdown(
    name: &str,
    description: &str,
    domain: &SecurityDomain,
    task: &str,
) -> String {
    let domain_label = format!("{domain:?}");
    format!(
        "---\nname: {name}\ndescription: {description}\n---\n\n# {name}\n\n**Domain**: {domain_label}\n\n## Task\n\n{task}\n\n## Steps\n\n1. Analyze the target\n2. Execute domain-specific checks\n3. Report findings with severity ratings\n4. Recommend mitigations\n"
    )
}

#[derive(Debug, Clone, PartialEq)]
pub enum SkillType {
    Detection,
    Response,
    Hunting,
    Analysis,
    Reporting,
    Orchestration,
}

#[derive(Debug, Clone)]
pub struct SkillTemplate {
    pub name: String,
    pub description: String,
    pub triggers: Vec<String>,
    pub workflow_steps: Vec<String>,
    pub skill_type: SkillType,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct SkillSpec {
    pub name: String,
    pub domain: String,
    pub input_format: String,
    pub output_format: String,
    pub required_tools: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ThreatIntelReport {
    pub title: String,
    pub threat_actor: Option<String>,
    pub techniques: Vec<String>,
    pub iocs: Vec<String>,
    pub confidence: u8,
}

#[derive(Debug, Clone)]
pub struct VulnerabilityPattern {
    pub id: String,
    pub name: String,
    pub description: String,
    pub affected_languages: Vec<String>,
    pub detection_regex: String,
}

pub fn generate_skill_from_pattern(
    vuln_pattern: &VulnerabilityPattern,
) -> anyhow::Result<SkillTemplate> {
    let mut metadata = HashMap::new();
    metadata.insert("pattern_id".to_string(), vuln_pattern.id.clone());
    metadata.insert(
        "affected_languages".to_string(),
        vuln_pattern.affected_languages.join(", "),
    );
    metadata.insert(
        "detection_regex".to_string(),
        vuln_pattern.detection_regex.clone(),
    );

    let template = SkillTemplate {
        name: format!(
            "detect-{}",
            vuln_pattern.id.to_lowercase().replace(' ', "-")
        ),
        description: format!(
            "Detects {} vulnerability: {}",
            vuln_pattern.name, vuln_pattern.description
        ),
        triggers: vec![
            format!("vulnerability:{}", vuln_pattern.id),
            format!("pattern:{}", vuln_pattern.name),
        ],
        workflow_steps: vec![
            format!("Scan code using regex: {}", vuln_pattern.detection_regex),
            "Report findings with line numbers and context".to_string(),
            "Suggest remediation steps".to_string(),
        ],
        skill_type: SkillType::Detection,
        metadata,
    };
    Ok(template)
}

pub fn generate_skill_from_threat_intel(
    intel: &ThreatIntelReport,
) -> anyhow::Result<SkillTemplate> {
    let mut metadata = HashMap::new();
    metadata.insert("confidence".to_string(), intel.confidence.to_string());
    if let Some(actor) = &intel.threat_actor {
        metadata.insert("threat_actor".to_string(), actor.clone());
    }
    metadata.insert("ioc_count".to_string(), intel.iocs.len().to_string());

    let triggers: Vec<String> = intel
        .techniques
        .iter()
        .map(|t| format!("technique:{t}"))
        .chain(intel.iocs.iter().map(|ioc| format!("ioc:{ioc}")))
        .collect();

    let workflow_steps = vec![
        format!("Check IOCs: {}", intel.iocs.join(", ")),
        format!("Detect techniques: {}", intel.techniques.join(", ")),
        "Correlate with existing alerts".to_string(),
        "Generate detection report".to_string(),
    ];

    let template = SkillTemplate {
        name: format!("detect-{}", intel.title.to_lowercase().replace(' ', "-")),
        description: format!("Detection skill derived from threat intel: {}", intel.title),
        triggers,
        workflow_steps,
        skill_type: SkillType::Detection,
        metadata,
    };
    Ok(template)
}

pub fn generate_skill_markdown(template: &SkillTemplate) -> String {
    let skill_type = format!("{:?}", template.skill_type);
    let triggers = template.triggers.join("\n- ");
    let steps = template
        .workflow_steps
        .iter()
        .enumerate()
        .map(|(i, s)| format!("{}. {s}", i + 1))
        .collect::<Vec<_>>()
        .join("\n");
    let meta = template
        .metadata
        .iter()
        .map(|(k, v)| format!("- **{k}**: {v}"))
        .collect::<Vec<_>>()
        .join("\n");

    format!(
        "# Skill: {}\n\n## Description\n\n{}\n\n## Type\n\n{skill_type}\n\n## Triggers\n\n- {triggers}\n\n## Workflow Steps\n\n{steps}\n\n## Metadata\n\n{meta}\n",
        template.name, template.description,
    )
}

pub fn validate_skill_template(template: &SkillTemplate) -> anyhow::Result<()> {
    anyhow::ensure!(!template.name.is_empty(), "skill name must not be empty");
    anyhow::ensure!(
        !template.description.is_empty(),
        "skill description must not be empty"
    );
    anyhow::ensure!(
        !template.workflow_steps.is_empty(),
        "skill must have at least one workflow step"
    );
    Ok(())
}
