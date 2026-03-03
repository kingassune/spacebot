//! Detection rule generation and validation for blue team defensive operations.

use anyhow::Result;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq)]
pub enum RuleFormat {
    Yara,
    Sigma,
    Suricata,
    Snort,
    Kql,
    Spl,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Informational,
}

#[derive(Debug, Clone)]
pub struct DetectionRule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub format: RuleFormat,
    pub severity: Severity,
    pub content: String,
}

impl DetectionRule {
    pub fn new(name: &str, format: RuleFormat, content: String) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            name: name.to_string(),
            description: String::new(),
            format,
            severity: Severity::Medium,
            content,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DetectionConfig {
    pub rule_sources: Vec<String>,
    pub severity_threshold: Severity,
    pub output_dir: String,
}

#[derive(Debug, Clone)]
pub struct ValidationResult {
    pub valid: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum IndicatorType {
    IpAddress,
    Domain,
    Hash,
    Url,
    Email,
    FilePath,
}

#[derive(Debug, Clone)]
pub struct Indicator {
    pub value: String,
    pub indicator_type: IndicatorType,
}

#[derive(Debug, Clone)]
pub struct NetworkIndicator {
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    pub dst_port: Option<u16>,
    pub protocol: String,
    pub signature: String,
}

#[derive(Debug, Clone)]
pub struct MitreAttackTechnique {
    pub id: String,
    pub name: String,
    pub tactic: String,
}

pub fn generate_yara_rule(indicator: &Indicator) -> String {
    let safe_name = indicator.value.replace(['.', '/', '@', ':'], "_");
    let type_tag = match indicator.indicator_type {
        IndicatorType::IpAddress => "ip",
        IndicatorType::Domain => "domain",
        IndicatorType::Hash => "hash",
        IndicatorType::Url => "url",
        IndicatorType::Email => "email",
        IndicatorType::FilePath => "filepath",
    };
    format!(
        r#"rule {type_tag}_{safe_name}
{{
    meta:
        description = "Indicator match for {value}"
        indicator_type = "{type_tag}"
    strings:
        $indicator = "{value}"
    condition:
        $indicator
}}"#,
        type_tag = type_tag,
        safe_name = safe_name,
        value = indicator.value,
    )
}

pub fn generate_sigma_rule(technique: &MitreAttackTechnique) -> String {
    format!(
        r#"title: Detection for {name}
status: experimental
description: Detects activity associated with MITRE ATT&CK {id} ({name})
tags:
    - attack.{tactic}
    - attack.{id_lower}
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - '{id}'
    condition: selection
falsepositives:
    - Unknown
level: medium"#,
        name = technique.name,
        id = technique.id,
        tactic = technique.tactic.to_lowercase().replace(' ', "_"),
        id_lower = technique.id.to_lowercase(),
    )
}

pub fn generate_suricata_rule(network_indicator: &NetworkIndicator) -> String {
    let src = network_indicator.src_ip.as_deref().unwrap_or("any");
    let dst = network_indicator.dst_ip.as_deref().unwrap_or("any");
    let port = network_indicator
        .dst_port
        .map(|p| p.to_string())
        .unwrap_or_else(|| "any".to_string());
    let proto = network_indicator.protocol.to_lowercase();
    let sid = uuid_to_u32_sid();
    format!(
        r#"alert {proto} {src} any -> {dst} {port} (msg:"{sig}"; sid:{sid}; rev:1;)"#,
        proto = proto,
        src = src,
        dst = dst,
        port = port,
        sig = network_indicator.signature,
        sid = sid,
    )
}

fn uuid_to_u32_sid() -> u32 {
    let id = Uuid::new_v4();
    let bytes = id.as_bytes();
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

pub fn validate_rule(rule: &str, format: &RuleFormat) -> Result<ValidationResult> {
    let mut errors = Vec::new();
    let warnings = Vec::new();

    let valid = match format {
        RuleFormat::Yara => {
            if !rule.contains("rule ") {
                errors.push("YARA rule must start with 'rule' keyword".to_string());
            }
            if !rule.contains("condition:") {
                errors.push("YARA rule must have a 'condition' section".to_string());
            }
            errors.is_empty()
        }
        RuleFormat::Sigma => {
            if !rule.contains("title:") {
                errors.push("Sigma rule must contain 'title' field".to_string());
            }
            if !rule.contains("detection:") {
                errors.push("Sigma rule must contain 'detection' section".to_string());
            }
            errors.is_empty()
        }
        RuleFormat::Suricata | RuleFormat::Snort => {
            let valid_actions = ["alert", "log", "pass", "drop", "reject", "sdrop"];
            let starts_valid = valid_actions.iter().any(|a| rule.trim().starts_with(a));
            if !starts_valid {
                errors
                    .push("Suricata/Snort rule must start with a valid action keyword".to_string());
            }
            if !rule.contains("sid:") {
                errors.push("Suricata/Snort rule must contain 'sid'".to_string());
            }
            errors.is_empty()
        }
        RuleFormat::Kql => {
            if rule.trim().is_empty() {
                errors.push("KQL query must not be empty".to_string());
            }
            errors.is_empty()
        }
        RuleFormat::Spl => {
            if rule.trim().is_empty() {
                errors.push("SPL query must not be empty".to_string());
            }
            errors.is_empty()
        }
    };

    Ok(ValidationResult {
        valid,
        errors,
        warnings,
    })
}
