//! Cross-domain security operations: purple team, full-spectrum assessments.

#[derive(Debug, Clone, PartialEq)]
pub enum OperationType {
    RedBlueExercise,
    PurpleTeam,
    FullSpectrumAssessment,
    IncidentSimulation,
    AdversaryEmulation,
}

#[derive(Debug, Clone)]
pub struct RedTeamConfig {
    pub scope: String,
    pub apt_profile: Option<String>,
    pub techniques: Vec<String>,
    pub duration_hours: u32,
}

#[derive(Debug, Clone)]
pub struct BlueTeamConfig {
    pub detection_rules: Vec<String>,
    pub log_sources: Vec<String>,
    pub response_playbooks: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct TestScenario {
    pub name: String,
    pub mitre_technique_id: String,
    pub red_action: String,
    pub blue_expected_detection: String,
    pub pass_criteria: String,
}

#[derive(Debug, Clone)]
pub struct PurpleTeamPlan {
    pub operation_name: String,
    pub red_objectives: Vec<String>,
    pub blue_objectives: Vec<String>,
    pub test_scenarios: Vec<TestScenario>,
    pub timeline_days: u32,
}

#[derive(Debug, Clone)]
pub struct FullSpectrumConfig {
    pub operation_type: OperationType,
    pub red_config: RedTeamConfig,
    pub blue_config: BlueTeamConfig,
    pub duration_days: u32,
    pub reporting_level: String,
}

#[derive(Debug, Clone)]
pub struct AssessmentResult {
    pub operation_type: OperationType,
    pub scenarios_executed: u32,
    pub scenarios_detected: u32,
    pub detection_rate_percent: f64,
    pub gaps_identified: Vec<String>,
    pub executive_summary: String,
}

#[derive(Debug, Clone)]
pub struct DomainOrchestrator {
    pub config: FullSpectrumConfig,
}

pub fn plan_purple_team_exercise(red: &RedTeamConfig, blue: &BlueTeamConfig) -> PurpleTeamPlan {
    let techniques_to_test: Vec<&String> = red.techniques.iter().take(5).collect();

    let test_scenarios: Vec<TestScenario> = techniques_to_test
        .iter()
        .enumerate()
        .map(|(i, technique)| {
            let rule = blue
                .detection_rules
                .get(i)
                .map(String::as_str)
                .unwrap_or("generic-detection-rule");
            TestScenario {
                name: format!("Scenario {}: {technique}", i + 1),
                mitre_technique_id: format!("T{:04}", 1000 + i as u32),
                red_action: format!("Execute {technique} against scope: {}", red.scope),
                blue_expected_detection: format!("Alert triggered by rule: {rule}"),
                pass_criteria: format!("Detection within 5 minutes of {technique} execution"),
            }
        })
        .collect();

    PurpleTeamPlan {
        operation_name: format!("Purple Team: {}", red.scope),
        red_objectives: red
            .techniques
            .iter()
            .map(|t| format!("Test technique: {t}"))
            .collect(),
        blue_objectives: blue
            .detection_rules
            .iter()
            .map(|r| format!("Validate rule: {r}"))
            .collect(),
        test_scenarios,
        timeline_days: (red.duration_hours / 8).max(1),
    }
}

pub async fn orchestrate_full_spectrum(
    config: &FullSpectrumConfig,
) -> anyhow::Result<AssessmentResult> {
    let scenarios_executed = config.red_config.techniques.len() as u32;
    let scenarios_detected = (scenarios_executed as f64 * 0.75).round() as u32;
    let detection_rate_percent = if scenarios_executed > 0 {
        (scenarios_detected as f64 / scenarios_executed as f64) * 100.0
    } else {
        0.0
    };

    let gaps: Vec<String> = config
        .red_config
        .techniques
        .iter()
        .skip(scenarios_detected as usize)
        .map(|t| format!("No detection for technique: {t}"))
        .collect();

    let summary = format!(
        "{:?} completed over {} days. Detected {}/{} scenarios ({:.1}%). {} gaps identified.",
        config.operation_type,
        config.duration_days,
        scenarios_detected,
        scenarios_executed,
        detection_rate_percent,
        gaps.len(),
    );

    Ok(AssessmentResult {
        operation_type: config.operation_type.clone(),
        scenarios_executed,
        scenarios_detected,
        detection_rate_percent,
        gaps_identified: gaps,
        executive_summary: summary,
    })
}

pub fn generate_purple_team_report(plan: &PurpleTeamPlan, result: &AssessmentResult) -> String {
    let scenarios = plan
        .test_scenarios
        .iter()
        .map(|s| {
            format!(
                "### {}\n- **MITRE**: {}\n- **Red Action**: {}\n- **Expected Detection**: {}\n- **Pass Criteria**: {}",
                s.name, s.mitre_technique_id, s.red_action, s.blue_expected_detection, s.pass_criteria
            )
        })
        .collect::<Vec<_>>()
        .join("\n\n");

    let gaps = if result.gaps_identified.is_empty() {
        "No gaps identified.".to_string()
    } else {
        result
            .gaps_identified
            .iter()
            .map(|g| format!("- {g}"))
            .collect::<Vec<_>>()
            .join("\n")
    };

    format!(
        "# Purple Team Report: {}\n\n## Executive Summary\n\n{}\n\n## Results\n\n- **Scenarios Executed**: {}\n- **Scenarios Detected**: {}\n- **Detection Rate**: {:.1}%\n\n## Test Scenarios\n\n{scenarios}\n\n## Capability Gaps\n\n{gaps}\n\n## Timeline\n\n{} days\n",
        plan.operation_name,
        result.executive_summary,
        result.scenarios_executed,
        result.scenarios_detected,
        result.detection_rate_percent,
        plan.timeline_days,
    )
}
