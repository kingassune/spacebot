//! Incident response playbooks and workflow management for blue team operations.

use chrono::Utc;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Informational,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Severity::Critical => "Critical",
            Severity::High => "High",
            Severity::Medium => "Medium",
            Severity::Low => "Low",
            Severity::Informational => "Informational",
        };
        write!(f, "{s}")
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum IncidentPhase {
    Preparation,
    Identification,
    Containment,
    Eradication,
    Recovery,
    LessonsLearned,
}

impl std::fmt::Display for IncidentPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            IncidentPhase::Preparation => "Preparation",
            IncidentPhase::Identification => "Identification",
            IncidentPhase::Containment => "Containment",
            IncidentPhase::Eradication => "Eradication",
            IncidentPhase::Recovery => "Recovery",
            IncidentPhase::LessonsLearned => "Lessons Learned",
        };
        write!(f, "{s}")
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum ContainmentAction {
    NetworkIsolation,
    AccountDisable,
    ProcessKill,
    FirewallRule,
    DnsBlackhole,
    SystemShutdown,
}

#[derive(Debug, Clone)]
pub struct PlaybookPhase {
    pub phase: IncidentPhase,
    pub steps: Vec<String>,
    pub responsible_team: String,
    pub time_limit_hours: u32,
}

#[derive(Debug, Clone)]
pub struct IrPlaybook {
    pub name: String,
    pub severity: Severity,
    pub phases: Vec<PlaybookPhase>,
    pub escalation_contacts: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct IncidentConfig {
    pub incident_id: String,
    pub severity: Severity,
    pub affected_systems: Vec<String>,
    pub assigned_team: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct IncidentRecord {
    pub id: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub severity: Severity,
    pub current_phase: IncidentPhase,
    pub actions_taken: Vec<String>,
}

pub fn generate_ir_playbook(severity: &Severity) -> IrPlaybook {
    let (time_limits, escalation) = match severity {
        Severity::Critical => (
            vec![1u32, 1, 2, 4, 8, 24],
            vec![
                "ciso@org.example".to_string(),
                "cto@org.example".to_string(),
            ],
        ),
        Severity::High => (
            vec![2, 2, 4, 8, 24, 48],
            vec!["security-lead@org.example".to_string()],
        ),
        Severity::Medium => (
            vec![4, 4, 8, 24, 72, 72],
            vec!["soc@org.example".to_string()],
        ),
        Severity::Low | Severity::Informational => (
            vec![8, 8, 24, 48, 96, 96],
            vec!["soc@org.example".to_string()],
        ),
    };

    let phases = vec![
        PlaybookPhase {
            phase: IncidentPhase::Preparation,
            steps: vec![
                "Confirm IR team availability".to_string(),
                "Verify communication channels are operational".to_string(),
                "Ensure forensics tooling is ready".to_string(),
            ],
            responsible_team: "SOC".to_string(),
            time_limit_hours: time_limits[0],
        },
        PlaybookPhase {
            phase: IncidentPhase::Identification,
            steps: vec![
                "Triage and validate the alert".to_string(),
                "Determine scope of affected systems".to_string(),
                "Classify incident severity".to_string(),
                "Notify stakeholders".to_string(),
            ],
            responsible_team: "SOC".to_string(),
            time_limit_hours: time_limits[1],
        },
        PlaybookPhase {
            phase: IncidentPhase::Containment,
            steps: vec![
                "Isolate affected systems from the network".to_string(),
                "Disable compromised accounts".to_string(),
                "Apply emergency firewall rules".to_string(),
                "Preserve forensic evidence".to_string(),
            ],
            responsible_team: "IR Team".to_string(),
            time_limit_hours: time_limits[2],
        },
        PlaybookPhase {
            phase: IncidentPhase::Eradication,
            steps: vec![
                "Remove malicious artifacts from affected systems".to_string(),
                "Patch or remediate exploited vulnerabilities".to_string(),
                "Reset compromised credentials".to_string(),
                "Verify removal of attacker persistence mechanisms".to_string(),
            ],
            responsible_team: "IR Team".to_string(),
            time_limit_hours: time_limits[3],
        },
        PlaybookPhase {
            phase: IncidentPhase::Recovery,
            steps: vec![
                "Restore systems from clean backups".to_string(),
                "Re-enable network connectivity with monitoring".to_string(),
                "Validate systems are operating normally".to_string(),
                "Monitor for signs of re-compromise".to_string(),
            ],
            responsible_team: "Operations".to_string(),
            time_limit_hours: time_limits[4],
        },
        PlaybookPhase {
            phase: IncidentPhase::LessonsLearned,
            steps: vec![
                "Conduct post-incident review meeting".to_string(),
                "Document timeline and findings".to_string(),
                "Identify detection and response gaps".to_string(),
                "Update playbooks and controls".to_string(),
            ],
            responsible_team: "Security Management".to_string(),
            time_limit_hours: time_limits[5],
        },
    ];

    IrPlaybook {
        name: format!("{severity} Incident Response Playbook"),
        severity: severity.clone(),
        phases,
        escalation_contacts: escalation,
    }
}

pub fn record_action(record: &mut IncidentRecord, action: &str) {
    let timestamp = Utc::now().format("%Y-%m-%dT%H:%M:%SZ");
    record.actions_taken.push(format!("[{timestamp}] {action}"));
}

pub fn advance_phase(record: &mut IncidentRecord) {
    record.current_phase = match record.current_phase {
        IncidentPhase::Preparation => IncidentPhase::Identification,
        IncidentPhase::Identification => IncidentPhase::Containment,
        IncidentPhase::Containment => IncidentPhase::Eradication,
        IncidentPhase::Eradication => IncidentPhase::Recovery,
        IncidentPhase::Recovery => IncidentPhase::LessonsLearned,
        IncidentPhase::LessonsLearned => IncidentPhase::LessonsLearned,
    };
}

pub fn generate_incident_report(record: &IncidentRecord) -> String {
    let actions = if record.actions_taken.is_empty() {
        "  _None recorded._".to_string()
    } else {
        record
            .actions_taken
            .iter()
            .map(|a| format!("- {a}"))
            .collect::<Vec<_>>()
            .join("\n")
    };

    format!(
        "# Incident Report\n\n\
        **Incident ID:** {id}\n\
        **Created:** {created}\n\
        **Severity:** {severity}\n\
        **Current Phase:** {phase}\n\n\
        ## Actions Taken\n\n{actions}\n",
        id = record.id,
        created = record.created_at.format("%Y-%m-%dT%H:%M:%SZ"),
        severity = record.severity,
        phase = record.current_phase,
        actions = actions,
    )
}

impl IncidentRecord {
    pub fn new(severity: Severity) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            created_at: Utc::now(),
            severity,
            current_phase: IncidentPhase::Preparation,
            actions_taken: Vec::new(),
        }
    }
}
