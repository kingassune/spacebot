//! Workflow definition and execution for meta-agent security tasks.

use chrono::{DateTime, Utc};
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq)]
pub enum FailureAction {
    Abort,
    Retry,
    Skip,
    Escalate,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ExecutionStatus {
    Pending,
    Running,
    Success,
    Failed,
    TimedOut,
}

#[derive(Debug, Clone)]
pub struct WorkflowStep {
    pub id: String,
    pub action: String,
    pub inputs: HashMap<String, String>,
    pub outputs: Vec<String>,
    pub timeout_secs: u64,
}

#[derive(Debug, Clone)]
pub struct WorkflowDefinition {
    pub id: String,
    pub name: String,
    pub steps: Vec<WorkflowStep>,
    pub triggers: Vec<String>,
    pub on_failure: FailureAction,
}

#[derive(Debug, Clone)]
pub struct WorkflowExecution {
    pub workflow_id: String,
    pub status: ExecutionStatus,
    pub current_step: usize,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}

pub fn create_workflow(name: &str, steps: Vec<WorkflowStep>) -> WorkflowDefinition {
    WorkflowDefinition {
        id: format!("{}-{}", name.to_lowercase().replace(' ', "-"), Utc::now().timestamp()),
        name: name.to_string(),
        steps,
        triggers: Vec::new(),
        on_failure: FailureAction::Abort,
    }
}

/// Advances `execution` to the next step. Returns `false` when all steps are complete.
pub fn advance_step(execution: &mut WorkflowExecution, workflow: &WorkflowDefinition) -> bool {
    if execution.current_step + 1 < workflow.steps.len() {
        execution.current_step += 1;
        true
    } else {
        execution.status = ExecutionStatus::Success;
        execution.completed_at = Some(Utc::now());
        false
    }
}

pub fn generate_workflow_report(execution: &WorkflowExecution) -> String {
    let completed = execution
        .completed_at
        .map(|t| t.to_rfc3339())
        .unwrap_or_else(|| "in progress".to_string());

    format!(
        "# Workflow Execution Report\n\n- **Workflow ID**: {}\n- **Status**: {:?}\n- **Current Step**: {}\n- **Started**: {}\n- **Completed**: {}\n",
        execution.workflow_id,
        execution.status,
        execution.current_step,
        execution.started_at.to_rfc3339(),
        completed,
    )
}
