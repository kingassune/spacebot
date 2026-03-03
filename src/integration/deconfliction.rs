//! Deconfliction module for multi-team operations.
//!
//! Prevents red/blue team interference, manages engagement boundaries,
//! and tracks all authorized actions.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Configuration for the deconfliction service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeconflictionConfig {
    /// Engagement identifier shared between red and blue teams.
    pub engagement_id: String,
    /// List of teams participating in the engagement.
    pub teams: Vec<String>,
    /// Whether to automatically block out-of-scope actions.
    pub enforce_boundaries: bool,
    /// Whether to notify blue team of red team actions in real time.
    pub realtime_notify: bool,
}

impl Default for DeconflictionConfig {
    fn default() -> Self {
        Self {
            engagement_id: "ENG-001".to_string(),
            teams: vec!["red".to_string(), "blue".to_string()],
            enforce_boundaries: true,
            realtime_notify: false,
        }
    }
}

/// Defines the authorized scope boundaries for an engagement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngagementBoundary {
    /// IP ranges or hostnames in scope.
    pub in_scope_targets: Vec<String>,
    /// Explicitly excluded targets.
    pub excluded_targets: Vec<String>,
    /// Allowed attack techniques (ATT&CK IDs).
    pub allowed_techniques: Vec<String>,
    /// Hard stop time for the engagement.
    pub engagement_end: DateTime<Utc>,
}

impl EngagementBoundary {
    /// Check whether a given target is in scope.
    pub fn is_in_scope(&self, target: &str) -> bool {
        if self.excluded_targets.contains(&target.to_string()) {
            return false;
        }
        self.in_scope_targets
            .iter()
            .any(|t| target.starts_with(t.as_str()) || t == target)
    }

    /// Check whether a technique is authorized.
    pub fn is_technique_authorized(&self, technique_id: &str) -> bool {
        self.allowed_techniques.is_empty()
            || self.allowed_techniques.contains(&technique_id.to_string())
    }
}

/// An authorized action recorded by the deconfliction system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizedAction {
    pub action_id: String,
    pub team: String,
    pub technique_id: String,
    pub target: String,
    pub timestamp: DateTime<Utc>,
    pub authorized: bool,
    pub reason: String,
}

/// An event where a conflict or boundary violation was detected.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConflictEvent {
    pub event_id: String,
    pub event_type: ConflictType,
    pub team: String,
    pub target: String,
    pub technique_id: String,
    pub detected_at: DateTime<Utc>,
    pub resolution: String,
}

/// Classification of a deconfliction conflict.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ConflictType {
    /// Red team action hit an excluded target.
    OutOfScope,
    /// Red team technique not in the authorized list.
    UnauthorizedTechnique,
    /// Simultaneous red/blue activity on the same host.
    TeamConflict,
    /// Action took place outside authorized time window.
    TimeViolation,
}

/// Deconfliction service for multi-team engagements.
#[derive(Debug, Clone)]
pub struct Deconfliction {
    pub config: DeconflictionConfig,
    pub boundary: Option<EngagementBoundary>,
    pub action_log: Vec<AuthorizedAction>,
    pub conflict_log: Vec<ConflictEvent>,
}

impl Deconfliction {
    pub fn new(config: DeconflictionConfig) -> Self {
        Self {
            config,
            boundary: None,
            action_log: Vec::new(),
            conflict_log: Vec::new(),
        }
    }

    /// Set the engagement boundary.
    pub fn set_boundary(&mut self, boundary: EngagementBoundary) {
        self.boundary = Some(boundary);
    }

    /// Request authorization for an action.
    /// Returns `Ok(AuthorizedAction)` if permitted, or `Err` with the reason.
    pub fn authorize_action(
        &mut self,
        team: &str,
        technique_id: &str,
        target: &str,
    ) -> Result<AuthorizedAction, Box<ConflictEvent>> {
        let action_id = uuid::Uuid::new_v4().to_string();
        let now = Utc::now();

        if let Some(boundary) = &self.boundary {
            if !boundary.is_in_scope(target) {
                let event = ConflictEvent {
                    event_id: uuid::Uuid::new_v4().to_string(),
                    event_type: ConflictType::OutOfScope,
                    team: team.to_string(),
                    target: target.to_string(),
                    technique_id: technique_id.to_string(),
                    detected_at: now,
                    resolution: format!(
                        "Action blocked: target '{target}' is out of engagement scope."
                    ),
                };
                self.conflict_log.push(event.clone());
                return Err(Box::new(event));
            }

            if !boundary.is_technique_authorized(technique_id) {
                let event = ConflictEvent {
                    event_id: uuid::Uuid::new_v4().to_string(),
                    event_type: ConflictType::UnauthorizedTechnique,
                    team: team.to_string(),
                    target: target.to_string(),
                    technique_id: technique_id.to_string(),
                    detected_at: now,
                    resolution: format!(
                        "Action blocked: technique '{technique_id}' is not authorized for this engagement."
                    ),
                };
                self.conflict_log.push(event.clone());
                return Err(Box::new(event));
            }
        }

        let action = AuthorizedAction {
            action_id,
            team: team.to_string(),
            technique_id: technique_id.to_string(),
            target: target.to_string(),
            timestamp: now,
            authorized: true,
            reason: "Within engagement boundary".to_string(),
        };
        self.action_log.push(action.clone());
        Ok(action)
    }

    /// Returns a list of all conflict events.
    pub fn conflict_summary(&self) -> &[ConflictEvent] {
        &self.conflict_log
    }

    /// Returns all authorized actions for a given team.
    pub fn team_actions(&self, team: &str) -> Vec<&AuthorizedAction> {
        self.action_log.iter().filter(|a| a.team == team).collect()
    }

    /// Detect overlapping activity between teams on the same target.
    pub fn detect_team_conflicts(&mut self) {
        let red_targets: std::collections::HashSet<&str> = self
            .action_log
            .iter()
            .filter(|a| a.team == "red")
            .map(|a| a.target.as_str())
            .collect();
        let blue_targets: std::collections::HashSet<&str> = self
            .action_log
            .iter()
            .filter(|a| a.team == "blue")
            .map(|a| a.target.as_str())
            .collect();

        for overlap in red_targets.intersection(&blue_targets) {
            self.conflict_log.push(ConflictEvent {
                event_id: uuid::Uuid::new_v4().to_string(),
                event_type: ConflictType::TeamConflict,
                team: "both".to_string(),
                target: overlap.to_string(),
                technique_id: "N/A".to_string(),
                detected_at: Utc::now(),
                resolution: format!(
                    "Simultaneous red/blue activity detected on '{overlap}'. Coordinate via deconfliction channel."
                ),
            });
        }
    }
}
