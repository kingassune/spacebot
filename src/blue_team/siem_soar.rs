//! SIEM/SOAR integration, query building, alert ingestion, and correlation for blue team operations.

use anyhow::{Result, anyhow};
use chrono::Utc;
use sha2::Digest as _;
use uuid::Uuid;

/// Base confidence increment per alert in a correlation group.
const CORRELATION_CONFIDENCE_FACTOR: f64 = 0.1;

#[derive(Debug, Clone, PartialEq)]
pub enum SiemPlatform {
    Elastic,
    Splunk,
    QRadar,
    Sentinel,
    Chronicle,
    Opensearch,
}

#[derive(Debug, Clone)]
pub struct SiemConfig {
    pub platform: SiemPlatform,
    pub host: String,
    pub port: u16,
    pub api_key: String,
    pub index: String,
}

#[derive(Debug, Clone)]
pub struct PlaybookCondition {
    pub field: String,
    pub operator: String,
    pub value: String,
}

#[derive(Debug, Clone)]
pub enum PlaybookAction {
    RunScript(String),
    CreateTicket(String),
    SendAlert(String),
    BlockIp(String),
    DisableAccount(String),
    IsolateHost(String),
}

#[derive(Debug, Clone)]
pub struct SoarPlaybook {
    pub id: String,
    pub name: String,
    pub triggers: Vec<String>,
    pub conditions: Vec<PlaybookCondition>,
    pub actions: Vec<PlaybookAction>,
    pub notifications: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct AlertCorrelation {
    pub correlation_id: String,
    pub alert_ids: Vec<String>,
    pub technique: String,
    pub confidence: f64,
    pub first_seen: chrono::DateTime<chrono::Utc>,
    pub last_seen: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone)]
pub struct QueryBuilder {
    pub platform: SiemPlatform,
    pub base_query: String,
    filters: Vec<(String, String)>,
}

impl QueryBuilder {
    pub fn new(platform: SiemPlatform) -> Self {
        Self {
            platform,
            base_query: String::new(),
            filters: Vec::new(),
        }
    }

    pub fn add_filter(&mut self, field: &str, value: &str) -> &mut Self {
        self.filters.push((field.to_string(), value.to_string()));
        self
    }

    pub fn build(&self) -> String {
        match self.platform {
            SiemPlatform::Elastic | SiemPlatform::Opensearch | SiemPlatform::Sentinel => {
                // KQL format: field:"value" AND field2:"value2"
                let filter_parts: Vec<String> = self
                    .filters
                    .iter()
                    .map(|(f, v)| format!("{f}:\"{v}\""))
                    .collect();
                if self.base_query.is_empty() {
                    filter_parts.join(" AND ")
                } else if filter_parts.is_empty() {
                    self.base_query.clone()
                } else {
                    format!("{} AND {}", self.base_query, filter_parts.join(" AND "))
                }
            }
            SiemPlatform::Splunk => {
                // SPL format: search base | where field="value"
                let base = if self.base_query.is_empty() {
                    "search *".to_string()
                } else {
                    format!("search {}", self.base_query)
                };
                let where_clauses: Vec<String> = self
                    .filters
                    .iter()
                    .map(|(f, v)| format!("{f}=\"{v}\""))
                    .collect();
                if where_clauses.is_empty() {
                    base
                } else {
                    format!("{base} | where {}", where_clauses.join(" AND "))
                }
            }
            SiemPlatform::QRadar => {
                // AQL format: SELECT * FROM events WHERE field='value'
                let where_clauses: Vec<String> = self
                    .filters
                    .iter()
                    .map(|(f, v)| format!("{f}='{v}'"))
                    .collect();
                let source = if self.base_query.is_empty() {
                    "events".to_string()
                } else {
                    self.base_query.clone()
                };
                if where_clauses.is_empty() {
                    format!("SELECT * FROM {source}")
                } else {
                    format!(
                        "SELECT * FROM {source} WHERE {}",
                        where_clauses.join(" AND ")
                    )
                }
            }
            SiemPlatform::Chronicle => {
                // YARA-L 2.0 format
                let conditions: Vec<String> = self
                    .filters
                    .iter()
                    .map(|(f, v)| format!("  $event.{f} = \"{v}\""))
                    .collect();
                let condition_block = if conditions.is_empty() {
                    "  true".to_string()
                } else {
                    conditions.join("\n")
                };
                format!(
                    "rule detection_rule {{\n  meta:\n    description = \"{base}\"\n  events:\n{condition_block}\n  condition:\n    $event\n}}",
                    base = self.base_query,
                    condition_block = condition_block,
                )
            }
        }
    }
}

pub async fn ingest_alert(config: &SiemConfig, alert_json: &str) -> Result<String> {
    // Parse the incoming JSON to validate it and extract a stable alert ID.
    let value: serde_json::Value =
        serde_json::from_str(alert_json).map_err(|e| anyhow!("invalid alert JSON: {e}"))?;

    // Use an existing `id` field when present, otherwise derive one from a
    // deterministic SHA-256 hash of the content so duplicate alerts collapse
    // consistently across Rust versions and deployments.
    let alert_id = if let Some(id) = value.get("id").and_then(|v| v.as_str()) {
        id.to_string()
    } else {
        let mut hasher = sha2::Sha256::new();
        hasher.update(alert_json.as_bytes());
        hasher.update(config.index.as_bytes());
        format!("alert-{:x}", hasher.finalize())
    };

    tracing::debug!(
        platform = ?config.platform,
        host = %config.host,
        index = %config.index,
        alert_id = %alert_id,
        "ingested SIEM alert"
    );

    Ok(alert_id)
}

pub fn correlate_alerts(alerts: &[String]) -> Vec<AlertCorrelation> {
    if alerts.is_empty() {
        return vec![];
    }

    // Parse each JSON alert and group by the `technique` or `event_type` field.
    let mut technique_groups: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();

    for alert in alerts {
        let technique = serde_json::from_str::<serde_json::Value>(alert)
            .ok()
            .and_then(|v| {
                v.get("technique")
                    .or_else(|| v.get("event_type"))
                    .and_then(|t| t.as_str())
                    .map(|s| s.to_string())
            })
            .unwrap_or_else(|| "unknown".to_string());

        technique_groups
            .entry(technique)
            .or_default()
            .push(alert.clone());
    }

    // Emit a correlation record for each technique group with >=2 alerts.
    technique_groups
        .into_iter()
        .filter(|(_, group)| group.len() >= 2)
        .map(|(technique, group_alerts)| {
            let count = group_alerts.len();
            AlertCorrelation::new(
                group_alerts,
                &technique,
                (count as f64 * CORRELATION_CONFIDENCE_FACTOR).min(1.0),
            )
        })
        .collect()
}

impl SoarPlaybook {
    pub fn new(name: &str) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            name: name.to_string(),
            triggers: Vec::new(),
            conditions: Vec::new(),
            actions: Vec::new(),
            notifications: Vec::new(),
        }
    }
}

impl AlertCorrelation {
    pub fn new(alert_ids: Vec<String>, technique: &str, confidence: f64) -> Self {
        let now = Utc::now();
        Self {
            correlation_id: Uuid::new_v4().to_string(),
            alert_ids,
            technique: technique.to_string(),
            confidence,
            first_seen: now,
            last_seen: now,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn elastic_config() -> SiemConfig {
        SiemConfig {
            platform: SiemPlatform::Elastic,
            host: "localhost".to_string(),
            port: 9200,
            api_key: "test".to_string(),
            index: "alerts".to_string(),
        }
    }

    #[tokio::test]
    async fn ingest_alert_uses_existing_id() {
        let config = elastic_config();
        let alert = r#"{"id":"abc-123","event_type":"login_failure"}"#;
        let result = ingest_alert(&config, alert).await.unwrap();
        assert_eq!(result, "abc-123");
    }

    #[tokio::test]
    async fn ingest_alert_generates_stable_id() {
        let config = elastic_config();
        let alert = r#"{"event_type":"brute_force","source":"10.0.0.1"}"#;
        let id1 = ingest_alert(&config, alert).await.unwrap();
        let id2 = ingest_alert(&config, alert).await.unwrap();
        assert_eq!(id1, id2, "same alert content should produce the same ID");
        assert!(id1.starts_with("alert-"), "generated ID should have prefix");
    }

    #[tokio::test]
    async fn ingest_alert_rejects_invalid_json() {
        let config = elastic_config();
        let result = ingest_alert(&config, "not json").await;
        assert!(result.is_err(), "invalid JSON should return an error");
    }

    #[test]
    fn correlate_alerts_empty() {
        assert!(correlate_alerts(&[]).is_empty());
    }

    #[test]
    fn correlate_alerts_single_no_correlation() {
        let alerts = vec![r#"{"technique":"T1078"}"#.to_string()];
        assert!(correlate_alerts(&alerts).is_empty());
    }

    #[test]
    fn correlate_alerts_groups_by_technique() {
        let alerts = vec![
            r#"{"technique":"T1078","src":"10.0.0.1"}"#.to_string(),
            r#"{"technique":"T1078","src":"10.0.0.2"}"#.to_string(),
        ];
        let correlations = correlate_alerts(&alerts);
        assert_eq!(correlations.len(), 1);
        assert_eq!(correlations[0].technique, "T1078");
        assert_eq!(correlations[0].alert_ids.len(), 2);
    }

    #[test]
    fn query_builder_elastic() {
        let mut qb = QueryBuilder::new(SiemPlatform::Elastic);
        qb.add_filter("host.ip", "10.0.0.1");
        let query = qb.build();
        assert!(query.contains("10.0.0.1"), "query: {query}");
    }

    #[test]
    fn query_builder_splunk() {
        let mut qb = QueryBuilder::new(SiemPlatform::Splunk);
        qb.base_query = "index=security".to_string();
        qb.add_filter("src_ip", "192.168.1.1");
        let query = qb.build();
        assert!(query.contains("src_ip=192.168.1.1"), "query: {query}");
    }
}
