//! Continuous monitoring configuration and anomaly detection for blue team defensive operations.
//!
//! Covers metric collection, anomaly detection, alerting rules, and dashboard data assembly.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Category of metric being monitored.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum MetricCategory {
    /// Host resource metrics (CPU, memory, disk).
    System,
    /// Network traffic and connection metrics.
    Network,
    /// Authentication and access-control events.
    Authentication,
    /// Application-level telemetry.
    Application,
    /// Security-specific events (IDS/IPS, firewall).
    Security,
}

/// A collected monitoring metric sample.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricSample {
    /// Category of this metric.
    pub category: MetricCategory,
    /// Metric name (e.g. "cpu_utilisation_pct").
    pub name: String,
    /// Numeric value of the sample.
    pub value: f64,
    /// Unit of measurement.
    pub unit: String,
    /// Timestamp when the sample was collected.
    pub timestamp: DateTime<Utc>,
    /// Source host or service.
    pub source: String,
}

/// Severity level for monitoring alerts.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum AlertSeverity {
    Critical,
    High,
    Medium,
    Low,
    Informational,
}

/// An alerting rule that fires when a threshold is exceeded.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRule {
    /// Unique identifier for the rule.
    pub id: String,
    /// Human-readable rule name.
    pub name: String,
    /// Metric to watch.
    pub metric_name: String,
    /// Threshold value that triggers the alert.
    pub threshold: f64,
    /// Comparison operator (">", "<", ">=", "<=", "==").
    pub operator: String,
    /// Severity if this rule fires.
    pub severity: AlertSeverity,
    /// Message to include in the generated alert.
    pub message_template: String,
}

/// A triggered monitoring alert.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoringAlert {
    /// Rule that triggered this alert.
    pub rule_id: String,
    /// Rule name for display.
    pub rule_name: String,
    /// Observed value that breached the threshold.
    pub observed_value: f64,
    /// Severity of the alert.
    pub severity: AlertSeverity,
    /// Human-readable alert description.
    pub message: String,
    /// Timestamp of the alert.
    pub triggered_at: DateTime<Utc>,
    /// Source host or service.
    pub source: String,
}

/// Configuration for the continuous monitoring subsystem.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoringConfig {
    /// How often to collect metrics, in seconds.
    pub collection_interval_secs: u64,
    /// Alert rules to evaluate on every collection cycle.
    pub alert_rules: Vec<AlertRule>,
    /// Minimum severity level to forward alerts.
    pub min_alert_severity: AlertSeverity,
    /// Whether anomaly detection is enabled.
    pub anomaly_detection_enabled: bool,
    /// Sliding window size (in samples) for anomaly detection.
    pub anomaly_window_size: usize,
    /// Number of standard deviations above the rolling mean to flag as anomalous.
    pub anomaly_std_dev_threshold: f64,
}

impl Default for MonitoringConfig {
    fn default() -> Self {
        Self {
            collection_interval_secs: 60,
            alert_rules: default_alert_rules(),
            min_alert_severity: AlertSeverity::Medium,
            anomaly_detection_enabled: true,
            anomaly_window_size: 60,
            anomaly_std_dev_threshold: 3.0,
        }
    }
}

/// An anomaly detected by statistical analysis of a metric time series.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyDetection {
    /// Name of the metric with the anomaly.
    pub metric_name: String,
    /// Anomalous observed value.
    pub observed_value: f64,
    /// Rolling mean over the analysis window.
    pub baseline_mean: f64,
    /// Standard deviation of the analysis window.
    pub baseline_std_dev: f64,
    /// Number of standard deviations from the mean.
    pub deviation_score: f64,
    /// Timestamp of the anomalous sample.
    pub detected_at: DateTime<Utc>,
    /// Source host or service.
    pub source: String,
}

/// Aggregated data for a monitoring dashboard panel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardPanel {
    /// Panel title.
    pub title: String,
    /// Category of metrics shown.
    pub category: MetricCategory,
    /// Most recent samples for display.
    pub recent_samples: Vec<MetricSample>,
    /// Active alerts in this category.
    pub active_alerts: Vec<MonitoringAlert>,
    /// Detected anomalies in this category.
    pub anomalies: Vec<AnomalyDetection>,
}

/// Full dashboard snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoringDashboard {
    /// Panels grouped by category.
    pub panels: Vec<DashboardPanel>,
    /// Total active critical alerts.
    pub critical_alert_count: usize,
    /// Timestamp of the snapshot.
    pub snapshot_time: DateTime<Utc>,
}

/// Evaluate alert rules against a batch of metric samples.
pub fn evaluate_alert_rules(
    rules: &[AlertRule],
    samples: &[MetricSample],
) -> Vec<MonitoringAlert> {
    let mut alerts = Vec::new();
    for sample in samples {
        for rule in rules {
            if rule.metric_name != sample.name {
                continue;
            }
            let triggered = match rule.operator.as_str() {
                ">" => sample.value > rule.threshold,
                "<" => sample.value < rule.threshold,
                ">=" => sample.value >= rule.threshold,
                "<=" => sample.value <= rule.threshold,
                "==" => (sample.value - rule.threshold).abs() < f64::EPSILON,
                _ => false,
            };
            if triggered {
                alerts.push(MonitoringAlert {
                    rule_id: rule.id.clone(),
                    rule_name: rule.name.clone(),
                    observed_value: sample.value,
                    severity: rule.severity.clone(),
                    message: rule
                        .message_template
                        .replace("{value}", &sample.value.to_string())
                        .replace("{source}", &sample.source),
                    triggered_at: sample.timestamp,
                    source: sample.source.clone(),
                });
            }
        }
    }
    alerts
}

/// Detect anomalies in a metric time series using a rolling Z-score.
pub fn detect_anomalies(
    metric_name: &str,
    samples: &[MetricSample],
    window_size: usize,
    std_dev_threshold: f64,
) -> Vec<AnomalyDetection> {
    let values: Vec<f64> = samples.iter().map(|s| s.value).collect();
    if values.len() < window_size {
        return Vec::new();
    }

    let mut anomalies = Vec::new();
    for i in window_size..values.len() {
        let window = &values[(i - window_size)..i];
        let mean = window.iter().sum::<f64>() / window.len() as f64;
        let variance = window.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / window.len() as f64;
        let std_dev = variance.sqrt();
        if std_dev < f64::EPSILON {
            continue;
        }
        let z_score = (values[i] - mean).abs() / std_dev;
        if z_score > std_dev_threshold {
            anomalies.push(AnomalyDetection {
                metric_name: metric_name.to_string(),
                observed_value: values[i],
                baseline_mean: mean,
                baseline_std_dev: std_dev,
                deviation_score: z_score,
                detected_at: samples[i].timestamp,
                source: samples[i].source.clone(),
            });
        }
    }
    anomalies
}

/// Build an empty monitoring dashboard snapshot.
pub fn build_dashboard(
    samples: &[MetricSample],
    alerts: &[MonitoringAlert],
    anomalies: &[AnomalyDetection],
) -> MonitoringDashboard {
    let categories = [
        MetricCategory::System,
        MetricCategory::Network,
        MetricCategory::Authentication,
        MetricCategory::Application,
        MetricCategory::Security,
    ];
    let panels: Vec<DashboardPanel> = categories
        .into_iter()
        .map(|cat| {
            let recent_samples: Vec<MetricSample> = samples
                .iter()
                .filter(|s| s.category == cat)
                .cloned()
                .collect();
            let active_alerts: Vec<MonitoringAlert> = alerts.to_vec();
            let panel_anomalies: Vec<AnomalyDetection> = anomalies.to_vec();
            DashboardPanel {
                title: format!("{:?} Metrics", cat),
                category: cat,
                recent_samples,
                active_alerts,
                anomalies: panel_anomalies,
            }
        })
        .collect();

    let critical_alert_count = alerts
        .iter()
        .filter(|a| a.severity == AlertSeverity::Critical)
        .count();

    MonitoringDashboard {
        panels,
        critical_alert_count,
        snapshot_time: Utc::now(),
    }
}

/// Default alert rules for common security thresholds.
fn default_alert_rules() -> Vec<AlertRule> {
    vec![
        AlertRule {
            id: "cpu-high".to_string(),
            name: "High CPU Utilisation".to_string(),
            metric_name: "cpu_utilisation_pct".to_string(),
            threshold: 90.0,
            operator: ">".to_string(),
            severity: AlertSeverity::High,
            message_template: "CPU at {value}% on {source}".to_string(),
        },
        AlertRule {
            id: "auth-failures".to_string(),
            name: "Excessive Authentication Failures".to_string(),
            metric_name: "auth_failure_count".to_string(),
            threshold: 10.0,
            operator: ">=".to_string(),
            severity: AlertSeverity::Critical,
            message_template: "{value} auth failures detected on {source}".to_string(),
        },
        AlertRule {
            id: "disk-full".to_string(),
            name: "Disk Utilisation High".to_string(),
            metric_name: "disk_utilisation_pct".to_string(),
            threshold: 85.0,
            operator: ">".to_string(),
            severity: AlertSeverity::Medium,
            message_template: "Disk at {value}% on {source}".to_string(),
        },
    ]
}
