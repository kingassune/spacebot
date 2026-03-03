//! Capability analysis and gap detection for security operations.

use chrono::{DateTime, Utc};

/// Engagement type used to scope capability analysis.
#[derive(Debug, Clone, PartialEq)]
pub enum EngagementType {
    Pentest,
    RedTeamOp,
    BlueTeamDefense,
    BlockchainAudit,
    IncidentResponse,
    ThreatHunting,
}

/// Aggregated capability analysis report for an engagement type.
#[derive(Debug, Clone)]
pub struct CapabilityReport {
    pub engagement: EngagementType,
    pub covered_areas: Vec<String>,
    pub gaps: Vec<CapabilityGap>,
    pub recommendations: Vec<String>,
    pub coverage_percent: f64,
    pub generated_at: DateTime<Utc>,
}

/// Inventories current capabilities and identifies gaps for a given engagement.
#[derive(Debug, Clone)]
pub struct CapabilityAnalyzer {
    pub capability_map: CapabilityMap,
}

impl CapabilityAnalyzer {
    pub fn new(capability_map: CapabilityMap) -> Self {
        Self { capability_map }
    }

    /// Analyze capabilities and produce a report for the given engagement type.
    pub fn analyze_capabilities(&self, engagement: &EngagementType) -> CapabilityReport {
        let required = required_areas(engagement);
        let covered_areas: Vec<String> = required
            .iter()
            .filter(|area| {
                self.capability_map
                    .coverage_domains
                    .iter()
                    .any(|d| d.to_lowercase().contains(&area.to_lowercase()))
            })
            .cloned()
            .collect();

        let gaps: Vec<CapabilityGap> = required
            .iter()
            .filter(|area| !covered_areas.contains(area))
            .map(|area| CapabilityGap {
                domain: area.clone(),
                missing_capability: format!("No coverage for: {area}"),
                priority: GapPriority::High,
                recommended_skills: vec![
                    format!("detect-{}", area.to_lowercase()),
                    format!("respond-{}", area.to_lowercase()),
                ],
            })
            .collect();

        let coverage_percent = if required.is_empty() {
            100.0
        } else {
            (covered_areas.len() as f64 / required.len() as f64) * 100.0
        };

        let recommendations: Vec<String> = gaps
            .iter()
            .map(|g| format!("Add skill coverage for: {}", g.domain))
            .collect();

        CapabilityReport {
            engagement: engagement.clone(),
            covered_areas,
            gaps,
            recommendations,
            coverage_percent,
            generated_at: Utc::now(),
        }
    }
}

fn required_areas(engagement: &EngagementType) -> Vec<String> {
    match engagement {
        EngagementType::Pentest => vec![
            "network".to_string(),
            "web".to_string(),
            "vulnerability".to_string(),
            "reporting".to_string(),
        ],
        EngagementType::RedTeamOp => vec![
            "recon".to_string(),
            "exploitation".to_string(),
            "persistence".to_string(),
            "c2".to_string(),
        ],
        EngagementType::BlueTeamDefense => vec![
            "detection".to_string(),
            "siem".to_string(),
            "endpoint".to_string(),
            "intelligence".to_string(),
        ],
        EngagementType::BlockchainAudit => vec![
            "smart-contract".to_string(),
            "defi".to_string(),
            "bridge".to_string(),
            "token".to_string(),
        ],
        EngagementType::IncidentResponse => vec![
            "forensics".to_string(),
            "containment".to_string(),
            "eradication".to_string(),
            "recovery".to_string(),
        ],
        EngagementType::ThreatHunting => vec![
            "intelligence".to_string(),
            "network".to_string(),
            "endpoint".to_string(),
            "siem".to_string(),
        ],
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum MaturityLevel {
    Initial,
    Developing,
    Defined,
    Managed,
    Optimizing,
}

#[derive(Debug, Clone, PartialEq)]
pub enum GapPriority {
    Critical,
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone)]
pub struct Capability {
    pub name: String,
    pub domain: String,
    pub maturity_level: MaturityLevel,
    pub coverage_percent: f64,
}

#[derive(Debug, Clone)]
pub struct CapabilityMap {
    pub capabilities: Vec<Capability>,
    pub coverage_domains: Vec<String>,
    pub last_updated: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct ThreatProfile {
    pub name: String,
    pub techniques: Vec<String>,
    pub target_domains: Vec<String>,
    pub sophistication: String,
}

#[derive(Debug, Clone)]
pub struct CapabilityGap {
    pub domain: String,
    pub missing_capability: String,
    pub priority: GapPriority,
    pub recommended_skills: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ExtensionRecommendation {
    pub gap: CapabilityGap,
    pub implementation_effort_days: u32,
    pub expected_coverage_improvement: f64,
    pub prerequisites: Vec<String>,
}

pub fn analyze_gaps(current: &CapabilityMap, threats: &[ThreatProfile]) -> Vec<CapabilityGap> {
    let mut gaps = Vec::new();
    for threat in threats {
        for domain in &threat.target_domains {
            if !current.coverage_domains.contains(domain) {
                gaps.push(CapabilityGap {
                    domain: domain.clone(),
                    missing_capability: format!("Coverage for domain: {domain}"),
                    priority: GapPriority::High,
                    recommended_skills: vec![
                        format!("detect-{}", domain.to_lowercase()),
                        format!("respond-{}", domain.to_lowercase()),
                    ],
                });
            }
        }
        for technique in &threat.techniques {
            let covered = current.capabilities.iter().any(|c| {
                c.name.to_lowercase().contains(&technique.to_lowercase())
                    || technique.to_lowercase().contains(&c.name.to_lowercase())
            });
            if !covered {
                gaps.push(CapabilityGap {
                    domain: threat.name.clone(),
                    missing_capability: format!("Technique coverage: {technique}"),
                    priority: if threat.sophistication == "high"
                        || threat.sophistication == "advanced"
                    {
                        GapPriority::Critical
                    } else {
                        GapPriority::Medium
                    },
                    recommended_skills: vec![format!(
                        "detect-{}",
                        technique.to_lowercase().replace(' ', "-")
                    )],
                });
            }
        }
    }
    gaps
}

pub fn recommend_extensions(gaps: &[CapabilityGap]) -> Vec<ExtensionRecommendation> {
    gaps.iter()
        .filter(|g| matches!(g.priority, GapPriority::Critical | GapPriority::High))
        .map(|gap| {
            let effort = match gap.priority {
                GapPriority::Critical => 5,
                GapPriority::High => 10,
                GapPriority::Medium => 20,
                GapPriority::Low => 30,
            };
            ExtensionRecommendation {
                gap: gap.clone(),
                implementation_effort_days: effort,
                expected_coverage_improvement: if gap.priority == GapPriority::Critical {
                    0.25
                } else {
                    0.15
                },
                prerequisites: vec![
                    "threat-intel-feed".to_string(),
                    "log-aggregation".to_string(),
                ],
            }
        })
        .collect()
}

pub fn build_initial_capability_map() -> CapabilityMap {
    let capabilities = vec![
        Capability {
            name: "Network Intrusion Detection".to_string(),
            domain: "network".to_string(),
            maturity_level: MaturityLevel::Defined,
            coverage_percent: 70.0,
        },
        Capability {
            name: "Endpoint Detection and Response".to_string(),
            domain: "endpoint".to_string(),
            maturity_level: MaturityLevel::Managed,
            coverage_percent: 85.0,
        },
        Capability {
            name: "Log Analysis".to_string(),
            domain: "siem".to_string(),
            maturity_level: MaturityLevel::Defined,
            coverage_percent: 75.0,
        },
        Capability {
            name: "Vulnerability Scanning".to_string(),
            domain: "vulnerability".to_string(),
            maturity_level: MaturityLevel::Developing,
            coverage_percent: 55.0,
        },
        Capability {
            name: "Threat Intelligence".to_string(),
            domain: "intelligence".to_string(),
            maturity_level: MaturityLevel::Initial,
            coverage_percent: 30.0,
        },
    ];
    let coverage_domains = capabilities.iter().map(|c| c.domain.clone()).collect();
    CapabilityMap {
        capabilities,
        coverage_domains,
        last_updated: Utc::now(),
    }
}
