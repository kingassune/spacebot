//! Threat intelligence feed management, IOC enrichment, and correlation for blue team operations.

use anyhow::Result;
use chrono::Utc;
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq)]
pub enum IntelFeed {
    Misp,
    Otx,
    AbuseCh,
    VirusTotal,
    ThreatConnect,
    Mandiant,
    OpenPhish,
}

#[derive(Debug, Clone, PartialEq)]
pub enum StixObjectType {
    Indicator,
    ThreatActor,
    Campaign,
    Malware,
    AttackPattern,
    Tool,
    CourseOfAction,
}

#[derive(Debug, Clone, PartialEq)]
pub enum IocType {
    IpAddress,
    Domain,
    Url,
    FileHash,
    Email,
    Certificate,
}

impl std::fmt::Display for IocType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            IocType::IpAddress => "ip-address",
            IocType::Domain => "domain",
            IocType::Url => "url",
            IocType::FileHash => "file-hash",
            IocType::Email => "email",
            IocType::Certificate => "certificate",
        };
        write!(f, "{s}")
    }
}

#[derive(Debug, Clone)]
pub struct Ioc {
    pub value: String,
    pub ioc_type: IocType,
    pub confidence: u8,
    pub source: String,
    pub tags: Vec<String>,
    pub first_seen: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Clone)]
pub struct ThreatActor {
    pub name: String,
    pub aliases: Vec<String>,
    pub motivation: String,
    pub sophistication: String,
    pub country: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ThreatIntelReport {
    pub actor: Option<ThreatActor>,
    pub iocs: Vec<Ioc>,
    pub ttps: Vec<String>,
    pub confidence: u8,
    pub report_date: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone)]
pub struct ThreatIntelConfig {
    pub feeds: Vec<IntelFeed>,
    pub api_keys: HashMap<String, String>,
    pub cache_dir: String,
}

pub async fn fetch_intel(config: &ThreatIntelConfig) -> Result<Vec<ThreatIntelReport>> {
    if config.feeds.is_empty() {
        return Ok(vec![]);
    }

    let cache_path = std::path::Path::new(&config.cache_dir);

    let mut reports = Vec::new();

    for feed in &config.feeds {
        let cache_file = cache_path.join(format!("{feed:?}.json").to_lowercase());

        // Try to load from cache first.
        if let Ok(cached) = tokio::fs::read_to_string(&cache_file).await {
            if let Ok(cached_reports) = serde_json::from_str::<Vec<ThreatIntelReport>>(&cached) {
                tracing::debug!(feed = ?feed, "loaded threat intel from cache");
                reports.extend(cached_reports);
                continue;
            }
        }

        // Log which feed would be queried; live queries require API keys and
        // external connectivity that may not be present in all deployments.
        let api_key = config.api_keys.get(&format!("{feed:?}"));
        if api_key.is_none() {
            tracing::debug!(
                feed = ?feed,
                "no API key configured for feed, skipping live query"
            );
        } else {
            tracing::info!(
                feed = ?feed,
                "threat intel feed configured but live query not yet implemented — \
                 populate cache directory to serve pre-fetched reports"
            );
        }
    }

    Ok(reports)
}

pub fn enrich_ioc(ioc: &mut Ioc, reports: &[ThreatIntelReport]) {
    for report in reports {
        let matches = report
            .iocs
            .iter()
            .any(|r| r.value == ioc.value && r.ioc_type == ioc.ioc_type);
        if matches {
            for tag in &report.ttps {
                if !ioc.tags.contains(tag) {
                    ioc.tags.push(tag.clone());
                }
            }
            if let Some(actor) = &report.actor {
                let actor_tag = format!("actor:{}", actor.name);
                if !ioc.tags.contains(&actor_tag) {
                    ioc.tags.push(actor_tag);
                }
            }
        }
    }
}

pub fn correlate_iocs(iocs: &[Ioc]) -> Vec<Vec<Ioc>> {
    // Group IOCs by type as a basic correlation strategy.
    let mut groups: HashMap<String, Vec<Ioc>> = HashMap::new();
    for ioc in iocs {
        let key = ioc.ioc_type.to_string();
        groups.entry(key).or_default().push(ioc.clone());
    }
    groups.into_values().filter(|g| !g.is_empty()).collect()
}

pub fn score_ioc(ioc: &Ioc) -> u8 {
    ioc.confidence
}

impl Ioc {
    pub fn new(value: &str, ioc_type: IocType, source: &str) -> Self {
        Self {
            value: value.to_string(),
            ioc_type,
            confidence: 50,
            source: source.to_string(),
            tags: Vec::new(),
            first_seen: Some(Utc::now()),
        }
    }
}

impl ThreatIntelReport {
    pub fn new() -> Self {
        Self {
            actor: None,
            iocs: Vec::new(),
            ttps: Vec::new(),
            confidence: 0,
            report_date: Utc::now(),
        }
    }
}

impl Default for ThreatIntelReport {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_config(feeds: Vec<IntelFeed>) -> ThreatIntelConfig {
        ThreatIntelConfig {
            feeds,
            api_keys: HashMap::new(),
            cache_dir: "/tmp/nonexistent_intel_cache".to_string(),
        }
    }

    #[tokio::test]
    async fn fetch_intel_empty_feeds() {
        let config = make_config(vec![]);
        let reports = fetch_intel(&config).await.unwrap();
        assert!(reports.is_empty());
    }

    #[tokio::test]
    async fn fetch_intel_no_cache_returns_empty() {
        // No API keys, no cache — should return empty without error.
        let config = make_config(vec![IntelFeed::Otx]);
        let reports = fetch_intel(&config).await.unwrap();
        assert!(reports.is_empty());
    }

    #[test]
    fn correlate_iocs_groups_by_type() {
        let iocs = vec![
            Ioc::new("1.2.3.4", IocType::IpAddress, "test"),
            Ioc::new("5.6.7.8", IocType::IpAddress, "test"),
            Ioc::new("evil.com", IocType::Domain, "test"),
        ];
        let groups = correlate_iocs(&iocs);
        assert_eq!(groups.len(), 2, "expected 2 groups (IP and domain)");
        let ip_group = groups.iter().find(|g| g[0].ioc_type == IocType::IpAddress);
        assert!(ip_group.is_some());
        assert_eq!(ip_group.unwrap().len(), 2);
    }

    #[test]
    fn enrich_ioc_adds_tags_from_matching_report() {
        let mut ioc = Ioc::new("1.2.3.4", IocType::IpAddress, "test");
        let report = ThreatIntelReport {
            actor: Some(ThreatActor {
                name: "APT28".to_string(),
                aliases: vec![],
                motivation: "espionage".to_string(),
                sophistication: "high".to_string(),
                country: Some("RU".to_string()),
            }),
            iocs: vec![Ioc::new("1.2.3.4", IocType::IpAddress, "test")],
            ttps: vec!["T1078".to_string()],
            confidence: 80,
            report_date: Utc::now(),
        };
        enrich_ioc(&mut ioc, &[report]);
        assert!(ioc.tags.contains(&"T1078".to_string()));
        assert!(ioc.tags.contains(&"actor:APT28".to_string()));
    }

    #[test]
    fn score_ioc_returns_confidence() {
        let mut ioc = Ioc::new("evil.com", IocType::Domain, "test");
        ioc.confidence = 75;
        assert_eq!(score_ioc(&ioc), 75);
    }
}
