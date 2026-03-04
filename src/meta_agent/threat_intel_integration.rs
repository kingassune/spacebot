//! Threat intelligence connector for the meta-agent.
//!
//! Provides MITRE ATT&CK framework mapping, CVE/NVD query types,
//! threat actor profile management, IOC correlation, and TTP mapping.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// — MITRE ATT&CK types —

/// MITRE ATT&CK tactic identifier (TA-XXXX).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TacticId(pub String);

/// MITRE ATT&CK technique identifier (T-XXXX or T-XXXX.YYY for sub-techniques).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TechniqueId(pub String);

/// A single MITRE ATT&CK technique entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackTechnique {
    /// Technique identifier (e.g. "T1566.001").
    pub id: TechniqueId,
    /// Human-readable name.
    pub name: String,
    /// Parent tactic(s) this technique belongs to.
    pub tactics: Vec<TacticId>,
    /// Brief description of the technique.
    pub description: String,
    /// Data sources that may detect this technique.
    pub detection_sources: Vec<String>,
    /// Relevant MITRE ATT&CK URL.
    pub url: String,
}

/// Mapping from a threat actor operation to MITRE ATT&CK techniques.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackMapping {
    /// Operation or engagement being mapped.
    pub operation_name: String,
    /// Techniques used.
    pub techniques: Vec<AttackTechnique>,
    /// Tactics covered by the mapped techniques.
    pub tactics_covered: Vec<TacticId>,
    /// Coverage percentage across all 14 ATT&CK tactics (0.0–1.0).
    pub tactic_coverage: f64,
}

// — CVE/NVD types —

/// CVE severity level per CVSS v3.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CvssV3Severity {
    None,
    Low,
    Medium,
    High,
    Critical,
}

/// A CVE entry from the NVD database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CveEntry {
    /// CVE identifier (e.g. "CVE-2023-12345").
    pub cve_id: String,
    /// Brief description.
    pub description: String,
    /// CVSS v3 base score (0.0–10.0).
    pub cvss_v3_score: f32,
    /// CVSS v3 severity.
    pub severity: CvssV3Severity,
    /// Affected CPE strings.
    pub affected_cpes: Vec<String>,
    /// Publication date (ISO 8601).
    pub published: String,
    /// Last modification date (ISO 8601).
    pub last_modified: String,
    /// Associated CWE identifiers.
    pub cwes: Vec<String>,
    /// Known public exploit available.
    pub has_known_exploit: bool,
}

/// Query parameters for NVD CVE lookups.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NvdQuery {
    /// Free-text keyword search.
    pub keyword: Option<String>,
    /// Filter by CPE string.
    pub cpe_name: Option<String>,
    /// Minimum CVSS v3 score.
    pub min_cvss_score: Option<f32>,
    /// Limit to CVEs with known exploits.
    pub exploitable_only: bool,
    /// ISO 8601 start date filter.
    pub published_after: Option<String>,
    /// Maximum results to return.
    pub max_results: usize,
}

impl Default for NvdQuery {
    fn default() -> Self {
        Self {
            keyword: None,
            cpe_name: None,
            min_cvss_score: None,
            exploitable_only: false,
            published_after: None,
            max_results: 20,
        }
    }
}

/// Result of an NVD query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NvdQueryResult {
    pub query: NvdQuery,
    pub total_results: usize,
    pub entries: Vec<CveEntry>,
}

// — Threat actor profile types —

/// Known nation-state or criminal threat actor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatActorProfile {
    /// Common name or codename (e.g. "APT29").
    pub name: String,
    /// Alternative names or aliases.
    pub aliases: Vec<String>,
    /// Suspected sponsoring nation-state or organisation.
    pub sponsor: String,
    /// Primary motivation: "Espionage", "Financial", "Sabotage", "Hacktivism".
    pub motivation: String,
    /// First observed year.
    pub first_observed: u16,
    /// Commonly used ATT&CK technique IDs.
    pub techniques: Vec<TechniqueId>,
    /// Known tools and malware families.
    pub tooling: Vec<String>,
    /// Industries typically targeted.
    pub target_industries: Vec<String>,
    /// Geographic regions typically targeted.
    pub target_regions: Vec<String>,
    /// Notable campaigns.
    pub known_campaigns: Vec<String>,
    /// MITRE ATT&CK group reference URL.
    pub mitre_url: String,
}

impl ThreatActorProfile {
    /// Returns a built-in profile for a well-known APT group by name.
    pub fn lookup(name: &str) -> Option<Self> {
        builtin_threat_actor_profiles()
            .into_iter()
            .find(|p| p.name.eq_ignore_ascii_case(name) || p.aliases.iter().any(|a| a.eq_ignore_ascii_case(name)))
    }

    /// Returns all built-in threat actor profiles.
    pub fn all() -> Vec<Self> {
        builtin_threat_actor_profiles()
    }
}

// — IOC types —

/// Category of an Indicator of Compromise.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum IocKind {
    Ip,
    Domain,
    Url,
    FileHash,
    Email,
    RegistryKey,
    MutexName,
    CertificateHash,
    Yara,
}

/// A single Indicator of Compromise.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ioc {
    /// IOC category.
    pub kind: IocKind,
    /// Raw indicator value.
    pub value: String,
    /// Confidence level: "High", "Medium", "Low".
    pub confidence: String,
    /// Threat actor(s) this IOC is attributed to.
    pub attributed_to: Vec<String>,
    /// Associated malware families.
    pub malware_families: Vec<String>,
    /// First seen date (ISO 8601).
    pub first_seen: String,
    /// Last seen date (ISO 8601).
    pub last_seen: String,
    /// Additional tags.
    pub tags: Vec<String>,
}

/// Result of correlating a set of IOCs with known threat actors.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IocCorrelationResult {
    /// IOCs submitted for correlation.
    pub submitted_iocs: Vec<Ioc>,
    /// Threat actors with at least one matching IOC.
    pub matched_actors: Vec<String>,
    /// Correlation confidence per actor (actor name → score 0.0–1.0).
    pub actor_confidence: HashMap<String, f64>,
    /// Summary narrative.
    pub summary: String,
}

// — TTP mapping types —

/// Kill chain phase names (Lockheed Martin model).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum KillChainPhase {
    Reconnaissance,
    Weaponization,
    Delivery,
    Exploitation,
    Installation,
    CommandAndControl,
    ActionsOnObjectives,
}

impl std::fmt::Display for KillChainPhase {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            Self::Reconnaissance => "Reconnaissance",
            Self::Weaponization => "Weaponization",
            Self::Delivery => "Delivery",
            Self::Exploitation => "Exploitation",
            Self::Installation => "Installation",
            Self::CommandAndControl => "Command & Control",
            Self::ActionsOnObjectives => "Actions on Objectives",
        };
        formatter.write_str(label)
    }
}

/// A TTP (Tactic, Technique, Procedure) entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ttp {
    /// ATT&CK technique this TTP maps to.
    pub technique_id: TechniqueId,
    /// Kill chain phase.
    pub kill_chain_phase: KillChainPhase,
    /// Concrete procedure description.
    pub procedure: String,
    /// Tools or malware used to execute this procedure.
    pub tools: Vec<String>,
    /// Suggested detection rules or data sources.
    pub detections: Vec<String>,
}

/// Result of mapping a set of observables to TTPs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TtpMappingResult {
    /// Source of the TTPs (e.g. actor name or campaign).
    pub source: String,
    /// Mapped TTPs.
    pub ttps: Vec<Ttp>,
    /// Kill chain phases covered.
    pub phases_covered: Vec<KillChainPhase>,
    /// Detection coverage score (0.0–1.0).
    pub detection_coverage: f64,
}

// — Threat intelligence engine —

/// Connects to threat intelligence data sources and provides query/correlation capabilities.
#[derive(Debug, Clone)]
pub struct ThreatIntelConnector {
    /// Cache of threat actor profiles.
    pub actor_profiles: Vec<ThreatActorProfile>,
    /// Cached IOC entries.
    pub ioc_cache: Vec<Ioc>,
}

impl ThreatIntelConnector {
    /// Create a new connector pre-loaded with built-in threat actor profiles.
    pub fn new() -> Self {
        Self {
            actor_profiles: builtin_threat_actor_profiles(),
            ioc_cache: Vec::new(),
        }
    }

    /// Look up a threat actor profile by name or alias.
    pub fn get_actor_profile(&self, name: &str) -> Option<&ThreatActorProfile> {
        self.actor_profiles.iter().find(|profile| {
            profile.name.eq_ignore_ascii_case(name)
                || profile
                    .aliases
                    .iter()
                    .any(|alias| alias.eq_ignore_ascii_case(name))
        })
    }

    /// Map an actor's known techniques to the Lockheed Martin Kill Chain.
    pub fn map_actor_to_kill_chain(&self, actor_name: &str) -> TtpMappingResult {
        let profile = self.get_actor_profile(actor_name);
        let ttps = profile
            .map(|profile| build_ttps_from_techniques(&profile.techniques))
            .unwrap_or_default();

        let phases_covered: Vec<KillChainPhase> = ttps
            .iter()
            .map(|ttp| ttp.kill_chain_phase.clone())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        let detection_coverage = if ttps.is_empty() {
            0.0
        } else {
            ttps.iter()
                .filter(|ttp| !ttp.detections.is_empty())
                .count() as f64
                / ttps.len() as f64
        };

        TtpMappingResult {
            source: actor_name.to_string(),
            ttps,
            phases_covered,
            detection_coverage,
        }
    }

    /// Correlate a list of IOCs against known threat actor profiles.
    pub fn correlate_iocs(&mut self, iocs: Vec<Ioc>) -> IocCorrelationResult {
        let mut actor_matches: HashMap<String, usize> = HashMap::new();

        for ioc in &iocs {
            for actor in &ioc.attributed_to {
                *actor_matches.entry(actor.clone()).or_insert(0) += 1;
            }
        }

        let total = iocs.len().max(1);
        let actor_confidence: HashMap<String, f64> = actor_matches
            .iter()
            .map(|(actor, count)| (actor.clone(), *count as f64 / total as f64))
            .collect();

        let matched_actors: Vec<String> = actor_confidence.keys().cloned().collect();

        let summary = if matched_actors.is_empty() {
            "No threat actor attribution found for submitted IOCs.".to_string()
        } else {
            format!(
                "{} IOC(s) correlated with {} threat actor(s): {}",
                iocs.len(),
                matched_actors.len(),
                matched_actors.join(", ")
            )
        };

        self.ioc_cache.extend(iocs.iter().cloned());

        IocCorrelationResult {
            submitted_iocs: iocs,
            matched_actors,
            actor_confidence,
            summary,
        }
    }

    /// Query simulated NVD data for CVEs matching the given query.
    pub fn query_nvd(&self, query: &NvdQuery) -> NvdQueryResult {
        // In production this would call the NVD REST API.
        // Here we return a structured empty result to satisfy the interface.
        NvdQueryResult {
            query: query.clone(),
            total_results: 0,
            entries: Vec::new(),
        }
    }
}

impl Default for ThreatIntelConnector {
    fn default() -> Self {
        Self::new()
    }
}

// — Internal helpers —

fn builtin_threat_actor_profiles() -> Vec<ThreatActorProfile> {
    vec![
        ThreatActorProfile {
            name: "APT29".to_string(),
            aliases: vec!["Cozy Bear".to_string(), "Midnight Blizzard".to_string()],
            sponsor: "Russia (SVR)".to_string(),
            motivation: "Espionage".to_string(),
            first_observed: 2008,
            techniques: vec![
                TechniqueId("T1195.002".to_string()),
                TechniqueId("T1071.001".to_string()),
                TechniqueId("T1027".to_string()),
                TechniqueId("T1566.001".to_string()),
            ],
            tooling: vec!["WellMess".to_string(), "WellMail".to_string(), "SUNBURST".to_string()],
            target_industries: vec!["Government".to_string(), "Healthcare".to_string(), "Energy".to_string()],
            target_regions: vec!["US".to_string(), "EU".to_string(), "NATO".to_string()],
            known_campaigns: vec!["SolarWinds".to_string(), "COVID-19 Vaccine Research".to_string()],
            mitre_url: "https://attack.mitre.org/groups/G0016/".to_string(),
        },
        ThreatActorProfile {
            name: "APT28".to_string(),
            aliases: vec!["Fancy Bear".to_string(), "Forest Blizzard".to_string()],
            sponsor: "Russia (GRU)".to_string(),
            motivation: "Espionage".to_string(),
            first_observed: 2004,
            techniques: vec![
                TechniqueId("T1566.001".to_string()),
                TechniqueId("T1059.005".to_string()),
                TechniqueId("T1003.001".to_string()),
            ],
            tooling: vec!["X-Agent".to_string(), "Sofacy".to_string(), "Zebrocy".to_string()],
            target_industries: vec!["Government".to_string(), "Military".to_string(), "Media".to_string()],
            target_regions: vec!["US".to_string(), "EU".to_string(), "Ukraine".to_string()],
            known_campaigns: vec!["DNC Hack 2016".to_string(), "French Election 2017".to_string()],
            mitre_url: "https://attack.mitre.org/groups/G0007/".to_string(),
        },
        ThreatActorProfile {
            name: "Lazarus".to_string(),
            aliases: vec!["Hidden Cobra".to_string(), "Guardians of Peace".to_string()],
            sponsor: "North Korea (RGB)".to_string(),
            motivation: "Financial".to_string(),
            first_observed: 2009,
            techniques: vec![
                TechniqueId("T1566.001".to_string()),
                TechniqueId("T1486".to_string()),
                TechniqueId("T1059.001".to_string()),
            ],
            tooling: vec!["HOPLIGHT".to_string(), "AppleJeus".to_string(), "BLINDINGCAN".to_string()],
            target_industries: vec!["Finance".to_string(), "Cryptocurrency".to_string(), "Defense".to_string()],
            target_regions: vec!["Global".to_string()],
            known_campaigns: vec!["Sony Hack 2014".to_string(), "SWIFT Attacks".to_string(), "Axie Infinity Hack".to_string()],
            mitre_url: "https://attack.mitre.org/groups/G0032/".to_string(),
        },
    ]
}

fn build_ttps_from_techniques(technique_ids: &[TechniqueId]) -> Vec<Ttp> {
    let mapping: HashMap<&str, (&str, KillChainPhase, &str)> = [
        ("T1566.001", ("Spearphishing Attachment", KillChainPhase::Delivery, "Email gateway logs, attachment sandboxing")),
        ("T1195.002", ("Compromise Software Supply Chain", KillChainPhase::Delivery, "Software integrity checks, SBOMs")),
        ("T1071.001", ("Application Layer Protocol: Web", KillChainPhase::CommandAndControl, "Network traffic analysis, proxy logs")),
        ("T1027", ("Obfuscated Files or Information", KillChainPhase::Installation, "File system monitoring, AV signatures")),
        ("T1003.001", ("LSASS Memory", KillChainPhase::Exploitation, "Credential access alerts, LSASS protection")),
        ("T1059.001", ("PowerShell", KillChainPhase::Exploitation, "PowerShell logging, AMSI events")),
        ("T1059.005", ("Visual Basic", KillChainPhase::Exploitation, "Office macro alerts, script block logging")),
        ("T1486", ("Data Encrypted for Impact", KillChainPhase::ActionsOnObjectives, "Backup monitoring, ransomware canaries")),
    ]
    .into_iter()
    .collect();

    technique_ids
        .iter()
        .filter_map(|technique_id| {
            mapping.get(technique_id.0.as_str()).map(|(name, phase, detection)| Ttp {
                technique_id: technique_id.clone(),
                kill_chain_phase: phase.clone(),
                procedure: name.to_string(),
                tools: Vec::new(),
                detections: vec![detection.to_string()],
            })
        })
        .collect()
}
