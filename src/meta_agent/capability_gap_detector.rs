//! Capability gap detector for the James meta-agent.
//!
//! Scans incoming security tasks and platform capabilities to identify
//! coverage gaps, then prioritises new skill/module development based on
//! threat-landscape relevance and request frequency.

use std::collections::HashMap;

/// A detected capability gap — something the platform cannot yet handle.
#[derive(Debug, Clone)]
pub struct CapabilityGap {
    /// Short identifier for the gap (e.g., `"rust-smart-contract-audit"`).
    pub id: String,
    /// Human-readable description of what is missing.
    pub description: String,
    /// Security domain this gap belongs to.
    pub domain: SecurityDomain,
    /// Number of times this gap has been observed in incoming requests.
    pub observed_count: u32,
    /// MITRE ATT&CK coverage percentage for this domain (0–100).
    pub mitre_coverage_percent: u8,
    /// Suggested skill or module name to build.
    pub suggested_artifact: String,
    /// Estimated development priority (higher = more urgent).
    pub priority: GapPriority,
}

/// Security domain classification.
#[derive(Debug, Clone, PartialEq)]
pub enum SecurityDomain {
    Blockchain,
    RedTeam,
    BlueTeam,
    ExploitDevelopment,
    CloudSecurity,
    MobileSecurity,
    WebSecurity,
    NetworkSecurity,
    CryptographyAudit,
    SupplyChain,
    SocialEngineering,
    ForensicsAndIR,
    ThreatIntelligence,
    Other(String),
}

impl SecurityDomain {
    /// Returns the domain name as a string slice.
    pub fn name(&self) -> String {
        match self {
            SecurityDomain::Blockchain => "Blockchain".to_string(),
            SecurityDomain::RedTeam => "Red Team".to_string(),
            SecurityDomain::BlueTeam => "Blue Team".to_string(),
            SecurityDomain::ExploitDevelopment => "Exploit Development".to_string(),
            SecurityDomain::CloudSecurity => "Cloud Security".to_string(),
            SecurityDomain::MobileSecurity => "Mobile Security".to_string(),
            SecurityDomain::WebSecurity => "Web Security".to_string(),
            SecurityDomain::NetworkSecurity => "Network Security".to_string(),
            SecurityDomain::CryptographyAudit => "Cryptography Audit".to_string(),
            SecurityDomain::SupplyChain => "Supply Chain".to_string(),
            SecurityDomain::SocialEngineering => "Social Engineering".to_string(),
            SecurityDomain::ForensicsAndIR => "Forensics & IR".to_string(),
            SecurityDomain::ThreatIntelligence => "Threat Intelligence".to_string(),
            SecurityDomain::Other(name) => name.clone(),
        }
    }
}

/// Priority level for addressing a capability gap.
#[derive(Debug, Clone, PartialEq, PartialOrd)]
pub enum GapPriority {
    Low,
    Medium,
    High,
    Critical,
}

/// Report summarising all detected capability gaps.
#[derive(Debug, Clone)]
pub struct GapReport {
    pub gaps: Vec<CapabilityGap>,
    pub total_domains_covered: usize,
    pub total_domains_missing: usize,
    pub mitre_total_coverage_percent: u8,
    pub recommended_next_build: Option<String>,
}

/// Detects capability gaps in the James platform.
///
/// Maintains a frequency map of unhandled request types and compares
/// platform capabilities against the MITRE ATT&CK framework coverage
/// to surface the highest-value gaps to fill next.
#[derive(Debug, Clone)]
pub struct CapabilityGapDetector {
    /// Known platform capabilities (skill names and module names).
    pub known_capabilities: Vec<String>,
    /// Frequency counter for unhandled request categories.
    observation_counts: HashMap<String, u32>,
}

impl CapabilityGapDetector {
    /// Create a new detector pre-seeded with the platform's known capabilities.
    pub fn new(known_capabilities: Vec<String>) -> Self {
        Self {
            known_capabilities,
            observation_counts: HashMap::new(),
        }
    }

    /// Record an observation that a given capability or domain was requested
    /// but could not be fully handled.
    pub fn observe_gap(&mut self, capability_key: impl Into<String>) {
        let key = capability_key.into();
        *self.observation_counts.entry(key).or_insert(0) += 1;
    }

    /// Scan the given task description text for keywords that suggest
    /// capability gaps and record observations automatically.
    pub fn scan_task(&mut self, task_description: &str) {
        let task_lower = task_description.to_lowercase();

        let domain_keywords: &[(&str, &str)] = &[
            ("solana", "solana-contract-audit"),
            ("move", "move-contract-audit"),
            ("starknet", "starknet-cairo-audit"),
            ("zk proof", "zk-circuit-audit"),
            ("zero knowledge", "zk-circuit-audit"),
            ("cairo", "starknet-cairo-audit"),
            ("kubernetes", "kubernetes-security"),
            ("k8s", "kubernetes-security"),
            ("terraform", "iac-security"),
            ("infrastructure as code", "iac-security"),
            ("mobile", "mobile-security-analysis"),
            ("android", "android-security-analysis"),
            ("ios", "ios-security-analysis"),
            ("hardware", "hardware-security"),
            ("firmware", "firmware-analysis"),
            ("iot", "iot-security"),
            ("rust unsafe", "rust-unsafe-audit"),
            ("assembly", "assembly-analysis"),
            ("obfuscation", "deobfuscation"),
            ("yara", "yara-rule-generation"),
            ("sigma", "sigma-rule-generation"),
        ];

        for (keyword, gap_key) in domain_keywords {
            if task_lower.contains(keyword) {
                self.observe_gap(*gap_key);
            }
        }
    }

    /// Analyse the current observation data and produce a gap report.
    pub fn generate_report(&self) -> GapReport {
        let mut gaps: Vec<CapabilityGap> = Vec::new();

        for (key, &count) in &self.observation_counts {
            if self
                .known_capabilities
                .iter()
                .any(|c| c.to_lowercase() == key.to_lowercase())
            {
                // Already covered — skip.
                continue;
            }

            let domain = domain_for_key(key);
            let priority = if count >= 10 {
                GapPriority::Critical
            } else if count >= 5 {
                GapPriority::High
            } else if count >= 2 {
                GapPriority::Medium
            } else {
                GapPriority::Low
            };

            let mitre_coverage = mitre_coverage_for_domain(&domain);

            gaps.push(CapabilityGap {
                id: key.clone(),
                description: format!(
                    "Unhandled capability: '{}' (observed {} time(s))",
                    key, count
                ),
                domain,
                observed_count: count,
                mitre_coverage_percent: mitre_coverage,
                suggested_artifact: format!("skills/{}", key),
                priority,
            });
        }

        // Sort gaps by priority (critical first) then by observation count.
        gaps.sort_by(|a, b| {
            b.priority
                .partial_cmp(&a.priority)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then(b.observed_count.cmp(&a.observed_count))
        });

        let total_domains_covered = self.known_capabilities.len();
        let total_domains_missing = gaps.len();
        let recommended_next_build = gaps.first().map(|g| g.suggested_artifact.clone());

        // Compute an overall MITRE coverage percentage across all domains.
        let all_domains = [
            SecurityDomain::RedTeam,
            SecurityDomain::BlueTeam,
            SecurityDomain::ExploitDevelopment,
            SecurityDomain::Blockchain,
            SecurityDomain::CloudSecurity,
            SecurityDomain::WebSecurity,
            SecurityDomain::NetworkSecurity,
            SecurityDomain::ForensicsAndIR,
        ];
        let avg_mitre_coverage = {
            let sum: u32 = all_domains
                .iter()
                .map(|d| mitre_coverage_for_domain(d) as u32)
                .sum();
            let count = all_domains.len() as u32;
            // Round to nearest integer rather than truncating.
            ((sum * 10 / count + 5) / 10) as u8
        };

        GapReport {
            gaps,
            total_domains_covered,
            total_domains_missing,
            mitre_total_coverage_percent: avg_mitre_coverage,
            recommended_next_build,
        }
    }

    /// Returns the top-N highest-priority gaps.
    pub fn top_gaps(&self, n: usize) -> Vec<CapabilityGap> {
        let report = self.generate_report();
        report.gaps.into_iter().take(n).collect()
    }

    /// Compare the platform's known capabilities against a given set of
    /// MITRE ATT&CK technique IDs to surface coverage holes.
    pub fn compare_against_mitre(&self, technique_ids: &[&str]) -> Vec<String> {
        let mut uncovered = Vec::new();
        for id in technique_ids {
            if !self.known_capabilities.iter().any(|cap| cap.contains(id)) {
                uncovered.push(id.to_string());
            }
        }
        uncovered
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn domain_for_key(key: &str) -> SecurityDomain {
    let key_lower = key.to_lowercase();
    if key_lower.contains("blockchain")
        || key_lower.contains("contract")
        || key_lower.contains("defi")
        || key_lower.contains("zk")
        || key_lower.contains("solana")
        || key_lower.contains("cairo")
        || key_lower.contains("starknet")
    {
        SecurityDomain::Blockchain
    } else if key_lower.contains("exploit")
        || key_lower.contains("red")
        || key_lower.contains("apt")
        || key_lower.contains("nation")
    {
        SecurityDomain::RedTeam
    } else if key_lower.contains("blue")
        || key_lower.contains("detection")
        || key_lower.contains("forensic")
        || key_lower.contains("siem")
    {
        SecurityDomain::BlueTeam
    } else if key_lower.contains("cloud")
        || key_lower.contains("kubernetes")
        || key_lower.contains("iac")
        || key_lower.contains("terraform")
    {
        SecurityDomain::CloudSecurity
    } else if key_lower.contains("mobile")
        || key_lower.contains("android")
        || key_lower.contains("ios")
    {
        SecurityDomain::MobileSecurity
    } else if key_lower.contains("web") || key_lower.contains("http") || key_lower.contains("api") {
        SecurityDomain::WebSecurity
    } else if key_lower.contains("crypto") || key_lower.contains("cipher") {
        SecurityDomain::CryptographyAudit
    } else if key_lower.contains("supply") || key_lower.contains("sbom") {
        SecurityDomain::SupplyChain
    } else if key_lower.contains("threat") || key_lower.contains("intel") {
        SecurityDomain::ThreatIntelligence
    } else {
        SecurityDomain::Other(key.to_string())
    }
}

fn mitre_coverage_for_domain(domain: &SecurityDomain) -> u8 {
    match domain {
        SecurityDomain::RedTeam => 72,
        SecurityDomain::BlueTeam => 68,
        SecurityDomain::ExploitDevelopment => 55,
        SecurityDomain::Blockchain => 40,
        SecurityDomain::CloudSecurity => 50,
        SecurityDomain::MobileSecurity => 35,
        SecurityDomain::WebSecurity => 60,
        SecurityDomain::NetworkSecurity => 65,
        SecurityDomain::CryptographyAudit => 30,
        SecurityDomain::SupplyChain => 45,
        SecurityDomain::SocialEngineering => 55,
        SecurityDomain::ForensicsAndIR => 62,
        SecurityDomain::ThreatIntelligence => 70,
        SecurityDomain::Other(_) => 20,
    }
}
