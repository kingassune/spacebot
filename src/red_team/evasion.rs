//! Advanced detection evasion techniques for authorized red team engagements.

use serde::{Deserialize, Serialize};

/// High-level category of an evasion technique.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum EvasionCategory {
    /// Techniques that hide process execution (e.g., process hollowing).
    ProcessEvasion,
    /// Techniques that bypass or disable AV/EDR products.
    AvBypass,
    /// Techniques that evade network-based detection.
    NetworkEvasion,
    /// Obfuscation and encoding to avoid signature detection.
    SignatureEvasion,
    /// Abuse of living-off-the-land binaries (LOLBins).
    LolbinAbuse,
    /// Timestomping, log clearing, and other anti-forensic techniques.
    AntiForensics,
    /// Techniques that disable or tamper with logging.
    LogTampering,
}

/// A specific evasion technique with ATT&CK mapping.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvasionTechnique {
    pub id: String,
    pub name: String,
    pub category: EvasionCategory,
    pub mitre_id: String,
    /// Estimated bypass rate against common EDR solutions (0.0–1.0).
    pub bypass_rate: f64,
    pub description: String,
    pub implementation_notes: String,
}

/// Configuration for an evasion chain selection and execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvasionConfig {
    /// Target defensive technology stack (e.g., ["CrowdStrike", "Sysmon"]).
    pub defender_stack: Vec<String>,
    /// Required evasion categories.
    pub required_categories: Vec<EvasionCategory>,
    /// Minimum acceptable bypass rate (0.0–1.0).
    pub min_bypass_rate: f64,
    /// Whether to use only LOLBins (no dropped files).
    pub fileless_only: bool,
}

impl Default for EvasionConfig {
    fn default() -> Self {
        Self {
            defender_stack: vec!["Windows Defender".to_string()],
            required_categories: vec![EvasionCategory::AvBypass, EvasionCategory::ProcessEvasion],
            min_bypass_rate: 0.6,
            fileless_only: false,
        }
    }
}

/// Result of an evasion test run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvasionResult {
    pub techniques_tested: Vec<EvasionTechnique>,
    pub techniques_succeeded: usize,
    pub overall_stealth_score: f64,
    pub detections_triggered: Vec<String>,
    pub recommendations: Vec<String>,
}

/// Records where a detection bypass was achieved and what was used.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionBypass {
    pub technique: EvasionTechnique,
    pub defender: String,
    pub bypassed: bool,
    pub detection_signature: Option<String>,
}

/// Select an optimal evasion chain for the given configuration.
pub fn select_evasion_chain(config: &EvasionConfig) -> Vec<EvasionTechnique> {
    let all_techniques = known_techniques();
    let mut chain: Vec<EvasionTechnique> = all_techniques
        .into_iter()
        .filter(|t| {
            config.required_categories.contains(&t.category)
                && t.bypass_rate >= config.min_bypass_rate
        })
        .collect();

    if config.fileless_only {
        chain.retain(|t| t.category == EvasionCategory::LolbinAbuse);
    }

    // Sort by bypass rate descending, pick the best two per category.
    chain.sort_by(|a, b| b.bypass_rate.partial_cmp(&a.bypass_rate).unwrap());
    chain.truncate(6);
    chain
}

/// Test an evasion chain against the configured defender stack.
pub fn test_evasion(techniques: &[EvasionTechnique], config: &EvasionConfig) -> EvasionResult {
    let mut detections = Vec::new();
    let mut succeeded = 0usize;

    for technique in techniques {
        let bypassed = technique_bypasses_stack(technique, &config.defender_stack);
        if bypassed {
            succeeded += 1;
        } else {
            detections.push(format!(
                "{} ({}) detected by {:?}",
                technique.name, technique.mitre_id, config.defender_stack
            ));
        }
    }

    let score = if techniques.is_empty() {
        0.0
    } else {
        succeeded as f64 / techniques.len() as f64
    };

    let recommendations = generate_recommendations(&detections, config);

    EvasionResult {
        techniques_tested: techniques.to_vec(),
        techniques_succeeded: succeeded,
        overall_stealth_score: score,
        detections_triggered: detections,
        recommendations,
    }
}

/// Compute an overall stealth score for the selected techniques.
pub fn score_stealth(techniques: &[EvasionTechnique]) -> f64 {
    if techniques.is_empty() {
        return 0.0;
    }
    let total: f64 = techniques.iter().map(|t| t.bypass_rate).sum();
    total / techniques.len() as f64
}

/// Adapt the evasion chain based on triggered detections.
pub fn adapt_to_detection(
    current: &[EvasionTechnique],
    detected: &[String],
) -> Vec<EvasionTechnique> {
    // Remove techniques that were detected and substitute with alternatives.
    let detected_ids: Vec<&str> = detected
        .iter()
        .filter_map(|d| {
            current
                .iter()
                .find(|t| d.contains(&t.name))
                .map(|t| t.id.as_str())
        })
        .collect();

    let mut adapted: Vec<EvasionTechnique> = current
        .iter()
        .filter(|t| !detected_ids.contains(&t.id.as_str()))
        .cloned()
        .collect();

    // Add alternative techniques not currently in the chain.
    let alternatives: Vec<EvasionTechnique> = known_techniques()
        .into_iter()
        .filter(|t| !current.iter().any(|c| c.id == t.id))
        .collect();

    for alt in alternatives.into_iter().take(detected_ids.len()) {
        adapted.push(alt);
    }

    adapted
}

// — Internal helpers —

fn technique_bypasses_stack(technique: &EvasionTechnique, stack: &[String]) -> bool {
    // Heuristic: LOLBin techniques bypass Windows Defender but not CrowdStrike.
    for defender in stack {
        if (defender.contains("CrowdStrike") || defender.contains("SentinelOne"))
            && technique.category == EvasionCategory::LolbinAbuse
        {
            return false;
        }
    }
    technique.bypass_rate >= 0.5
}

fn generate_recommendations(detections: &[String], config: &EvasionConfig) -> Vec<String> {
    let mut recs = Vec::new();
    if !detections.is_empty() {
        recs.push(format!(
            "{} technique(s) triggered alerts. Consider rotating to alternative LOLBins or obfuscation methods.",
            detections.len()
        ));
    }
    if config
        .defender_stack
        .iter()
        .any(|d| d.contains("CrowdStrike"))
    {
        recs.push(
            "CrowdStrike in stack: prefer indirect syscall techniques over direct API calls."
                .to_string(),
        );
    }
    if config.fileless_only {
        recs.push("Fileless constraint active: all tradecraft must remain in-memory.".to_string());
    }
    recs
}

fn known_techniques() -> Vec<EvasionTechnique> {
    vec![
        EvasionTechnique {
            id: "EVA-001".to_string(),
            name: "Process Hollowing".to_string(),
            category: EvasionCategory::ProcessEvasion,
            mitre_id: "T1055.012".to_string(),
            bypass_rate: 0.75,
            description: "Unmaps legitimate process memory and replaces with malicious payload."
                .to_string(),
            implementation_notes: "Use CreateProcess(SUSPENDED) + NtUnmapViewOfSection."
                .to_string(),
        },
        EvasionTechnique {
            id: "EVA-002".to_string(),
            name: "AMSI Bypass via Memory Patch".to_string(),
            category: EvasionCategory::AvBypass,
            mitre_id: "T1562.001".to_string(),
            bypass_rate: 0.80,
            description: "Patches amsi.dll AmsiScanBuffer to always return AMSI_RESULT_CLEAN."
                .to_string(),
            implementation_notes:
                "Patch bytes [0xB8, 0x57, 0x00, 0x07, 0x80] at AmsiScanBuffer offset.".to_string(),
        },
        EvasionTechnique {
            id: "EVA-003".to_string(),
            name: "DNS over HTTPS C2 Tunneling".to_string(),
            category: EvasionCategory::NetworkEvasion,
            mitre_id: "T1071.004".to_string(),
            bypass_rate: 0.70,
            description:
                "Encodes C2 traffic as DNS queries over HTTPS to avoid network inspection."
                    .to_string(),
            implementation_notes: "Use Cloudflare or Google DoH resolvers as C2 relay.".to_string(),
        },
        EvasionTechnique {
            id: "EVA-004".to_string(),
            name: "Powershell Base64 Obfuscation".to_string(),
            category: EvasionCategory::SignatureEvasion,
            mitre_id: "T1027".to_string(),
            bypass_rate: 0.60,
            description: "Encodes PowerShell payloads in Base64 to evade string-based signatures."
                .to_string(),
            implementation_notes: "Use -EncodedCommand flag; layer with string concatenation."
                .to_string(),
        },
        EvasionTechnique {
            id: "EVA-005".to_string(),
            name: "MSBuild LOLBin Execution".to_string(),
            category: EvasionCategory::LolbinAbuse,
            mitre_id: "T1127.001".to_string(),
            bypass_rate: 0.65,
            description:
                "Uses MSBuild.exe to execute inline C# tasks, bypassing application whitelisting."
                    .to_string(),
            implementation_notes:
                "Craft .csproj file with inline task payload; invoke via MSBuild.".to_string(),
        },
        EvasionTechnique {
            id: "EVA-006".to_string(),
            name: "Timestomping".to_string(),
            category: EvasionCategory::AntiForensics,
            mitre_id: "T1070.006".to_string(),
            bypass_rate: 0.85,
            description: "Modifies file MACE timestamps to blend in with system files.".to_string(),
            implementation_notes: "Use SetFileTime() API to set timestamps to OS install date."
                .to_string(),
        },
        EvasionTechnique {
            id: "EVA-007".to_string(),
            name: "Event Log Clearing".to_string(),
            category: EvasionCategory::LogTampering,
            mitre_id: "T1070.001".to_string(),
            bypass_rate: 0.55,
            description: "Clears Windows security and application event logs to remove IOCs."
                .to_string(),
            implementation_notes: "Use wevtutil cl Security; may itself generate audit event."
                .to_string(),
        },
    ]
}
