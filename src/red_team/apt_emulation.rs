//! APT emulation for authorized adversary simulation engagements.

/// Difficulty of detecting a given technique.
#[derive(Debug, Clone, PartialEq)]
pub enum DetectionDifficulty {
    Easy,
    Medium,
    Hard,
    VeryHard,
}

/// A single MITRE ATT&CK technique.
#[derive(Debug, Clone)]
pub struct MitreAttackTechnique {
    pub id: String,
    pub name: String,
    pub tactic: String,
    pub detection_difficulty: DetectionDifficulty,
}

/// Known APT threat actor groups.
#[derive(Debug, Clone, PartialEq)]
pub enum AptGroup {
    Apt28,
    Apt29,
    Lazarus,
    CozyBear,
    FancyBear,
    EquationGroup,
    Turla,
    Sandworm,
    Apt41,
    Kimsuky,
    CharmingKitten,
    OceanLotus,
}

/// A structured profile of an APT group's known TTPs.
#[derive(Debug, Clone)]
pub struct AptProfile {
    pub name: String,
    pub nation_state: String,
    pub mitre_tactics: Vec<String>,
    pub ttps: Vec<MitreAttackTechnique>,
    pub known_tools: Vec<String>,
    pub objectives: Vec<String>,
}

/// Scope boundaries for an APT emulation engagement.
#[derive(Debug, Clone)]
pub struct EngagementScope {
    pub target_org: String,
    pub allowed_systems: Vec<String>,
    pub excluded_systems: Vec<String>,
    pub max_noise_level: u8,
}

/// Results of an APT emulation exercise.
#[derive(Debug, Clone)]
pub struct EmulationResult {
    pub apt_group: AptGroup,
    pub techniques_used: Vec<MitreAttackTechnique>,
    pub success_rate: f64,
    pub detection_events: u32,
    pub report_path: String,
}

/// Returns a pre-built TTP profile for the given APT group.
pub fn load_apt_profile(group: &AptGroup) -> AptProfile {
    match group {
        AptGroup::Apt28 | AptGroup::FancyBear => AptProfile {
            name: "APT28 (Fancy Bear)".to_string(),
            nation_state: "Russia".to_string(),
            mitre_tactics: vec![
                "Initial Access".to_string(),
                "Execution".to_string(),
                "Persistence".to_string(),
                "Credential Access".to_string(),
                "Collection".to_string(),
                "Exfiltration".to_string(),
            ],
            ttps: vec![
                MitreAttackTechnique {
                    id: "T1566.001".to_string(),
                    name: "Spearphishing Attachment".to_string(),
                    tactic: "Initial Access".to_string(),
                    detection_difficulty: DetectionDifficulty::Medium,
                },
                MitreAttackTechnique {
                    id: "T1059.005".to_string(),
                    name: "Visual Basic".to_string(),
                    tactic: "Execution".to_string(),
                    detection_difficulty: DetectionDifficulty::Medium,
                },
                MitreAttackTechnique {
                    id: "T1003.001".to_string(),
                    name: "LSASS Memory".to_string(),
                    tactic: "Credential Access".to_string(),
                    detection_difficulty: DetectionDifficulty::Hard,
                },
                MitreAttackTechnique {
                    id: "T1041".to_string(),
                    name: "Exfiltration Over C2 Channel".to_string(),
                    tactic: "Exfiltration".to_string(),
                    detection_difficulty: DetectionDifficulty::Hard,
                },
            ],
            known_tools: vec![
                "X-Agent".to_string(),
                "X-Tunnel".to_string(),
                "Sofacy".to_string(),
                "CHOPSTICK".to_string(),
            ],
            objectives: vec![
                "Espionage".to_string(),
                "Political Influence Operations".to_string(),
            ],
        },
        AptGroup::Apt29 | AptGroup::CozyBear => AptProfile {
            name: "APT29 (Cozy Bear)".to_string(),
            nation_state: "Russia".to_string(),
            mitre_tactics: vec![
                "Initial Access".to_string(),
                "Defense Evasion".to_string(),
                "Lateral Movement".to_string(),
                "Collection".to_string(),
                "Command and Control".to_string(),
            ],
            ttps: vec![
                MitreAttackTechnique {
                    id: "T1195.002".to_string(),
                    name: "Compromise Software Supply Chain".to_string(),
                    tactic: "Initial Access".to_string(),
                    detection_difficulty: DetectionDifficulty::VeryHard,
                },
                MitreAttackTechnique {
                    id: "T1027".to_string(),
                    name: "Obfuscated Files or Information".to_string(),
                    tactic: "Defense Evasion".to_string(),
                    detection_difficulty: DetectionDifficulty::Hard,
                },
                MitreAttackTechnique {
                    id: "T1550.002".to_string(),
                    name: "Pass the Hash".to_string(),
                    tactic: "Lateral Movement".to_string(),
                    detection_difficulty: DetectionDifficulty::Hard,
                },
            ],
            known_tools: vec![
                "SUNBURST".to_string(),
                "TEARDROP".to_string(),
                "MiniDuke".to_string(),
                "CosmicDuke".to_string(),
            ],
            objectives: vec!["Intelligence Collection".to_string(), "Espionage".to_string()],
        },
        AptGroup::Lazarus => AptProfile {
            name: "Lazarus Group".to_string(),
            nation_state: "North Korea".to_string(),
            mitre_tactics: vec![
                "Initial Access".to_string(),
                "Execution".to_string(),
                "Impact".to_string(),
                "Exfiltration".to_string(),
            ],
            ttps: vec![
                MitreAttackTechnique {
                    id: "T1566.002".to_string(),
                    name: "Spearphishing Link".to_string(),
                    tactic: "Initial Access".to_string(),
                    detection_difficulty: DetectionDifficulty::Medium,
                },
                MitreAttackTechnique {
                    id: "T1486".to_string(),
                    name: "Data Encrypted for Impact".to_string(),
                    tactic: "Impact".to_string(),
                    detection_difficulty: DetectionDifficulty::Easy,
                },
            ],
            known_tools: vec!["BLINDINGCAN".to_string(), "HOPLIGHT".to_string()],
            objectives: vec!["Financial Gain".to_string(), "Sabotage".to_string()],
        },
        AptGroup::EquationGroup => AptProfile {
            name: "Equation Group".to_string(),
            nation_state: "United States".to_string(),
            mitre_tactics: vec![
                "Initial Access".to_string(),
                "Persistence".to_string(),
                "Defense Evasion".to_string(),
                "Command and Control".to_string(),
            ],
            ttps: vec![
                MitreAttackTechnique {
                    id: "T1542.001".to_string(),
                    name: "System Firmware".to_string(),
                    tactic: "Persistence".to_string(),
                    detection_difficulty: DetectionDifficulty::VeryHard,
                },
                MitreAttackTechnique {
                    id: "T1090.003".to_string(),
                    name: "Multi-hop Proxy".to_string(),
                    tactic: "Command and Control".to_string(),
                    detection_difficulty: DetectionDifficulty::VeryHard,
                },
            ],
            known_tools: vec![
                "DOUBLEFANTASY".to_string(),
                "EQUATIONDRUG".to_string(),
                "GRAYFISH".to_string(),
            ],
            objectives: vec!["Long-term Espionage".to_string()],
        },
        AptGroup::Turla => AptProfile {
            name: "Turla".to_string(),
            nation_state: "Russia".to_string(),
            mitre_tactics: vec![
                "Initial Access".to_string(),
                "Collection".to_string(),
                "Command and Control".to_string(),
            ],
            ttps: vec![MitreAttackTechnique {
                id: "T1071.003".to_string(),
                name: "Mail Protocols".to_string(),
                tactic: "Command and Control".to_string(),
                detection_difficulty: DetectionDifficulty::Hard,
            }],
            known_tools: vec!["Carbon".to_string(), "Uroburos".to_string()],
            objectives: vec!["Diplomatic Espionage".to_string()],
        },
        AptGroup::Sandworm => AptProfile {
            name: "Sandworm".to_string(),
            nation_state: "Russia".to_string(),
            mitre_tactics: vec![
                "Initial Access".to_string(),
                "Impact".to_string(),
                "Lateral Movement".to_string(),
            ],
            ttps: vec![MitreAttackTechnique {
                id: "T1561.002".to_string(),
                name: "Disk Structure Wipe".to_string(),
                tactic: "Impact".to_string(),
                detection_difficulty: DetectionDifficulty::Easy,
            }],
            known_tools: vec!["BlackEnergy".to_string(), "Industroyer".to_string()],
            objectives: vec!["Critical Infrastructure Disruption".to_string()],
        },
        AptGroup::Apt41 => AptProfile {
            name: "APT41".to_string(),
            nation_state: "China".to_string(),
            mitre_tactics: vec![
                "Initial Access".to_string(),
                "Privilege Escalation".to_string(),
                "Exfiltration".to_string(),
            ],
            ttps: vec![MitreAttackTechnique {
                id: "T1190".to_string(),
                name: "Exploit Public-Facing Application".to_string(),
                tactic: "Initial Access".to_string(),
                detection_difficulty: DetectionDifficulty::Medium,
            }],
            known_tools: vec!["ShadowPad".to_string(), "Speculoos".to_string()],
            objectives: vec!["Espionage".to_string(), "Financial Gain".to_string()],
        },
        AptGroup::Kimsuky => AptProfile {
            name: "Kimsuky".to_string(),
            nation_state: "North Korea".to_string(),
            mitre_tactics: vec!["Initial Access".to_string(), "Collection".to_string()],
            ttps: vec![MitreAttackTechnique {
                id: "T1598.003".to_string(),
                name: "Spearphishing Link".to_string(),
                tactic: "Reconnaissance".to_string(),
                detection_difficulty: DetectionDifficulty::Medium,
            }],
            known_tools: vec!["BabyShark".to_string(), "AppleSeed".to_string()],
            objectives: vec!["Intelligence Collection".to_string()],
        },
        AptGroup::CharmingKitten => AptProfile {
            name: "Charming Kitten (APT35)".to_string(),
            nation_state: "Iran".to_string(),
            mitre_tactics: vec!["Initial Access".to_string(), "Credential Access".to_string()],
            ttps: vec![MitreAttackTechnique {
                id: "T1111".to_string(),
                name: "Multi-Factor Authentication Interception".to_string(),
                tactic: "Credential Access".to_string(),
                detection_difficulty: DetectionDifficulty::Hard,
            }],
            known_tools: vec!["HYPERSCRAPE".to_string()],
            objectives: vec!["Espionage".to_string(), "Surveillance".to_string()],
        },
        AptGroup::OceanLotus => AptProfile {
            name: "OceanLotus (APT32)".to_string(),
            nation_state: "Vietnam".to_string(),
            mitre_tactics: vec![
                "Initial Access".to_string(),
                "Execution".to_string(),
                "Collection".to_string(),
            ],
            ttps: vec![MitreAttackTechnique {
                id: "T1059.007".to_string(),
                name: "JavaScript".to_string(),
                tactic: "Execution".to_string(),
                detection_difficulty: DetectionDifficulty::Medium,
            }],
            known_tools: vec!["Denis".to_string(), "WINDSHIELD".to_string()],
            objectives: vec!["Regional Espionage".to_string()],
        },
    }
}

/// Simulates an APT emulation exercise within the given scope.
pub async fn emulate_apt(
    group: &AptGroup,
    profile: &AptProfile,
    scope: &EngagementScope,
) -> anyhow::Result<EmulationResult> {
    let techniques_used = profile.ttps.clone();
    let technique_count = techniques_used.len() as f64;
    // Simulated success rate: 0% by default (no real execution occurs).
    let success_rate = if technique_count > 0.0 { 0.5 } else { 0.0 };

    Ok(EmulationResult {
        apt_group: group.clone(),
        techniques_used,
        success_rate,
        detection_events: 0,
        report_path: format!("/tmp/apt_emulation_{}.md", scope.target_org.replace(' ', "_")),
    })
}

/// Generates a Markdown report from an APT emulation result.
pub fn generate_apt_report(result: &EmulationResult) -> String {
    let mut report = format!(
        "# APT Emulation Report\n\n**Group:** {:?}\n**Success Rate:** {:.0}%\n**Detection Events:** {}\n\n",
        result.apt_group, result.success_rate * 100.0, result.detection_events
    );

    report.push_str("## Techniques Used\n\n");
    report.push_str("| ID | Name | Tactic | Detection Difficulty |\n");
    report.push_str("|---|---|---|---|\n");
    for technique in &result.techniques_used {
        report.push_str(&format!(
            "| {} | {} | {} | {:?} |\n",
            technique.id, technique.name, technique.tactic, technique.detection_difficulty
        ));
    }

    report.push_str(&format!("\n**Report saved to:** {}\n", result.report_path));
    report
}
