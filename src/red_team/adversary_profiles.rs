//! Structured APT (Advanced Persistent Threat) adversary profiles.
//!
//! Provides machine-readable profiles for well-known nation-state threat actors,
//! including their MITRE ATT&CK technique mappings, target sectors, and known toolsets.
//! All profiles are sourced from publicly available threat intelligence reports.

/// A single MITRE ATT&CK technique reference.
#[derive(Debug, Clone)]
pub struct MitreTechnique {
    /// Technique ID (e.g., `"T1059.001"`).
    pub id: String,
    /// Technique name (e.g., `"PowerShell"`).
    pub name: String,
    /// ATT&CK tactic category (e.g., `"Execution"`).
    pub tactic: String,
    /// Sub-technique identifier, if any.
    pub sub_technique: Option<String>,
}

/// Phases of a multi-stage adversary campaign.
#[derive(Debug, Clone)]
pub struct CampaignPhases {
    pub initial_access: Vec<MitreTechnique>,
    pub execution: Vec<MitreTechnique>,
    pub persistence: Vec<MitreTechnique>,
    pub privilege_escalation: Vec<MitreTechnique>,
    pub defense_evasion: Vec<MitreTechnique>,
    pub credential_access: Vec<MitreTechnique>,
    pub lateral_movement: Vec<MitreTechnique>,
    pub collection: Vec<MitreTechnique>,
    pub exfiltration: Vec<MitreTechnique>,
    pub impact: Vec<MitreTechnique>,
}

impl CampaignPhases {
    /// Returns a flat list of all techniques across all phases.
    pub fn all_techniques(&self) -> Vec<&MitreTechnique> {
        let mut all = Vec::new();
        all.extend(&self.initial_access);
        all.extend(&self.execution);
        all.extend(&self.persistence);
        all.extend(&self.privilege_escalation);
        all.extend(&self.defense_evasion);
        all.extend(&self.credential_access);
        all.extend(&self.lateral_movement);
        all.extend(&self.collection);
        all.extend(&self.exfiltration);
        all.extend(&self.impact);
        all
    }
}

/// Attribution artefacts — indicators that link activity to a specific threat actor.
#[derive(Debug, Clone)]
pub struct AttributionIndicators {
    /// Malware family names associated with this actor.
    pub malware_families: Vec<String>,
    /// Infrastructure patterns (e.g., domain naming conventions).
    pub infrastructure_patterns: Vec<String>,
    /// Code similarity or compilation artefacts.
    pub code_artefacts: Vec<String>,
    /// Operational timing patterns.
    pub operational_timing: String,
}

/// A structured profile of a nation-state APT group.
#[derive(Debug, Clone)]
pub struct AdversaryProfile {
    /// Common name for the group (e.g., `"APT28"`).
    pub name: String,
    /// Alternative names and aliases used across vendors.
    pub aliases: Vec<String>,
    /// Assessed nation-state sponsor.
    pub nation_state: String,
    /// Mapped MITRE ATT&CK techniques.
    pub mitre_techniques: Vec<MitreTechnique>,
    /// Industry verticals this actor commonly targets.
    pub target_sectors: Vec<String>,
    /// Known offensive tools associated with this actor.
    pub known_tools: Vec<String>,
    /// Structured campaign phase TTPs.
    pub typical_ttps: CampaignPhases,
    /// Attribution artefacts.
    pub attribution_indicators: AttributionIndicators,
    /// MITRE ATT&CK group identifier.
    pub mitre_group_id: String,
}

impl AdversaryProfile {
    /// Returns an estimated stealth rating (0-10) based on defence evasion technique count.
    pub fn stealth_rating(&self) -> u8 {
        let evasion_count = self.typical_ttps.defense_evasion.len();
        (evasion_count.min(10)) as u8
    }

    /// Returns true if the actor is known to target the given sector.
    pub fn targets_sector(&self, sector: &str) -> bool {
        self.target_sectors
            .iter()
            .any(|s| s.to_lowercase() == sector.to_lowercase())
    }
}

// ── Built-in profiles ────────────────────────────────────────────────────────

/// Returns the profile for APT28 (Fancy Bear) — Russia/GRU.
pub fn apt28() -> AdversaryProfile {
    AdversaryProfile {
        name: "APT28".to_string(),
        aliases: vec![
            "Fancy Bear".to_string(),
            "Sofacy".to_string(),
            "Pawn Storm".to_string(),
            "Sednit".to_string(),
            "STRONTIUM".to_string(),
        ],
        nation_state: "Russia".to_string(),
        mitre_group_id: "G0007".to_string(),
        target_sectors: vec![
            "Government".to_string(),
            "Military".to_string(),
            "Defense".to_string(),
            "Media".to_string(),
            "Political Organizations".to_string(),
        ],
        known_tools: vec![
            "X-Agent".to_string(),
            "X-Tunnel".to_string(),
            "Sofacy".to_string(),
            "Drovorub".to_string(),
            "LoJax".to_string(),
        ],
        mitre_techniques: vec![
            MitreTechnique {
                id: "T1566.001".to_string(),
                name: "Spearphishing Attachment".to_string(),
                tactic: "Initial Access".to_string(),
                sub_technique: Some("001".to_string()),
            },
            MitreTechnique {
                id: "T1059.003".to_string(),
                name: "Windows Command Shell".to_string(),
                tactic: "Execution".to_string(),
                sub_technique: Some("003".to_string()),
            },
        ],
        typical_ttps: apt28_campaign_phases(),
        attribution_indicators: AttributionIndicators {
            malware_families: vec!["X-Agent".to_string(), "Sofacy".to_string()],
            infrastructure_patterns: vec![
                "Typosquatted government domains".to_string(),
                "Dynamic DNS providers".to_string(),
            ],
            code_artefacts: vec![
                "Russian-language compile-time paths".to_string(),
                "Shared crypto routines".to_string(),
            ],
            operational_timing: "Monday-Friday, 08:00-18:00 Moscow time (UTC+3)".to_string(),
        },
    }
}

fn apt28_campaign_phases() -> CampaignPhases {
    CampaignPhases {
        initial_access: vec![
            MitreTechnique {
                id: "T1566.001".to_string(),
                name: "Spearphishing Attachment".to_string(),
                tactic: "Initial Access".to_string(),
                sub_technique: Some("001".to_string()),
            },
            MitreTechnique {
                id: "T1190".to_string(),
                name: "Exploit Public-Facing Application".to_string(),
                tactic: "Initial Access".to_string(),
                sub_technique: None,
            },
        ],
        execution: vec![MitreTechnique {
            id: "T1059.001".to_string(),
            name: "PowerShell".to_string(),
            tactic: "Execution".to_string(),
            sub_technique: Some("001".to_string()),
        }],
        persistence: vec![MitreTechnique {
            id: "T1547.001".to_string(),
            name: "Registry Run Keys / Startup Folder".to_string(),
            tactic: "Persistence".to_string(),
            sub_technique: Some("001".to_string()),
        }],
        privilege_escalation: vec![MitreTechnique {
            id: "T1068".to_string(),
            name: "Exploitation for Privilege Escalation".to_string(),
            tactic: "Privilege Escalation".to_string(),
            sub_technique: None,
        }],
        defense_evasion: vec![
            MitreTechnique {
                id: "T1036".to_string(),
                name: "Masquerading".to_string(),
                tactic: "Defense Evasion".to_string(),
                sub_technique: None,
            },
            MitreTechnique {
                id: "T1055".to_string(),
                name: "Process Injection".to_string(),
                tactic: "Defense Evasion".to_string(),
                sub_technique: None,
            },
        ],
        credential_access: vec![MitreTechnique {
            id: "T1003".to_string(),
            name: "OS Credential Dumping".to_string(),
            tactic: "Credential Access".to_string(),
            sub_technique: None,
        }],
        lateral_movement: vec![MitreTechnique {
            id: "T1021.001".to_string(),
            name: "Remote Desktop Protocol".to_string(),
            tactic: "Lateral Movement".to_string(),
            sub_technique: Some("001".to_string()),
        }],
        collection: vec![MitreTechnique {
            id: "T1005".to_string(),
            name: "Data from Local System".to_string(),
            tactic: "Collection".to_string(),
            sub_technique: None,
        }],
        exfiltration: vec![MitreTechnique {
            id: "T1041".to_string(),
            name: "Exfiltration Over C2 Channel".to_string(),
            tactic: "Exfiltration".to_string(),
            sub_technique: None,
        }],
        impact: vec![],
    }
}

/// Returns the profile for APT29 (Cozy Bear) — Russia/SVR.
pub fn apt29() -> AdversaryProfile {
    AdversaryProfile {
        name: "APT29".to_string(),
        aliases: vec![
            "Cozy Bear".to_string(),
            "The Dukes".to_string(),
            "YTTRIUM".to_string(),
            "Midnight Blizzard".to_string(),
            "NOBELIUM".to_string(),
        ],
        nation_state: "Russia".to_string(),
        mitre_group_id: "G0016".to_string(),
        target_sectors: vec![
            "Government".to_string(),
            "Think Tanks".to_string(),
            "Healthcare".to_string(),
            "Technology".to_string(),
            "Finance".to_string(),
        ],
        known_tools: vec![
            "MiniDuke".to_string(),
            "CosmicDuke".to_string(),
            "MagicWeb".to_string(),
            "SUNBURST".to_string(),
        ],
        mitre_techniques: vec![MitreTechnique {
            id: "T1195.002".to_string(),
            name: "Compromise Software Supply Chain".to_string(),
            tactic: "Initial Access".to_string(),
            sub_technique: Some("002".to_string()),
        }],
        typical_ttps: apt29_campaign_phases(),
        attribution_indicators: AttributionIndicators {
            malware_families: vec!["MiniDuke".to_string(), "CozyDuke".to_string()],
            infrastructure_patterns: vec![
                "Compromised legitimate websites".to_string(),
                "Cloud services for C2".to_string(),
            ],
            code_artefacts: vec![
                "Modular malware framework".to_string(),
                "Twitter/Dropbox C2".to_string(),
            ],
            operational_timing: "Low-and-slow; blends with business hours".to_string(),
        },
    }
}

fn apt29_campaign_phases() -> CampaignPhases {
    CampaignPhases {
        initial_access: vec![MitreTechnique {
            id: "T1195.002".to_string(),
            name: "Compromise Software Supply Chain".to_string(),
            tactic: "Initial Access".to_string(),
            sub_technique: Some("002".to_string()),
        }],
        execution: vec![MitreTechnique {
            id: "T1059.003".to_string(),
            name: "Windows Command Shell".to_string(),
            tactic: "Execution".to_string(),
            sub_technique: Some("003".to_string()),
        }],
        persistence: vec![MitreTechnique {
            id: "T1543.003".to_string(),
            name: "Windows Service".to_string(),
            tactic: "Persistence".to_string(),
            sub_technique: Some("003".to_string()),
        }],
        privilege_escalation: vec![MitreTechnique {
            id: "T1134".to_string(),
            name: "Access Token Manipulation".to_string(),
            tactic: "Privilege Escalation".to_string(),
            sub_technique: None,
        }],
        defense_evasion: vec![
            MitreTechnique {
                id: "T1027".to_string(),
                name: "Obfuscated Files or Information".to_string(),
                tactic: "Defense Evasion".to_string(),
                sub_technique: None,
            },
            MitreTechnique {
                id: "T1070".to_string(),
                name: "Indicator Removal".to_string(),
                tactic: "Defense Evasion".to_string(),
                sub_technique: None,
            },
            MitreTechnique {
                id: "T1036".to_string(),
                name: "Masquerading".to_string(),
                tactic: "Defense Evasion".to_string(),
                sub_technique: None,
            },
        ],
        credential_access: vec![MitreTechnique {
            id: "T1555".to_string(),
            name: "Credentials from Password Stores".to_string(),
            tactic: "Credential Access".to_string(),
            sub_technique: None,
        }],
        lateral_movement: vec![MitreTechnique {
            id: "T1550.003".to_string(),
            name: "Pass the Ticket".to_string(),
            tactic: "Lateral Movement".to_string(),
            sub_technique: Some("003".to_string()),
        }],
        collection: vec![MitreTechnique {
            id: "T1114".to_string(),
            name: "Email Collection".to_string(),
            tactic: "Collection".to_string(),
            sub_technique: None,
        }],
        exfiltration: vec![MitreTechnique {
            id: "T1048".to_string(),
            name: "Exfiltration Over Alternative Protocol".to_string(),
            tactic: "Exfiltration".to_string(),
            sub_technique: None,
        }],
        impact: vec![],
    }
}

/// Returns the profile for Lazarus Group — North Korea/DPRK.
pub fn lazarus_group() -> AdversaryProfile {
    AdversaryProfile {
        name: "Lazarus Group".to_string(),
        aliases: vec![
            "HIDDEN COBRA".to_string(),
            "Guardians of Peace".to_string(),
            "ZINC".to_string(),
            "Diamond Sleet".to_string(),
        ],
        nation_state: "North Korea".to_string(),
        mitre_group_id: "G0032".to_string(),
        target_sectors: vec![
            "Cryptocurrency".to_string(),
            "Finance".to_string(),
            "Defense".to_string(),
            "Media".to_string(),
            "Critical Infrastructure".to_string(),
        ],
        known_tools: vec![
            "BLINDINGCAN".to_string(),
            "HOPLIGHT".to_string(),
            "AppleJeus".to_string(),
            "WannaCry".to_string(),
        ],
        mitre_techniques: vec![MitreTechnique {
            id: "T1566.002".to_string(),
            name: "Spearphishing Link".to_string(),
            tactic: "Initial Access".to_string(),
            sub_technique: Some("002".to_string()),
        }],
        typical_ttps: lazarus_campaign_phases(),
        attribution_indicators: AttributionIndicators {
            malware_families: vec!["AppleJeus".to_string(), "BLINDINGCAN".to_string()],
            infrastructure_patterns: vec![
                "Fake cryptocurrency exchange websites".to_string(),
                "Trojanised trading applications".to_string(),
            ],
            code_artefacts: vec![
                "Korean-language error strings".to_string(),
                "Shared code with DarkSeoul campaign".to_string(),
            ],
            operational_timing: "09:00-17:00 Pyongyang time (UTC+9)".to_string(),
        },
    }
}

fn lazarus_campaign_phases() -> CampaignPhases {
    CampaignPhases {
        initial_access: vec![MitreTechnique {
            id: "T1566.002".to_string(),
            name: "Spearphishing Link".to_string(),
            tactic: "Initial Access".to_string(),
            sub_technique: Some("002".to_string()),
        }],
        execution: vec![MitreTechnique {
            id: "T1204".to_string(),
            name: "User Execution".to_string(),
            tactic: "Execution".to_string(),
            sub_technique: None,
        }],
        persistence: vec![MitreTechnique {
            id: "T1053.005".to_string(),
            name: "Scheduled Task".to_string(),
            tactic: "Persistence".to_string(),
            sub_technique: Some("005".to_string()),
        }],
        privilege_escalation: vec![MitreTechnique {
            id: "T1068".to_string(),
            name: "Exploitation for Privilege Escalation".to_string(),
            tactic: "Privilege Escalation".to_string(),
            sub_technique: None,
        }],
        defense_evasion: vec![
            MitreTechnique {
                id: "T1562.001".to_string(),
                name: "Disable or Modify Tools".to_string(),
                tactic: "Defense Evasion".to_string(),
                sub_technique: Some("001".to_string()),
            },
            MitreTechnique {
                id: "T1070.004".to_string(),
                name: "File Deletion".to_string(),
                tactic: "Defense Evasion".to_string(),
                sub_technique: Some("004".to_string()),
            },
        ],
        credential_access: vec![MitreTechnique {
            id: "T1056".to_string(),
            name: "Input Capture".to_string(),
            tactic: "Credential Access".to_string(),
            sub_technique: None,
        }],
        lateral_movement: vec![MitreTechnique {
            id: "T1570".to_string(),
            name: "Lateral Tool Transfer".to_string(),
            tactic: "Lateral Movement".to_string(),
            sub_technique: None,
        }],
        collection: vec![MitreTechnique {
            id: "T1005".to_string(),
            name: "Data from Local System".to_string(),
            tactic: "Collection".to_string(),
            sub_technique: None,
        }],
        exfiltration: vec![MitreTechnique {
            id: "T1041".to_string(),
            name: "Exfiltration Over C2 Channel".to_string(),
            tactic: "Exfiltration".to_string(),
            sub_technique: None,
        }],
        impact: vec![MitreTechnique {
            id: "T1486".to_string(),
            name: "Data Encrypted for Impact".to_string(),
            tactic: "Impact".to_string(),
            sub_technique: None,
        }],
    }
}

/// Returns the profile for APT41 — China (dual espionage + cybercrime).
pub fn apt41() -> AdversaryProfile {
    AdversaryProfile {
        name: "APT41".to_string(),
        aliases: vec![
            "Double Dragon".to_string(),
            "Winnti".to_string(),
            "Barium".to_string(),
            "Wicked Panda".to_string(),
        ],
        nation_state: "China".to_string(),
        mitre_group_id: "G0096".to_string(),
        target_sectors: vec![
            "Technology".to_string(),
            "Healthcare".to_string(),
            "Telecom".to_string(),
            "Gaming".to_string(),
            "Finance".to_string(),
        ],
        known_tools: vec![
            "HIGHNOON".to_string(),
            "MESSAGETAP".to_string(),
            "Cobalt Strike".to_string(),
            "Winnti".to_string(),
        ],
        mitre_techniques: vec![MitreTechnique {
            id: "T1190".to_string(),
            name: "Exploit Public-Facing Application".to_string(),
            tactic: "Initial Access".to_string(),
            sub_technique: None,
        }],
        typical_ttps: apt41_campaign_phases(),
        attribution_indicators: AttributionIndicators {
            malware_families: vec!["Winnti".to_string(), "HIGHNOON".to_string()],
            infrastructure_patterns: vec![
                "Compromised hosting providers".to_string(),
                "Fast-flux DNS".to_string(),
            ],
            code_artefacts: vec![
                "Shared Winnti backdoor framework".to_string(),
                "PlugX rootkit components".to_string(),
            ],
            operational_timing: "Business hours (UTC+8) but also off-hours for ransomware ops"
                .to_string(),
        },
    }
}

fn apt41_campaign_phases() -> CampaignPhases {
    CampaignPhases {
        initial_access: vec![MitreTechnique {
            id: "T1190".to_string(),
            name: "Exploit Public-Facing Application".to_string(),
            tactic: "Initial Access".to_string(),
            sub_technique: None,
        }],
        execution: vec![MitreTechnique {
            id: "T1059.001".to_string(),
            name: "PowerShell".to_string(),
            tactic: "Execution".to_string(),
            sub_technique: Some("001".to_string()),
        }],
        persistence: vec![MitreTechnique {
            id: "T1505.003".to_string(),
            name: "Web Shell".to_string(),
            tactic: "Persistence".to_string(),
            sub_technique: Some("003".to_string()),
        }],
        privilege_escalation: vec![MitreTechnique {
            id: "T1055".to_string(),
            name: "Process Injection".to_string(),
            tactic: "Privilege Escalation".to_string(),
            sub_technique: None,
        }],
        defense_evasion: vec![
            MitreTechnique {
                id: "T1036.005".to_string(),
                name: "Match Legitimate Name or Location".to_string(),
                tactic: "Defense Evasion".to_string(),
                sub_technique: Some("005".to_string()),
            },
            MitreTechnique {
                id: "T1027".to_string(),
                name: "Obfuscated Files or Information".to_string(),
                tactic: "Defense Evasion".to_string(),
                sub_technique: None,
            },
        ],
        credential_access: vec![MitreTechnique {
            id: "T1003.001".to_string(),
            name: "LSASS Memory".to_string(),
            tactic: "Credential Access".to_string(),
            sub_technique: Some("001".to_string()),
        }],
        lateral_movement: vec![MitreTechnique {
            id: "T1021.002".to_string(),
            name: "SMB/Windows Admin Shares".to_string(),
            tactic: "Lateral Movement".to_string(),
            sub_technique: Some("002".to_string()),
        }],
        collection: vec![MitreTechnique {
            id: "T1213".to_string(),
            name: "Data from Information Repositories".to_string(),
            tactic: "Collection".to_string(),
            sub_technique: None,
        }],
        exfiltration: vec![MitreTechnique {
            id: "T1048.003".to_string(),
            name: "Exfiltration Over Unencrypted Protocol".to_string(),
            tactic: "Exfiltration".to_string(),
            sub_technique: Some("003".to_string()),
        }],
        impact: vec![],
    }
}

/// Returns all built-in adversary profiles.
pub fn all_profiles() -> Vec<AdversaryProfile> {
    vec![apt28(), apt29(), lazarus_group(), apt41()]
}

/// Look up a profile by name or alias (case-insensitive).
pub fn find_profile(name: &str) -> Option<AdversaryProfile> {
    let name_lower = name.to_lowercase();
    all_profiles().into_iter().find(|p| {
        p.name.to_lowercase() == name_lower
            || p.aliases.iter().any(|a| a.to_lowercase() == name_lower)
    })
}
