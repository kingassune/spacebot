//! Nation-state adversary emulation engine.
//!
//! Provides TTP-based simulation of advanced persistent threat (APT) actors
//! mapped to the MITRE ATT&CK framework. All emulation is strictly
//! simulation-only and must be used exclusively within a documented,
//! authorised red team engagement.

use crate::red_team::{
    adversary_profiles::{self, AdversaryProfile},
    campaign::{Campaign, CampaignResult, RulesOfEngagement},
};

/// Infrastructure type used for command-and-control emulation.
#[derive(Debug, Clone, PartialEq)]
pub enum C2InfrastructureType {
    /// HTTP/S beaconing via compromised or rented servers.
    HttpBeacon,
    /// DNS tunnelling for exfiltration and C2.
    DnsTunnel,
    /// Domain fronting through a CDN.
    DomainFronting,
    /// Peer-to-peer mesh C2.
    P2pMesh,
    /// Steganography-based C2 (e.g., hiding data in images).
    Steganography,
    /// Legitimate cloud services (Dropbox, OneDrive, Twitter DMs).
    CloudServiceAbuse,
}

/// An evasion technique employed by a nation-state actor.
#[derive(Debug, Clone)]
pub struct EvasionTechnique {
    /// MITRE ATT&CK technique ID.
    pub mitre_id: String,
    /// Human-readable name.
    pub name: String,
    /// Description of how the technique evades detection.
    pub description: String,
    /// Living-off-the-land binary or script used, if any.
    pub lolbin: Option<String>,
}

/// Summary of a nation-state emulation run.
#[derive(Debug, Clone)]
pub struct EmulationSummary {
    pub actor_name: String,
    pub campaign_result: CampaignResult,
    pub c2_infrastructure: C2InfrastructureType,
    pub evasion_techniques_used: Vec<EvasionTechnique>,
    pub attribution_left: Vec<String>,
    pub detection_opportunities: Vec<String>,
}

/// NationStateEmulator — orchestrates multi-phase APT emulation campaigns.
///
/// Given an adversary profile and rules of engagement, builds and executes
/// a structured campaign that follows the actor's known TTPs step-by-step.
#[derive(Debug, Clone)]
pub struct NationStateEmulator {
    /// The APT profile to emulate.
    pub profile: AdversaryProfile,
    /// Bounding rules for the engagement.
    pub rules_of_engagement: RulesOfEngagement,
}

impl NationStateEmulator {
    /// Create a new emulator for a named APT group.
    ///
    /// Returns `None` if the name is not recognised in the built-in profile library.
    pub fn for_actor(name: &str, rules_of_engagement: RulesOfEngagement) -> Option<Self> {
        adversary_profiles::find_profile(name).map(|profile| Self {
            profile,
            rules_of_engagement,
        })
    }

    /// Create an emulator from an explicit [`AdversaryProfile`].
    pub fn with_profile(profile: AdversaryProfile, rules_of_engagement: RulesOfEngagement) -> Self {
        Self {
            profile,
            rules_of_engagement,
        }
    }

    /// Execute the full emulation campaign and return a structured summary.
    ///
    /// The emulator:
    /// 1. Builds a campaign from the adversary's TTP phases.
    /// 2. Runs each phase, respecting the rules of engagement.
    /// 3. Selects a C2 infrastructure type representative of the actor.
    /// 4. Catalogues evasion techniques employed.
    /// 5. Identifies artefacts left behind and detection opportunities.
    pub fn run(
        &self,
        objectives: Vec<String>,
        target_system: impl Into<String>,
    ) -> EmulationSummary {
        let target = target_system.into();
        let mut roe = self.rules_of_engagement.clone();
        if !roe.in_scope_systems.contains(&target) {
            roe.in_scope_systems.push(target.clone());
        }

        let mut campaign = Campaign::new(self.profile.clone(), objectives, roe);
        let campaign_result = campaign.run();

        let c2_infrastructure = self.select_c2_type();
        let evasion_techniques = self.catalogue_evasion_techniques();
        let attribution_left = self.compute_attribution_artefacts();
        let detection_opportunities = self.derive_detection_opportunities(&evasion_techniques);

        EmulationSummary {
            actor_name: self.profile.name.clone(),
            campaign_result,
            c2_infrastructure,
            evasion_techniques_used: evasion_techniques,
            attribution_left,
            detection_opportunities,
        }
    }

    /// Select a C2 infrastructure type representative of this actor's known patterns.
    fn select_c2_type(&self) -> C2InfrastructureType {
        let infra_patterns = &self.profile.attribution_indicators.infrastructure_patterns;
        if infra_patterns
            .iter()
            .any(|p| p.to_lowercase().contains("dns"))
        {
            C2InfrastructureType::DnsTunnel
        } else if infra_patterns
            .iter()
            .any(|p| p.to_lowercase().contains("cloud"))
        {
            C2InfrastructureType::CloudServiceAbuse
        } else if infra_patterns
            .iter()
            .any(|p| p.to_lowercase().contains("cdn"))
        {
            C2InfrastructureType::DomainFronting
        } else {
            C2InfrastructureType::HttpBeacon
        }
    }

    /// Return a catalogue of evasion techniques from the adversary's defence-evasion phase.
    fn catalogue_evasion_techniques(&self) -> Vec<EvasionTechnique> {
        self.profile
            .typical_ttps
            .defense_evasion
            .iter()
            .map(|t| EvasionTechnique {
                mitre_id: t.id.clone(),
                name: t.name.clone(),
                description: format!(
                    "Defence evasion technique employed by {}: {}",
                    self.profile.name, t.name
                ),
                lolbin: lolbin_for_technique(&t.id),
            })
            .collect()
    }

    /// Compute attribution artefacts the emulation would leave behind.
    fn compute_attribution_artefacts(&self) -> Vec<String> {
        let indicators = &self.profile.attribution_indicators;
        let mut artefacts = indicators.malware_families.clone();
        artefacts.extend(indicators.code_artefacts.clone());
        artefacts
    }

    /// Derive high-value detection opportunities from the evasion techniques used.
    fn derive_detection_opportunities(&self, evasion: &[EvasionTechnique]) -> Vec<String> {
        let mut opportunities = Vec::new();
        for technique in evasion {
            opportunities.push(format!(
                "Monitor for {}: {}",
                technique.mitre_id, technique.name
            ));
        }
        // Add generic campaign-level detection hints.
        opportunities.push("Alert on unusual scheduled task creation or modification.".to_string());
        opportunities.push("Monitor for LSASS access from non-system processes.".to_string());
        opportunities.push(
            "Detect anomalous outbound traffic to known cloud file-sharing services.".to_string(),
        );
        opportunities
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Return a common LOLBin associated with a MITRE technique, if any.
fn lolbin_for_technique(mitre_id: &str) -> Option<String> {
    match mitre_id {
        "T1059.001" => Some("powershell.exe".to_string()),
        "T1059.003" => Some("cmd.exe".to_string()),
        "T1218.010" => Some("regsvr32.exe".to_string()),
        "T1218.011" => Some("rundll32.exe".to_string()),
        "T1218.005" => Some("mshta.exe".to_string()),
        "T1053.005" => Some("schtasks.exe".to_string()),
        "T1047" => Some("wmic.exe".to_string()),
        "T1548.002" => Some("eventvwr.exe".to_string()),
        _ => None,
    }
}
