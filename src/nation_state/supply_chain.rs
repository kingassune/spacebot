//! Supply chain attack simulation for nation-state operations.

/// Attack vector used in a supply chain compromise.
#[derive(Debug, Clone, PartialEq)]
pub enum SupplyChainVector {
    /// Compromise the build system to inject malicious code.
    BuildSystemCompromise,
    /// Exploit dependency confusion in package registries.
    DependencyConfusion,
    /// Register typo-squatted package names.
    TypoSquatting,
    /// Compromise a trusted package maintainer's account.
    MaintainerCompromise,
    /// Hijack the software update mechanism.
    UpdateHijacking,
    /// Compromise the code-signing certificate or process.
    CodeSigningCompromise,
    /// Poison a package mirror or distribution point.
    MirrorPoisoning,
    /// Compromise the CI/CD pipeline directly.
    CICompromise,
}

/// How difficult the attack is to detect by defenders.
#[derive(Debug, Clone, PartialEq)]
pub enum DetectionDifficulty {
    /// Easily detected by standard controls.
    Low,
    /// Requires specific monitoring to detect.
    Medium,
    /// Evades most standard controls.
    High,
    /// Extremely difficult to detect even with advanced monitoring.
    Critical,
}

/// A weak link in the dependency or supply chain graph.
#[derive(Debug, Clone)]
pub struct WeakLink {
    /// Name or identifier of the component.
    pub component: String,
    /// Reason this component is considered a weak link.
    pub reason: String,
    /// Estimated exploitation difficulty (0.0 = trivial, 1.0 = very hard).
    pub exploitation_difficulty: f64,
}

/// Result of a supply chain attack simulation.
#[derive(Debug, Clone)]
pub struct SupplyChainSimResult {
    /// Whether the simulated attack succeeded.
    pub success: bool,
    /// Number of downstream components affected.
    pub affected_components: usize,
    /// Estimated time to detection in hours.
    pub time_to_detection_hours: f64,
    /// Summary narrative of the simulation.
    pub narrative: String,
}

/// Supply chain attack simulation configuration and results.
#[derive(Debug, Clone)]
pub struct SupplyChainAttack {
    /// Name of the target software or ecosystem.
    pub target_software: String,
    /// Attack vector chosen for this simulation.
    pub attack_vector: SupplyChainVector,
    /// Depth of compromise in the dependency tree (1 = direct).
    pub compromise_depth: u32,
    /// Estimated detection difficulty.
    pub detection_difficulty: DetectionDifficulty,
}

impl SupplyChainAttack {
    /// Create a new supply chain attack scenario.
    pub fn new(
        target_software: impl Into<String>,
        attack_vector: SupplyChainVector,
        compromise_depth: u32,
    ) -> Self {
        let detection_difficulty = estimate_detection_difficulty(&attack_vector, compromise_depth);
        Self {
            target_software: target_software.into(),
            attack_vector,
            compromise_depth,
            detection_difficulty,
        }
    }

    /// Simulate the supply chain attack and return results.
    pub fn simulate_supply_chain_attack(&self) -> SupplyChainSimResult {
        let success = self.compromise_depth >= 1;
        let affected_components = self.compromise_depth as usize * 15;
        let time_to_detection_hours = detection_time_hours(&self.detection_difficulty);

        let narrative = format!(
            "Simulated {:?} against '{}' at depth {}. {} downstream components potentially affected. \
             Estimated time to detection: {:.1}h.",
            self.attack_vector,
            self.target_software,
            self.compromise_depth,
            affected_components,
            time_to_detection_hours
        );

        SupplyChainSimResult {
            success,
            affected_components,
            time_to_detection_hours,
            narrative,
        }
    }

    /// Analyse the dependency tree and return a list of potentially compromisable paths.
    pub fn analyze_dependency_tree(&self) -> Vec<String> {
        (1..=self.compromise_depth)
            .map(|depth| {
                format!(
                    "Depth {depth}: {} → transitive dependency ({})",
                    self.target_software,
                    match depth {
                        1 => "direct dependency",
                        2 => "first-order transitive",
                        _ => "deep transitive",
                    }
                )
            })
            .collect()
    }

    /// Identify weak links in the supply chain for this target.
    pub fn identify_weak_links(&self) -> Vec<WeakLink> {
        let mut weak_links = Vec::new();

        if matches!(
            self.attack_vector,
            SupplyChainVector::MaintainerCompromise | SupplyChainVector::DependencyConfusion
        ) {
            weak_links.push(WeakLink {
                component: format!("{}-core", self.target_software),
                reason: "Single maintainer with no 2FA enforcement.".to_string(),
                exploitation_difficulty: 0.3,
            });
        }

        if matches!(
            self.attack_vector,
            SupplyChainVector::BuildSystemCompromise | SupplyChainVector::CICompromise
        ) {
            weak_links.push(WeakLink {
                component: format!("{}/ci-pipeline", self.target_software),
                reason: "CI pipeline executes untrusted PRs with write access to artifacts."
                    .to_string(),
                exploitation_difficulty: 0.5,
            });
        }

        if self.compromise_depth >= 2 {
            weak_links.push(WeakLink {
                component: "shared-utils".to_string(),
                reason: "Widely-used transitive dependency with high downstream blast radius."
                    .to_string(),
                exploitation_difficulty: 0.6,
            });
        }

        weak_links
    }

    /// Generate a supply chain attack report.
    pub fn generate_supply_chain_report(&self) -> String {
        let sim_result = self.simulate_supply_chain_attack();
        let weak_links = self.identify_weak_links();

        let weak_link_text: Vec<String> = weak_links
            .iter()
            .map(|wl| {
                format!(
                    "  - {} (difficulty {:.1}): {}",
                    wl.component, wl.exploitation_difficulty, wl.reason
                )
            })
            .collect();

        format!(
            "=== Supply Chain Attack Report ===\n\
             Target:      {}\n\
             Vector:      {:?}\n\
             Depth:       {}\n\
             Detection:   {:?}\n\n\
             Simulation Result:\n  {}\n\n\
             Weak Links Identified:\n{}",
            self.target_software,
            self.attack_vector,
            self.compromise_depth,
            self.detection_difficulty,
            sim_result.narrative,
            if weak_link_text.is_empty() {
                "  None identified at this depth.".to_string()
            } else {
                weak_link_text.join("\n")
            }
        )
    }
}

/// Estimate detection difficulty based on vector and depth.
fn estimate_detection_difficulty(vector: &SupplyChainVector, depth: u32) -> DetectionDifficulty {
    let base = match vector {
        SupplyChainVector::TypoSquatting => DetectionDifficulty::Low,
        SupplyChainVector::DependencyConfusion => DetectionDifficulty::Medium,
        SupplyChainVector::MaintainerCompromise => DetectionDifficulty::High,
        SupplyChainVector::BuildSystemCompromise => DetectionDifficulty::High,
        SupplyChainVector::CICompromise => DetectionDifficulty::High,
        SupplyChainVector::UpdateHijacking => DetectionDifficulty::Critical,
        SupplyChainVector::CodeSigningCompromise => DetectionDifficulty::Critical,
        SupplyChainVector::MirrorPoisoning => DetectionDifficulty::Critical,
    };

    if depth >= 3 {
        DetectionDifficulty::Critical
    } else {
        base
    }
}

/// Return the estimated hours to detection for a given difficulty.
fn detection_time_hours(difficulty: &DetectionDifficulty) -> f64 {
    match difficulty {
        DetectionDifficulty::Low => 2.0,
        DetectionDifficulty::Medium => 24.0,
        DetectionDifficulty::High => 168.0,
        DetectionDifficulty::Critical => 2160.0,
    }
}
