//! Supply chain attack simulation for authorized red team engagements.

use serde::{Deserialize, Serialize};

/// Classification of supply chain attack vectors.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SupplyChainVector {
    /// Compromise a third-party software dependency.
    DependencyConfusion,
    /// Typosquatting attack on a popular package.
    Typosquatting,
    /// Malicious code injected into an open-source repository.
    RepositoryCompromise,
    /// Compromise of a CI/CD pipeline.
    CiCdPipelineAttack,
    /// Tampered hardware or firmware in the supply chain.
    HardwareTampering,
    /// Software vendor compromise (similar to SolarWinds).
    VendorCompromise,
    /// Malicious update delivered through a legitimate update mechanism.
    MaliciousUpdate,
}

impl SupplyChainVector {
    pub fn label(&self) -> &'static str {
        match self {
            Self::DependencyConfusion => "Dependency Confusion",
            Self::Typosquatting => "Typosquatting",
            Self::RepositoryCompromise => "Repository Compromise",
            Self::CiCdPipelineAttack => "CI/CD Pipeline Attack",
            Self::HardwareTampering => "Hardware Tampering",
            Self::VendorCompromise => "Vendor Compromise",
            Self::MaliciousUpdate => "Malicious Update",
        }
    }

    /// ATT&CK technique ID most closely mapping to this vector.
    pub fn mitre_id(&self) -> &'static str {
        match self {
            Self::DependencyConfusion => "T1195.001",
            Self::Typosquatting => "T1195.001",
            Self::RepositoryCompromise => "T1195.002",
            Self::CiCdPipelineAttack => "T1195.002",
            Self::HardwareTampering => "T1195.003",
            Self::VendorCompromise => "T1195.002",
            Self::MaliciousUpdate => "T1195.002",
        }
    }
}

/// A dependency or vendor target in the supply chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyTarget {
    pub name: String,
    pub version: String,
    pub ecosystem: String,
    pub is_internal: bool,
    pub download_count: Option<u64>,
    pub maintainer_count: u32,
    pub risk_score: u8,
}

/// Configuration for a supply chain attack simulation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupplyChainConfig {
    /// Organization or target environment.
    pub target_org: String,
    /// Attack vectors to simulate.
    pub vectors: Vec<SupplyChainVector>,
    /// Maximum depth for dependency tree traversal.
    pub max_depth: u32,
    /// Authorized scope: package namespaces to test.
    pub scope_namespaces: Vec<String>,
}

impl Default for SupplyChainConfig {
    fn default() -> Self {
        Self {
            target_org: "undefined".to_string(),
            vectors: vec![
                SupplyChainVector::DependencyConfusion,
                SupplyChainVector::Typosquatting,
            ],
            max_depth: 3,
            scope_namespaces: Vec::new(),
        }
    }
}

/// Aggregated result of a supply chain attack simulation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupplyChainResult {
    pub target_org: String,
    pub dependencies_enumerated: Vec<DependencyTarget>,
    pub attack_simulations: Vec<AttackSimulation>,
    pub overall_risk_score: u8,
    pub high_value_targets: Vec<String>,
    pub recommendations: Vec<String>,
    pub report: String,
}

/// Result of simulating a single supply chain attack.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackSimulation {
    pub vector: SupplyChainVector,
    pub target_package: String,
    pub success_probability: f64,
    pub blast_radius: String,
    pub detection_difficulty: String,
    pub notes: String,
}

/// Enumerate the supply chain of the target organization.
pub fn enumerate_supply_chain(config: &SupplyChainConfig) -> Vec<DependencyTarget> {
    // Simulated dependency enumeration for the target org.
    let mut dependencies = vec![
        DependencyTarget {
            name: "lodash".to_string(),
            version: "4.17.21".to_string(),
            ecosystem: "npm".to_string(),
            is_internal: false,
            download_count: Some(50_000_000),
            maintainer_count: 3,
            risk_score: 30,
        },
        DependencyTarget {
            name: "requests".to_string(),
            version: "2.28.0".to_string(),
            ecosystem: "pip".to_string(),
            is_internal: false,
            download_count: Some(30_000_000),
            maintainer_count: 5,
            risk_score: 25,
        },
        DependencyTarget {
            name: format!(
                "{}-internal-utils",
                config.target_org.to_lowercase().replace(' ', "-")
            ),
            version: "1.0.0".to_string(),
            ecosystem: "npm".to_string(),
            is_internal: true,
            download_count: None,
            maintainer_count: 2,
            risk_score: 70,
        },
    ];

    // Add scoped packages if configured.
    for ns in &config.scope_namespaces {
        dependencies.push(DependencyTarget {
            name: format!("@{ns}/core"),
            version: "2.1.0".to_string(),
            ecosystem: "npm".to_string(),
            is_internal: true,
            download_count: None,
            maintainer_count: 1,
            risk_score: 80,
        });
    }

    dependencies
}

/// Simulate a supply chain attack against specified dependencies.
pub fn simulate_dependency_attack(
    config: &SupplyChainConfig,
    dependencies: &[DependencyTarget],
) -> SupplyChainResult {
    let mut simulations = Vec::new();

    for vector in &config.vectors {
        for dep in dependencies {
            let simulation = simulate_vector(vector, dep);
            simulations.push(simulation);
        }
    }

    let high_value: Vec<String> = dependencies
        .iter()
        .filter(|d| d.risk_score >= 60)
        .map(|d| d.name.clone())
        .collect();

    let overall_risk = calculate_overall_risk(dependencies, &simulations);
    let recommendations = generate_recommendations(config, &simulations);
    let report = build_report(
        config,
        dependencies,
        &simulations,
        overall_risk,
        &high_value,
    );

    SupplyChainResult {
        target_org: config.target_org.clone(),
        dependencies_enumerated: dependencies.to_vec(),
        attack_simulations: simulations,
        overall_risk_score: overall_risk,
        high_value_targets: high_value,
        recommendations,
        report,
    }
}

/// Assess the overall supply chain risk for an organization.
pub fn assess_supply_chain_risk(config: &SupplyChainConfig) -> SupplyChainResult {
    let deps = enumerate_supply_chain(config);
    simulate_dependency_attack(config, &deps)
}

// — Internal helpers —

fn simulate_vector(vector: &SupplyChainVector, dep: &DependencyTarget) -> AttackSimulation {
    let (success_prob, blast_radius, difficulty, notes) = match vector {
        SupplyChainVector::DependencyConfusion => {
            if dep.is_internal {
                (
                    0.7,
                    "High — internal package used across many services".to_string(),
                    "Low".to_string(),
                    format!(
                        "Internal package '{}' could be confused with a public package of the same name.",
                        dep.name
                    ),
                )
            } else {
                (
                    0.1,
                    "Low".to_string(),
                    "High".to_string(),
                    "Public package; confusion attack unlikely.".to_string(),
                )
            }
        }
        SupplyChainVector::Typosquatting => {
            let typo = generate_typo(&dep.name);
            (
                0.3,
                "Medium".to_string(),
                "Medium".to_string(),
                format!(
                    "Typo variant '{}' of '{}' could be registered.",
                    typo, dep.name
                ),
            )
        }
        SupplyChainVector::CiCdPipelineAttack => (
            0.5,
            "Critical — CI/CD compromise affects all produced artifacts".to_string(),
            "Medium".to_string(),
            "Malicious build script injection possible if pipeline lacks integrity checks."
                .to_string(),
        ),
        SupplyChainVector::RepositoryCompromise => (
            0.4,
            "High".to_string(),
            "High".to_string(),
            format!(
                "If '{}' maintainer accounts are compromised, all consumers are affected.",
                dep.name
            ),
        ),
        SupplyChainVector::MaliciousUpdate => (
            0.35,
            "High".to_string(),
            "Medium".to_string(),
            "Automatic update mechanisms without integrity verification are vulnerable."
                .to_string(),
        ),
        SupplyChainVector::VendorCompromise => (
            0.25,
            "Critical".to_string(),
            "Very High".to_string(),
            "Full vendor build infrastructure compromise needed (SolarWinds-style).".to_string(),
        ),
        SupplyChainVector::HardwareTampering => (
            0.1,
            "Critical".to_string(),
            "Very High".to_string(),
            "Requires physical access to supply chain; very difficult to simulate in software."
                .to_string(),
        ),
    };

    AttackSimulation {
        vector: vector.clone(),
        target_package: dep.name.clone(),
        success_probability: success_prob,
        blast_radius,
        detection_difficulty: difficulty,
        notes,
    }
}

fn generate_typo(name: &str) -> String {
    if name.len() > 3 {
        let mut chars: Vec<char> = name.chars().collect();
        chars.swap(1, 2);
        chars.iter().collect()
    } else {
        format!("{name}s")
    }
}

fn calculate_overall_risk(deps: &[DependencyTarget], sims: &[AttackSimulation]) -> u8 {
    if deps.is_empty() {
        return 0;
    }
    let dep_risk: f64 = deps.iter().map(|d| d.risk_score as f64).sum::<f64>() / deps.len() as f64;
    let sim_risk: f64 = if sims.is_empty() {
        0.0
    } else {
        sims.iter()
            .map(|s| s.success_probability * 100.0)
            .sum::<f64>()
            / sims.len() as f64
    };
    ((dep_risk * 0.6 + sim_risk * 0.4) as u8).min(100)
}

fn generate_recommendations(_config: &SupplyChainConfig, sims: &[AttackSimulation]) -> Vec<String> {
    let mut recs = Vec::new();
    let high_risk: Vec<&AttackSimulation> = sims
        .iter()
        .filter(|s| s.success_probability >= 0.5)
        .collect();

    if !high_risk.is_empty() {
        recs.push(format!(
            "{} high-probability attack vector(s) identified. Prioritize package namespace reservation and lock files.",
            high_risk.len()
        ));
    }
    recs.push("Implement SLSA supply chain security framework".to_string());
    recs.push("Pin all dependencies to exact versions with integrity hashes".to_string());
    recs.push("Monitor for package namespace squatting on public registries".to_string());
    recs.push("Enforce signed commits and verified releases in CI/CD".to_string());
    recs
}

fn build_report(
    config: &SupplyChainConfig,
    deps: &[DependencyTarget],
    sims: &[AttackSimulation],
    overall_risk: u8,
    high_value: &[String],
) -> String {
    let mut report = format!(
        "Supply Chain Risk Report — {}\n\
         ===========================================\n\
         Overall Risk Score: {}/100\n\
         Dependencies Analysed: {}\n\
         Attack Simulations Run: {}\n\
         High-Value Targets: {}\n\n",
        config.target_org,
        overall_risk,
        deps.len(),
        sims.len(),
        high_value.join(", ")
    );

    for sim in sims {
        report.push_str(&format!(
            "[{:.0}% success] {} → {}\n  Blast radius: {}\n  Detection difficulty: {}\n  {}\n\n",
            sim.success_probability * 100.0,
            sim.vector.label(),
            sim.target_package,
            sim.blast_radius,
            sim.detection_difficulty,
            sim.notes,
        ));
    }
    report
}
