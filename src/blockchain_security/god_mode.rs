//! GodMode unified blockchain security analysis orchestrator.
//!
//! Chains all blockchain security modules into a single comprehensive
//! audit pipeline for maximum coverage across smart contracts, DeFi
//! protocols, bridges, ZK circuits, wallets, and consensus mechanisms.

use crate::blockchain_security::{
    bridge::{self, BridgeType},
    consensus::{self, ConsensusType},
    contract_analysis::{Chain, ContractAnalyzer, SeverityLevel},
    defi,
    formal_verification::{self, PropertySpec, VerificationConfig},
    wallet::{self, WalletType},
    zk::{self, ZkCircuitInfo, ZkSystem},
};

/// Severity level of a god-mode audit finding.
#[derive(Debug, Clone, PartialEq)]
pub enum FindingSeverity {
    Critical,
    High,
    Medium,
    Low,
    Informational,
}

/// A single finding from the unified audit pipeline.
#[derive(Debug, Clone)]
pub struct AuditFinding {
    pub id: String,
    pub title: String,
    pub description: String,
    pub severity: FindingSeverity,
    pub module: String,
    pub recommendation: String,
}

/// The complete result of a full blockchain security audit.
#[derive(Debug, Clone)]
pub struct FullAuditResult {
    pub target: String,
    pub findings: Vec<AuditFinding>,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub info_count: usize,
    pub risk_score: f32,
    pub summary: String,
}

impl FullAuditResult {
    fn from_findings(target: String, findings: Vec<AuditFinding>) -> Self {
        let critical_count = findings
            .iter()
            .filter(|f| f.severity == FindingSeverity::Critical)
            .count();
        let high_count = findings
            .iter()
            .filter(|f| f.severity == FindingSeverity::High)
            .count();
        let medium_count = findings
            .iter()
            .filter(|f| f.severity == FindingSeverity::Medium)
            .count();
        let low_count = findings
            .iter()
            .filter(|f| f.severity == FindingSeverity::Low)
            .count();
        let info_count = findings
            .iter()
            .filter(|f| f.severity == FindingSeverity::Informational)
            .count();

        let risk_score = (critical_count as f32 * 10.0
            + high_count as f32 * 5.0
            + medium_count as f32 * 2.0
            + low_count as f32 * 0.5)
            .min(100.0);

        let summary = format!(
            "Full audit complete: {} critical, {} high, {} medium, {} low, {} informational. \
             Risk score: {:.1}/100.",
            critical_count, high_count, medium_count, low_count, info_count, risk_score
        );

        Self {
            target,
            findings,
            critical_count,
            high_count,
            medium_count,
            low_count,
            info_count,
            risk_score,
            summary,
        }
    }
}

/// Configuration for a god-mode full blockchain security audit.
#[derive(Debug, Clone)]
pub struct GodModeConfig {
    /// Contract source code (Solidity / Vyper / Move / Rust) to audit.
    pub contract_source: String,
    /// Blockchain network identifier (e.g., `"ethereum"`, `"solana"`).
    pub chain: String,
    /// Run formal verification alongside static analysis.
    pub enable_formal_verification: bool,
    /// Analyse DeFi integration risks (flash loans, oracles, MEV).
    pub enable_defi_analysis: bool,
    /// Analyse cross-chain bridge interactions.
    pub enable_bridge_analysis: bool,
    /// Audit ZK circuit constraints if applicable.
    pub enable_zk_audit: bool,
    /// Analyse wallet approval chains and key management.
    pub enable_wallet_analysis: bool,
    /// Model consensus-level attack vectors.
    pub enable_consensus_analysis: bool,
    /// Approximate number of validators for consensus analysis.
    pub validator_count: u32,
}

impl Default for GodModeConfig {
    fn default() -> Self {
        Self {
            contract_source: String::new(),
            chain: "ethereum".to_string(),
            enable_formal_verification: true,
            enable_defi_analysis: true,
            enable_bridge_analysis: true,
            enable_zk_audit: false,
            enable_wallet_analysis: true,
            enable_consensus_analysis: false,
            validator_count: 100,
        }
    }
}

/// GodModeAnalyzer — orchestrates all blockchain security analysis modules
/// into a single comprehensive audit pipeline.
///
/// Chains together `contract_analysis`, `defi`, `bridge`, `consensus`,
/// `wallet`, `zk`, and `formal_verification` to produce a single ranked
/// finding list with a unified risk score.
#[derive(Debug, Clone)]
pub struct GodModeAnalyzer {
    pub config: GodModeConfig,
}

impl GodModeAnalyzer {
    /// Create a new analyzer with the given configuration.
    pub fn new(config: GodModeConfig) -> Self {
        Self { config }
    }

    /// Create an analyzer with default settings targeting the given contract source.
    pub fn for_contract(contract_source: impl Into<String>, chain: impl Into<String>) -> Self {
        Self::new(GodModeConfig {
            contract_source: contract_source.into(),
            chain: chain.into(),
            ..Default::default()
        })
    }

    /// Run the complete blockchain security audit pipeline.
    ///
    /// Executes all enabled analysis modules in sequence and aggregates
    /// findings into a single [`FullAuditResult`] with a unified risk score.
    pub fn run_full_audit(&self) -> anyhow::Result<FullAuditResult> {
        let mut findings: Vec<AuditFinding> = Vec::new();

        // 1. Core smart contract vulnerability analysis.
        let chain = chain_from_str(&self.config.chain);
        let analyzer = ContractAnalyzer::new(chain);
        let contract_result = analyzer.analyze(&self.config.contract_source)?;
        findings.extend(contract_result.findings.into_iter().map(|f| AuditFinding {
            id: format!("CONTRACT-{}", f.id),
            title: format!("{:?}", f.pattern),
            description: f.description,
            severity: map_severity_level(&f.severity),
            module: "contract_analysis".to_string(),
            recommendation: f.recommendation,
        }));

        // 2. DeFi protocol risk assessment.
        if self.config.enable_defi_analysis {
            let flash_risks = defi::detect_flash_loan_vulnerability(&self.config.contract_source)?;
            for risk in flash_risks {
                findings.push(AuditFinding {
                    id: format!("DEFI-FLASH-{}", risk.contract_address),
                    title: "Flash Loan Vulnerability".to_string(),
                    description: format!("Flash loan attack path detected: {}", risk.attack_path),
                    severity: FindingSeverity::High,
                    module: "defi".to_string(),
                    recommendation: "Implement reentrancy guards and use commit-reveal or \
                                     check-effects-interactions patterns."
                        .to_string(),
                });
            }

            let oracle_risk = defi::analyze_oracle_dependency(&self.config.contract_source)?;
            if oracle_risk.manipulation_risk != "low" {
                findings.push(AuditFinding {
                    id: "DEFI-ORACLE-001".to_string(),
                    title: "Oracle Manipulation Risk".to_string(),
                    description: format!(
                        "Oracle type: {}. Manipulation risk: {}",
                        oracle_risk.oracle_type, oracle_risk.manipulation_risk
                    ),
                    severity: FindingSeverity::High,
                    module: "defi".to_string(),
                    recommendation: oracle_risk.recommended_mitigation,
                });
            }
        }

        // 3. Cross-chain bridge security.
        if self.config.enable_bridge_analysis {
            let bridge_result = bridge::analyze_bridge_contract(
                &self.config.contract_source,
                &BridgeType::MessagePassing,
            )?;
            for vuln in &bridge_result.vulnerabilities {
                findings.push(AuditFinding {
                    id: format!("BRIDGE-{:?}", vuln),
                    title: format!("Bridge Vulnerability: {:?}", vuln),
                    description: bridge_result.findings.first().cloned().unwrap_or_default(),
                    severity: FindingSeverity::High,
                    module: "bridge".to_string(),
                    recommendation: bridge_result
                        .recommendations
                        .first()
                        .cloned()
                        .unwrap_or_default(),
                });
            }
        }

        // 4. ZK circuit auditing (uses placeholder metadata when auditing source only).
        if self.config.enable_zk_audit {
            let circuit_info = ZkCircuitInfo {
                system: ZkSystem::Groth16,
                constraint_count: if self.config.contract_source.contains("constraint") {
                    1
                } else {
                    0
                },
                input_count: 1,
                output_count: 1,
                has_trusted_setup: self.config.contract_source.contains("setup"),
                setup_participants: 1,
            };
            let zk_result = zk::analyze_zk_circuit(&circuit_info);
            for finding in &zk_result.findings {
                findings.push(AuditFinding {
                    id: format!("ZK-{:?}", zk_result.system),
                    title: "ZK Circuit Security Issue".to_string(),
                    description: finding.clone(),
                    severity: FindingSeverity::High,
                    module: "zk".to_string(),
                    recommendation:
                        "Review circuit constraints and verify the trusted setup ceremony."
                            .to_string(),
                });
            }
        }

        // 5. Wallet and approval chain auditing.
        if self.config.enable_wallet_analysis {
            let wallet_report = wallet::audit_wallet(
                "0x0000000000000000000000000000000000000000",
                &WalletType::SmartWallet,
            );
            for vuln in &wallet_report.vulnerabilities {
                findings.push(AuditFinding {
                    id: format!("WALLET-{:?}", vuln),
                    title: format!("Wallet Vulnerability: {:?}", vuln),
                    description: format!("Wallet security issue: {:?}", vuln),
                    severity: FindingSeverity::Medium,
                    module: "wallet".to_string(),
                    recommendation: wallet_report
                        .recommendations
                        .first()
                        .cloned()
                        .unwrap_or_default(),
                });
            }
        }

        // 6. Consensus mechanism attack modelling.
        if self.config.enable_consensus_analysis {
            let consensus_analysis = consensus::analyze_consensus(
                &ConsensusType::ProofOfStake,
                self.config.validator_count,
            );
            for attack in &consensus_analysis.vulnerabilities {
                findings.push(AuditFinding {
                    id: format!("CONSENSUS-{:?}", attack),
                    title: format!("Consensus Attack Vector: {:?}", attack),
                    description: format!(
                        "Attack threshold: {:.1}%. Finality time: {}s.",
                        consensus_analysis.attack_threshold_percent,
                        consensus_analysis.finality_time_secs
                    ),
                    severity: FindingSeverity::High,
                    module: "consensus".to_string(),
                    recommendation: "Increase validator set diversity and stake distribution."
                        .to_string(),
                });
            }
        }

        // 7. Formal verification pass.
        if self.config.enable_formal_verification {
            let fv_config = VerificationConfig {
                source: self.config.contract_source.clone(),
                contract_name: "Contract".to_string(),
                properties: vec![
                    PropertySpec {
                        name: "no-reentrancy".to_string(),
                        predicate: "!reentrancy".to_string(),
                        invariant_type: formal_verification::InvariantType::StateInvariant,
                        is_safety: true,
                    },
                    PropertySpec {
                        name: "no-integer-overflow".to_string(),
                        predicate: "no_overflow".to_string(),
                        invariant_type: formal_verification::InvariantType::RangeInvariant,
                        is_safety: true,
                    },
                ],
                max_depth: 50,
                timeout_secs: 120,
            };
            let fv_result = formal_verification::verify_contract_properties(&fv_config);
            for outcome in &fv_result.violations {
                findings.push(AuditFinding {
                    id: format!("FV-{}", outcome.property.name),
                    title: format!("Formal Verification Failure: {}", outcome.property.name),
                    description: outcome.notes.clone(),
                    severity: FindingSeverity::Critical,
                    module: "formal_verification".to_string(),
                    recommendation: "Fix the property violation identified by formal verification."
                        .to_string(),
                });
            }
        }

        // Sort findings by severity (critical first).
        findings.sort_by_key(|f| severity_order(&f.severity));

        let target = self
            .config
            .contract_source
            .chars()
            .take(64)
            .collect::<String>();

        Ok(FullAuditResult::from_findings(target, findings))
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn severity_order(s: &FindingSeverity) -> u8 {
    match s {
        FindingSeverity::Critical => 0,
        FindingSeverity::High => 1,
        FindingSeverity::Medium => 2,
        FindingSeverity::Low => 3,
        FindingSeverity::Informational => 4,
    }
}

fn map_severity_level(s: &SeverityLevel) -> FindingSeverity {
    match s {
        SeverityLevel::Critical => FindingSeverity::Critical,
        SeverityLevel::High => FindingSeverity::High,
        SeverityLevel::Medium => FindingSeverity::Medium,
        SeverityLevel::Low => FindingSeverity::Low,
        SeverityLevel::Informational => FindingSeverity::Informational,
        // Gas-level findings are informational in the unified audit report.
        SeverityLevel::Gas => FindingSeverity::Informational,
    }
}

fn chain_from_str(s: &str) -> Chain {
    match s.to_lowercase().as_str() {
        "solana" => Chain::Solana,
        "cosmos" => Chain::Cosmos,
        "ton" => Chain::Ton,
        "substrate" | "polkadot" => Chain::Polkadot,
        "algorand" => Chain::Algorand,
        "starknet" => Chain::StarkNet,
        "aptos" => Chain::Aptos,
        "sui" => Chain::Sui,
        "near" => Chain::Near,
        "avalanche" => Chain::Avalanche,
        _ => Chain::Ethereum,
    }
}
