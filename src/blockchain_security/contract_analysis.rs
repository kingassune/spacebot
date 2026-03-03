//! Smart contract vulnerability analysis and audit framework.

use std::collections::HashMap;

/// Supported contract languages.
#[derive(Debug, Clone, PartialEq)]
pub enum ContractLanguage {
    Solidity,
    Vyper,
    Rust,
    Move,
    Unknown,
}

/// Slither static analyzer integration.
#[derive(Debug, Clone)]
pub struct SlitherIntegration {
    pub slither_path: String,
    pub extra_args: Vec<String>,
}

impl SlitherIntegration {
    pub fn new(slither_path: impl Into<String>) -> Self {
        Self {
            slither_path: slither_path.into(),
            extra_args: Vec::new(),
        }
    }

    /// Parse Slither's JSON output into a list of finding descriptions.
    pub fn parse_json_output(json: &str) -> anyhow::Result<Vec<String>> {
        let value: serde_json::Value = serde_json::from_str(json)?;
        let results = value
            .get("results")
            .and_then(|r| r.get("detectors"))
            .and_then(|d| d.as_array())
            .cloned()
            .unwrap_or_default();

        let findings = results
            .iter()
            .filter_map(|d| {
                let check = d.get("check")?.as_str()?;
                let impact = d.get("impact")?.as_str().unwrap_or("Unknown");
                Some(format!("[{impact}] {check}"))
            })
            .collect();
        Ok(findings)
    }
}

/// Configuration for Echidna property-based fuzzing.
#[derive(Debug, Clone)]
pub struct EchidnaFuzzConfig {
    pub test_limit: u64,
    pub corpus_dir: Option<String>,
    pub contract_addr: Option<String>,
    pub properties: Vec<String>,
    pub extra_args: HashMap<String, String>,
}

impl EchidnaFuzzConfig {
    pub fn new(test_limit: u64) -> Self {
        Self {
            test_limit,
            corpus_dir: None,
            contract_addr: None,
            properties: Vec::new(),
            extra_args: HashMap::new(),
        }
    }

    /// Render config as YAML for an echidna-test run.
    pub fn to_yaml(&self) -> String {
        let mut lines = vec![format!("testLimit: {}", self.test_limit)];
        if let Some(dir) = &self.corpus_dir {
            lines.push(format!("corpusDir: \"{dir}\""));
        }
        if !self.properties.is_empty() {
            lines.push("testMode: \"property\"".to_string());
        }
        lines.join("\n")
    }
}

/// Detect the source language based on common syntax markers.
pub fn detect_language(source: &str) -> ContractLanguage {
    if source.contains("@version")
        || source.contains("def ") && source.contains(":") && !source.contains("function ")
    {
        ContractLanguage::Vyper
    } else if source.contains("pragma solidity") || source.contains("contract ") {
        ContractLanguage::Solidity
    } else if source.contains("pub fn") && source.contains("use anchor")
        || source.contains("use solana_program")
    {
        ContractLanguage::Rust
    } else if source.contains("module ") && source.contains("public fun") {
        ContractLanguage::Move
    } else {
        ContractLanguage::Unknown
    }
}

/// Analyze Vyper contract source for common vulnerability patterns.
pub fn analyze_vyper(source: &str) -> anyhow::Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let mut id_counter: u32 = 1;

    // Vyper reentrancy: missing @nonreentrant decorator
    if (source.contains("raw_call(") || source.contains("send("))
        && !source.contains("@nonreentrant")
    {
        findings.push(Finding {
            id: format!("VY-{id_counter:03}"),
            pattern: VulnerabilityPattern::Reentrancy,
            severity: SeverityLevel::Critical,
            line_number: line_of(source, "raw_call(").or_else(|| line_of(source, "send(")),
            description: "External call without @nonreentrant guard; reentrancy risk.".into(),
            recommendation: "Add @nonreentrant('lock') decorator to functions with external calls."
                .into(),
            code_snippet: snippet(source, "raw_call("),
        });
        id_counter += 1;
    }

    // Vyper storage collision in proxy patterns
    if source.contains("delegatecall") || source.contains("create_forwarder_to") {
        findings.push(Finding {
            id: format!("VY-{id_counter:03}"),
            pattern: VulnerabilityPattern::StorageCollision,
            severity: SeverityLevel::High,
            line_number: line_of(source, "delegatecall"),
            description: "Proxy/forwarder pattern may cause storage slot collisions.".into(),
            recommendation: "Verify storage layouts match across proxy and implementation.".into(),
            code_snippet: None,
        });
        id_counter += 1;
    }

    // Cross-function reentrancy: state read before external call in a Vyper @view
    if source.contains("@view") && source.contains("raw_call(") {
        findings.push(Finding {
            id: format!("VY-{id_counter:03}"),
            pattern: VulnerabilityPattern::Reentrancy,
            severity: SeverityLevel::Medium,
            line_number: None,
            description:
                "View function performs external call; cross-function reentrancy possible.".into(),
            recommendation: "Remove external calls from @view functions.".into(),
            code_snippet: None,
        });
        id_counter += 1;
    }

    // ABI encoding edge case: packed encoding with dynamic types
    if source.contains("abi_encode(") && source.contains("Bytes[") {
        findings.push(Finding {
            id: format!("VY-{id_counter:03}"),
            pattern: VulnerabilityPattern::TypeConfusion,
            severity: SeverityLevel::Medium,
            line_number: line_of(source, "abi_encode("),
            description: "abi_encode with dynamic Bytes type; verify hash collision resistance."
                .into(),
            recommendation: "Use abi_encode_packed carefully; prefer keccak256 over packed encoding for signatures.".into(),
            code_snippet: snippet(source, "abi_encode("),
        });
    }

    Ok(findings)
}
#[derive(Debug, Clone, PartialEq)]
pub enum Chain {
    Ethereum,
    Solana,
    Cosmos,
    Ton,
    Substrate,
    Algorand,
    StarkNet,
    Aptos,
    Sui,
    Near,
    Polkadot,
    Avalanche,
}

/// Severity classification for audit findings.
#[derive(Debug, Clone, PartialEq)]
pub enum SeverityLevel {
    Critical,
    High,
    Medium,
    Low,
    Informational,
    Gas,
}

/// Known smart contract vulnerability patterns.
#[derive(Debug, Clone, PartialEq)]
pub enum VulnerabilityPattern {
    Reentrancy,
    IntegerOverflow,
    IntegerUnderflow,
    AccessControl,
    UncheckedReturn,
    DelegatecallInjection,
    TxOrigin,
    TimestampDependence,
    Frontrunning,
    FlashLoanAttack,
    PriceOracleManipulation,
    StorageCollision,
    UninitializedProxy,
    SelfDestruct,
    DenialOfService,
    InsufficientGasGriefing,
    SignatureReplay,
    CrossChainReplay,
    ArithmeticOverflow,
    UnprotectedSelfDestruct,
    IncorrectInheritanceOrder,
    WeakRandomness,
    UncheckedCallReturn,
    PrivilegeEscalation,
    MissingEventLogging,
    GasLimitDoS,
    TypeConfusion,
    Underflow,
    BackdoorFunction,
    HiddenOwner,
}

/// A single audit finding produced by contract analysis.
#[derive(Debug, Clone)]
pub struct Finding {
    pub id: String,
    pub pattern: VulnerabilityPattern,
    pub severity: SeverityLevel,
    pub line_number: Option<u32>,
    pub description: String,
    pub recommendation: String,
    pub code_snippet: Option<String>,
}

/// A gas optimisation opportunity identified during analysis.
#[derive(Debug, Clone)]
pub struct GasOptimization {
    pub description: String,
    pub estimated_gas_saved: u64,
    pub line_number: Option<u32>,
}

/// Aggregated result of analysing one contract.
#[derive(Debug, Clone)]
pub struct AnalysisResult {
    pub chain: Chain,
    pub findings: Vec<Finding>,
    pub gas_optimizations: Vec<GasOptimization>,
    pub code_quality_score: f64,
    pub critical_count: u32,
    pub high_count: u32,
}

impl AnalysisResult {
    pub fn new(chain: Chain) -> Self {
        Self {
            chain,
            findings: Vec::new(),
            gas_optimizations: Vec::new(),
            code_quality_score: 100.0,
            critical_count: 0,
            high_count: 0,
        }
    }

    pub fn add_finding(&mut self, finding: Finding) {
        match finding.severity {
            SeverityLevel::Critical => self.critical_count += 1,
            SeverityLevel::High => self.high_count += 1,
            _ => {}
        }
        self.findings.push(finding);
        self.code_quality_score = compute_quality_score(&self.findings);
    }

    pub fn summary(&self) -> String {
        format!(
            "Chain: {:?} | Findings: {} | Critical: {} | High: {} | Score: {:.1}",
            self.chain,
            self.findings.len(),
            self.critical_count,
            self.high_count,
            self.code_quality_score,
        )
    }
}

/// Configures and runs contract analysis for a specific chain.
#[derive(Debug, Clone)]
pub struct ContractAnalyzer {
    pub chain: Chain,
    pub patterns: Vec<VulnerabilityPattern>,
}

impl ContractAnalyzer {
    pub fn new(chain: Chain) -> Self {
        Self {
            chain,
            patterns: Vec::new(),
        }
    }

    pub fn with_patterns(mut self, patterns: Vec<VulnerabilityPattern>) -> Self {
        self.patterns = patterns;
        self
    }

    /// Analyze a contract source file, dispatching to the language-specific analyzer.
    pub fn analyze(&self, source: &str) -> anyhow::Result<AnalysisResult> {
        let mut result = AnalysisResult::new(self.chain.clone());

        let findings = match self.chain {
            Chain::Solana => analyze_rust_contract(source)?,
            Chain::Aptos | Chain::Sui => analyze_move_contract(source)?,
            _ => {
                let lang = detect_language(source);
                if lang == ContractLanguage::Vyper {
                    analyze_vyper(source)?
                } else {
                    analyze_solidity(source)?
                }
            }
        };

        for finding in findings {
            result.add_finding(finding);
        }

        Ok(result)
    }
}

/// Analyze Solidity source for common vulnerability patterns.
pub fn analyze_solidity(source: &str) -> anyhow::Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let mut id_counter: u32 = 1;

    // tx.origin authentication bypass
    if source.contains("tx.origin") {
        findings.push(Finding {
            id: format!("SOL-{id_counter:03}"),
            pattern: VulnerabilityPattern::TxOrigin,
            severity: SeverityLevel::High,
            line_number: line_of(source, "tx.origin"),
            description:
                "Use of tx.origin for authentication can be exploited via phishing contracts."
                    .into(),
            recommendation: "Replace tx.origin with msg.sender for authentication checks.".into(),
            code_snippet: snippet(source, "tx.origin"),
        });
        id_counter += 1;
    }

    // selfdestruct / suicide
    if source.contains("selfdestruct") || source.contains("suicide(") {
        let keyword = if source.contains("selfdestruct") {
            "selfdestruct"
        } else {
            "suicide("
        };
        findings.push(Finding {
            id: format!("SOL-{id_counter:03}"),
            pattern: VulnerabilityPattern::SelfDestruct,
            severity: SeverityLevel::Critical,
            line_number: line_of(source, keyword),
            description: "Unprotected selfdestruct can destroy the contract and drain Ether."
                .into(),
            recommendation: "Gate selfdestruct behind strict access control or remove it entirely."
                .into(),
            code_snippet: snippet(source, keyword),
        });
        id_counter += 1;
    }

    // block.timestamp
    if source.contains("block.timestamp") {
        findings.push(Finding {
            id: format!("SOL-{id_counter:03}"),
            pattern: VulnerabilityPattern::TimestampDependence,
            severity: SeverityLevel::Medium,
            line_number: line_of(source, "block.timestamp"),
            description: "block.timestamp can be manipulated by miners within ~15 seconds.".into(),
            recommendation: "Use block.number or a commit-reveal scheme for time-sensitive logic."
                .into(),
            code_snippet: snippet(source, "block.timestamp"),
        });
        id_counter += 1;
    }

    // .call{value without return check
    if source.contains(".call{value") {
        let has_require = source.contains("require(") || source.contains("if (!");
        if !has_require {
            findings.push(Finding {
                id: format!("SOL-{id_counter:03}"),
                pattern: VulnerabilityPattern::UncheckedCallReturn,
                severity: SeverityLevel::High,
                line_number: line_of(source, ".call{value"),
                description:
                    "Low-level call return value is not checked; failed transfers go unnoticed."
                        .into(),
                recommendation:
                    "Check the bool return of .call or use Address.sendValue from OpenZeppelin."
                        .into(),
                code_snippet: snippet(source, ".call{value"),
            });
            id_counter += 1;
        }
    }

    // delegatecall
    if source.contains("delegatecall") {
        findings.push(Finding {
            id: format!("SOL-{id_counter:03}"),
            pattern: VulnerabilityPattern::DelegatecallInjection,
            severity: SeverityLevel::Critical,
            line_number: line_of(source, "delegatecall"),
            description: "delegatecall to user-supplied address allows arbitrary code execution in the caller's context.".into(),
            recommendation: "Validate and whitelist delegation targets; prefer a known, audited proxy pattern.".into(),
            code_snippet: snippet(source, "delegatecall"),
        });
        id_counter += 1;
    }

    // Reentrancy heuristic: external call before state update
    // Look for a .call pattern followed (anywhere later) by a storage assignment
    let has_external_call = source.contains(".call(") || source.contains(".call{value");
    let has_state_after = {
        let call_pos = source
            .find(".call(")
            .or_else(|| source.find(".call{value"))
            .unwrap_or(usize::MAX);
        let assign_pos = source[call_pos.min(source.len())..]
            .find(" = ")
            .map(|p| p + call_pos)
            .unwrap_or(usize::MAX);
        assign_pos < usize::MAX
    };
    if has_external_call && has_state_after {
        findings.push(Finding {
            id: format!("SOL-{id_counter:03}"),
            pattern: VulnerabilityPattern::Reentrancy,
            severity: SeverityLevel::Critical,
            line_number: None,
            description: "External call detected before state change; classic reentrancy risk."
                .into(),
            recommendation:
                "Apply the Checks-Effects-Interactions pattern and consider a ReentrancyGuard."
                    .into(),
            code_snippet: None,
        });
    }

    Ok(findings)
}

/// Analyze Rust-based contracts (Solana programs, CosmWasm).
pub fn analyze_rust_contract(source: &str) -> anyhow::Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let mut id_counter: u32 = 1;

    // unwrap() indicates missing error propagation
    if source.contains("unwrap()") {
        findings.push(Finding {
            id: format!("RUST-{id_counter:03}"),
            pattern: VulnerabilityPattern::UncheckedReturn,
            severity: SeverityLevel::Medium,
            line_number: line_of(source, "unwrap()"),
            description:
                "unwrap() will panic on error, causing a transaction abort and potential DoS."
                    .into(),
            recommendation: "Replace unwrap() with proper error propagation using ? or match."
                .into(),
            code_snippet: snippet(source, "unwrap()"),
        });
        id_counter += 1;
    }

    // Missing access control: no authority/owner check visible
    let has_auth = source.contains("#[access_control")
        || source.contains("ctx.accounts.authority")
        || source.contains("require_keys_eq!")
        || source.contains("has_one =")
        || source.contains("constraint =");
    if !has_auth && (source.contains("pub fn") && source.contains("Context<")) {
        findings.push(Finding {
            id: format!("RUST-{id_counter:03}"),
            pattern: VulnerabilityPattern::AccessControl,
            severity: SeverityLevel::High,
            line_number: None,
            description:
                "No authority or access-control constraint detected in instruction handler.".into(),
            recommendation:
                "Add Anchor constraints (has_one, constraint) or explicit signer checks.".into(),
            code_snippet: None,
        });
    }

    Ok(findings)
}

/// Analyze Move-based contracts (Aptos, Sui).
pub fn analyze_move_contract(source: &str) -> anyhow::Result<Vec<Finding>> {
    let mut findings = Vec::new();

    // Missing admin abort guard
    let has_admin_check = source.contains("abort_if_not_admin")
        || source.contains("assert!(signer::address_of")
        || source.contains("assert!(caller ==")
        || source.contains("only_owner");
    if !has_admin_check && source.contains("public fun") {
        findings.push(Finding {
            id: "MOVE-001".into(),
            pattern: VulnerabilityPattern::AccessControl,
            severity: SeverityLevel::High,
            line_number: None,
            description: "Public function lacks admin/signer check; any account can call privileged logic.".into(),
            recommendation: "Add an abort_if_not_admin guard or assert!(signer::address_of(&account) == ADMIN_ADDR).".into(),
            code_snippet: None,
        });
    }

    Ok(findings)
}

/// Compute a code quality score from 100.0 by deducting points per finding severity.
pub fn compute_quality_score(findings: &[Finding]) -> f64 {
    let deduction: f64 = findings
        .iter()
        .map(|f| match f.severity {
            SeverityLevel::Critical => 20.0,
            SeverityLevel::High => 10.0,
            SeverityLevel::Medium => 5.0,
            SeverityLevel::Low => 2.0,
            SeverityLevel::Informational => 0.5,
            SeverityLevel::Gas => 0.0,
        })
        .sum();
    (100.0_f64 - deduction).max(0.0)
}

// ── helpers ──────────────────────────────────────────────────────────────────

fn line_of(source: &str, pattern: &str) -> Option<u32> {
    source.lines().enumerate().find_map(|(i, line)| {
        if line.contains(pattern) {
            Some(i as u32 + 1)
        } else {
            None
        }
    })
}

fn snippet(source: &str, pattern: &str) -> Option<String> {
    source
        .lines()
        .find(|l| l.contains(pattern))
        .map(|l| l.trim().to_string())
}
