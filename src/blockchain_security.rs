//! Blockchain and smart contract security analysis framework.

pub mod bridge;
pub mod consensus;
pub mod contract_analysis;
pub mod defi;
pub mod mev_protection;
pub mod token_security;
pub mod wallet;
pub mod zk;

use contract_analysis::{AnalysisResult, Chain, ContractAnalyzer};

pub use mev_protection::{MevAnalysisResult, MevAnalyzer};
pub use token_security::{TokenAuditResult, TokenSecurityAnalyzer};

/// Top-level engine that dispatches contract analysis across all supported chains.
#[derive(Debug, Clone)]
pub struct BlockchainSecurityEngine {
    pub default_chain: Chain,
}

impl BlockchainSecurityEngine {
    pub fn new(default_chain: Chain) -> Self {
        Self { default_chain }
    }

    /// Analyse a contract source using the engine's default chain.
    pub fn analyze(&self, source: &str) -> anyhow::Result<AnalysisResult> {
        ContractAnalyzer::new(self.default_chain.clone()).analyze(source)
    }

    /// Analyse a contract source targeting an explicit chain.
    pub fn analyze_for_chain(&self, source: &str, chain: Chain) -> anyhow::Result<AnalysisResult> {
        ContractAnalyzer::new(chain).analyze(source)
    }
}
