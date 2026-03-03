//! Blockchain and smart contract security analysis framework.

pub mod bridge;
pub mod consensus;
pub mod contract_analysis;
pub mod defi;
pub mod formal_verification;
pub mod invariant_testing;
pub mod mev_protection;
pub mod token_analysis;
pub mod token_security;
pub mod wallet;
pub mod zk;

use contract_analysis::{AnalysisResult, Chain, ContractAnalyzer};

pub use formal_verification::{VerificationConfig, VerificationResult, verify_contract_properties};
pub use invariant_testing::{FuzzCampaignResult, InvariantTestConfig, run_invariant_campaign};
pub use mev_protection::{MevAnalysisResult, MevAnalyzer};
pub use token_analysis::{TokenAnalysisResult, analyze_token_contract};
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

    /// Run formal verification on a contract.
    pub fn verify(
        &self,
        config: &formal_verification::VerificationConfig,
    ) -> formal_verification::VerificationResult {
        formal_verification::verify_contract_properties(config)
    }

    /// Run an invariant fuzzing campaign.
    pub fn fuzz_invariants(
        &self,
        config: &invariant_testing::InvariantTestConfig,
    ) -> invariant_testing::FuzzCampaignResult {
        invariant_testing::run_invariant_campaign(config)
    }

    /// Run deep token security analysis.
    pub fn analyze_token(&self, source: &str, name: &str) -> token_analysis::TokenAnalysisResult {
        token_analysis::analyze_token_contract(source, name)
    }

    /// Analyse MEV exposure.
    pub fn analyze_mev(&self, source: &str, name: &str) -> mev_protection::MevAnalysisResult {
        mev_protection::MevAnalyzer::analyze(source, name)
    }
}
