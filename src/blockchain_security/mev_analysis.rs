//! Maximal Extractable Value (MEV) attack analysis for DeFi protocols.

/// Type of MEV attack or extraction strategy.
#[derive(Debug, Clone, PartialEq)]
pub enum MevAttackType {
    /// Insert a transaction before a target to profit from price movement.
    Frontrunning,
    /// Insert a transaction immediately after a target to capitalise on state changes.
    Backrunning,
    /// Sandwich the target with both a front-run and back-run.
    SandwichAttack,
    /// Provide concentrated liquidity just before a large swap and withdraw after.
    JustInTimeLiquidity,
    /// Trigger liquidations in lending protocols to earn liquidation bonuses.
    Liquidation,
    /// Exploit price differences across DEXs.
    Arbitrage,
    /// Snipe NFT mints at floor price before public becomes aware.
    NFTSniping,
    /// Exploit governance vote timing for profitable outcomes.
    GovernanceExploit,
    /// Reorder transactions within a block for maximum extraction.
    TimebanditAttack,
    /// Exploit transactions in uncle blocks for additional MEV.
    UncleBlockBandit,
}

/// A transaction or call data subject to MEV analysis.
#[derive(Debug, Clone)]
pub struct MevTransaction {
    /// Transaction hash or identifier.
    pub tx_hash: String,
    /// Sender address.
    pub from: String,
    /// Target contract or recipient address.
    pub to: String,
    /// Human-readable description of the transaction.
    pub description: String,
    /// Gas price in Gwei.
    pub gas_price_gwei: f64,
    /// Transaction value in ETH.
    pub value_eth: f64,
}

/// Analysis result for MEV vulnerability in a transaction or protocol.
#[derive(Debug, Clone)]
pub struct MevAnalysis {
    /// Transaction under analysis.
    pub transaction: MevTransaction,
    /// Identified MEV attack type.
    pub attack_type: MevAttackType,
    /// Estimated profit in ETH for the MEV searcher.
    pub profit_estimate_eth: f64,
    /// Number of users/LPs potentially affected.
    pub affected_users: u64,
    /// Slippage impact in basis points.
    pub slippage_bps: u64,
    /// Recommended mitigations.
    pub recommendations: Vec<String>,
}

/// Searcher pattern identified in mempool data.
#[derive(Debug, Clone)]
pub struct SearcherPattern {
    /// Searcher address or bundle submitter.
    pub searcher_address: String,
    /// Primary MEV strategy employed.
    pub strategy: MevAttackType,
    /// Estimated historical success rate (0.0–1.0).
    pub success_rate: f64,
    /// Estimated average profit per extracted opportunity in ETH.
    pub avg_profit_eth: f64,
}

/// Analyser for MEV exposure in DeFi transactions and protocols.
#[derive(Debug, Clone)]
pub struct MevAnalyzer {
    /// Name of the protocol being analysed.
    pub protocol_name: String,
}

impl MevAnalyzer {
    /// Create a new MEV analyser for the given protocol.
    pub fn new(protocol_name: impl Into<String>) -> Self {
        Self {
            protocol_name: protocol_name.into(),
        }
    }

    /// Analyse a transaction for mempool-level MEV vulnerability.
    pub fn analyze_mempool_vulnerability(&self, tx: &MevTransaction) -> Vec<MevAttackType> {
        let mut vulnerabilities = Vec::new();

        if tx.value_eth > 1.0 {
            vulnerabilities.push(MevAttackType::Frontrunning);
            vulnerabilities.push(MevAttackType::SandwichAttack);
        }

        if tx.gas_price_gwei < 5.0 {
            vulnerabilities.push(MevAttackType::Backrunning);
        }

        if tx.description.to_lowercase().contains("swap") {
            vulnerabilities.push(MevAttackType::Arbitrage);
        }

        vulnerabilities
    }

    /// Simulate a sandwich attack on the given transaction.
    ///
    /// Returns the estimated profit in ETH for the sandwich attacker.
    pub fn simulate_sandwich_attack(&self, tx: &MevTransaction, slippage_tolerance_bps: u64) -> f64 {
        let affected_amount = tx.value_eth;
        let slippage_captured = (slippage_tolerance_bps as f64 / 10_000.0) * affected_amount;
        slippage_captured * 0.7
    }

    /// Calculate total MEV exposure for a set of transactions.
    pub fn calculate_mev_exposure(&self, transactions: &[MevTransaction]) -> f64 {
        transactions
            .iter()
            .map(|tx| tx.value_eth * 0.02)
            .sum()
    }

    /// Recommend protections to reduce MEV exposure.
    pub fn recommend_mev_protections(&self) -> Vec<String> {
        vec![
            "Use a private RPC endpoint (e.g. Flashbots Protect) to avoid public mempool exposure.".to_string(),
            "Set tight slippage tolerances (0.1%–0.5%) on swap transactions.".to_string(),
            "Implement commit-reveal schemes for sensitive on-chain actions.".to_string(),
            "Use batch auctions (e.g. CoW Protocol) to eliminate front-running.".to_string(),
            "Add minimum output amount checks to all DEX interactions.".to_string(),
        ]
    }

    /// Detect known MEV searcher patterns in a set of transactions.
    pub fn detect_searcher_patterns(&self, transactions: &[MevTransaction]) -> Vec<SearcherPattern> {
        let mut patterns = Vec::new();

        let mut by_sender: std::collections::HashMap<&str, Vec<&MevTransaction>> =
            std::collections::HashMap::new();
        for tx in transactions {
            by_sender.entry(&tx.from).or_default().push(tx);
        }

        for (address, txs) in by_sender {
            if txs.len() >= 2 {
                patterns.push(SearcherPattern {
                    searcher_address: address.to_string(),
                    strategy: MevAttackType::SandwichAttack,
                    success_rate: 0.65,
                    avg_profit_eth: txs.iter().map(|t| t.value_eth * 0.01).sum::<f64>()
                        / txs.len() as f64,
                });
            }
        }

        patterns
    }

    /// Generate a full MEV analysis report for a single transaction.
    pub fn generate_analysis(
        &self,
        tx: &MevTransaction,
        attack_type: MevAttackType,
        slippage_bps: u64,
    ) -> MevAnalysis {
        let profit_estimate = self.simulate_sandwich_attack(tx, slippage_bps);
        let recommendations = self.recommend_mev_protections();

        MevAnalysis {
            transaction: tx.clone(),
            attack_type,
            profit_estimate_eth: profit_estimate,
            affected_users: 1,
            slippage_bps,
            recommendations,
        }
    }
}
