//! MEV (Maximal Extractable Value) exposure analysis for DeFi protocols.

/// MEV attack vector classification.
#[derive(Debug, Clone, PartialEq)]
pub enum MevAttackVector {
    Sandwich,
    Frontrunning,
    Backrunning,
    TimeBandit,
    JitLiquidity,
    LiquidationMev,
}

/// A detected MEV exposure finding.
#[derive(Debug, Clone)]
pub struct MevFinding {
    pub vector: MevAttackVector,
    pub severity: String,
    pub description: String,
    pub estimated_loss_bps: u32,
    pub mitigation: String,
}

/// Aggregated MEV analysis result.
#[derive(Debug, Clone)]
pub struct MevAnalysisResult {
    pub contract_name: String,
    pub findings: Vec<MevFinding>,
    pub total_mev_exposure_bps: u32,
    pub recommendations: Vec<String>,
    pub executive_summary: String,
}

/// Analyzes DeFi protocol contracts for MEV exposure vectors.
pub struct MevAnalyzer;

impl MevAnalyzer {
    /// Analyze contract source for MEV exposure.
    pub fn analyze(source: &str, contract_name: &str) -> MevAnalysisResult {
        let mut findings = Vec::new();
        let mut recommendations = Vec::new();

        // Sandwich attack: swap with no slippage protection
        if (source.contains("swap(") || source.contains("swapExactTokensForTokens"))
            && !source.contains("amountOutMin")
        {
            findings.push(MevFinding {
                vector: MevAttackVector::Sandwich,
                severity: "High".into(),
                description: "Swap without minimum output amount; sandwich attacks extract value by manipulating price around the trade.".into(),
                estimated_loss_bps: 30,
                mitigation: "Set amountOutMin based on on-chain TWAP; add slippage tolerance check.".into(),
            });
            recommendations
                .push("Use commit-reveal or batch auctions to hide trade intent.".into());
        }

        // Frontrunning: public mempool transactions with high value
        if source.contains("block.timestamp") && !source.contains("deadline") {
            findings.push(MevFinding {
                vector: MevAttackVector::Frontrunning,
                severity: "Medium".into(),
                description: "Time-sensitive logic without deadline parameter; frontrunning window remains open.".into(),
                estimated_loss_bps: 15,
                mitigation: "Add a deadline parameter that reverts stale transactions.".into(),
            });
            recommendations.push("Add deadline parameter to all time-sensitive operations.".into());
        }

        // Backrunning: oracle update or price-sensitive read
        if source.contains("update(") && source.contains("price") {
            findings.push(MevFinding {
                vector: MevAttackVector::Backrunning,
                severity: "Medium".into(),
                description: "Price oracle update detectable in mempool; backrunners can exploit price transitions.".into(),
                estimated_loss_bps: 10,
                mitigation: "Use private mempools (MEV-Share, Flashbots Protect) for price-sensitive transactions.".into(),
            });
            recommendations
                .push("Route oracle updates through MEV-Share or Flashbots Protect.".into());
        }

        // Time-bandit: reorg incentive from high-value operations
        if source.contains("transfer(") && source.contains("block.number") {
            findings.push(MevFinding {
                vector: MevAttackVector::TimeBandit,
                severity: "Low".into(),
                description: "High-value block.number-dependent logic may incentivize chain reorgs on low-hashrate chains.".into(),
                estimated_loss_bps: 5,
                mitigation: "Deploy on chains with finality guarantees; avoid block.number for high-value conditional logic.".into(),
            });
        }

        // JIT liquidity: just-in-time concentrated liquidity provision
        if source.contains("addLiquidity") && !source.contains("lockPeriod") {
            findings.push(MevFinding {
                vector: MevAttackVector::JitLiquidity,
                severity: "Low".into(),
                description: "Liquidity can be added and removed within the same block (JIT); fee dilution for passive LPs.".into(),
                estimated_loss_bps: 8,
                mitigation: "Implement a minimum liquidity lock period (e.g. 1 block) to deter JIT strategies.".into(),
            });
            recommendations.push("Add minimum liquidity lock to prevent JIT extraction.".into());
        }

        // Liquidation MEV
        if source.contains("liquidate(") && !source.contains("liquidationBonus <= MAX_BONUS") {
            findings.push(MevFinding {
                vector: MevAttackVector::LiquidationMev,
                severity: "Medium".into(),
                description: "Liquidation bonus not bounded; MEV bots compete to extract maximum value from liquidations.".into(),
                estimated_loss_bps: 20,
                mitigation: "Cap liquidation bonus and use a Dutch auction mechanism for fair distribution.".into(),
            });
            recommendations.push("Use Dutch auction liquidation to reduce MEV incentive.".into());
        }

        let total_exposure_bps: u32 = findings.iter().map(|f| f.estimated_loss_bps).sum();

        let summary = format!(
            "'{}' MEV analysis: {} vector(s) found, estimated exposure {total_exposure_bps} bps.",
            contract_name,
            findings.len(),
        );

        // Dedup recommendations
        recommendations.dedup();

        MevAnalysisResult {
            contract_name: contract_name.to_string(),
            findings,
            total_mev_exposure_bps: total_exposure_bps,
            recommendations,
            executive_summary: summary,
        }
    }
}
