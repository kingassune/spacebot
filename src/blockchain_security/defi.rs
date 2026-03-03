//! DeFi protocol risk analysis: flash loans, oracle manipulation, MEV, and liquidity pools.

/// Classification of DeFi protocol types.
#[derive(Debug, Clone, PartialEq)]
pub enum DefiProtocolType {
    Dex,
    LendingPool,
    Vault,
    Bridge,
    Oracle,
    Stablecoin,
    Derivatives,
    Insurance,
    LaunchPad,
    NftMarketplace,
}

/// Attack vectors relevant to DeFi protocols.
#[derive(Debug, Clone, PartialEq)]
pub enum DefiAttackVector {
    FlashLoanAttack,
    OracleManipulation,
    SandwichAttack,
    FrontrunMev,
    BackrunMev,
    JitLiquidity,
    ReentrancyAttack,
    PriceManipulation,
    GovernanceAttack,
    RugPull,
    InfiniteApproval,
    TokenImbalance,
}

/// Risk associated with flash loan exploitability of a contract.
#[derive(Debug, Clone)]
pub struct FlashLoanRisk {
    pub contract_address: String,
    pub risk_level: String,
    pub attack_path: String,
    pub estimated_profit_usd: Option<f64>,
}

/// Assessment of oracle dependency and manipulation risk.
#[derive(Debug, Clone)]
pub struct OracleRiskAssessment {
    pub oracle_type: String,
    pub manipulation_risk: String,
    pub recommended_mitigation: String,
    pub twap_available: bool,
}

/// Result of a simulated sandwich-attack assessment.
#[derive(Debug, Clone)]
pub struct SandwichResult {
    pub vulnerable: bool,
    pub estimated_profit_wei: u64,
    pub attack_sequence: Vec<String>,
}

/// Simplified representation of an on-chain transaction.
#[derive(Debug, Clone)]
pub struct Transaction {
    pub hash: String,
    pub from: String,
    pub to: String,
    pub value_wei: u64,
    pub input_data: String,
    pub gas_price: u64,
}

/// Flash-loan capability and associated attack vector analysis.
#[derive(Debug, Clone)]
pub struct FlashLoanAnalysis {
    pub protocol: String,
    pub max_loan_amount_usd: f64,
    pub attack_vectors: Vec<DefiAttackVector>,
    pub requires_collateral: bool,
}

/// MEV opportunity estimates for a given context.
#[derive(Debug, Clone)]
pub struct MevAnalysis {
    pub sandwich_opportunities: u32,
    pub frontrun_opportunities: u32,
    pub backrun_opportunities: u32,
    pub estimated_daily_mev_usd: f64,
}

/// Liquidity pool composition and impermanent-loss analysis.
#[derive(Debug, Clone)]
pub struct LiquidityPoolAnalysis {
    pub pool_address: String,
    pub token_a: String,
    pub token_b: String,
    pub imbalance_ratio: f64,
    pub impermanent_loss_percent: f64,
}

/// Scan contract source for flash-loan entry points.
pub fn detect_flash_loan_vulnerability(contract: &str) -> anyhow::Result<Vec<FlashLoanRisk>> {
    let mut risks = Vec::new();

    let flash_patterns = [
        ("flashLoan", "ERC-3156 / Aave flash loan entry point"),
        ("IERC3156", "ERC-3156 flash lender interface"),
        ("executeOperation", "Aave V2/V3 flash loan callback"),
        ("uniswapV2Call", "Uniswap V2 flash swap callback"),
        ("pancakeCall", "PancakeSwap flash loan callback"),
    ];

    for (pattern, label) in &flash_patterns {
        if contract.contains(pattern) {
            risks.push(FlashLoanRisk {
                contract_address: String::new(),
                risk_level: "High".into(),
                attack_path: format!("Pattern `{pattern}` ({label}) detected; verify atomicity and reentrancy guards."),
                estimated_profit_usd: None,
            });
        }
    }

    Ok(risks)
}

/// Analyze contract source for oracle dependency and price-feed risk.
pub fn analyze_oracle_dependency(contract: &str) -> anyhow::Result<OracleRiskAssessment> {
    let uses_chainlink =
        contract.contains("AggregatorV3Interface") || contract.contains("latestRoundData");
    let uses_uniswap_oracle = contract.contains("consult(") || contract.contains("observe(");
    let uses_twap = contract.contains("TWAP") || contract.contains("twap") || uses_uniswap_oracle;

    let (oracle_type, manipulation_risk, recommended_mitigation) = if uses_chainlink {
        (
            "Chainlink price feed".into(),
            "Low – Chainlink aggregates multiple sources but stale data is possible.".into(),
            "Validate roundId and updatedAt; add circuit breakers for stale feeds.".into(),
        )
    } else if uses_uniswap_oracle {
        (
            "Uniswap V2/V3 TWAP".into(),
            "Medium – short observation windows are susceptible to flash-loan manipulation.".into(),
            "Use a TWAP window of at least 30 minutes and cross-validate with a secondary feed."
                .into(),
        )
    } else if contract.contains("getPrice") || contract.contains("price()") {
        (
            "Custom price feed".into(),
            "High – unverified custom price feed, single point of failure.".into(),
            "Replace with a decentralised oracle (Chainlink, Pyth) and add TWAP.".into(),
        )
    } else {
        (
            "None detected".into(),
            "N/A".into(),
            "Ensure any price-sensitive logic uses a reputable, manipulation-resistant oracle."
                .into(),
        )
    };

    Ok(OracleRiskAssessment {
        oracle_type,
        manipulation_risk,
        recommended_mitigation,
        twap_available: uses_twap,
    })
}

/// Simulate a sandwich-attack scenario for a transaction.
pub fn simulate_sandwich_attack(tx: &Transaction) -> anyhow::Result<SandwichResult> {
    // Heuristic: high-value swaps with moderate gas prices are sandwichable.
    let is_swap = tx.input_data.starts_with("0x38ed1739") // swapExactTokensForTokens
        || tx.input_data.starts_with("0x7ff36ab5") // swapExactETHForTokens
        || tx.input_data.starts_with("0x18cbafe5"); // swapExactTokensForETH

    if !is_swap || tx.value_wei == 0 {
        return Ok(SandwichResult {
            vulnerable: false,
            estimated_profit_wei: 0,
            attack_sequence: Vec::new(),
        });
    }

    let estimated_profit_wei = (tx.value_wei as f64 * 0.003) as u64; // ~0.3 % slippage capture
    Ok(SandwichResult {
        vulnerable: true,
        estimated_profit_wei,
        attack_sequence: vec![
            format!(
                "1. Frontrun: buy before tx {} with higher gas price.",
                tx.hash
            ),
            format!("2. Victim tx {} executes at worse price.", tx.hash),
            "3. Backrun: sell immediately after victim tx.".into(),
        ],
    })
}

/// Compute impermanent loss for a given price-ratio change.
///
/// Formula: `IL = 2 * sqrt(ratio) / (1 + ratio) - 1`
///
/// The result is ≤ 0: zero means no loss (ratio = 1), while a negative value
/// represents the fractional loss a liquidity provider suffers compared to
/// simply holding the tokens (e.g. −0.057 means 5.7 % impermanent loss).
pub fn calculate_impermanent_loss(price_ratio_change: f64) -> f64 {
    let ratio = price_ratio_change.max(0.0);
    2.0 * ratio.sqrt() / (1.0 + ratio) - 1.0
}

/// Return a liquidity pool analysis with placeholder on-chain data.
pub fn analyze_liquidity_pool(pool_address: &str) -> anyhow::Result<LiquidityPoolAnalysis> {
    Ok(LiquidityPoolAnalysis {
        pool_address: pool_address.to_string(),
        token_a: "TOKEN_A".into(),
        token_b: "TOKEN_B".into(),
        imbalance_ratio: 1.0,
        impermanent_loss_percent: 0.0,
    })
}

// ── Governance Attack Analysis ─────────────────────────────────────────────

/// Type of governance attack vector.
#[derive(Debug, Clone, PartialEq)]
pub enum GovernanceAttackVector {
    VoteBuying,
    FlashLoanGovernance,
    TimelockBypass,
    QuorumManipulation,
    DelegateFront,
}

/// Analysis of governance mechanism vulnerabilities.
#[derive(Debug, Clone)]
pub struct GovernanceAttack {
    pub protocol: String,
    pub vectors: Vec<GovernanceAttackVector>,
    pub quorum_percent: f64,
    pub timelock_delay_secs: u64,
    pub findings: Vec<String>,
    pub recommendations: Vec<String>,
}

/// Analyze a governance contract source for known attack vectors.
pub fn analyze_governance(source: &str, protocol: &str) -> anyhow::Result<GovernanceAttack> {
    let mut vectors = Vec::new();
    let mut findings = Vec::new();
    let mut recommendations = Vec::new();

    // Flash loan governance attack: token snapshot without time delay
    if source.contains("token.balanceOf(")
        && !source.contains("snapshot")
        && !source.contains("getPriorVotes")
    {
        vectors.push(GovernanceAttackVector::FlashLoanGovernance);
        findings.push("Voting power read from live balance; flash loan attack possible.".into());
        recommendations.push("Use snapshotted or time-locked voting power (e.g. ERC20Snapshot or Compound's getPriorVotes).".into());
    }

    // Timelock bypass: very short delay
    if (source.contains("delay = ") || source.contains("TIMELOCK_DELAY"))
        && !source.contains("require(delay >= ")
    {
        vectors.push(GovernanceAttackVector::TimelockBypass);
        findings
            .push("Timelock delay is not enforced with a minimum; bypass may be possible.".into());
        recommendations.push("Require a minimum timelock delay (e.g. 48 hours).".into());
    }

    // Vote buying: off-chain delegation without revocation
    if source.contains("delegate(") && !source.contains("revokeDelegate") {
        vectors.push(GovernanceAttackVector::VoteBuying);
        findings.push("Delegation without revocation mechanism detected; vote buying risk.".into());
        recommendations
            .push("Implement delegation revocation and consider vote-lock mechanisms.".into());
    }

    Ok(GovernanceAttack {
        protocol: protocol.to_string(),
        vectors,
        quorum_percent: 4.0,
        timelock_delay_secs: 172800,
        findings,
        recommendations,
    })
}

// ── Lending Protocol Analysis ──────────────────────────────────────────────

/// Lending market analysis with liquidation manipulation detection.
#[derive(Debug, Clone)]
pub struct LendingProtocolAnalysis {
    pub protocol: String,
    pub liquidation_threshold: f64,
    pub liquidation_penalty: f64,
    pub oracle_dependency: String,
    pub manipulation_risks: Vec<String>,
    pub recommendations: Vec<String>,
}

/// Analyze a lending protocol source for liquidation and oracle manipulation.
pub fn analyze_lending_protocol(
    source: &str,
    protocol: &str,
) -> anyhow::Result<LendingProtocolAnalysis> {
    let mut manipulation_risks = Vec::new();
    let mut recommendations = Vec::new();

    if !source.contains("TWAP") && !source.contains("twap") && source.contains("getPrice") {
        manipulation_risks.push("Spot price oracle used; flash loan manipulation possible.".into());
        recommendations.push("Replace spot price with TWAP oracle.".into());
    }

    if source.contains("liquidate") && !source.contains("maxLiquidation") {
        manipulation_risks.push("Unbounded liquidation amount; dust attack risk.".into());
        recommendations
            .push("Cap maximum liquidation per call to prevent market-impact manipulation.".into());
    }

    Ok(LendingProtocolAnalysis {
        protocol: protocol.to_string(),
        liquidation_threshold: 0.80,
        liquidation_penalty: 0.05,
        oracle_dependency: if source.contains("AggregatorV3Interface") {
            "Chainlink".into()
        } else {
            "Custom".into()
        },
        manipulation_risks,
        recommendations,
    })
}

// ── AMM Invariant Checker ──────────────────────────────────────────────────

/// AMM invariant type.
#[derive(Debug, Clone, PartialEq)]
pub enum AmmInvariant {
    ConstantProduct,
    ConstantSum,
    StableSwap,
    WeightedProduct,
}

/// Result of an AMM invariant verification.
#[derive(Debug, Clone)]
pub struct AmmInvariantResult {
    pub invariant: AmmInvariant,
    pub invariant_holds: bool,
    pub deviation_percent: f64,
    pub findings: Vec<String>,
}

/// Verify that an AMM's price formula matches the expected invariant.
pub struct AmmInvariantChecker;

impl AmmInvariantChecker {
    /// Check constant-product invariant: k = x * y must be non-decreasing.
    pub fn check_constant_product(
        reserve_x: f64,
        reserve_y: f64,
        k_before: f64,
    ) -> AmmInvariantResult {
        let k_after = reserve_x * reserve_y;
        let deviation = ((k_after - k_before) / k_before.max(f64::EPSILON)).abs();
        let invariant_holds = k_after >= k_before * (1.0 - 1e-6);
        let mut findings = Vec::new();
        if !invariant_holds {
            findings.push(format!(
                "k decreased from {k_before:.6} to {k_after:.6} ({deviation:.4}% deviation); invariant violated."
            ));
        }
        AmmInvariantResult {
            invariant: AmmInvariant::ConstantProduct,
            invariant_holds,
            deviation_percent: deviation * 100.0,
            findings,
        }
    }

    /// Check constant-sum invariant: x + y must be non-decreasing.
    pub fn check_constant_sum(
        reserve_x: f64,
        reserve_y: f64,
        sum_before: f64,
    ) -> AmmInvariantResult {
        let sum_after = reserve_x + reserve_y;
        let deviation = ((sum_after - sum_before) / sum_before.max(f64::EPSILON)).abs();
        let invariant_holds = sum_after >= sum_before * (1.0 - 1e-6);
        let mut findings = Vec::new();
        if !invariant_holds {
            findings.push(format!(
                "sum decreased from {sum_before:.6} to {sum_after:.6}; constant-sum invariant violated."
            ));
        }
        AmmInvariantResult {
            invariant: AmmInvariant::ConstantSum,
            invariant_holds,
            deviation_percent: deviation * 100.0,
            findings,
        }
    }
}
