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

/// Analyse contract source for oracle dependency and price-feed risk.
pub fn analyze_oracle_dependency(contract: &str) -> anyhow::Result<OracleRiskAssessment> {
    let uses_chainlink = contract.contains("AggregatorV3Interface") || contract.contains("latestRoundData");
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
            "Use a TWAP window of at least 30 minutes and cross-validate with a secondary feed.".into(),
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
            "Ensure any price-sensitive logic uses a reputable, manipulation-resistant oracle.".into(),
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
            format!("1. Frontrun: buy before tx {} with higher gas price.", tx.hash),
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
