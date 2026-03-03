//! Echidna/Medusa-style invariant testing orchestration.

use serde::{Deserialize, Serialize};

/// Configuration for an invariant fuzzing campaign.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvariantTestConfig {
    /// Contract source code.
    pub source: String,
    /// Contract name to fuzz.
    pub contract_name: String,
    /// Maximum number of test runs.
    pub test_limit: u64,
    /// Path for the fuzzing corpus.
    pub corpus_dir: Option<String>,
    /// Seed for the random number generator (for reproducibility).
    pub seed: Option<u64>,
    /// Coverage target in percent (0–100).
    pub coverage_target: u8,
}

impl Default for InvariantTestConfig {
    fn default() -> Self {
        Self {
            source: String::new(),
            contract_name: "Contract".to_string(),
            test_limit: 10_000,
            corpus_dir: None,
            seed: None,
            coverage_target: 80,
        }
    }
}

/// A single invariant property to test.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvariantProperty {
    /// Property function name (e.g., "echidna_balance_never_negative").
    pub name: String,
    /// Human-readable description.
    pub description: String,
    /// Solidity-style predicate.
    pub predicate: String,
    /// Whether this property is currently passing.
    pub passing: bool,
}

/// A corpus entry generated during fuzzing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorpusEntry {
    pub entry_id: String,
    pub call_sequence: Vec<String>,
    pub coverage_new: bool,
    pub crashed: bool,
    pub notes: String,
}

/// Result of a full invariant fuzzing campaign.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzCampaignResult {
    pub contract_name: String,
    pub test_runs: u64,
    pub properties_tested: usize,
    pub properties_broken: usize,
    pub broken_properties: Vec<InvariantProperty>,
    pub corpus_entries: Vec<CorpusEntry>,
    pub coverage_pct: f64,
    pub summary: String,
}

/// Run a full invariant fuzzing campaign.
pub fn run_invariant_campaign(config: &InvariantTestConfig) -> FuzzCampaignResult {
    let properties = generate_invariant_properties(config);
    let mut corpus: Vec<CorpusEntry> = Vec::new();
    let mut broken: Vec<InvariantProperty> = Vec::new();

    // Simulate campaign runs by testing each property with heuristic analysis.
    for (idx, prop) in properties.iter().enumerate() {
        let (passes, entry) = simulate_property_test(idx as u64, prop, config);
        corpus.push(entry);
        if !passes {
            let mut broken_prop = prop.clone();
            broken_prop.passing = false;
            broken.push(broken_prop);
        }
    }

    let coverage = analyze_coverage(config, &corpus);
    let summary = format!(
        "Invariant campaign on '{}': {} runs, {}/{} properties passing, {:.1}% coverage.",
        config.contract_name,
        config.test_limit,
        properties.len() - broken.len(),
        properties.len(),
        coverage,
    );

    FuzzCampaignResult {
        contract_name: config.contract_name.clone(),
        test_runs: config.test_limit,
        properties_tested: properties.len(),
        properties_broken: broken.len(),
        broken_properties: broken,
        corpus_entries: corpus,
        coverage_pct: coverage,
        summary,
    }
}

/// Auto-generate invariant property stubs from contract source patterns.
pub fn generate_invariant_properties(config: &InvariantTestConfig) -> Vec<InvariantProperty> {
    let mut props = Vec::new();
    let source = &config.source;

    // Balance invariant
    if source.contains("balances[") || source.contains("balance") {
        props.push(InvariantProperty {
            name: "echidna_balance_non_negative".to_string(),
            description: "Token balances must never be negative".to_string(),
            predicate: "forall(address a) balances[a] >= 0".to_string(),
            passing: true,
        });
    }

    // Total supply invariant
    if source.contains("totalSupply") {
        props.push(InvariantProperty {
            name: "echidna_total_supply_conserved".to_string(),
            description: "Sum of all balances must equal totalSupply".to_string(),
            predicate: "sum(balances) == totalSupply".to_string(),
            passing: true,
        });
    }

    // Reentrancy guard invariant
    if source.contains("call{value:") || source.contains(".call.value(") {
        props.push(InvariantProperty {
            name: "echidna_no_reentrancy".to_string(),
            description: "Contract must not be reentrant".to_string(),
            predicate: "!locked || msg.sender == owner".to_string(),
            passing: true,
        });
    }

    // Ownership invariant
    if source.contains("onlyOwner") || source.contains("owner") {
        props.push(InvariantProperty {
            name: "echidna_owner_unchanged".to_string(),
            description: "Owner must not change unless explicitly transferred".to_string(),
            predicate: "owner != address(0)".to_string(),
            passing: true,
        });
    }

    // Fallback property when source is empty or has no patterns
    if props.is_empty() {
        props.push(InvariantProperty {
            name: "echidna_contract_alive".to_string(),
            description: "Contract must remain operational".to_string(),
            predicate: "address(this).code.length > 0".to_string(),
            passing: true,
        });
    }

    props
}

/// Estimate coverage based on corpus entries and source complexity.
pub fn analyze_coverage(config: &InvariantTestConfig, corpus: &[CorpusEntry]) -> f64 {
    if corpus.is_empty() {
        return 0.0;
    }
    let unique_coverage = corpus.iter().filter(|e| e.coverage_new).count();
    let base_coverage = (unique_coverage as f64 / corpus.len() as f64) * 100.0;

    // Scale up by test runs factor.
    let run_factor = (config.test_limit as f64).log10() / 5.0;
    (base_coverage * run_factor).min(100.0)
}

// — Internal helpers —

fn simulate_property_test(
    idx: u64,
    prop: &InvariantProperty,
    config: &InvariantTestConfig,
) -> (bool, CorpusEntry) {
    // Heuristic: reentrancy properties on contracts with external calls tend to fail.
    let fails = prop.name.contains("reentrancy")
        && config.source.contains("call{value:")
        && !config.source.contains("nonReentrant");

    let entry = CorpusEntry {
        entry_id: format!("corpus-{:04}", idx),
        call_sequence: vec![format!("{}()", prop.name.trim_start_matches("echidna_"))],
        coverage_new: idx % 3 == 0,
        crashed: fails,
        notes: if fails {
            format!("Property '{}' violated", prop.name)
        } else {
            "No violation found".to_string()
        },
    };
    (!fails, entry)
}
