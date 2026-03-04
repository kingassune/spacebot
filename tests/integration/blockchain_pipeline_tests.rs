//! Integration tests for the blockchain security end-to-end pipeline.
//!
//! Tests contract analysis → formal verification → invariant fuzzing → MEV analysis flows.

#[cfg(test)]
mod blockchain_pipeline_tests {
    use james::blockchain_security::{
        contract_analysis::Chain,
        formal_verification::{PropertySpec, VerificationConfig},
        invariant_testing::InvariantTestConfig,
        BlockchainSecurityEngine,
    };

    #[test]
    fn engine_analyzes_solidity_contract() {
        let engine = BlockchainSecurityEngine::new(Chain::Ethereum);
        let source = r#"
            pragma solidity ^0.8.0;
            contract Vault {
                mapping(address => uint256) public balances;
                function deposit() external payable {
                    balances[msg.sender] += msg.value;
                }
                function withdraw(uint256 amount) external {
                    require(balances[msg.sender] >= amount, "Insufficient balance");
                    (bool ok, ) = msg.sender.call{value: amount}("");
                    require(ok, "Transfer failed");
                    balances[msg.sender] -= amount;
                }
            }
        "#;

        let result = engine.analyze(source).expect("analysis should succeed");
        assert!(
            result.code_quality_score >= 0.0 && result.code_quality_score <= 100.0,
            "quality score should be in valid range"
        );
    }

    #[test]
    fn formal_verification_runs_property_checks() {
        let engine = BlockchainSecurityEngine::new(Chain::Ethereum);
        let config = VerificationConfig {
            source: "pragma solidity ^0.8.0; contract T { uint x; }".to_string(),
            contract_name: "T".to_string(),
            properties: vec![PropertySpec {
                name: "no_overflow".to_string(),
                predicate: "x < type(uint256).max".to_string(),
                invariant_type:
                    james::blockchain_security::formal_verification::InvariantType::StateInvariant,
                is_safety: true,
            }],
            max_depth: 50,
            timeout_secs: 30,
        };

        let result = engine.verify(&config);
        assert_eq!(result.contract_name, "T");
        assert!(
            result.properties_checked > 0,
            "should have checked at least one property"
        );
    }

    #[test]
    fn invariant_fuzzing_runs_campaign() {
        let engine = BlockchainSecurityEngine::new(Chain::Ethereum);
        let config = InvariantTestConfig {
            source: "pragma solidity ^0.8.0; contract T { uint x; }".to_string(),
            contract_name: "T".to_string(),
            test_limit: 100,
            corpus_dir: None,
            seed: Some(42),
            coverage_target: 80,
        };

        let result = engine.fuzz_invariants(&config);
        assert_eq!(result.contract_name, "T");
        assert!(
            result.test_runs > 0,
            "should have executed at least one run"
        );
    }

    #[test]
    fn mev_analysis_runs_against_source() {
        let engine = BlockchainSecurityEngine::new(Chain::Ethereum);
        let source =
            "pragma solidity ^0.8.0; contract Swap { function swap() public {} }";
        let result = engine.analyze_mev(source, "Swap");
        assert_eq!(result.contract_name, "Swap");
    }
}

