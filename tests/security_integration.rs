//! Integration tests for James security modules.

#[cfg(test)]
mod meta_agent_tests {
    use james::meta_agent::capability_analysis::build_initial_capability_map;
    use james::meta_agent::{
        CapabilityAnalyzer, CrossDomainCoordinator, EngagementScope, EngagementType, PluginBuilder,
        PluginConfig, SecurityDomain, SkillGenerator,
    };

    #[test]
    fn skill_generator_produces_valid_skill_md() {
        let generator = SkillGenerator::default();
        let skill = generator.generate_skill("detect SQL injection", SecurityDomain::Pentest);

        assert!(!skill.name.is_empty(), "skill name should not be empty");
        assert!(
            !skill.markdown.is_empty(),
            "skill markdown should not be empty"
        );
        assert!(
            skill.markdown.contains("---"),
            "markdown should contain frontmatter delimiter"
        );
        assert!(
            skill.markdown.contains("name:"),
            "markdown should contain name frontmatter"
        );
        assert!(
            skill.markdown.contains("description:"),
            "markdown should contain description frontmatter"
        );
        assert_eq!(skill.domain, SecurityDomain::Pentest);
    }

    #[test]
    fn skill_generator_prefixes_domain_correctly() {
        let generator = SkillGenerator::default();

        let pentest_skill = generator.generate_skill("web scan", SecurityDomain::Pentest);
        assert!(
            pentest_skill.name.starts_with("pentest-"),
            "pentest skill should be prefixed"
        );

        let red_team_skill = generator.generate_skill("lateral move", SecurityDomain::RedTeam);
        assert!(
            red_team_skill.name.starts_with("redteam-"),
            "red team skill should be prefixed"
        );

        let blockchain_skill =
            generator.generate_skill("reentrancy check", SecurityDomain::Blockchain);
        assert!(
            blockchain_skill.name.starts_with("blockchain-"),
            "blockchain skill should be prefixed"
        );
    }

    #[test]
    fn capability_analyzer_identifies_module_coverage() {
        let map = build_initial_capability_map();
        assert!(
            !map.capabilities.is_empty(),
            "initial capability map should have capabilities"
        );
        assert!(
            !map.coverage_domains.is_empty(),
            "initial capability map should have domains"
        );

        let analyzer = CapabilityAnalyzer::new(map);
        let report = analyzer.analyze_capabilities(&EngagementType::BlueTeamDefense);

        assert_eq!(report.engagement, EngagementType::BlueTeamDefense);
        assert!(report.coverage_percent >= 0.0 && report.coverage_percent <= 100.0);
    }

    #[test]
    fn capability_analyzer_reports_all_engagement_types() {
        let map = build_initial_capability_map();
        let analyzer = CapabilityAnalyzer::new(map);

        let engagements = vec![
            EngagementType::Pentest,
            EngagementType::RedTeamOp,
            EngagementType::BlueTeamDefense,
            EngagementType::BlockchainAudit,
            EngagementType::IncidentResponse,
            EngagementType::ThreatHunting,
        ];

        for engagement in engagements {
            let report = analyzer.analyze_capabilities(&engagement);
            assert!(
                report.coverage_percent >= 0.0,
                "coverage should be non-negative for {:?}",
                engagement
            );
        }
    }

    #[test]
    fn cross_domain_coordinator_decomposes_multi_domain_engagement() {
        let coordinator = CrossDomainCoordinator::new();
        let scope = EngagementScope {
            name: "test-engagement".to_string(),
            domains: vec![
                "blockchain".to_string(),
                "network".to_string(),
                "web".to_string(),
            ],
            objectives: vec!["Identify critical vulnerabilities".to_string()],
            target_systems: vec!["example.com".to_string()],
            duration_days: 10,
        };

        let plan = coordinator.plan_engagement(&scope);

        assert_eq!(plan.name, "test-engagement");
        assert_eq!(
            plan.sub_tasks.len(),
            3,
            "should create one sub-task per domain"
        );
        assert_eq!(
            plan.domain_assignments.len(),
            3,
            "should assign each domain to an engine"
        );

        // Verify domain assignment for blockchain
        let blockchain_assignment = plan
            .domain_assignments
            .iter()
            .find(|(domain, _)| domain == "blockchain");
        assert!(
            blockchain_assignment.is_some(),
            "blockchain domain should be assigned"
        );
        let (_, engine) = blockchain_assignment.unwrap();
        assert!(
            engine.contains("Blockchain"),
            "blockchain should map to BlockchainSecurityEngine"
        );
    }

    #[test]
    fn plugin_builder_scaffolds_plugin_manifest() {
        let builder = PluginBuilder::new("plugins");
        let config = PluginConfig {
            name: "test-plugin".to_string(),
            domain: "pentest".to_string(),
            description: "Test plugin for pentest".to_string(),
            version: "1.0.0".to_string(),
            include_hooks: true,
            include_commands: false,
        };

        let manifest = builder
            .build_plugin(&config)
            .expect("build_plugin should succeed");

        assert_eq!(manifest.name, "test-plugin");
        assert_eq!(manifest.version, "1.0.0");
        assert!(
            manifest
                .capabilities
                .contains(&"domain:pentest".to_string()),
            "capabilities should include domain"
        );
        assert!(
            manifest
                .capabilities
                .contains(&"hooks:lifecycle".to_string()),
            "capabilities should include hooks when include_hooks=true"
        );
    }

    #[test]
    fn skill_router_matches_registered_skills() {
        use james::meta_agent::skill_router::{RouteRequest, SkillRouter};

        let mut router = SkillRouter::new();
        router.register_skill("detect-reentrancy".to_string(), "blockchain".to_string());
        router.register_skill("pentest-web".to_string(), "web".to_string());

        let request = RouteRequest {
            task_description: "Find reentrancy in smart contract".to_string(),
            required_capabilities: vec!["blockchain".to_string()],
            priority: 1,
        };

        let result = router.route(&request);
        assert_eq!(result.selected_skill, "detect-reentrancy");
        assert!(result.confidence > 0.0);
    }
}

#[cfg(test)]
mod blockchain_security_tests {
    use james::blockchain_security::contract_analysis::{Chain, ContractAnalyzer};
    use james::blockchain_security::mev_protection::MevAnalyzer;
    use james::blockchain_security::token_security::TokenSecurityAnalyzer;

    #[test]
    fn contract_analyzer_detects_reentrancy_in_solidity() {
        let source = r#"
            pragma solidity ^0.8.0;
            contract Vulnerable {
                mapping(address => uint256) public balances;
                function withdraw() public {
                    uint256 amount = balances[msg.sender];
                    (bool success,) = msg.sender.call{value: amount}("");
                    require(success);
                    balances[msg.sender] = 0;
                }
            }
        "#;

        let analyzer = ContractAnalyzer::new(Chain::Ethereum);
        let result = analyzer.analyze(source).expect("analysis should succeed");

        assert!(!result.findings.is_empty(), "should detect vulnerabilities");
        let has_reentrancy = result.findings.iter().any(|f| {
            matches!(
                f.pattern,
                james::blockchain_security::contract_analysis::VulnerabilityPattern::Reentrancy
            )
        });
        assert!(has_reentrancy, "should detect reentrancy");
    }

    #[test]
    fn contract_analyzer_detects_tx_origin() {
        let source = r#"
            pragma solidity ^0.8.0;
            contract Auth {
                function sensitiveAction() public {
                    require(tx.origin == owner, "not owner");
                    doSomething();
                }
            }
        "#;

        let analyzer = ContractAnalyzer::new(Chain::Ethereum);
        let result = analyzer.analyze(source).expect("analysis should succeed");

        let has_tx_origin = result.findings.iter().any(|f| {
            matches!(
                f.pattern,
                james::blockchain_security::contract_analysis::VulnerabilityPattern::TxOrigin
            )
        });
        assert!(has_tx_origin, "should detect tx.origin usage");
    }

    #[test]
    fn contract_analyzer_handles_vyper_syntax() {
        let source = r#"
# @version 0.3.7
@external
def withdraw(amount: uint256):
    raw_call(msg.sender, b"", value=amount)
    self.balances[msg.sender] -= amount
        "#;

        let analyzer = ContractAnalyzer::new(Chain::Ethereum);
        let result = analyzer
            .analyze(source)
            .expect("vyper analysis should succeed");
        // Vyper without @nonreentrant should flag reentrancy
        assert!(
            !result.findings.is_empty(),
            "Vyper contract with raw_call should have findings"
        );
    }

    #[test]
    fn token_analyzer_detects_fee_on_transfer() {
        let source = r#"
            pragma solidity ^0.8.0;
            contract FeeToken is ERC20 {
                uint256 public taxRate = 2;
                function transfer(address to, uint256 amount) public override returns (bool) {
                    uint256 fee = (amount * taxRate) / 100;
                    super.transfer(to, amount - fee);
                    return true;
                }
            }
        "#;

        let result = TokenSecurityAnalyzer::analyze(source, "FeeToken");
        let has_fee = result.findings.iter().any(|f| {
            f.vulnerability
                == james::blockchain_security::token_security::TokenVulnerability::FeeOnTransfer
        });
        assert!(has_fee, "should detect fee-on-transfer");
    }

    #[test]
    fn token_analyzer_detects_standard_correctly() {
        let erc20_source = "pragma solidity ^0.8.0; contract T is ERC20 { function totalSupply() external view returns (uint256) {} }";
        let erc721_source = "pragma solidity ^0.8.0; contract NFT is ERC721 { function ownerOf(uint256 id) external view returns (address) {} }";

        assert_eq!(
            TokenSecurityAnalyzer::detect_standard(erc20_source),
            james::blockchain_security::token_security::TokenStandard::Erc20
        );
        assert_eq!(
            TokenSecurityAnalyzer::detect_standard(erc721_source),
            james::blockchain_security::token_security::TokenStandard::Erc721
        );
    }

    #[test]
    fn mev_analyzer_detects_sandwich_risk() {
        let source = r#"
            pragma solidity ^0.8.0;
            contract Router {
                function swap(address token, uint256 amountIn) external {
                    _swap(token, amountIn);
                }
            }
        "#;

        let result = MevAnalyzer::analyze(source, "Router");
        let has_sandwich = result.findings.iter().any(|f| {
            f.vector == james::blockchain_security::mev_protection::MevAttackVector::Sandwich
        });
        assert!(has_sandwich, "should detect sandwich attack risk");
        assert!(
            result.total_mev_exposure_bps > 0,
            "should have non-zero MEV exposure"
        );
    }

    #[test]
    fn quality_score_decreases_with_findings() {
        use james::blockchain_security::contract_analysis::compute_quality_score;
        use james::blockchain_security::contract_analysis::{
            Finding, SeverityLevel, VulnerabilityPattern,
        };

        let no_findings: Vec<Finding> = Vec::new();
        let with_critical = vec![Finding {
            id: "SOL-001".into(),
            pattern: VulnerabilityPattern::Reentrancy,
            severity: SeverityLevel::Critical,
            line_number: None,
            description: "test".into(),
            recommendation: "fix".into(),
            code_snippet: None,
        }];

        assert_eq!(compute_quality_score(&no_findings), 100.0);
        assert!(
            compute_quality_score(&with_critical) < 100.0,
            "critical finding should reduce quality score"
        );
    }
}
