//! Integration tests for the JamesOrchestrator full assessment flow.

#[cfg(test)]
mod orchestrator_tests {
    use james::orchestrator::{AssessmentTarget, JamesOrchestrator, PurpleTeamConfig};

    #[tokio::test]
    async fn orchestrator_new_initialises_all_engines() {
        let orchestrator = JamesOrchestrator::new();
        // Verify the engines are accessible.
        assert_eq!(orchestrator.red_team.engagement_id, "james-default");
        assert_eq!(orchestrator.blue_team.org_name, "James Org");
        assert!(!orchestrator.exploit_engine.workspace_dir.is_empty());
    }

    #[tokio::test]
    async fn run_full_assessment_produces_report() {
        let orchestrator = JamesOrchestrator::new();
        let target = AssessmentTarget {
            name: "test-target".to_string(),
            address: "192.168.1.1".to_string(),
            environment: "lab".to_string(),
            include_blockchain: false,
        };

        let report = orchestrator
            .run_full_assessment(&target)
            .await
            .expect("assessment should succeed");

        assert!(!report.findings.is_empty(), "report should have findings");
        assert!(!report.executive_summary.is_empty(), "should have a summary");
        assert!(
            report.metadata.modules_run.contains(&"red_team".to_string()),
            "red_team module should be listed"
        );
        assert!(
            report.metadata.modules_run.contains(&"blue_team".to_string()),
            "blue_team module should be listed"
        );
    }

    #[tokio::test]
    async fn run_full_assessment_includes_blockchain_when_requested() {
        let orchestrator = JamesOrchestrator::new();
        let target = AssessmentTarget {
            name: "defi-protocol".to_string(),
            address: "0xdeadbeef".to_string(),
            environment: "mainnet-fork".to_string(),
            include_blockchain: true,
        };

        let report = orchestrator
            .run_full_assessment(&target)
            .await
            .expect("assessment should succeed");

        assert!(
            report.metadata.modules_run.contains(&"blockchain".to_string()),
            "blockchain module should be listed when requested"
        );
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.source_modules.contains(&"blockchain".to_string())),
            "should have at least one blockchain finding"
        );
    }

    #[tokio::test]
    async fn nation_state_simulation_produces_report() {
        let orchestrator = JamesOrchestrator::new();
        let report = orchestrator
            .run_nation_state_simulation("APT29")
            .await
            .expect("simulation should succeed");

        assert_eq!(report.apt_profile, "APT29");
        assert!(
            !report.phases_simulated.is_empty(),
            "should have phases simulated"
        );
        assert!(
            report.detection_coverage_pct >= 0.0 && report.detection_coverage_pct <= 100.0,
            "coverage should be in valid range"
        );
        assert!(!report.summary.is_empty(), "summary should not be empty");
    }
}
