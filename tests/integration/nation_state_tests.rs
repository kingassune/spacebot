//! Integration tests for full APT simulation with detection coverage mapping.

#[cfg(test)]
mod nation_state_tests {
    use james::orchestrator::JamesOrchestrator;

    #[tokio::test]
    async fn apt29_simulation_produces_report() {
        let orchestrator = JamesOrchestrator::new();
        let report = orchestrator
            .run_nation_state_simulation("APT29")
            .await
            .expect("APT29 simulation should succeed");

        assert_eq!(report.apt_profile, "APT29");
        assert!(
            !report.phases_simulated.is_empty(),
            "APT29 simulation should have phases"
        );
        assert!(!report.summary.is_empty(), "should have a summary");
    }

    #[tokio::test]
    async fn apt41_simulation_produces_report() {
        let orchestrator = JamesOrchestrator::new();
        let report = orchestrator
            .run_nation_state_simulation("APT41")
            .await
            .expect("APT41 simulation should succeed");

        assert_eq!(report.apt_profile, "APT41");
        assert!(
            report.detection_coverage_pct >= 0.0 && report.detection_coverage_pct <= 100.0,
            "detection coverage should be a valid percentage"
        );
    }

    #[tokio::test]
    async fn nation_state_simulation_includes_findings() {
        let orchestrator = JamesOrchestrator::new();
        let report = orchestrator
            .run_nation_state_simulation("Lazarus Group")
            .await
            .expect("Lazarus simulation should succeed");

        assert!(!report.findings.is_empty(), "should produce findings");
        for finding in &report.findings {
            assert_eq!(
                finding.source_module, "nation_state",
                "findings should be attributed to nation_state module"
            );
            assert!(!finding.title.is_empty(), "findings should have titles");
        }
    }
}
