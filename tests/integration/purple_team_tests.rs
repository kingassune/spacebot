//! Integration tests for red + blue simultaneous purple team operation.

#[cfg(test)]
mod purple_team_tests {
    use james::orchestrator::{JamesOrchestrator, PurpleTeamConfig};

    #[tokio::test]
    async fn purple_team_produces_technique_pairs() {
        let orchestrator = JamesOrchestrator::new();
        let config = PurpleTeamConfig::default();

        let report = orchestrator
            .run_purple_team(&config)
            .await
            .expect("purple team should succeed");

        assert!(
            !report.pairs.is_empty(),
            "should produce technique-detection pairs"
        );
        assert_eq!(
            report.pairs.len(),
            config.techniques.len(),
            "one pair per technique"
        );
    }

    #[tokio::test]
    async fn purple_team_calculates_coverage_percentage() {
        let orchestrator = JamesOrchestrator::new();
        let config = PurpleTeamConfig {
            target: "test-env".to_string(),
            techniques: vec![
                "T1059.001".to_string(),
                "T1566.001".to_string(),
                "T1041".to_string(),
                "T1078".to_string(),
            ],
            coverage_threshold: 75,
        };

        let report = orchestrator
            .run_purple_team(&config)
            .await
            .expect("purple team should succeed");

        assert!(
            report.coverage_pct >= 0.0 && report.coverage_pct <= 100.0,
            "coverage should be a valid percentage"
        );
        assert!(
            !report.gap_analysis.is_empty(),
            "gap analysis should not be empty"
        );
    }

    #[tokio::test]
    async fn purple_team_identifies_gaps_for_undetected_techniques() {
        let orchestrator = JamesOrchestrator::new();
        let config = PurpleTeamConfig {
            target: "test-env".to_string(),
            // T1041 is intentionally an obscure technique to ensure a gap exists.
            techniques: vec!["T1041".to_string()],
            coverage_threshold: 100,
        };

        let report = orchestrator
            .run_purple_team(&config)
            .await
            .expect("purple team should succeed");

        let undetected: Vec<_> = report.pairs.iter().filter(|p| !p.detected).collect();
        assert!(
            undetected
                .iter()
                .all(|p| p.gap_note.is_some()),
            "all undetected techniques should have gap notes"
        );
    }
}
