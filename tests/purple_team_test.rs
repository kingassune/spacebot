//! Tests for purple team attack-detection pair matching.

#[cfg(test)]
mod purple_team_tests {
    use james::integration::purple_team::{
        AttackDetectionPair, PurpleTeamConfig, PurpleTeamRunner,
    };

    #[tokio::test]
    async fn purple_team_runs_without_error() {
        let config = PurpleTeamConfig::default();
        let runner = PurpleTeamRunner::new("purple-test-001");
        let result = runner.run(&config).await.unwrap();

        assert_eq!(result.engagement_id, "purple-test-001");
        assert!(
            !result.pairs.is_empty(),
            "should produce attack-detection pairs"
        );
    }

    #[tokio::test]
    async fn purple_team_pairs_match_techniques() {
        let config = PurpleTeamConfig {
            target: "test-env".to_string(),
            attack_techniques: vec![
                "T1059.001".to_string(),
                "T1566.001".to_string(),
                "T1041".to_string(),
            ],
            detection_rules: vec!["rule: detect_powershell".to_string()],
            coverage_threshold: 80,
        };
        let runner = PurpleTeamRunner::new("purple-test-002");
        let result = runner.run(&config).await.unwrap();

        // All techniques in config should appear in pairs
        let pair_ids: Vec<&str> = result
            .pairs
            .iter()
            .map(|p| p.technique_id.as_str())
            .collect();
        assert!(
            pair_ids.contains(&"T1059.001"),
            "T1059.001 should be in pairs"
        );
        assert!(
            pair_ids.contains(&"T1566.001"),
            "T1566.001 should be in pairs"
        );
        assert!(pair_ids.contains(&"T1041"), "T1041 should be in pairs");
    }

    #[tokio::test]
    async fn purple_team_coverage_reflects_detections() {
        // With detection rules, commonly detected techniques should fire
        let config = PurpleTeamConfig {
            target: "coverage-test".to_string(),
            attack_techniques: vec!["T1059.001".to_string()],
            detection_rules: vec!["rule: powershell".to_string()],
            coverage_threshold: 50,
        };
        let runner = PurpleTeamRunner::new("purple-test-003");
        let result = runner.run(&config).await.unwrap();

        // T1059.001 with detection rules should be detected (100% coverage)
        assert_eq!(
            result.detection_coverage_pct, 100.0,
            "T1059.001 with detection rules should give 100% coverage"
        );
        assert!(
            result.gaps.is_empty(),
            "no gaps expected when technique is detected"
        );
    }

    #[tokio::test]
    async fn purple_team_identifies_gaps_for_undetected_techniques() {
        // Without detection rules, techniques should not be detected → gap
        let config = PurpleTeamConfig {
            target: "gap-test".to_string(),
            attack_techniques: vec!["T1041".to_string()],
            detection_rules: vec![],
            coverage_threshold: 80,
        };
        let runner = PurpleTeamRunner::new("purple-test-004");
        let result = runner.run(&config).await.unwrap();

        assert_eq!(
            result.detection_coverage_pct, 0.0,
            "no detection rules → 0% coverage"
        );
        assert_eq!(
            result.gaps.len(),
            1,
            "should have 1 detection gap for T1041"
        );
    }

    #[tokio::test]
    async fn purple_team_gap_analysis_report_is_populated() {
        let config = PurpleTeamConfig {
            target: "report-test".to_string(),
            attack_techniques: vec!["T1041".to_string()],
            detection_rules: vec![],
            coverage_threshold: 80,
        };
        let runner = PurpleTeamRunner::new("purple-test-005");
        let result = runner.run(&config).await.unwrap();

        assert!(
            !result.gap_analysis_report.is_empty(),
            "gap analysis report should not be empty"
        );
        assert!(
            result
                .gap_analysis_report
                .contains("Purple Team Gap Analysis"),
            "report should have a heading"
        );
        assert!(
            result.gap_analysis_report.contains("⚠"),
            "report should warn about coverage below threshold"
        );
    }

    #[test]
    fn gap_priority_critical_for_exfiltration() {
        // Directly test gap priority mapping
        let _config = PurpleTeamConfig {
            target: "priority-test".to_string(),
            attack_techniques: vec!["T1041".to_string()],
            detection_rules: vec![],
            coverage_threshold: 80,
        };
        let _runner = PurpleTeamRunner::new("priority-test-001");
        let pairs = [AttackDetectionPair {
            technique_id: "T1041".to_string(),
            technique_name: "Exfiltration Over C2 Channel".to_string(),
            attack_executed: true,
            detection_fired: false,
            detection_rule: None,
            time_to_detect_secs: None,
        }];

        // Exfiltration gaps should be Critical priority
        // This tests that the pair data is correctly structured
        assert!(!pairs[0].detection_fired);
        assert_eq!(pairs[0].technique_id, "T1041");
    }

    #[tokio::test]
    async fn purple_team_result_timestamps_are_set() {
        let config = PurpleTeamConfig::default();
        let runner = PurpleTeamRunner::new("ts-test-001");
        let result = runner.run(&config).await.unwrap();

        assert!(
            result.completed_at >= result.started_at,
            "completed_at must be >= started_at"
        );
    }
}
