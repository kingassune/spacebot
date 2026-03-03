//! Integration tests for the security pipeline.

#[cfg(test)]
mod pipeline_tests {
    use james::integration::pipeline::{PipelineConfig, PipelineStage, SecurityPipeline};

    #[tokio::test]
    async fn pipeline_runs_all_default_stages() {
        let config = PipelineConfig::default();
        let pipeline = SecurityPipeline::new("test-engagement-001");
        let result = pipeline.run_full_engagement(&config).await.unwrap();

        assert_eq!(result.stage_results.len(), 5, "should have 5 stages");
        assert!(result.success, "all stages should succeed");
        assert!(
            result.total_findings > 0,
            "should produce at least one finding"
        );
        assert!(
            !result.executive_summary.is_empty(),
            "summary should not be empty"
        );
    }

    #[tokio::test]
    async fn pipeline_stages_chain_in_order() {
        let config = PipelineConfig::default();
        let pipeline = SecurityPipeline::new("test-engagement-002");
        let result = pipeline.run_full_engagement(&config).await.unwrap();

        let expected_order = [
            PipelineStage::Reconnaissance,
            PipelineStage::VulnResearch,
            PipelineStage::ExploitDevelopment,
            PipelineStage::DetectionValidation,
            PipelineStage::Reporting,
        ];

        for (i, stage_result) in result.stage_results.iter().enumerate() {
            assert_eq!(
                stage_result.stage, expected_order[i],
                "stage {i} should be {:?}",
                expected_order[i]
            );
        }
    }

    #[tokio::test]
    async fn pipeline_abort_on_failure_stops_early() {
        let config = PipelineConfig {
            target: "test-target".to_string(),
            operator: "test-op".to_string(),
            stages: vec![
                PipelineStage::Reconnaissance,
                PipelineStage::VulnResearch,
                PipelineStage::Reporting,
            ],
            abort_on_failure: false,
            stage_timeout_secs: 60,
        };
        let pipeline = SecurityPipeline::new("test-engagement-003");
        let result = pipeline.run_full_engagement(&config).await.unwrap();

        assert_eq!(result.stage_results.len(), 3);
    }

    #[tokio::test]
    async fn pipeline_purple_team_runs_subset() {
        let config = PipelineConfig {
            target: "purple-target".to_string(),
            ..Default::default()
        };
        let pipeline = SecurityPipeline::new("purple-engagement-001");
        let result = pipeline.run_purple_team(&config).await.unwrap();

        // Purple team runs only recon + detection validation + reporting
        assert_eq!(result.stage_results.len(), 3);
        assert_eq!(result.stage_results[0].stage, PipelineStage::Reconnaissance);
        assert_eq!(
            result.stage_results[1].stage,
            PipelineStage::DetectionValidation
        );
        assert_eq!(result.stage_results[2].stage, PipelineStage::Reporting);
    }

    #[tokio::test]
    async fn pipeline_records_engagement_id() {
        let config = PipelineConfig::default();
        let engagement_id = "unique-engagement-xyz";
        let pipeline = SecurityPipeline::new(engagement_id);
        let result = pipeline.run_full_engagement(&config).await.unwrap();

        assert_eq!(result.engagement_id, engagement_id);
    }
}

#[cfg(test)]
mod campaign_tests {
    use james::integration::campaign::{Campaign, CampaignConfig, CampaignState};

    #[test]
    fn campaign_starts_in_planned_state() {
        let config = CampaignConfig::default();
        let campaign = Campaign::new(config);
        assert_eq!(campaign.state, CampaignState::Planned);
    }

    #[test]
    fn campaign_transitions_to_active_on_start() {
        let config = CampaignConfig::default();
        let mut campaign = Campaign::new(config);
        campaign.start();
        assert_eq!(campaign.state, CampaignState::Active);
    }

    #[test]
    fn campaign_can_be_paused_and_resumed() {
        let config = CampaignConfig::default();
        let mut campaign = Campaign::new(config);
        campaign.start();
        campaign.pause();
        assert_eq!(campaign.state, CampaignState::Paused);
        campaign.resume();
        assert_eq!(campaign.state, CampaignState::Active);
    }

    #[test]
    fn campaign_finalize_returns_result() {
        let config = CampaignConfig {
            name: "TestCampaign".to_string(),
            target: "TestOrg".to_string(),
            ..Default::default()
        };
        let campaign = Campaign::new(config);
        let result = campaign.finalize();
        assert_eq!(result.campaign_name, "TestCampaign");
        assert_eq!(result.target, "TestOrg");
        assert!(!result.executive_summary.is_empty());
    }
}
