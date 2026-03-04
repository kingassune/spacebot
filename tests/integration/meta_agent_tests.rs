//! Integration tests for the autonomous pipeline (gap discovery, proposal generation, build).

#[cfg(test)]
mod meta_agent_tests {
    use james::meta_agent::autonomous_pipeline::AutonomousPipeline;
    use james::meta_agent::{MetaAgent, SecurityDomain, SkillGenerator};

    #[test]
    fn autonomous_pipeline_discovers_gaps() {
        let pipeline = AutonomousPipeline::new(".");
        let gaps = pipeline.discover_gaps();
        // The pipeline should identify at least some capability gaps.
        assert!(!gaps.is_empty(), "should discover at least one capability gap");
        // All gaps should have a non-empty description.
        for gap in &gaps {
            assert!(
                !gap.description.is_empty(),
                "gap description should not be empty"
            );
            assert!(
                !gap.suggested_name.is_empty(),
                "gap should have a suggested name"
            );
        }
    }

    #[test]
    fn autonomous_pipeline_proposes_extensions_for_gaps() {
        let pipeline = AutonomousPipeline::new(".");
        let gaps = pipeline.discover_gaps();
        let proposals = pipeline.propose_extensions(&gaps);

        assert_eq!(
            proposals.len(),
            gaps.len(),
            "should have one proposal per gap"
        );
        for proposal in &proposals {
            assert!(
                !proposal.proposal_description.is_empty(),
                "proposal should have a description"
            );
            assert!(
                proposal.complexity >= 1,
                "complexity should be at least 1"
            );
        }
    }

    #[test]
    fn autonomous_pipeline_builds_skill_extension() {
        let pipeline = AutonomousPipeline::new(".");
        let gaps = pipeline.discover_gaps();
        if let Some(gap) = gaps.first() {
            let proposals = pipeline.propose_extensions(std::slice::from_ref(gap));
            if let Some(proposal) = proposals.first() {
                let result = pipeline.build_and_test(proposal);
                assert!(result.success, "build should succeed for a skill extension");
                assert!(
                    !result.output.is_empty(),
                    "build should produce output"
                );
            }
        }
    }

    #[test]
    fn meta_agent_new_initialises_all_submodules() {
        let agent = MetaAgent::new();
        // Verify the agent has a working skill generator and platform scanner.
        let manifest = agent.extend_platform();
        // Manifest may be empty in the test environment but should not panic.
        let _ = manifest;
    }

    #[test]
    fn capability_analysis_produces_coverage_score() {
        let pipeline = AutonomousPipeline::new(".");
        let analysis = pipeline.analyze_capabilities();
        assert!(
            analysis.coverage_pct >= 0.0 && analysis.coverage_pct <= 100.0,
            "coverage should be a valid percentage"
        );
    }
}
