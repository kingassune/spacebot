//! Integration test suite for the James unified security platform.
//!
//! Verifies cross-module behaviour including the orchestrator, purple team
//! operations, event bus, blockchain pipeline, meta-agent, and nation-state
//! simulation.

pub mod blockchain_pipeline_tests;
pub mod event_bus_tests;
pub mod meta_agent_tests;
pub mod nation_state_tests;
pub mod orchestrator_tests;
pub mod purple_team_tests;
