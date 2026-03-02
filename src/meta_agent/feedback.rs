//! Feedback loop management for iterative skill improvement.

use chrono::{DateTime, Utc};

#[derive(Debug, Clone)]
pub struct FeedbackLoop {
    pub id: String,
    pub iteration: u32,
    pub max_iterations: u32,
    pub converged: bool,
    last_delta: f64,
}

#[derive(Debug, Clone)]
pub struct FeedbackEntry {
    pub iteration: u32,
    pub input_quality: f64,
    pub output_quality: f64,
    pub delta: f64,
    pub timestamp: DateTime<Utc>,
}

impl FeedbackLoop {
    pub fn new(id: String, max_iterations: u32) -> Self {
        Self {
            id,
            iteration: 0,
            max_iterations,
            converged: false,
            last_delta: f64::MAX,
        }
    }

    pub fn record_feedback(&mut self, input_quality: f64, output_quality: f64) -> FeedbackEntry {
        self.iteration += 1;
        let delta = (output_quality - input_quality).abs();
        self.last_delta = delta;
        FeedbackEntry {
            iteration: self.iteration,
            input_quality,
            output_quality,
            delta,
            timestamp: Utc::now(),
        }
    }

    pub fn should_continue(&self) -> bool {
        !self.converged && self.iteration < self.max_iterations
    }

    pub fn check_convergence(&mut self, threshold: f64) {
        if self.last_delta < threshold {
            self.converged = true;
        }
    }
}

pub fn run_feedback_iteration(
    loop_def: &mut FeedbackLoop,
    input_quality: f64,
    output_quality: f64,
) -> FeedbackEntry {
    let entry = loop_def.record_feedback(input_quality, output_quality);
    loop_def.check_convergence(0.01);
    entry
}
