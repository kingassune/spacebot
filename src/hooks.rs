//! Prompt hooks for observing and controlling agent behavior.

pub mod cortex;
pub mod james;

pub use cortex::CortexHook;
pub use james::JamesHook;
