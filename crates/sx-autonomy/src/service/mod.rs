//! Service layer.
//!
//! - [`scheduler`] — tick driver / shutdown signal used by the engine.
//! - [`validation_engine`] — continuous BAS validation loop.
//! - [`pr_safety`] — branch and diff-size guards for the PR generator.
//! - [`pr_generator`] — auto-remediation PR generator.
//! - [`threat_network`] — opt-in anonymised threat-network client.

pub mod pr_generator;
pub mod pr_safety;
pub mod scheduler;
pub mod threat_network;
pub mod validation_engine;
