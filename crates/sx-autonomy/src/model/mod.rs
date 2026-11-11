//! Domain model for the autonomy crate.
//!
//! - [`schedule`] — the cron-like schedule descriptor for the validation
//!   engine.
//! - [`validation_report`] — per-run pass/fail records emitted by the engine.
//! - [`pr_proposal`] — repo target + file-change set fed into the PR
//!   generator.
//! - [`consent`] — opt-in artifact required before a tenant may share with
//!   the threat network.
//! - [`threat_share`] — anonymised observation payload submitted upstream.

pub mod consent;
pub mod pr_proposal;
pub mod schedule;
pub mod threat_share;
pub mod validation_report;
