//! Domain model for Breach & Attack Simulation.
//!
//! - [`mode`] — the [`mode::AttackMode`] ladder.
//! - [`technique`] — the [`technique::AttackTechnique`] trait + MITRE tagging.
//! - [`approval`] — dual-approval ledger and Rules of Engagement.
//! - [`window`] — change-window value object.
//! - [`simulation`] — request, outcome, and per-step plumbing.

pub mod approval;
pub mod chain;
pub mod mode;
pub mod simulation;
pub mod technique;
pub mod window;
