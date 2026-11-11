//! 24/7 continuous attack simulator.
//!
//! This module hosts the long-running continuous simulator that polls a
//! [`scheduler::ContinuousSimulator`] for one technique dispatch at a
//! time, gated by a per-day token bucket
//! ([`budget::DailyBudget`]) and an engagement-wide
//! [`scheduler::KillSwitch`].
//!
//! The scheduler is intentionally *not* a cron — caller decides cadence
//! (e.g. a tokio interval, an external orchestrator, or a feedback loop
//! tied to telemetry). The scheduler only owns the "pick + dispatch + tick
//! the budget" step.

pub mod budget;
pub mod scheduler;
