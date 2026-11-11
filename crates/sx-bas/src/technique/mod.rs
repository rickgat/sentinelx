//! Safe-only sample techniques.
//!
//! Every technique in this crate is wired to short-circuit to a
//! [`crate::model::simulation::StepResult::Simulated`] or
//! [`crate::model::simulation::StepResult::Skipped`] outcome — no real
//! network I/O is performed. Production wiring for OOB-collaborator
//! callbacks, HTTP probes, and credential validation lives in adapter
//! crates and is gated by feature flags that are NEVER enabled here.
//!
//! P1-008 expansion adds 25 additional safe-mode-only techniques organised
//! into tactic-scoped submodules:
//!
//! - [`initial_access`] (TA0001)
//! - [`persistence`] (TA0003)
//! - [`privilege_escalation`] (TA0004)
//! - [`credential_access`] (TA0006)
//! - [`lateral_movement`] (TA0008)

pub mod passive_cve_match;
pub mod safe_cred_validator;
pub mod safe_ssrf_probe;
pub mod theoretical_reachability;

pub mod credential_access;
pub mod initial_access;
pub mod lateral_movement;
pub mod persistence;
pub mod privilege_escalation;
