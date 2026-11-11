//! `sx-autonomy` — `SentinelX` autonomy: continuous validation, auto-PR
//! remediation, and opt-in anonymised threat-network sharing.
//!
//! This crate owns three top-level capabilities (TRD §13, §3.7.3, §12 of
//! expansion items):
//!
//! 1. [`service::validation_engine::ContinuousValidationEngine`] — schedules
//!    BAS techniques against a fixed engagement on a cron-like interval and
//!    emits a [`model::validation_report::ValidationReport`] per run. The
//!    engine never bypasses the BAS safety pipeline and stops the moment the
//!    underlying simulator returns a `Killed` outcome.
//! 2. [`service::pr_generator::AutoRemediationPrGenerator`] — turns a
//!    remediation proposal into a GitHub Pull Request against a non-protected
//!    branch. Hard safety rules are enforced before any HTTP call: branch
//!    protection, diff-size ceiling, mandatory `Signed-off-by` footer, and
//!    inclusion of the finding identifier and upstream references in the PR
//!    body.
//! 3. [`service::threat_network::ThreatNetworkClient`] — lets opt-in tenants
//!    contribute anonymised vulnerability-frequency observations to a global
//!    ledger. Tenant identifiers and asset identifiers are hashed with a
//!    per-platform pepper, counts only are transmitted, and HTTPS is required.
//!
//! # Safety contract
//!
//! - `#![forbid(unsafe_code)]` (also enforced workspace-wide).
//! - No `unwrap`, `expect`, or `panic!` on production paths — every error
//!   flows through [`error::AutonomyError`].
//! - The PR generator refuses to push to `main`, `master`, or any branch
//!   matching `^(release|prod)/.*`, and refuses diffs above
//!   [`service::pr_generator::PrGeneratorConfig::max_diff_loc`] (default 200).
//! - The threat-network client refuses non-HTTPS endpoints and submissions
//!   without an explicit [`model::consent::TenantConsent`] artifact whose
//!   scope covers vulnerability-frequency sharing.
//!
//! See the [`prelude`] module for typical call-site imports.

#![forbid(unsafe_code)]

pub mod continuous;
pub mod controller;
pub mod error;
pub mod gtn;
pub mod model;
pub mod prelude;
pub mod redteam;
pub mod service;

pub use crate::error::AutonomyError;
