//! SentinelX Risk-Based Authentication engine.
//!
//! This crate implements the MVP described in P1-003 of
//! `docs/SECURITY_GAP_REMEDIATION_TASKS.md`. It exposes:
//!
//! * A collection of [`signals`] (IP geo lookup, login velocity, time-of-day
//!   business-hours check) that the login flow can compute cheaply from a
//!   single `LoginContext`.
//! * A [`scorer`] that combines those signals into a 0-100 risk score using
//!   per-tenant tunable weights.
//! * A [`service::RbaService`] that orchestrates collection + scoring,
//!   maps the score to an [`RbaAction`] (allow / step-up MFA / block) and
//!   audits every decision in an in-memory ring buffer.
//!
//! ## Why a rule-based MVP
//!
//! The acceptance criteria explicitly target a rule-based scorer with no
//! ML dependencies; that lets us ship in a single sprint while remaining
//! tunable per tenant (see [`config::RbaConfig`]). Production deployments
//! can swap in a richer model later by implementing a new [`scorer::Scorer`].
//!
//! ## Threading model
//!
//! Every type that the API layer hands an `Arc<dyn ...>` of (the service,
//! the velocity tracker, the decision log) is internally synchronised
//! with `DashMap` / `parking_lot`-style primitives. The service is
//! cheap to clone and trivially `Send + Sync`.
//!
//! ## Strict lints
//!
//! The workspace forbids `unsafe_code` and denies `unwrap_used` /
//! `expect_used` in production code paths. Test modules opt-in to
//! `clippy::unwrap_used` only where it materially shortens an assertion.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
// Pedantic / nursery nits we accept across the crate so the engine code
// stays readable. Each lint here is either purely stylistic, conflicts
// with prose-heavy module headers (`doc_markdown`), or is impractical
// for an MVP scoring kernel (`suboptimal_flops` — readability wins over
// micro-fused FMAs in the 0-100 risk arithmetic).
#![allow(
    clippy::doc_markdown,
    clippy::too_long_first_doc_paragraph,
    clippy::struct_field_names,
    clippy::enum_variant_names,
    clippy::missing_const_for_fn,
    clippy::suboptimal_flops,
    clippy::significant_drop_tightening,
    clippy::option_if_let_else,
    clippy::map_identity
)]

pub mod baseline;
pub mod config;
pub mod finding;
pub mod metrics;
pub mod scorer;
pub mod service;
pub mod signals;

pub use config::{RbaConfig, RbaFeatureFlags, RbaWeights};
pub use finding::{
    block_decision_description, RBA_HIGH_RISK_BLOCK_CHECK_ID, RBA_HIGH_RISK_BLOCK_DOTTED,
};
pub use scorer::SignalContribution;
pub use service::{
    bucket_action, DecisionAudit, EnrichedDecision, LoginContext, RbaAction, RbaDecision, RbaError,
    RbaService, SignalSnapshot,
};
pub use signals::SignalKind;
