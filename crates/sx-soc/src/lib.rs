//! `sx-soc` — autonomous SOC alert correlator and rule engine for `SentinelX`.
//!
//! This crate ingests a stream of structured events (audit events,
//! finding-update notifications, signals from BAS / discovery / autonomy) and
//! fires [`Alert`]s when configured [`Rule`]s match.
//!
//! # Architecture
//!
//! ```text
//!     mpsc::Receiver<Value>          (events)
//!             │
//!             ▼
//!     ┌──────────────┐
//!     │  Correlator  │  ── throttle state per (rule_id, tenant_id, kind)
//!     └──────────────┘
//!             │
//!             ▼
//!     ┌──────────────┐
//!     │  RuleEngine  │  ── evaluates Condition DSL against each event
//!     └──────────────┘
//!             │
//!             ▼  Vec<Alert>
//!     ┌──────────────┐
//!     │ AlertSink(s) │  ── LogAlertSink, BufferAlertSink, ... (forwarders)
//!     └──────────────┘
//! ```
//!
//! # Condition DSL grammar
//!
//! See [`rule::Condition`] for the full small-step grammar. Supported operators:
//!
//! - `Eq(field, value)` — JSON-pointer field equals scalar value.
//! - `Contains(field, substring)` — substring match on string fields.
//! - `GreaterThan(field, n)` — numeric `>` comparison.
//! - `WithinLast(duration, then)` — event must have an RFC3339 `ts` newer
//!   than (now - duration) AND the inner condition must hold.
//! - `AnyOf(vec)` — short-circuits OR.
//! - `AllOf(vec)` — short-circuits AND.
//!
//! # Safety
//!
//! - `#![forbid(unsafe_code)]`.
//! - No panics, no `unwrap`, no `expect` outside `#[cfg(test)]`.
//! - This crate does NOT touch the monolith; it is wired in by an integration
//!   layer elsewhere.

#![forbid(unsafe_code)]

pub mod alert;
pub mod correlator;
pub mod engine;
pub mod error;
pub mod rule;
pub mod rule_pack;
pub mod sink;
pub mod ueba;

pub use alert::{Alert, EvidenceRef, Severity};
pub use correlator::{Correlator, CorrelatorStats};
pub use engine::RuleEngine;
pub use error::SocError;
pub use rule::impossible_travel::{
    evaluate as evaluate_impossible_travel,
    evaluate_with_allowlist as evaluate_impossible_travel_with_allowlist, haversine_km,
    InMemoryLoginHistoryRepo, LoginHistoryRepo, LoginRecord, TenantVpnAllowlist, TravelAnomaly,
    TravelDecision,
};
pub use rule::{Condition, Rule};
pub use rule_pack::starter_pack;
pub use sink::{AlertSink, BufferAlertSink, LogAlertSink};
pub use ueba::{
    detect_anomaly, severity_from_score, update_baseline_from_event, AnomalyDim,
    InMemoryUebaService, UebaAnomaly, UebaEvent, UebaService, UserBehaviorBaseline,
};
