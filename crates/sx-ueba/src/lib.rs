//! `sx-ueba` — freeze-aware UEBA baseline orchestration (HIGH-010).
//!
//! This crate sits **on top of** the statistical primitives in
//! [`sx_soc::ueba`] and adds operator-controlled baseline lifecycle:
//!
//! - [`BaselineState::Learning`] — observe events, accumulate stats, do **not**
//!   score (so cold-start users don't fire a stream of false alerts).
//! - [`BaselineState::Active`] — score every event against the running baseline
//!   and fold the event back into it (today's behaviour).
//! - [`BaselineState::Frozen`] — score every event against the **snapshot at
//!   freeze-time**; new events MUST NOT update the underlying baseline. This
//!   is the core anti-poisoning lever: an operator who suspects an attacker is
//!   slowly drifting a user's baseline can freeze it, contain the incident,
//!   and only later thaw back to `Active` once the drift detector has confirmed
//!   the user's "true" behaviour has not silently shifted.
//!
//! The crate keeps the original [`sx_soc::ueba::service::UebaService`] trait
//! intact — every existing SOC adapter call site still works — and layers a
//! new [`FreezeAwareUebaService`] over it that the API admin endpoints (and
//! the SOC event ingest path) wire through.
//!
//! # State transitions
//!
//! ```text
//!                                  freeze
//!     Learning ──promote──►  Active ────────►  Frozen
//!         ▲                     ▲                 │
//!         │                     │                 │
//!         └─────reset───────────┴────unfreeze─────┘
//!                                     (with drift scan)
//! ```
//!
//! - `Learning → Active` is the natural "warm-up complete" transition. The
//!   service auto-promotes once the warm-up sample threshold is crossed,
//!   but operators can also force it via the admin endpoint.
//! - `Active → Frozen` snapshots the current baseline and routes subsequent
//!   events through the snapshot only; the live baseline is not mutated
//!   while frozen.
//! - `Frozen → Active` runs the drift detector: every counter that has
//!   diverged from the frozen snapshot by more than 3σ on the matching
//!   dimension is emitted as a [`DriftFinding`] for SOC follow-up. The
//!   detector compares the **frozen snapshot** to the live baseline as it
//!   stood **the moment freeze was requested** (post-snapshot writes were
//!   blocked, so they don't exist) — i.e. the drift is bounded to the time
//!   window the operator wants to scrutinise. Because the spec says
//!   "anything > 3σ from the unfrozen baseline" we use the snapshot's own
//!   moments as the reference distribution.
//!
//! # Audit
//!
//! Every state transition is recorded via the [`UebaAuditSink`] port. A
//! [`TracingUebaAuditSink`] implementation is provided that emits structured
//! `tracing::info!` events on the `ueba.audit` target; the monolith
//! composition root substitutes a real [`sx_audit::prelude::AuditSink`]-backed
//! adapter when wired.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod audit;
pub mod drift;
pub mod findings;
pub mod service;
pub mod snapshot;
pub mod state;

pub use audit::{CapturingUebaAuditSink, TracingUebaAuditSink, UebaAuditEvent, UebaAuditSink};
pub use drift::{detect_drift, DriftFinding, DRIFT_SIGMA_THRESHOLD};
pub use findings::{CapturingFindingPipelineSink, FindingPipelineSink, NullFindingPipelineSink};
pub use service::{
    BaselineStateView, FreezeAwareUebaService, FreezeAwareUebaServiceImpl, FreezeError,
    FrozenBaselineSnapshot, LEARNING_WARMUP_SAMPLES,
};
pub use snapshot::BaselineSnapshot;
pub use state::BaselineState;
