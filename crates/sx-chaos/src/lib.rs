//! `sx-chaos` — opt-in chaos engineering hooks (P2-012).
//!
//! Provides a tiny fault-injection framework used by the HTTP middleware
//! and repository wrappers (Postgres + Redis). Faults are organised by
//! [`ChaosKind`]:
//!
//! * [`ChaosKind::Latency`] — sleep before passing through.
//! * [`ChaosKind::ErrorRate`] — random fraction returns a synthetic error.
//! * [`ChaosKind::Dependency`] — mark a backing dependency (`db`, `redis`,
//!   `external`) as either `unavailable` or timing-out so the surrounding
//!   layer can short-circuit.
//!
//! ## Activation
//!
//! Chaos is **opt-in and OFF by default**. Two layered gates must both
//! be true:
//!
//! 1. `SX_CHAOS_ENABLED=1` must be set in the process environment.
//! 2. Each `SX_CHAOS_<KIND>_FRACTION=<0..=1>` is independent. A fraction
//!    of `0.0` disables that specific kind.
//!
//! ## Production safety
//!
//! [`ChaosRegistry::from_env`] refuses to enable chaos when
//! `APP_ENV=production`. The PUT admin endpoint applies the same guard.
//!
//! See [`registry`], [`http`], [`repo`], and [`admin`] for the surfaces.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod admin;
pub mod http;
pub mod repo;

mod metrics;
pub mod model;
mod registry;
mod sampler;

pub use crate::metrics::{
    record_injection, METRIC_CHAOS_INJECTIONS, OUTCOME_DEPENDENCY_TIMEOUT,
    OUTCOME_DEPENDENCY_UNAVAILABLE, OUTCOME_ERROR, OUTCOME_LATENCY, OUTCOME_PASS,
};
pub use crate::model::{
    ChaosConfig, ChaosError, ChaosInjector, ChaosKind, ChaosOutcome, DependencyConfig,
    DependencyKind, DependencyOutcome, ErrorRateConfig, KindName, LatencyConfig, ENV_APP_ENV,
    ENV_CHAOS_DEPENDENCY_FRACTION, ENV_CHAOS_ENABLED, ENV_CHAOS_ERROR_RATE_FRACTION,
    ENV_CHAOS_LATENCY_FRACTION, PROD_ENV_VALUE,
};
pub use crate::registry::{ChaosRegistry, SharedChaosRegistry};
pub use crate::sampler::{deterministic_sampler, Sampler, ThreadRngSampler};
