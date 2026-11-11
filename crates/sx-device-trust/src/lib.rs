//! # sx-device-trust — Device posture + per-tenant device-trust evaluator.
//!
//! Implements P2-008 (Device trust + posture check) of the security-gap
//! remediation plan. A posture signal is a signed JWT carried on every
//! authenticated request via the `X-Sentinelx-Device-Posture` header. The
//! middleware in `sx-api` decodes & validates the JWT; this crate owns:
//!
//! * the [`posture`] claim model (OS info, disk-encryption claim, screen-lock,
//!   EDR presence, ...),
//! * the [`policy`] model (per-tenant allow/block lists + minimum OS versions),
//! * the evaluation engine in [`service`] that turns a `(tenant, claims)`
//!   tuple into a [`service::DeviceTrustDecision`].
//!
//! ## Security posture
//!
//! * `#![forbid(unsafe_code)]`.
//! * No `.unwrap()` / `.expect()` / `panic!` in non-test code.
//! * Posture claims default to **least-trust**: a missing signal counts as
//!   "untrusted" rather than "trusted by default".
//! * Header JWTs are bounded by a `max_age_seconds` window (default = 3600,
//!   one hour) to make stale snapshots stand out as `Stale`.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod policy;
pub mod posture;
pub mod service;

pub use crate::policy::{PosturePolicy, PostureRule};
pub use crate::posture::{PostureClaims, PostureJwtError};
pub use crate::service::{
    DeviceTrustDecision, DeviceTrustService, DeviceTrustStatus, InMemoryDeviceTrustService,
};
