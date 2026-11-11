//! User and Entity Behavioural Analytics (UEBA) — MVP statistical model.
//!
//! The UEBA pipeline maintains a per-user behavioural baseline derived from
//! the SOC event stream and flags individual events that deviate from the
//! baseline.
//!
//! # Baseline dimensions (MVP)
//!
//! - **Login hour-of-day** — bounded histogram with 24 buckets indexed by the
//!   UTC hour at which the user logged in.
//! - **Source IP /16 prefix** — bounded set (`<= 100`) of the most-seen
//!   `/16` prefixes the user has logged in from.
//! - **Accessed asset ids** — bounded set (`<= 100`) of asset ids the user
//!   has interacted with.
//!
//! # Anomaly model (MVP)
//!
//! Statistical only — no neural nets. An event is anomalous when **any** of:
//!
//! 1. The login-hour bucket count z-score exceeds `3.0` against the user's
//!    own histogram (rare hour-of-day).
//! 2. The source `/16` prefix has never been seen for the user before
//!    (brand-new IP block).
//! 3. The accessed asset id has never been seen for the user before
//!    (brand-new asset).
//!
//! The aggregate `score` is the maximum dimension score; severity is derived
//! from `score` via [`crate::ueba::anomaly::severity_from_score`].
//!
//! # Safety
//!
//! - No panics, no `unwrap` / `expect` outside `#[cfg(test)]`.
//! - Histograms are bounded by construction (24 buckets, 100-prefix /
//!   100-asset caps with LRU-by-least-seen eviction).
//! - Baseline updates are idempotent on duplicate events: a per-user ring of
//!   recently-seen `event_id`s is consulted before any counter mutation.

pub mod anomaly;
pub mod baseline;
pub mod service;
pub mod update;

pub use anomaly::{detect_anomaly, severity_from_score, AnomalyDim, UebaAnomaly};
pub use baseline::{UebaEvent, UserBehaviorBaseline};
pub use service::{InMemoryUebaService, UebaService};
pub use update::update_baseline_from_event;
