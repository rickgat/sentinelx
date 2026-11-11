//! A single scanner's output for a single target.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::contracts::ScopeTarget;
use crate::model::observation::Observation;
use crate::service::scanner::ScannerId;

/// Time-bounded collection of [`Observation`]s produced by one scanner run.
///
/// `Eq` was dropped in TOP5-#3 Phase 1 when the contained
/// [`Observation::HttpVulnerability`] gained an optional CVSS payload
/// (which carries a non-`Eq` `f64`). `PartialEq` is preserved so tests
/// can still compare scan results structurally.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScanResult {
    /// Scanner that produced the observations.
    pub scanner_id: ScannerId,
    /// Target the scan ran against.
    pub target: ScopeTarget,
    /// Facts emitted by the scanner.
    pub observations: Vec<Observation>,
    /// When the scan started.
    #[serde(with = "time::serde::rfc3339")]
    pub started_at: OffsetDateTime,
    /// When the scan ended — `started_at <= ended_at`.
    #[serde(with = "time::serde::rfc3339")]
    pub ended_at: OffsetDateTime,
}

impl ScanResult {
    /// Number of observations recorded.
    #[must_use]
    pub const fn observation_count(&self) -> usize {
        self.observations.len()
    }

    /// Wall-clock duration of the scan.
    #[must_use]
    pub fn duration(&self) -> time::Duration {
        self.ended_at - self.started_at
    }
}
