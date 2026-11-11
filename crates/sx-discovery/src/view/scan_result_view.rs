//! Serializable rendering of one or more [`ScanResult`]s for the API layer.

use serde::{Deserialize, Serialize};

use crate::model::scan_result::ScanResult;

/// Wire-level view of a batch of [`ScanResult`]s, plus a summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResultView {
    /// All scan results produced by the run.
    pub results: Vec<ScanResult>,
    /// Total observation count across results.
    pub total_observations: usize,
    /// Number of distinct scanners that produced output.
    pub scanners_used: usize,
}

impl ScanResultView {
    /// Build a view from a list of [`ScanResult`]s.
    #[must_use]
    pub fn from_results(results: Vec<ScanResult>) -> Self {
        let total_observations = results.iter().map(ScanResult::observation_count).sum();
        let mut ids: Vec<_> = results.iter().map(|r| r.scanner_id.clone()).collect();
        ids.sort();
        ids.dedup();
        let scanners_used = ids.len();
        Self {
            results,
            total_observations,
            scanners_used,
        }
    }
}
