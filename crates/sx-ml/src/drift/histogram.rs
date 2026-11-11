//! Empirical histograms used by the drift detector.
//!
//! A [`Histogram`] is a thin wrapper around `bins: Vec<f64>` (the bin
//! edges) and `counts: Vec<u64>` (the per-bin count). For `n` bins we
//! expect `bins.len() == n + 1` edges, sorted strictly ascending.
//!
//! NaN samples are silently skipped (and counted in a `warn` log). Samples
//! outside the bin range are clamped to the first / last bin so the
//! histogram is always a proper probability mass distribution.

use serde::{Deserialize, Serialize};
use tracing::warn;

/// A binned empirical distribution.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Histogram {
    /// Bin edges, strictly ascending. `bins.len()` should equal
    /// `counts.len() + 1`.
    pub bins: Vec<f64>,
    /// One count per bin (`bins.len() - 1` entries).
    pub counts: Vec<u64>,
}

impl Histogram {
    /// Build a histogram from `samples` using the provided `bin_edges`.
    ///
    /// `bin_edges` must contain at least two strictly ascending values; if
    /// it does not, an empty histogram (no bins, no counts) is returned so
    /// callers never panic.
    ///
    /// NaN samples are skipped. Samples below the first edge are placed
    /// in the first bin; samples at or above the last edge are placed in
    /// the last bin. The right-most edge is inclusive so the canonical
    /// `[a, b)` half-open scheme still captures `x == last_edge`.
    #[must_use]
    pub fn from_samples(samples: &[f64], bin_edges: &[f64]) -> Self {
        // Validate bin edges: strictly ascending, len >= 2.
        if bin_edges.len() < 2 {
            return Self {
                bins: Vec::new(),
                counts: Vec::new(),
            };
        }
        for i in 1..bin_edges.len() {
            let prev = bin_edges.get(i.saturating_sub(1)).copied().unwrap_or(0.0);
            let curr = bin_edges.get(i).copied().unwrap_or(0.0);
            if !(prev.is_finite() && curr.is_finite()) || curr <= prev {
                return Self {
                    bins: Vec::new(),
                    counts: Vec::new(),
                };
            }
        }

        let n_bins = bin_edges.len().saturating_sub(1);
        let mut counts = vec![0_u64; n_bins];
        let last_idx = n_bins.saturating_sub(1);

        let mut skipped_nan = 0_u64;
        for &sample in samples {
            if sample.is_nan() {
                skipped_nan = skipped_nan.saturating_add(1);
                continue;
            }
            // Clamp +/- inf to the extremes.
            let bin = locate_bin(sample, bin_edges).unwrap_or_else(|| {
                if sample.is_sign_negative() {
                    0
                } else {
                    last_idx
                }
            });
            let bin = bin.min(last_idx);
            if let Some(slot) = counts.get_mut(bin) {
                *slot = slot.saturating_add(1);
            }
        }
        if skipped_nan > 0 {
            warn!(
                target: "sx_ml::drift",
                skipped = skipped_nan,
                "NaN samples skipped while building Histogram"
            );
        }

        Self {
            bins: bin_edges.to_vec(),
            counts,
        }
    }

    /// Number of bins.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.counts.len()
    }

    /// `true` if there are no bins.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.counts.is_empty()
    }

    /// Total observation count across all bins.
    #[must_use]
    pub fn total(&self) -> u64 {
        self.counts
            .iter()
            .fold(0_u64, |acc, c| acc.saturating_add(*c))
    }

    /// Per-bin probabilities (counts / total). Returns an empty vector if
    /// the histogram has no bins or zero total.
    #[must_use]
    pub fn probabilities(&self) -> Vec<f64> {
        let total = self.total();
        if total == 0 || self.counts.is_empty() {
            return vec![0.0_f64; self.counts.len()];
        }
        #[allow(clippy::cast_precision_loss)]
        let denom = total as f64;
        self.counts
            .iter()
            .map(|c| {
                #[allow(clippy::cast_precision_loss)]
                let v = *c as f64;
                v / denom
            })
            .collect()
    }
}

/// Locate the bin index for `x` given strictly-ascending `edges`.
/// Returns `None` if `x` is not finite.
fn locate_bin(x: f64, edges: &[f64]) -> Option<usize> {
    if !x.is_finite() {
        return None;
    }
    let n_bins = edges.len().saturating_sub(1);
    if n_bins == 0 {
        return None;
    }
    // Clamp below first edge.
    let first = edges.first().copied().unwrap_or(0.0);
    if x < first {
        return Some(0);
    }
    // Clamp at-or-above last edge.
    let last = edges.last().copied().unwrap_or(0.0);
    if x >= last {
        return Some(n_bins.saturating_sub(1));
    }
    // Linear scan is fine for small histograms; binary search would be
    // appropriate at scale but we keep the implementation dependency-free
    // and obvious.
    for i in 0..n_bins {
        let lo = edges.get(i).copied().unwrap_or(0.0);
        let hi = edges.get(i.saturating_add(1)).copied().unwrap_or(0.0);
        if x >= lo && x < hi {
            return Some(i);
        }
    }
    Some(n_bins.saturating_sub(1))
}
