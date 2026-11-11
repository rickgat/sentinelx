//! Kullback–Leibler divergence between two empirical histograms.
//!
//! Formula:
//!
//! ```text
//! D_KL(P || Q) = sum_i P_i * ln( P_i / Q_i )
//! ```
//!
//! To keep the result finite when some bins are empty we apply Laplace
//! smoothing — every bin receives a virtual `+epsilon` count before the
//! probabilities are normalised. `epsilon = 1e-12` by default.
//!
//! Histograms are required to have the same number of bins; if they do
//! not, the smaller width dictates the loop and the trailing bins of the
//! larger histogram are ignored. An empty pair returns `0.0`.

use serde::{Deserialize, Serialize};

use super::histogram::Histogram;

const SMOOTHING_EPSILON: f64 = 1.0e-12;

/// Compute `D_KL(p || q)` between two histograms.
///
/// Returns `0.0` for empty histograms or when both distributions are
/// identical. The result is non-negative and finite.
#[must_use]
pub fn kl_divergence(p: &Histogram, q: &Histogram) -> f64 {
    let n = p.len().min(q.len());
    if n == 0 {
        return 0.0;
    }

    let p_probs = smoothed_probabilities(&p.counts, n);
    let q_probs = smoothed_probabilities(&q.counts, n);

    let mut acc = 0.0_f64;
    for i in 0..n {
        let pi = p_probs.get(i).copied().unwrap_or(0.0);
        let qi = q_probs.get(i).copied().unwrap_or(SMOOTHING_EPSILON);
        if pi <= 0.0 {
            continue;
        }
        // After smoothing, qi is guaranteed > 0.
        let ratio = pi / qi;
        if ratio > 0.0 && ratio.is_finite() {
            acc += pi * ratio.ln();
        }
    }

    // Numerical noise can push identical distributions to a tiny negative
    // value; clamp to zero so callers can compare against thresholds
    // safely.
    if acc < 0.0 {
        0.0
    } else {
        acc
    }
}

/// Apply additive (Laplace) smoothing and normalise to a probability mass
/// vector of length `n`.
fn smoothed_probabilities(counts: &[u64], n: usize) -> Vec<f64> {
    let mut out = vec![SMOOTHING_EPSILON; n];
    let mut total = 0.0_f64;
    for (i, c) in counts.iter().take(n).enumerate() {
        #[allow(clippy::cast_precision_loss)]
        let v = *c as f64 + SMOOTHING_EPSILON;
        if let Some(slot) = out.get_mut(i) {
            *slot = v;
        }
        total += v;
    }
    // Pad shorter inputs.
    if counts.len() < n {
        for i in counts.len()..n {
            if let Some(slot) = out.get_mut(i) {
                *slot = SMOOTHING_EPSILON;
            }
            total += SMOOTHING_EPSILON;
        }
    }
    if total > 0.0 {
        for p in &mut out {
            *p /= total;
        }
    }
    out
}

/// Drift report — divergence with a caller-supplied threshold.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub struct DriftReport {
    /// `D_KL(p || q)` between the reference (`p`) and current (`q`)
    /// distributions.
    pub divergence: f64,
    /// Threshold the caller considers significant.
    pub threshold: f64,
    /// `divergence > threshold`.
    pub exceeds_threshold: bool,
}

impl DriftReport {
    /// Build a report from two histograms and a threshold.
    #[must_use]
    pub fn from_histograms(p: &Histogram, q: &Histogram, threshold: f64) -> Self {
        let divergence = kl_divergence(p, q);
        let threshold = if threshold.is_finite() {
            threshold
        } else {
            0.0
        };
        Self {
            divergence,
            threshold,
            exceeds_threshold: divergence > threshold,
        }
    }
}
