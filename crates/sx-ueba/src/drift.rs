//! Drift detection between a frozen baseline snapshot and the live baseline.
//!
//! Engaged on the `Frozen → Active` transition: every counter that has
//! diverged from the frozen snapshot by more than `DRIFT_SIGMA_THRESHOLD`
//! standard deviations (computed off the snapshot's own moments) is emitted
//! as a [`DriftFinding`] so SOC can investigate whether the user's
//! behaviour genuinely changed during the freeze window or whether the
//! pending unfreeze would re-open a poisoning channel.
//!
//! The detector is deliberately monotone: it scans the snapshot's
//! 24-bucket histogram and emits one finding per bucket whose magnitude
//! drift exceeds the threshold. IP-prefix and asset-id drift are reported
//! categorically (brand-new IP prefix or asset that did not exist in the
//! snapshot is always emitted as a `Medium`-severity finding because there
//! is no continuous magnitude to z-score against).

use serde::{Deserialize, Serialize};

use sx_soc::ueba::baseline::UserBehaviorBaseline;

use crate::snapshot::BaselineSnapshot;

/// Sigma threshold above which a histogram bucket counts as drift.
pub const DRIFT_SIGMA_THRESHOLD: f64 = 3.0;

/// One drift datum surfaced to SOC.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DriftFinding {
    /// Dimension label — matches the UEBA scorer's dimension codes for
    /// downstream playbook reuse: `hour_of_day`, `source_ip_prefix`,
    /// `asset_id`.
    pub dimension: String,
    /// Identifier inside the dimension (hour number stringified, prefix,
    /// asset id, etc).
    pub key: String,
    /// Counter value in the frozen snapshot.
    pub snapshot_count: u32,
    /// Counter value in the live baseline observed during the freeze (i.e.
    /// **as it stood when freeze was engaged** — frozen mode blocks live
    /// writes so this number does not advance while frozen).
    pub live_count: u32,
    /// Sigma-magnitude (|delta| / `σ_snapshot`) of the divergence, or
    /// `0.0` when the dimension is categorical (IP / asset).
    pub sigma: f64,
    /// One-line human reason rendered into the finding's `description`.
    pub reason: String,
}

/// Run drift detection between a frozen snapshot and a live baseline.
///
/// `snapshot` is the frozen one. `live` is the current in-memory baseline,
/// which under the freeze invariant should equal the snapshot — any
/// non-zero delta means writes leaked, an attacker rewound time, or the
/// operator extracted the snapshot at the wrong moment.
///
/// Returns a list of [`DriftFinding`]s suitable for routing to SOC.
#[must_use]
pub fn detect_drift(snapshot: &BaselineSnapshot, live: &UserBehaviorBaseline) -> Vec<DriftFinding> {
    let mut out: Vec<DriftFinding> = Vec::new();

    // ---- hour-of-day histogram ------------------------------------------
    let snap_mean: f64 = snapshot
        .login_hours_histogram
        .iter()
        .copied()
        .map(f64::from)
        .sum::<f64>()
        / 24.0;
    let snap_var: f64 = snapshot
        .login_hours_histogram
        .iter()
        .copied()
        .map(|c| {
            let d = f64::from(c) - snap_mean;
            d * d
        })
        .sum::<f64>()
        / 24.0;
    let snap_stddev = if snap_var > f64::EPSILON {
        snap_var.sqrt()
    } else {
        1.0
    };

    for (hour, (snap_bucket, live_bucket)) in snapshot
        .login_hours_histogram
        .iter()
        .copied()
        .zip(live.login_hours_histogram.iter().copied())
        .enumerate()
    {
        let delta = f64::from(live_bucket) - f64::from(snap_bucket);
        let sigma = delta.abs() / snap_stddev;
        if sigma > DRIFT_SIGMA_THRESHOLD {
            out.push(DriftFinding {
                dimension: "hour_of_day".into(),
                key: hour.to_string(),
                snapshot_count: snap_bucket,
                live_count: live_bucket,
                sigma,
                reason: format!(
                    "hour {hour} UTC drifted {sigma:.2}σ from frozen snapshot ({snap_bucket} → {live_bucket})",
                ),
            });
        }
    }

    // ---- /16 IP prefixes (categorical) ----------------------------------
    for (prefix, live_count) in &live.ip_prefixes {
        if !snapshot.ip_prefixes.contains_key(prefix) {
            out.push(DriftFinding {
                dimension: "source_ip_prefix".into(),
                key: prefix.clone(),
                snapshot_count: 0,
                live_count: *live_count,
                sigma: 0.0,
                reason: format!("brand-new prefix {prefix} observed since freeze"),
            });
        }
    }

    // ---- asset ids (categorical) ----------------------------------------
    for (asset, live_count) in &live.accessed_assets {
        if !snapshot.accessed_assets.contains_key(asset) {
            out.push(DriftFinding {
                dimension: "asset_id".into(),
                key: asset.clone(),
                snapshot_count: 0,
                live_count: *live_count,
                sigma: 0.0,
                reason: format!("brand-new asset {asset} observed since freeze"),
            });
        }
    }

    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use time::macros::datetime;

    fn snap_with_hour(hour: usize, count: u32) -> BaselineSnapshot {
        let mut b = UserBehaviorBaseline::new(Some("t-1".into()), "alice");
        b.login_hours_histogram[hour] = count;
        BaselineSnapshot::capture(&b, datetime!(2027-02-01 0:00:00 UTC))
    }

    #[test]
    fn identical_live_and_snapshot_yields_no_drift() {
        let snap = snap_with_hour(9, 12);
        let live = snap.as_scoring_baseline();
        let drift = detect_drift(&snap, &live);
        assert!(drift.is_empty());
    }

    #[test]
    fn large_histogram_delta_flags_drift() {
        let snap = snap_with_hour(9, 12);
        let mut live = snap.as_scoring_baseline();
        // Wildly distort hour 3: that's a brand-new login pattern.
        live.login_hours_histogram[3] = 500;
        let drift = detect_drift(&snap, &live);
        assert!(
            drift
                .iter()
                .any(|d| d.dimension == "hour_of_day" && d.key == "3"),
            "should have flagged hour 3 drift, got {drift:?}",
        );
    }

    #[test]
    fn brand_new_ip_prefix_flags_drift() {
        let snap = snap_with_hour(9, 12);
        let mut live = snap.as_scoring_baseline();
        let _ = live.ip_prefixes.insert("198.51.100.0/16".into(), 1);
        let drift = detect_drift(&snap, &live);
        assert!(
            drift
                .iter()
                .any(|d| d.dimension == "source_ip_prefix" && d.key == "198.51.100.0/16"),
            "should have flagged new /16 prefix",
        );
    }

    #[test]
    fn brand_new_asset_flags_drift() {
        let snap = snap_with_hour(9, 12);
        let mut live = snap.as_scoring_baseline();
        let _ = live.accessed_assets.insert("rogue-asset".into(), 1);
        let drift = detect_drift(&snap, &live);
        assert!(
            drift
                .iter()
                .any(|d| d.dimension == "asset_id" && d.key == "rogue-asset"),
            "should have flagged new asset",
        );
    }

    #[test]
    fn small_histogram_delta_below_threshold_is_silent() {
        // Build a histogram with substantial variance so a small delta
        // does not breach 3σ.
        let mut b = UserBehaviorBaseline::new(Some("t".into()), "u");
        for (i, slot) in b.login_hours_histogram.iter_mut().enumerate() {
            *slot = u32::try_from(i * 10).unwrap();
        }
        let snap = BaselineSnapshot::capture(&b, datetime!(2027-02-01 0:00:00 UTC));
        let mut live = snap.as_scoring_baseline();
        // Bump hour 0 by 1 — far below 3σ given the spread.
        live.login_hours_histogram[0] = live.login_hours_histogram[0].saturating_add(1);
        let drift = detect_drift(&snap, &live);
        assert!(
            drift.iter().all(|d| d.dimension != "hour_of_day"),
            "small bump should not breach threshold",
        );
    }
}
