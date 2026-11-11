//! UEBA anomaly detector.
//!
//! Given an event and the user's current baseline, [`detect_anomaly`]
//! returns the per-dimension anomaly attribution and the aggregate score.
//!
//! Detection rules (MVP):
//!
//! 1. **Login hour z-score** — if `total_login_samples >= 5` (warm-up) and
//!    the bucket count's deviation from the mean exceeds 3 sigma in the
//!    *low* direction (rare hour), flag it. The MVP treats z-score above
//!    3.0 as anomalous; an empty bucket at warm-up is treated as
//!    "infinitely rare" and yields a fixed score of `4.0`.
//! 2. **Brand-new /16 prefix** — flag `4.0` if the event's prefix has never
//!    been seen before for this user.
//! 3. **Brand-new asset id** — flag `4.0` if the asset has never been seen
//!    before for this user.
//!
//! Severity buckets (cf. [`severity_from_score`]):
//!
//! - `>= 5.0` → `High`
//! - `>= 3.0` → `Medium`
//! - else     → `Low`

use serde::{Deserialize, Serialize};

use crate::alert::Severity;
use crate::ueba::baseline::{ip_prefix_16, UebaEvent, UserBehaviorBaseline};

/// Minimum number of login samples before we trust the z-score statistic.
///
/// Below this threshold the hour-of-day dimension is silenced so first-time
/// users do not generate a stream of "rare hour" anomalies.
pub const HOUR_WARMUP_SAMPLES: u32 = 5;

/// Score threshold separating Low / Medium severity.
pub const SCORE_MEDIUM: f64 = 3.0;
/// Score threshold separating Medium / High severity.
pub const SCORE_HIGH: f64 = 5.0;

/// One anomaly dimension attribution.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AnomalyDim {
    /// Dimension name: `hour_of_day` | `source_ip_prefix` | `asset_id`.
    pub dimension: String,
    /// Per-dimension score (higher = more anomalous).
    pub score: f64,
    /// Single-line human reason rendered into [`crate::alert::Alert::description`].
    pub reason: String,
}

/// Aggregate UEBA anomaly attributed across dimensions.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UebaAnomaly {
    /// Aggregate anomaly score — the maximum of the per-dimension scores.
    pub score: f64,
    /// Per-dimension breakdown. Non-empty by construction (the detector
    /// returns `None` when no dimension triggered).
    pub dimensions: Vec<AnomalyDim>,
    /// Severity bucket derived from `score`.
    pub severity: Severity,
}

/// Run the three MVP detectors over `event` given the user's `baseline`.
///
/// Returns `None` when no dimension fires. Returns a populated
/// [`UebaAnomaly`] when at least one dimension triggers; `score` is the
/// maximum across dimensions and `severity` is derived from it.
#[must_use]
pub fn detect_anomaly(baseline: &UserBehaviorBaseline, event: &UebaEvent) -> Option<UebaAnomaly> {
    let mut dims: Vec<AnomalyDim> = Vec::with_capacity(3);

    // ---- hour-of-day ----------------------------------------------------
    let total = baseline.total_login_samples();
    if total >= HOUR_WARMUP_SAMPLES {
        // `time::OffsetDateTime::hour()` returns `u8` strictly in `0..=23`,
        // so the bucket lookup is bounds-safe via `.get(..)`.
        let hour = event.occurred_at.hour();
        if let Some(&count) = baseline.login_hours_histogram.get(usize::from(hour)) {
            let bucket = f64::from(count);
            let mean = baseline.login_hour_mean();
            let stddev = baseline.login_hour_stddev();
            // An empty bucket post-warm-up means the user has never logged
            // in at this hour before — treat as the canonical max score.
            if bucket <= f64::EPSILON {
                dims.push(AnomalyDim {
                    dimension: "hour_of_day".into(),
                    score: 4.0,
                    reason: format!("first login observed at hour {hour} UTC"),
                });
            } else {
                let denom = if stddev > f64::EPSILON { stddev } else { 1.0 };
                let z = (mean - bucket) / denom;
                if z > 3.0 {
                    dims.push(AnomalyDim {
                        dimension: "hour_of_day".into(),
                        score: z,
                        reason: format!(
                            "hour {hour} UTC is {z:.2} sigma below mean ({bucket} vs μ={mean:.2})",
                        ),
                    });
                }
            }
        }
    }

    // ---- source IP /16 prefix ------------------------------------------
    if let Some(ip) = event.source_ip.as_deref() {
        if let Some(prefix) = ip_prefix_16(ip) {
            if !baseline.ip_prefixes.contains_key(&prefix) {
                dims.push(AnomalyDim {
                    dimension: "source_ip_prefix".into(),
                    score: 4.0,
                    reason: format!("first observation of prefix {prefix}"),
                });
            }
        }
    }

    // ---- accessed asset id ---------------------------------------------
    if let Some(asset) = event.asset_id.as_deref() {
        if !baseline.accessed_assets.contains_key(asset) {
            dims.push(AnomalyDim {
                dimension: "asset_id".into(),
                score: 4.0,
                reason: format!("first access to asset {asset}"),
            });
        }
    }

    if dims.is_empty() {
        return None;
    }
    let score = dims
        .iter()
        .map(|d| d.score)
        .fold(0.0_f64, |a, b| if b > a { b } else { a });
    let severity = severity_from_score(score);
    Some(UebaAnomaly {
        score,
        dimensions: dims,
        severity,
    })
}

/// Map an anomaly score onto the canonical [`Severity`] bucket.
#[must_use]
pub fn severity_from_score(score: f64) -> Severity {
    if score >= SCORE_HIGH {
        Severity::High
    } else if score >= SCORE_MEDIUM {
        Severity::Medium
    } else {
        Severity::Low
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::ueba::update::update_baseline_from_event;
    use time::macros::datetime;

    fn event_at(hour: u8, ip: Option<&str>, asset: Option<&str>) -> UebaEvent {
        let dt = datetime!(2027-01-01 0:00:00 UTC)
            .replace_hour(hour)
            .unwrap();
        let mut e = UebaEvent::new("u", dt);
        e.source_ip = ip.map(str::to_owned);
        e.asset_id = asset.map(str::to_owned);
        e
    }

    #[test]
    fn empty_baseline_skips_hour_until_warmup() {
        let base = UserBehaviorBaseline::new(None, "u");
        let evt = event_at(3, None, None);
        // Hour silenced before warm-up + no IP/asset to fire → None.
        assert!(detect_anomaly(&base, &evt).is_none());
    }

    #[test]
    fn brand_new_ip_prefix_fires() {
        let base = UserBehaviorBaseline::new(None, "u");
        let evt = event_at(3, Some("198.51.100.7"), None);
        let an = detect_anomaly(&base, &evt).expect("should fire");
        assert!(matches!(an.severity, Severity::Medium));
        assert!(an
            .dimensions
            .iter()
            .any(|d| d.dimension == "source_ip_prefix"));
    }

    #[test]
    fn brand_new_asset_fires() {
        let base = UserBehaviorBaseline::new(None, "u");
        let evt = event_at(3, None, Some("crown-jewel-1"));
        let an = detect_anomaly(&base, &evt).expect("should fire");
        assert!(an.dimensions.iter().any(|d| d.dimension == "asset_id"));
    }

    #[test]
    fn rare_hour_fires_after_warmup() {
        let mut base = UserBehaviorBaseline::new(None, "u");
        // Seed 50 logins at hour 9 (typical 9-to-5 user).
        for i in 0..50 {
            let mut e = event_at(9, None, None);
            e.event_id = Some(format!("seed-{i}"));
            let _ = update_baseline_from_event(&mut base, &e);
        }
        // Now a 3am login should fire — empty bucket post-warm-up.
        let evt = event_at(3, None, None);
        let an = detect_anomaly(&base, &evt).expect("rare hour should fire");
        assert!(an.dimensions.iter().any(|d| d.dimension == "hour_of_day"));
    }

    #[test]
    fn typical_hour_does_not_fire() {
        let mut base = UserBehaviorBaseline::new(None, "u");
        // Even with a flat warm-up across 9-17, a fresh 10am login is not
        // anomalous because the bucket is non-empty and the z-score is
        // bounded.
        for (i, h) in (9_u8..18).enumerate() {
            for j in 0..3 {
                let mut e = event_at(h, None, None);
                e.event_id = Some(format!("seed-{i}-{j}"));
                let _ = update_baseline_from_event(&mut base, &e);
            }
        }
        // Seed the IP too so the IP dim does not fire.
        let mut warm = event_at(10, Some("10.0.0.1"), None);
        warm.event_id = Some("warm-ip".into());
        let _ = update_baseline_from_event(&mut base, &warm);

        let evt = event_at(10, Some("10.0.0.2"), None); // same /16 prefix
        assert!(detect_anomaly(&base, &evt).is_none());
    }

    #[test]
    fn severity_thresholds_round_correctly() {
        assert!(matches!(severity_from_score(6.0), Severity::High));
        assert!(matches!(severity_from_score(5.0), Severity::High));
        assert!(matches!(severity_from_score(4.999), Severity::Medium));
        assert!(matches!(severity_from_score(3.0), Severity::Medium));
        assert!(matches!(severity_from_score(2.999), Severity::Low));
        assert!(matches!(severity_from_score(0.0), Severity::Low));
    }

    #[test]
    fn aggregate_score_takes_max_dimension() {
        let base = UserBehaviorBaseline::new(None, "u");
        let evt = event_at(3, Some("198.51.100.7"), Some("crown"));
        let an = detect_anomaly(&base, &evt).expect("should fire");
        // Both dims contribute 4.0 → aggregate 4.0.
        assert!((an.score - 4.0).abs() < 1e-9);
    }
}
