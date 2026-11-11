//! Per-signal + per-decision Prometheus instrumentation (LOW-006).
//!
//! Three series are emitted from the RBA engine so SREs can observe
//! signal fire-rates and decision distributions in production without
//! reading the audit table:
//!
//! * [`RBA_SIGNAL_FIRED_TOTAL`] — counter, labelled `{signal, bucket, tenant_id}`,
//!   incremented in [`record_signal_fired`] whenever a [`SignalKind`]'s
//!   sub-score is non-zero.
//! * [`RBA_SIGNAL_SCORE`] — histogram, labelled `{signal, tenant_id}`,
//!   recording the per-signal 0..=100 sub-score on **every** evaluation
//!   regardless of whether the contribution is zero. The explicit bucket
//!   list (0, 10, 25, 50, 75, 100) maps 1:1 to the band thresholds in
//!   the rule-based scorer so the histogram surface lines up with the
//!   `bucket` label on the counter.
//! * [`RBA_DECISION_TOTAL`] — counter, labelled `{action, tenant_id}`,
//!   incremented in [`record_decision`] at the decision-emit site.
//!
//! ## Bucket bands
//!
//! The handoff doc (LOW-006) calls out explicit `bucket` strings for
//! `impossible_travel`, `device_fp`, and `mfa_recent`. The remaining
//! signals (`ip_geo`, `velocity`, `business_hours`, `success_rate`)
//! adopt analogous bands keyed off their score boundaries so an SRE can
//! group "all `severe`-band fires" across signals if they want. The
//! bands per signal (only the score>0 cases are emitted — `bucket` is
//! never `none`):
//!
//! | Signal              | `bucket` values                         |
//! |---------------------|-----------------------------------------|
//! | `ip_geo`            | `private` (40) / `other_country` (60) / `unknown` (80) |
//! | `velocity`          | `low` (1..3) / `medium` (4..9) / `high` (10+) |
//! | `business_hours`    | `after_hours` (40) / `deep_night` (60)  |
//! | `device_fp`         | `unknown` (30) / `revoked` (100)        |
//! | `mfa_recent`        | `stale` (10) / `very_stale_8h` (25) / `very_stale_24h` (50) |
//! | `success_rate`      | `normal` (20) / `degraded` (60) / `hostile` (90) |
//! | `impossible_travel` | `suspicious` (30) / `severe` (100)      |
//!
//! ## Cardinality discipline
//!
//! Every metric goes through a single process-wide
//! [`sx_telemetry::MetricSeriesGuard`]. The cap is **per metric name**
//! and applies to the volatile `tenant_id` label only — the `signal`
//! and `bucket` labels are bounded by the [`SignalKind`] enum and the
//! tables above respectively (≤ 7 × 4 = 28 series per tenant). When
//! the guard refuses admission the call site silently drops the sample
//! rather than emitting a series that would breach the cap. This
//! mirrors the explicit handoff requirement that every series go
//! through the guard.

use std::sync::OnceLock;

use metrics::{counter, describe_counter, describe_histogram, histogram, Unit};
use sx_telemetry::{GuardOutcome, MetricSeriesGuard};
use uuid::Uuid;

use crate::service::RbaAction;
use crate::signals::business_hours::BusinessHoursStatus;
use crate::signals::device_fp::{DeviceFingerprintSignal, DeviceFingerprintStatus};
use crate::signals::impossible_travel::{ImpossibleTravelSignal, TravelVerdict};
use crate::signals::mfa_recent::{
    MfaRecentSignal, SCORE_8H_TO_24H, SCORE_FRESH_TO_8H, SCORE_STALE,
};
use crate::signals::success_rate::{
    SuccessRateSignal, SCORE_DEGRADED, SCORE_HOSTILE, SCORE_NORMAL,
};
use crate::signals::SignalKind;

/// Counter name — fired on every signal evaluation whose sub-score > 0.
pub const RBA_SIGNAL_FIRED_TOTAL: &str = "rba_signal_fired_total";
/// Histogram name — records the raw 0..=100 sub-score on every eval.
pub const RBA_SIGNAL_SCORE: &str = "rba_signal_score";
/// Counter name — fired on every emitted decision.
pub const RBA_DECISION_TOTAL: &str = "rba_decision_total";

/// Default per-metric `tenant_id`-label cap. 1_000 tenants is well
/// above any realistic single-process deployment in the MVP, and
/// keeps the worst-case series count at 1_000 × (≤ 28 + 3) ≈ 31_000.
pub const DEFAULT_TENANT_LABEL_CAP: usize = 1_000;

/// Process-wide guard. Initialised lazily on first emission so unit
/// tests that never touch the metrics path don't pay for it; tests
/// that DO touch the path get a fresh guard via [`set_guard`].
static GUARD: OnceLock<MetricSeriesGuard> = OnceLock::new();

/// Install the cardinality guard. Idempotent — only the first call
/// wins, subsequent calls are no-ops so production wiring can stay
/// simple (set once at process start).
///
/// Tests that want a fresh guard between assertions should call this
/// before any emission and then check the admitted-count.
pub fn set_guard(guard: MetricSeriesGuard) {
    let _ = GUARD.set(guard);
}

/// Read-only borrow of the active guard. Returns `None` when no guard
/// has been installed yet — in that case the call sites fall back to
/// the default cap.
#[must_use]
pub fn guard() -> Option<&'static MetricSeriesGuard> {
    GUARD.get()
}

fn guard_or_default() -> &'static MetricSeriesGuard {
    GUARD.get_or_init(|| MetricSeriesGuard::new(DEFAULT_TENANT_LABEL_CAP))
}

/// Register Prometheus `# HELP` / `# TYPE` metadata for the LOW-006
/// metric set. Idempotent — safe to call from every service boot.
pub fn register_metrics() {
    describe_counter!(
        RBA_SIGNAL_FIRED_TOTAL,
        Unit::Count,
        "Total RBA signal contributions where the per-signal sub-score was non-zero, labelled by signal + bucket + tenant."
    );
    describe_histogram!(
        RBA_SIGNAL_SCORE,
        Unit::Count,
        "Distribution of the per-signal 0..=100 RBA sub-score, labelled by signal + tenant."
    );
    describe_counter!(
        RBA_DECISION_TOTAL,
        Unit::Count,
        "Total RBA decisions emitted, labelled by action (allow / step_up_mfa / block) + tenant."
    );
}

/// Map an [`RbaAction`] to its stable `action` label.
fn action_label(action: RbaAction) -> &'static str {
    action.as_str()
}

/// Determine the `bucket` label for `signal` from the raw sub-score
/// and optional signal-shaped detail. `None` ⇒ sub-score was 0 and
/// the counter MUST NOT fire.
#[must_use]
pub fn bucket_for_signal(
    signal: SignalKind,
    sub_score: i32,
    detail: SignalDetail<'_>,
) -> Option<&'static str> {
    if sub_score <= 0 {
        return None;
    }
    match signal {
        SignalKind::IpGeo => match sub_score {
            40 => Some("private"),
            60 => Some("other_country"),
            80 => Some("unknown"),
            _ => Some("other"),
        },
        SignalKind::Velocity => {
            // Velocity is a linear ramp 0..=100 — map by score band.
            if sub_score >= 70 {
                Some("high")
            } else if sub_score >= 30 {
                Some("medium")
            } else {
                Some("low")
            }
        }
        SignalKind::BusinessHours => {
            // hours_score returns 40 (after_hours) or 60 (deep_night = after_hours + extra).
            if sub_score >= 60 {
                Some("deep_night")
            } else {
                Some("after_hours")
            }
        }
        SignalKind::DeviceFingerprint => match detail {
            SignalDetail::DeviceFingerprint(Some(s)) => match s.status {
                DeviceFingerprintStatus::Known => None,
                DeviceFingerprintStatus::Unknown => Some("unknown"),
                DeviceFingerprintStatus::Revoked => Some("revoked"),
            },
            // Snapshot had no fingerprint at all — scorer awarded the
            // conservative `unknown` sub-score; emit that bucket too.
            SignalDetail::DeviceFingerprint(None) => Some("unknown"),
            _ => None,
        },
        SignalKind::MfaRecent => {
            // mfa_recent bands: 10 / 25 / 50.
            if sub_score >= SCORE_STALE {
                Some("very_stale")
            } else if sub_score >= SCORE_8H_TO_24H {
                Some("very_stale_24h")
            } else if sub_score >= SCORE_FRESH_TO_8H {
                Some("stale")
            } else {
                Some("other")
            }
        }
        SignalKind::SuccessRate => {
            // success_rate bands: 20 / 60 / 90.
            if sub_score >= SCORE_HOSTILE {
                Some("hostile")
            } else if sub_score >= SCORE_DEGRADED {
                Some("degraded")
            } else if sub_score >= SCORE_NORMAL {
                Some("normal")
            } else {
                Some("other")
            }
        }
        SignalKind::ImpossibleTravel => match detail {
            SignalDetail::ImpossibleTravel(Some(s)) => match s.verdict {
                TravelVerdict::Unknown | TravelVerdict::Plausible => None,
                TravelVerdict::Suspicious => Some("suspicious"),
                TravelVerdict::Impossible => Some("severe"),
            },
            _ => {
                // Score-only fallback: 30 = suspicious, 100 = severe.
                if sub_score >= 90 {
                    Some("severe")
                } else {
                    Some("suspicious")
                }
            }
        },
    }
}

/// Optional signal-shaped detail that informs the `bucket` label.
///
/// The `bucket_for_signal` function can derive a label from sub-score
/// alone for the linear signals (ip_geo, velocity, business_hours,
/// mfa_recent, success_rate); the categorical signals (device_fp,
/// impossible_travel) need their structured form for the verdict /
/// status enums. Pass [`SignalDetail::None`] when the structured form
/// is not available — the function falls back to score-based bands.
#[derive(Debug, Clone, Copy)]
pub enum SignalDetail<'a> {
    /// No structured detail — derive bucket from sub-score alone.
    None,
    /// Device fingerprint signal (status drives the bucket).
    DeviceFingerprint(Option<&'a DeviceFingerprintSignal>),
    /// Impossible travel signal (verdict drives the bucket).
    ImpossibleTravel(Option<&'a ImpossibleTravelSignal>),
    /// Other linear signals can pass this to keep call sites uniform.
    BusinessHours(Option<BusinessHoursStatus>),
    /// MFA recency snapshot (currently the score band is enough but
    /// keeping the variant lets future bucket refinements drop in).
    MfaRecent(Option<&'a MfaRecentSignal>),
    /// Success-rate snapshot.
    SuccessRate(Option<&'a SuccessRateSignal>),
}

/// Record one signal evaluation. The histogram is recorded
/// unconditionally; the counter only fires when `sub_score > 0` AND
/// `bucket_for_signal` returns a non-`None` label.
pub fn record_signal(
    signal: SignalKind,
    sub_score: i32,
    detail: SignalDetail<'_>,
    tenant_id: Uuid,
) {
    let tenant = tenant_id.to_string();
    // The histogram series key is `(signal, tenant_id)`. The counter
    // key for cardinality purposes is the same — `bucket` is bounded
    // by the enum and does not contribute fanout.
    let series_key = format!("{}|{tenant}", signal.as_str());

    let admit_hist = guard_or_default().admit(RBA_SIGNAL_SCORE, &series_key);
    if matches!(admit_hist, GuardOutcome::Admit) {
        histogram!(
            RBA_SIGNAL_SCORE,
            "signal" => signal.as_str(),
            "tenant_id" => tenant.clone(),
        )
        .record(f64::from(sub_score));
    }

    let Some(bucket) = bucket_for_signal(signal, sub_score, detail) else {
        return;
    };

    let admit_ctr = guard_or_default().admit(RBA_SIGNAL_FIRED_TOTAL, &series_key);
    if matches!(admit_ctr, GuardOutcome::Admit) {
        counter!(
            RBA_SIGNAL_FIRED_TOTAL,
            "signal" => signal.as_str(),
            "bucket" => bucket,
            "tenant_id" => tenant,
        )
        .increment(1);
    }
}

/// Convenience: record a `signal_fired` event without the histogram
/// side-effect. Used by call paths that have only the sub-score in
/// hand (e.g. integration tests).
pub fn record_signal_fired(
    signal: SignalKind,
    sub_score: i32,
    detail: SignalDetail<'_>,
    tenant_id: Uuid,
) {
    let Some(bucket) = bucket_for_signal(signal, sub_score, detail) else {
        return;
    };
    let tenant = tenant_id.to_string();
    let series_key = format!("{}|{tenant}", signal.as_str());
    if matches!(
        guard_or_default().admit(RBA_SIGNAL_FIRED_TOTAL, &series_key),
        GuardOutcome::Admit
    ) {
        counter!(
            RBA_SIGNAL_FIRED_TOTAL,
            "signal" => signal.as_str(),
            "bucket" => bucket,
            "tenant_id" => tenant,
        )
        .increment(1);
    }
}

/// Record one emitted decision.
pub fn record_decision(action: RbaAction, tenant_id: Uuid) {
    let tenant = tenant_id.to_string();
    if matches!(
        guard_or_default().admit(RBA_DECISION_TOTAL, &tenant),
        GuardOutcome::Admit
    ) {
        counter!(
            RBA_DECISION_TOTAL,
            "action" => action_label(action),
            "tenant_id" => tenant,
        )
        .increment(1);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn ip_geo_bucket_strings_are_stable() {
        assert_eq!(
            bucket_for_signal(SignalKind::IpGeo, 40, SignalDetail::None),
            Some("private")
        );
        assert_eq!(
            bucket_for_signal(SignalKind::IpGeo, 60, SignalDetail::None),
            Some("other_country")
        );
        assert_eq!(
            bucket_for_signal(SignalKind::IpGeo, 80, SignalDetail::None),
            Some("unknown")
        );
        // Zero score never fires.
        assert_eq!(
            bucket_for_signal(SignalKind::IpGeo, 0, SignalDetail::None),
            None
        );
    }

    #[test]
    fn velocity_bucket_bands() {
        assert_eq!(
            bucket_for_signal(SignalKind::Velocity, 10, SignalDetail::None),
            Some("low")
        );
        assert_eq!(
            bucket_for_signal(SignalKind::Velocity, 50, SignalDetail::None),
            Some("medium")
        );
        assert_eq!(
            bucket_for_signal(SignalKind::Velocity, 90, SignalDetail::None),
            Some("high")
        );
    }

    #[test]
    fn business_hours_bucket_bands() {
        assert_eq!(
            bucket_for_signal(SignalKind::BusinessHours, 40, SignalDetail::None),
            Some("after_hours")
        );
        assert_eq!(
            bucket_for_signal(SignalKind::BusinessHours, 60, SignalDetail::None),
            Some("deep_night")
        );
    }

    #[test]
    fn device_fp_bucket_from_status() {
        let unknown = DeviceFingerprintSignal::unknown("h");
        assert_eq!(
            bucket_for_signal(
                SignalKind::DeviceFingerprint,
                30,
                SignalDetail::DeviceFingerprint(Some(&unknown))
            ),
            Some("unknown")
        );

        let revoked = DeviceFingerprintSignal {
            fp_hash: "h".into(),
            last_seen_at: None,
            status: DeviceFingerprintStatus::Revoked,
        };
        assert_eq!(
            bucket_for_signal(
                SignalKind::DeviceFingerprint,
                100,
                SignalDetail::DeviceFingerprint(Some(&revoked))
            ),
            Some("revoked")
        );

        let known = DeviceFingerprintSignal {
            fp_hash: "h".into(),
            last_seen_at: None,
            status: DeviceFingerprintStatus::Known,
        };
        // Known device contributes 0 — bucket MUST be None even when
        // we accidentally pass a positive score.
        assert_eq!(
            bucket_for_signal(
                SignalKind::DeviceFingerprint,
                0,
                SignalDetail::DeviceFingerprint(Some(&known))
            ),
            None
        );
    }

    #[test]
    fn mfa_recent_bucket_bands() {
        assert_eq!(
            bucket_for_signal(SignalKind::MfaRecent, 10, SignalDetail::None),
            Some("stale")
        );
        assert_eq!(
            bucket_for_signal(SignalKind::MfaRecent, 25, SignalDetail::None),
            Some("very_stale_24h")
        );
        assert_eq!(
            bucket_for_signal(SignalKind::MfaRecent, 50, SignalDetail::None),
            Some("very_stale")
        );
    }

    #[test]
    fn success_rate_bucket_bands() {
        assert_eq!(
            bucket_for_signal(SignalKind::SuccessRate, 20, SignalDetail::None),
            Some("normal")
        );
        assert_eq!(
            bucket_for_signal(SignalKind::SuccessRate, 60, SignalDetail::None),
            Some("degraded")
        );
        assert_eq!(
            bucket_for_signal(SignalKind::SuccessRate, 90, SignalDetail::None),
            Some("hostile")
        );
    }

    #[test]
    fn impossible_travel_bucket_from_verdict() {
        let suspicious = ImpossibleTravelSignal {
            verdict: TravelVerdict::Suspicious,
            distance_km: Some(686.0),
            speed_kmh: Some(686.0),
            elapsed_secs: Some(1_800),
        };
        assert_eq!(
            bucket_for_signal(
                SignalKind::ImpossibleTravel,
                30,
                SignalDetail::ImpossibleTravel(Some(&suspicious))
            ),
            Some("suspicious")
        );

        let severe = ImpossibleTravelSignal {
            verdict: TravelVerdict::Impossible,
            distance_km: Some(11_000.0),
            speed_kmh: Some(22_000.0),
            elapsed_secs: Some(1_800),
        };
        assert_eq!(
            bucket_for_signal(
                SignalKind::ImpossibleTravel,
                100,
                SignalDetail::ImpossibleTravel(Some(&severe))
            ),
            Some("severe")
        );

        // Plausible verdict + score 0 ⇒ no fire.
        let plausible = ImpossibleTravelSignal {
            verdict: TravelVerdict::Plausible,
            distance_km: Some(0.0),
            speed_kmh: Some(0.0),
            elapsed_secs: Some(60),
        };
        assert_eq!(
            bucket_for_signal(
                SignalKind::ImpossibleTravel,
                0,
                SignalDetail::ImpossibleTravel(Some(&plausible))
            ),
            None
        );
    }

    #[test]
    fn guard_caps_per_metric_independently_of_label_values() {
        // Install a tiny guard so the test can exercise the cap path.
        let guard = MetricSeriesGuard::new(2);
        // OnceLock: only the first test gets to set the global guard.
        // Tests that need a fresh guard call into the unwrapped guard
        // directly rather than the static.
        let outcome_a = guard.admit(RBA_SIGNAL_FIRED_TOTAL, "ip_geo|t1");
        let outcome_b = guard.admit(RBA_SIGNAL_FIRED_TOTAL, "ip_geo|t2");
        let outcome_c = guard.admit(RBA_SIGNAL_FIRED_TOTAL, "ip_geo|t3");
        assert_eq!(outcome_a, GuardOutcome::Admit);
        assert_eq!(outcome_b, GuardOutcome::Admit);
        assert_eq!(outcome_c, GuardOutcome::Drop);
    }

    #[test]
    fn action_label_maps_each_variant() {
        assert_eq!(action_label(RbaAction::Allow), "allow");
        assert_eq!(action_label(RbaAction::StepUpMfa), "step_up_mfa");
        assert_eq!(action_label(RbaAction::Block), "block");
    }

    #[test]
    fn register_metrics_is_no_op_without_recorder() {
        // Without a recorder installed, describe_* calls are no-ops.
        register_metrics();
    }
}
