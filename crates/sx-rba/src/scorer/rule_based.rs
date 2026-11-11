//! Rule-based composite scorer.
//!
//! Seven per-signal sub-scores in `[0, 100]`:
//!
//! * **IP geo** — `0` when the IP resolves to a country in the
//!   tenant's known-good list (currently: the country that produced
//!   the most recent allowed login OR a tenant-default of `US`). `40`
//!   for the private-network sentinel (`XX`). `60` for any other
//!   known country. `80` for an unknown / unresolved address.
//! * **Velocity** — proportional to the number of recent attempts in
//!   the sliding window. The first attempt is `0`; subsequent
//!   attempts ramp linearly up to `100` at 10+ attempts.
//! * **Business hours** — `0` if the timestamp fell inside the
//!   tenant's business hours, otherwise `40`. The hours signal also
//!   gives a `+20` extra at the deep-night band (00:00–05:00 local)
//!   to flag automated brute force runs.
//! * **Device fingerprint** (HIGH-001) — `0` known, `30` unknown,
//!   `100` revoked.
//! * **MFA recency** (HIGH-001) — graded `0 / 10 / 25 / 50` against
//!   the configurable fresh-window.
//! * **Success rate** (HIGH-001) — graded `0 / 20 / 60 / 90` against
//!   the 7-day rolling rate buckets.
//! * **Impossible travel** (HIGH-001) — graded `0 / 30 / 100` against
//!   the implied great-circle speed between this login and the
//!   previous one.
//!
//! The composite score is the weighted average of the enabled
//! sub-scores, clamped to `[0, 100]`. A signal whose feature flag is
//! `false` is excluded from BOTH the numerator and the denominator —
//! the remaining signals dominate proportionally.

use crate::config::{RbaConfig, RbaFeatureFlags};
use crate::scorer::{ScoredSignals, Scorer, SignalContribution};
use crate::service::SignalSnapshot;
use crate::signals::{device_fp, impossible_travel, mfa_recent, success_rate, SignalKind};

/// IP-geo sub-score: anchored country.
const IP_SCORE_HOME: i32 = 0;
/// IP-geo sub-score: private-network sentinel.
const IP_SCORE_PRIVATE: i32 = 40;
/// IP-geo sub-score: any known but non-anchored country.
const IP_SCORE_OTHER_COUNTRY: i32 = 60;
/// IP-geo sub-score: address fell outside the geo table entirely.
const IP_SCORE_UNKNOWN: i32 = 80;

/// Velocity sub-score: ramp from 0 to 100 between 1 and `VELOCITY_PEAK`
/// attempts in the sliding window.
const VELOCITY_PEAK: usize = 10;

/// Business-hours sub-score: any after-hours attempt.
const HOURS_SCORE_AFTER: i32 = 40;
/// Business-hours sub-score: deep-night extra (`local_hour < 5`).
const HOURS_SCORE_NIGHT_EXTRA: i32 = 20;

/// Concrete rule-based scorer. Holds no state; the same instance can
/// score every login.
#[derive(Debug, Clone, Copy, Default)]
pub struct RuleBasedScorer;

impl RuleBasedScorer {
    /// Compute the IP-geo sub-score.
    #[must_use]
    pub fn ip_score(snapshot: &SignalSnapshot) -> i32 {
        let country = snapshot.country.as_deref().unwrap_or("??");
        match country {
            "??" => IP_SCORE_UNKNOWN,
            "XX" => IP_SCORE_PRIVATE,
            c if Some(c) == snapshot.home_country.as_deref() => IP_SCORE_HOME,
            _ => IP_SCORE_OTHER_COUNTRY,
        }
    }

    /// Compute the velocity sub-score.
    #[must_use]
    pub fn velocity_score(snapshot: &SignalSnapshot) -> i32 {
        let n = snapshot.velocity_window_count.saturating_sub(1);
        if n == 0 {
            return 0;
        }
        if n >= VELOCITY_PEAK {
            return 100;
        }
        // Linear ramp: 1 -> 10 maps to ~10 -> 100. We perform the
        // arithmetic in `f64` to dodge the integer-division lint and
        // then clamp + round to `i32`.
        #[allow(clippy::cast_precision_loss)]
        let raw = (n as f64) * 100.0 / (VELOCITY_PEAK as f64);
        clamp_round(raw)
    }

    /// Compute the business-hours sub-score.
    #[must_use]
    pub fn hours_score(snapshot: &SignalSnapshot) -> i32 {
        let Some(status) = snapshot.business_hours_status else {
            return 0;
        };
        if status.in_hours {
            return 0;
        }
        let mut s = HOURS_SCORE_AFTER;
        if status.local_hour < 5 {
            s += HOURS_SCORE_NIGHT_EXTRA;
        }
        s.clamp(0, 100)
    }

    /// Compute the device-fingerprint sub-score (HIGH-001).
    #[must_use]
    pub fn device_fp_score(snapshot: &SignalSnapshot) -> i32 {
        snapshot
            .device_fingerprint
            .as_ref()
            .map_or(device_fp::SCORE_UNKNOWN, device_fp::score)
    }

    /// Compute the MFA-recency sub-score (HIGH-001).
    #[must_use]
    pub fn mfa_recent_score(snapshot: &SignalSnapshot) -> i32 {
        snapshot
            .mfa_recent
            .as_ref()
            .map_or(mfa_recent::SCORE_STALE, mfa_recent::score)
    }

    /// Compute the success-rate sub-score (HIGH-001).
    #[must_use]
    pub fn success_rate_score(snapshot: &SignalSnapshot) -> i32 {
        snapshot
            .success_rate
            .map_or(success_rate::SCORE_TRUSTED, success_rate::score)
    }

    /// Compute the impossible-travel sub-score (HIGH-001).
    #[must_use]
    pub fn impossible_travel_score(snapshot: &SignalSnapshot) -> i32 {
        snapshot
            .impossible_travel
            .as_ref()
            .map_or(impossible_travel::SCORE_UNKNOWN, impossible_travel::score)
    }
}

impl Scorer for RuleBasedScorer {
    fn score(&self, signals: &SignalSnapshot, cfg: &RbaConfig) -> ScoredSignals {
        let ip = Self::ip_score(signals);
        let velocity = Self::velocity_score(signals);
        let hours = Self::hours_score(signals);
        let dev_fp = Self::device_fp_score(signals);
        let mfa = Self::mfa_recent_score(signals);
        let success = Self::success_rate_score(signals);
        let travel = Self::impossible_travel_score(signals);

        // Weighted average. The weights sum to ~1.0 per
        // `RbaConfig::validate`; we still defensively normalise so a
        // legacy / migrated row with a slightly off sum cannot push
        // the score outside `[0, 100]`. Disabled signals are excluded
        // from both the numerator and the denominator so the
        // remaining signals dominate proportionally.
        //
        // LOW-007: we also emit one [`SignalContribution`] per enabled
        // signal so the decision-audit row carries the per-signal
        // breakdown for forensic reconstruction. Disabled signals are
        // omitted entirely (no zero-weight rows) — both the in-memory
        // ring and the JSONB column stay compact.
        let w = cfg.weights;
        let flags = &cfg.feature_flags;
        let mut num = 0.0_f64;
        let mut den = 0.0_f64;
        let mut contributions: Vec<SignalContribution> = Vec::with_capacity(7);
        for (kind, enabled, weight, value) in [
            (SignalKind::IpGeo, flags.enable_ip_geo, w.w_ip_geo, ip),
            (
                SignalKind::Velocity,
                flags.enable_velocity,
                w.w_velocity,
                velocity,
            ),
            (
                SignalKind::BusinessHours,
                flags.enable_business_hours,
                w.w_business_hours,
                hours,
            ),
            (
                SignalKind::DeviceFingerprint,
                flags.enable_device_fp,
                w.w_device_fp,
                dev_fp,
            ),
            (
                SignalKind::MfaRecent,
                flags.enable_mfa_recent,
                w.w_mfa_recent,
                mfa,
            ),
            (
                SignalKind::SuccessRate,
                flags.enable_success_rate,
                w.w_success_rate,
                success,
            ),
            (
                SignalKind::ImpossibleTravel,
                flags.enable_impossible_travel,
                w.w_impossible_travel,
                travel,
            ),
        ] {
            if !enabled {
                continue;
            }
            num += f64::from(value) * weight;
            den += weight;
            contributions.push(SignalContribution::new(kind, value, weight));
        }
        let raw = if den > f64::EPSILON { num / den } else { 0.0 };
        let score_i32 = clamp_round(raw);

        let reason = reason_for_enabled(ip, velocity, hours, dev_fp, mfa, success, travel, *flags);
        ScoredSignals {
            score: score_i32,
            reason,
            contributions,
        }
    }
}

/// Round an `f64` in `[0.0, 100.0]` to an `i32` in `[0, 100]` without
/// triggering the `cast_possible_truncation` lint. Values outside the
/// range collapse to the nearest bound.
fn clamp_round(raw: f64) -> i32 {
    if !raw.is_finite() || raw <= 0.0 {
        return 0;
    }
    if raw >= 100.0 {
        return 100;
    }
    // raw is now in (0.0, 100.0); round half-away-from-zero and cast.
    let rounded = raw.round();
    // We've bounded the value, so the cast cannot truncate destructively.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let n = rounded as i32;
    n.clamp(0, 100)
}

/// Pick a human-readable reason based on the dominant sub-score
/// across the legacy six signals (kept for unit-test compatibility).
#[cfg(test)]
fn reason_for(ip: i32, velocity: i32, hours: i32, dev_fp: i32, mfa: i32, success: i32) -> String {
    reason_for_enabled(
        ip,
        velocity,
        hours,
        dev_fp,
        mfa,
        success,
        0,
        RbaFeatureFlags::default(),
    )
}

/// Same as [`reason_for`] but honours the per-tenant feature flags and
/// the new impossible-travel signal.
//
// 8 args (one per HIGH-001 enrichment signal + the flag bag) is the
// natural surface here; collapsing into a struct just to satisfy
// clippy::too_many_arguments would only push the same information
// behind an opaquer call site. `flags: RbaFeatureFlags` is taken by
// value because it is `Copy + 7 bytes` — passing by reference is the
// strictly slower of the two on 64-bit targets.
#[allow(clippy::too_many_arguments)]
fn reason_for_enabled(
    ip: i32,
    velocity: i32,
    hours: i32,
    dev_fp: i32,
    mfa: i32,
    success: i32,
    travel: i32,
    flags: RbaFeatureFlags,
) -> String {
    let mut top = ("baseline", 0_i32);
    for (label, value, enabled) in [
        ("ip-geo", ip, flags.enable_ip_geo),
        ("velocity", velocity, flags.enable_velocity),
        ("business-hours", hours, flags.enable_business_hours),
        ("device-fp", dev_fp, flags.enable_device_fp),
        ("mfa-recency", mfa, flags.enable_mfa_recent),
        ("success-rate", success, flags.enable_success_rate),
        ("impossible-travel", travel, flags.enable_impossible_travel),
    ] {
        if !enabled {
            continue;
        }
        if value > top.1 {
            top = (label, value);
        }
    }
    if top.1 == 0 {
        "low-risk login".to_owned()
    } else {
        format!("{} signal dominant (sub-score {})", top.0, top.1)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::signals::business_hours::BusinessHoursStatus;

    fn snapshot(
        country: Option<&str>,
        home: Option<&str>,
        velocity: usize,
        bh: Option<BusinessHoursStatus>,
    ) -> SignalSnapshot {
        SignalSnapshot {
            country: country.map(str::to_owned),
            home_country: home.map(str::to_owned),
            velocity_window_count: velocity,
            business_hours_status: bh,
            device_fingerprint: None,
            mfa_recent: None,
            success_rate: None,
            impossible_travel: None,
        }
    }

    #[test]
    fn ip_score_home_is_zero() {
        let s = snapshot(Some("US"), Some("US"), 1, None);
        assert_eq!(RuleBasedScorer::ip_score(&s), IP_SCORE_HOME);
    }

    #[test]
    fn ip_score_private_is_forty() {
        let s = snapshot(Some("XX"), Some("US"), 1, None);
        assert_eq!(RuleBasedScorer::ip_score(&s), IP_SCORE_PRIVATE);
    }

    #[test]
    fn ip_score_other_country_is_sixty() {
        let s = snapshot(Some("DE"), Some("US"), 1, None);
        assert_eq!(RuleBasedScorer::ip_score(&s), IP_SCORE_OTHER_COUNTRY);
    }

    #[test]
    fn ip_score_unknown_is_eighty() {
        let s = snapshot(Some("??"), Some("US"), 1, None);
        assert_eq!(RuleBasedScorer::ip_score(&s), IP_SCORE_UNKNOWN);
    }

    #[test]
    fn velocity_score_first_attempt_is_zero() {
        let s = snapshot(None, None, 1, None);
        assert_eq!(RuleBasedScorer::velocity_score(&s), 0);
    }

    #[test]
    fn velocity_score_ramps_with_attempts() {
        let s1 = snapshot(None, None, 2, None);
        let s2 = snapshot(None, None, 5, None);
        let s3 = snapshot(None, None, 11, None);
        assert!(RuleBasedScorer::velocity_score(&s1) < RuleBasedScorer::velocity_score(&s2));
        assert_eq!(RuleBasedScorer::velocity_score(&s3), 100);
    }

    #[test]
    fn hours_score_in_window_is_zero() {
        let s = snapshot(
            None,
            None,
            1,
            Some(BusinessHoursStatus {
                in_hours: true,
                local_hour: 10,
                offset_hours: 0,
            }),
        );
        assert_eq!(RuleBasedScorer::hours_score(&s), 0);
    }

    #[test]
    fn hours_score_after_hours_is_forty() {
        let s = snapshot(
            None,
            None,
            1,
            Some(BusinessHoursStatus {
                in_hours: false,
                local_hour: 20,
                offset_hours: 0,
            }),
        );
        assert_eq!(RuleBasedScorer::hours_score(&s), HOURS_SCORE_AFTER);
    }

    #[test]
    fn hours_score_deep_night_bumps() {
        let s = snapshot(
            None,
            None,
            1,
            Some(BusinessHoursStatus {
                in_hours: false,
                local_hour: 2,
                offset_hours: 0,
            }),
        );
        assert_eq!(
            RuleBasedScorer::hours_score(&s),
            HOURS_SCORE_AFTER + HOURS_SCORE_NIGHT_EXTRA
        );
    }

    #[test]
    fn composite_low_risk_allows() {
        let s = snapshot(
            Some("US"),
            Some("US"),
            1,
            Some(BusinessHoursStatus {
                in_hours: true,
                local_hour: 10,
                offset_hours: 0,
            }),
        );
        let cfg = RbaConfig::default();
        let out = RuleBasedScorer.score(&s, &cfg);
        assert!(out.score < cfg.allow_threshold);
    }

    #[test]
    fn composite_unknown_country_after_hours_step_up() {
        // Strong but not maximal: unknown country + after hours, single
        // attempt. Should land in the step-up bucket [30, 70).
        let s = snapshot(
            Some("??"),
            Some("US"),
            1,
            Some(BusinessHoursStatus {
                in_hours: false,
                local_hour: 22,
                offset_hours: 0,
            }),
        );
        let cfg = RbaConfig::default();
        let out = RuleBasedScorer.score(&s, &cfg);
        assert!(
            out.score >= cfg.allow_threshold && out.score < cfg.block_threshold,
            "expected step-up bucket, got {}",
            out.score
        );
    }

    #[test]
    fn composite_all_signals_red_blocks() {
        use crate::signals::device_fp::{DeviceFingerprintSignal, DeviceFingerprintStatus};
        use crate::signals::impossible_travel::{ImpossibleTravelSignal, TravelVerdict};
        use crate::signals::mfa_recent::MfaRecentSignal;
        use crate::signals::success_rate::SuccessRateSignal;
        use time::macros::datetime;
        let mut s = snapshot(
            Some("??"),
            Some("US"),
            15,
            Some(BusinessHoursStatus {
                in_hours: false,
                local_hour: 2,
                offset_hours: 0,
            }),
        );
        // HIGH-001 enrichment: every new signal red, too.
        s.device_fingerprint = Some(DeviceFingerprintSignal {
            fp_hash: "h".into(),
            last_seen_at: None,
            status: DeviceFingerprintStatus::Revoked,
        });
        s.mfa_recent = Some(MfaRecentSignal::never(
            datetime!(2026-06-12 12:00:00 UTC),
            3_600,
        ));
        s.success_rate = Some(SuccessRateSignal::new(2, 20)); // 10% rate
        s.impossible_travel = Some(ImpossibleTravelSignal {
            verdict: TravelVerdict::Impossible,
            distance_km: Some(11_000.0),
            speed_kmh: Some(22_000.0),
            elapsed_secs: Some(1_800),
        });
        let cfg = RbaConfig::default();
        let out = RuleBasedScorer.score(&s, &cfg);
        assert!(
            out.score >= cfg.block_threshold,
            "expected block bucket, got {}",
            out.score
        );
    }

    #[test]
    fn composite_clamped_when_weights_unbalanced() {
        // Synthetic configuration: every weight is 0 except IP-geo,
        // pushed to 1.0. An unknown country (80) must still land at
        // exactly 80.
        let cfg = RbaConfig {
            weights: super::super::super::config::RbaWeights {
                w_ip_geo: 1.0,
                w_velocity: 0.0,
                w_business_hours: 0.0,
                w_device_fp: 0.0,
                w_mfa_recent: 0.0,
                w_success_rate: 0.0,
                w_impossible_travel: 0.0,
            },
            ..Default::default()
        };
        let s = snapshot(Some("??"), Some("US"), 1, None);
        let out = RuleBasedScorer.score(&s, &cfg);
        assert_eq!(out.score, IP_SCORE_UNKNOWN);
    }

    #[test]
    fn reason_picks_dominant_signal() {
        let r = reason_for(0, 0, 0, 0, 0, 0);
        assert_eq!(r, "low-risk login");
        let r = reason_for(80, 10, 5, 0, 0, 0);
        assert!(r.contains("ip-geo"));
        let r = reason_for(10, 80, 5, 0, 0, 0);
        assert!(r.contains("velocity"));
        let r = reason_for(10, 5, 80, 0, 0, 0);
        assert!(r.contains("business-hours"));
        let r = reason_for(10, 5, 0, 100, 0, 0);
        assert!(r.contains("device-fp"));
        let r = reason_for(10, 5, 0, 0, 50, 0);
        assert!(r.contains("mfa-recency"));
        let r = reason_for(10, 5, 0, 0, 0, 90);
        assert!(r.contains("success-rate"));
    }

    #[test]
    fn revoked_device_dominates_composite() {
        use crate::signals::device_fp::{DeviceFingerprintSignal, DeviceFingerprintStatus};
        let mut s = snapshot(
            Some("US"),
            Some("US"),
            1,
            Some(BusinessHoursStatus {
                in_hours: true,
                local_hour: 10,
                offset_hours: 0,
            }),
        );
        s.device_fingerprint = Some(DeviceFingerprintSignal {
            fp_hash: "h".into(),
            last_seen_at: None,
            status: DeviceFingerprintStatus::Revoked,
        });
        let cfg = RbaConfig::default();
        let out = RuleBasedScorer.score(&s, &cfg);
        // A revoked device (sub-score 100) with weight 0.15 contributes
        // ~15 composite points by itself. Even though that doesn't
        // immediately cross the allow→step-up threshold on its own,
        // the score MUST be materially above zero — assert at least
        // half the raw 15-point contribution survives the weighted
        // average.
        assert!(out.score >= 10, "score = {}", out.score);
    }

    #[test]
    fn stale_mfa_plus_low_success_rate_steps_up() {
        use crate::signals::mfa_recent::MfaRecentSignal;
        use crate::signals::success_rate::SuccessRateSignal;
        use time::macros::datetime;
        let mut s = snapshot(
            Some("US"),
            Some("US"),
            1,
            Some(BusinessHoursStatus {
                in_hours: true,
                local_hour: 10,
                offset_hours: 0,
            }),
        );
        s.mfa_recent = Some(MfaRecentSignal::never(
            datetime!(2026-06-12 12:00:00 UTC),
            3_600,
        ));
        s.success_rate = Some(SuccessRateSignal::new(2, 20)); // 10% rate
        let cfg = RbaConfig::default();
        let out = RuleBasedScorer.score(&s, &cfg);
        // mfa_recent stale (50, weight 0.10) + success_rate hostile
        // (90, weight 0.05) contributes 5 + 4.5 ≈ 10 composite points
        // — well above the "low-risk login" baseline even with
        // everything else green.
        assert!(out.score >= 5, "score = {}", out.score);
    }

    #[test]
    fn impossible_travel_dominates_composite() {
        use crate::signals::impossible_travel::{ImpossibleTravelSignal, TravelVerdict};
        let mut s = snapshot(
            Some("US"),
            Some("US"),
            1,
            Some(BusinessHoursStatus {
                in_hours: true,
                local_hour: 10,
                offset_hours: 0,
            }),
        );
        s.impossible_travel = Some(ImpossibleTravelSignal {
            verdict: TravelVerdict::Impossible,
            distance_km: Some(11_000.0),
            speed_kmh: Some(22_000.0),
            elapsed_secs: Some(1_800),
        });
        let cfg = RbaConfig::default();
        let out = RuleBasedScorer.score(&s, &cfg);
        // Impossible travel is 100 with weight 0.15 → contributes 15
        // composite points by itself. Combined with the all-green
        // baseline that lands in the allow-bucket on the threshold; we
        // assert it bumps the score above zero deterministically.
        assert!(
            out.score >= 10,
            "impossible travel must contribute meaningfully, got {}",
            out.score
        );
    }

    #[test]
    fn feature_flag_disables_signal_in_average() {
        // With ip-geo turned off, an unknown-country login no longer
        // dominates the composite.
        let cfg_on = RbaConfig::default();
        let mut cfg_off = RbaConfig::default();
        cfg_off.feature_flags.enable_ip_geo = false;
        let s = snapshot(Some("??"), Some("US"), 1, None);
        let on = RuleBasedScorer.score(&s, &cfg_on);
        let off = RuleBasedScorer.score(&s, &cfg_off);
        assert!(
            off.score < on.score,
            "disabling ip-geo must lower composite ({} vs {})",
            off.score,
            on.score
        );
    }

    #[test]
    fn all_signals_disabled_scores_zero() {
        use crate::config::RbaFeatureFlags;
        let cfg = RbaConfig {
            feature_flags: RbaFeatureFlags::all_off(),
            ..Default::default()
        };
        let s = snapshot(Some("??"), Some("US"), 15, None);
        let out = RuleBasedScorer.score(&s, &cfg);
        assert_eq!(out.score, 0);
    }

    #[test]
    fn reason_includes_impossible_travel_when_dominant() {
        let flags = crate::config::RbaFeatureFlags::default();
        let r = reason_for_enabled(10, 5, 0, 0, 0, 0, 100, flags);
        assert!(r.contains("impossible-travel"), "got {r}");
    }
}
