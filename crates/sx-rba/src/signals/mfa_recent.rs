//! MFA-recently-completed signal (HIGH-001).
//!
//! A login from a session that completed a strong second factor
//! (WebAuthn assertion or TOTP confirmation) in the recent past is
//! materially less risky than one that did not. Conversely, a session
//! that has been live for many hours without ever exercising MFA is a
//! candidate for the "slow and low" adversary the rule-based scorer was
//! blind to before.
//!
//! The signal compares `now - last_mfa_at` against four buckets:
//!
//! | Age band                    | Sub-score |
//! |-----------------------------|-----------|
//! | ≤ 1h (configurable window)  | 0         |
//! | 1h ‥ 8h                     | 10        |
//! | 8h ‥ 24h                    | 25        |
//! | > 24h (or no record)        | 50        |
//!
//! The age table is centralised here so the same numbers feed both the
//! scorer and any downstream tests.

use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

/// Default "fresh" window — anything inside scores `0`.
pub const DEFAULT_RECENT_WINDOW_SECS: u64 = 3_600;
/// Inner end of the "stale" band — anything between the recent window
/// and 8h scores `SCORE_FRESH_TO_8H`.
pub const STALE_BAND_8H_SECS: u64 = 8 * 3_600;
/// Inner end of the "very stale" band — anything between 8h and 24h
/// scores `SCORE_8H_TO_24H`.
pub const STALE_BAND_24H_SECS: u64 = 24 * 3_600;

/// Sub-score awarded when MFA was completed inside the recent window.
pub const SCORE_FRESH: i32 = 0;
/// Sub-score awarded for the 1h ‥ 8h band.
pub const SCORE_FRESH_TO_8H: i32 = 10;
/// Sub-score awarded for the 8h ‥ 24h band.
pub const SCORE_8H_TO_24H: i32 = 25;
/// Sub-score awarded for the > 24h band (and the never-MFAd case).
pub const SCORE_STALE: i32 = 50;

/// Snapshot of a user's most recent successful strong-factor
/// completion, joined with the configured recent-window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MfaRecentSignal {
    /// Wall-clock time of the most recent successful MFA, if any.
    pub last_mfa_at: Option<OffsetDateTime>,
    /// "Now" the signal was computed at, used for testability.
    pub observed_at: OffsetDateTime,
    /// Recent-window in seconds (mirrors the per-tenant config).
    pub recent_window_secs: u64,
}

impl MfaRecentSignal {
    /// Convenience for the "never MFAd" case.
    #[must_use]
    pub fn never(observed_at: OffsetDateTime, recent_window_secs: u64) -> Self {
        Self {
            last_mfa_at: None,
            observed_at,
            recent_window_secs,
        }
    }

    /// Age in seconds, or `None` when MFA has never been completed.
    #[must_use]
    pub fn age_secs(&self) -> Option<u64> {
        let last = self.last_mfa_at?;
        let delta = self.observed_at - last;
        let whole_secs = delta.whole_seconds();
        if whole_secs < 0 {
            // Future-dated MFA. Treat as fresh — the only legitimate
            // way this happens is clock skew, and we want the optimistic
            // outcome for the user.
            Some(0)
        } else {
            u64::try_from(whole_secs).ok()
        }
    }
}

/// In-memory backing store. A production deployment will replace this
/// with a Postgres query over the WebAuthn/TOTP audit tables.
#[derive(Debug, Clone, Default)]
pub struct MfaRecentTracker {
    rows: Arc<DashMap<String, OffsetDateTime>>,
    window: Duration,
}

impl MfaRecentTracker {
    /// Build a tracker with the default 1h recent-window.
    #[must_use]
    pub fn new() -> Self {
        Self::with_window(Duration::from_secs(DEFAULT_RECENT_WINDOW_SECS))
    }

    /// Build a tracker with a custom recent-window.
    #[must_use]
    pub fn with_window(window: Duration) -> Self {
        Self {
            rows: Arc::new(DashMap::new()),
            window,
        }
    }

    /// Recent-window in seconds.
    #[must_use]
    pub fn window_secs(&self) -> u64 {
        self.window.as_secs()
    }

    /// Record a successful MFA completion (WebAuthn or TOTP).
    pub fn record(&self, tenant_id: Uuid, user_id: Uuid, at: OffsetDateTime) {
        let key = Self::key(tenant_id, user_id);
        self.rows.insert(key, at);
    }

    /// Read the current signal for `(tenant, user)`. Never mutates.
    #[must_use]
    pub fn lookup(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        observed_at: OffsetDateTime,
    ) -> MfaRecentSignal {
        let key = Self::key(tenant_id, user_id);
        let last = self.rows.get(&key).map(|r| *r.value());
        MfaRecentSignal {
            last_mfa_at: last,
            observed_at,
            recent_window_secs: self.window.as_secs(),
        }
    }

    fn key(tenant_id: Uuid, user_id: Uuid) -> String {
        format!("{tenant_id}|{user_id}")
    }
}

/// Score the MFA-recency signal.
#[must_use]
pub fn score(signal: &MfaRecentSignal) -> i32 {
    let Some(age) = signal.age_secs() else {
        return SCORE_STALE;
    };
    if age <= signal.recent_window_secs {
        return SCORE_FRESH;
    }
    if age <= STALE_BAND_8H_SECS {
        return SCORE_FRESH_TO_8H;
    }
    if age <= STALE_BAND_24H_SECS {
        return SCORE_8H_TO_24H;
    }
    SCORE_STALE
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use time::macros::datetime;

    fn now() -> OffsetDateTime {
        datetime!(2026-06-12 12:00:00 UTC)
    }

    #[test]
    fn never_mfad_scores_stale() {
        let s = MfaRecentSignal::never(now(), DEFAULT_RECENT_WINDOW_SECS);
        assert_eq!(score(&s), SCORE_STALE);
    }

    #[test]
    fn fresh_window_scores_zero() {
        let s = MfaRecentSignal {
            last_mfa_at: Some(now() - Duration::from_secs(30 * 60)),
            observed_at: now(),
            recent_window_secs: DEFAULT_RECENT_WINDOW_SECS,
        };
        assert_eq!(score(&s), SCORE_FRESH);
    }

    #[test]
    fn one_to_eight_h_band_scores_ten() {
        let s = MfaRecentSignal {
            last_mfa_at: Some(now() - Duration::from_secs(2 * 3_600)),
            observed_at: now(),
            recent_window_secs: DEFAULT_RECENT_WINDOW_SECS,
        };
        assert_eq!(score(&s), SCORE_FRESH_TO_8H);
    }

    #[test]
    fn eight_to_twentyfour_h_band_scores_twenty_five() {
        let s = MfaRecentSignal {
            last_mfa_at: Some(now() - Duration::from_secs(12 * 3_600)),
            observed_at: now(),
            recent_window_secs: DEFAULT_RECENT_WINDOW_SECS,
        };
        assert_eq!(score(&s), SCORE_8H_TO_24H);
    }

    #[test]
    fn beyond_twentyfour_h_scores_stale() {
        let s = MfaRecentSignal {
            last_mfa_at: Some(now() - Duration::from_secs(48 * 3_600)),
            observed_at: now(),
            recent_window_secs: DEFAULT_RECENT_WINDOW_SECS,
        };
        assert_eq!(score(&s), SCORE_STALE);
    }

    #[test]
    fn future_dated_mfa_treated_as_fresh() {
        let s = MfaRecentSignal {
            last_mfa_at: Some(now() + Duration::from_secs(60)),
            observed_at: now(),
            recent_window_secs: DEFAULT_RECENT_WINDOW_SECS,
        };
        assert_eq!(score(&s), SCORE_FRESH);
    }

    #[test]
    fn tracker_records_and_returns_age() {
        let t = MfaRecentTracker::new();
        let tenant = Uuid::new_v4();
        let user = Uuid::new_v4();
        let s = t.lookup(tenant, user, now());
        assert!(s.last_mfa_at.is_none());
        t.record(tenant, user, now() - Duration::from_secs(30 * 60));
        let s2 = t.lookup(tenant, user, now());
        assert!(s2.last_mfa_at.is_some());
        assert_eq!(score(&s2), SCORE_FRESH);
    }

    #[test]
    fn custom_window_changes_threshold() {
        let t = MfaRecentTracker::with_window(Duration::from_secs(60));
        let tenant = Uuid::new_v4();
        let user = Uuid::new_v4();
        t.record(tenant, user, now() - Duration::from_secs(120));
        let s = t.lookup(tenant, user, now());
        // 2 minutes ago > 60s window → should NOT be fresh.
        assert_ne!(score(&s), SCORE_FRESH);
    }
}
