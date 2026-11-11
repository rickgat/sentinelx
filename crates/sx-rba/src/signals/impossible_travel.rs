//! Impossible-travel detector (HIGH-001).
//!
//! Tracks the *last observed* (city/lat-lon, timestamp) per
//! `(tenant_id, user_id)`. On every subsequent login we compute the
//! great-circle distance from the previously-seen point to the current
//! one and divide by the elapsed wall-clock time. A travel speed in
//! excess of [`DEFAULT_MAX_SPEED_KMH`] (900 km/h — slightly above a
//! commercial jet's typical cruise) is treated as physically
//! implausible and contributes the maximum risk sub-score.
//!
//! ## Bucketing
//!
//! | Implied speed                       | Sub-score |
//! |-------------------------------------|-----------|
//! | unknown (first sighting, no geo)    | 0         |
//! | ≤ 200 km/h                          | 0         |
//! | 200 ‥ 900 km/h                      | 30        |
//! | > 900 km/h                          | 100       |
//!
//! The 200‥900 band catches edge cases like a high-speed train + VPN
//! exit that still raises some suspicion without blocking. The hard
//! ceiling at 900 km/h is the headline rule.
//!
//! ## Geo source
//!
//! Lat/lon is resolved via the existing [`crate::signals::ip_geo_centroid::IpGeoCentroid`]
//! reader — country-centroid accuracy is more than enough for the
//! 900 km/h threshold (continent-scale jumps exceed it trivially). The
//! reader already deals with private/unknown sentinels by returning
//! `None`; we treat that the same as "no signal" and score `0`.
//!
//! Production deployments can swap the centroid reader for a city-level
//! MaxMind GeoIP2-City reader behind the same `Option<(lat, lon)>`
//! contract — no changes to this module are required.
//!
//! ## Storage (LOW-005)
//!
//! The last-sighting backing store is pluggable via the [`TravelStore`]
//! trait. Two implementations are provided:
//!
//! * [`MemTravelStore`] — process-local `Arc<DashMap>`; survives only
//!   as long as the process. Used in unit tests and the dev/in-memory
//!   build of `sx-monolith`.
//! * [`crate::signals::travel_pg::PgTravelStore`] — backed by the
//!   `rba_last_sightings` Postgres table. Survives process restarts
//!   (closes the post-restart silent-downgrade gap that motivated
//!   LOW-005).
//!
//! Pre-LOW-005 code that constructed `TravelTracker` keeps working —
//! the symbol is now a type alias for [`MemTravelStore`].

use std::sync::Arc;

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

/// Sub-score for "no prior sighting" or "speed unresolvable".
pub const SCORE_UNKNOWN: i32 = 0;
/// Sub-score for "plausible" travel (≤ 200 km/h).
pub const SCORE_PLAUSIBLE: i32 = 0;
/// Sub-score for "suspicious" travel (200‥`DEFAULT_MAX_SPEED_KMH`).
pub const SCORE_SUSPICIOUS: i32 = 30;
/// Sub-score for "impossible" travel (> `DEFAULT_MAX_SPEED_KMH`).
pub const SCORE_IMPOSSIBLE: i32 = 100;

/// Upper bound on plausible ground-speed for a benign user
/// (commercial-jet ceiling rounded up). Travel speeds in excess of this
/// value classify as impossible.
pub const DEFAULT_MAX_SPEED_KMH: f64 = 900.0;
/// Upper bound on the "suspicious" band. Speeds below this but above
/// the obvious in-city/walking/short-train regime still raise some
/// score.
pub const SUSPICIOUS_SPEED_KMH: f64 = 200.0;

/// Earth's mean radius in kilometres, used by [`haversine_km`].
pub const EARTH_RADIUS_KM: f64 = 6_371.0;

/// Minimum dwell time (seconds) between two sightings before we score
/// travel. Two consecutive logins in the same second produce a
/// degenerate `Infinity` speed; we treat sub-second deltas as "same
/// session" and score `0`.
pub const MIN_DWELL_SECS: i64 = 5;

/// One recorded successful login geo-fix for a user.
#[derive(Debug, Clone, PartialEq)]
pub struct LastSighting {
    /// Latitude of the last successful login.
    pub lat: f64,
    /// Longitude of the last successful login.
    pub lon: f64,
    /// Wall-clock time the sighting was recorded at.
    pub at: OffsetDateTime,
}

/// Outcome of the impossible-travel check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TravelVerdict {
    /// First sighting or geo unresolvable — no opinion.
    Unknown,
    /// Implied speed is well within human travel speeds.
    Plausible,
    /// Implied speed is high but not physically impossible.
    Suspicious,
    /// Implied speed is faster than any commercial jet.
    Impossible,
}

impl TravelVerdict {
    /// Stable string form for SQL / JSON.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Plausible => "plausible",
            Self::Suspicious => "suspicious",
            Self::Impossible => "impossible",
        }
    }
}

/// Per-login signal handed to the scorer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ImpossibleTravelSignal {
    /// Verdict the detector reached.
    pub verdict: TravelVerdict,
    /// Implied great-circle distance to the previous sighting, in km.
    /// `None` when there was no previous sighting or the geo lookup
    /// returned no result.
    pub distance_km: Option<f64>,
    /// Implied travel speed in km/h. `None` for first sighting / unresolvable.
    pub speed_kmh: Option<f64>,
    /// Seconds elapsed since the previous sighting, if any.
    pub elapsed_secs: Option<i64>,
}

impl ImpossibleTravelSignal {
    /// Convenience constructor for the "no opinion" outcome.
    #[must_use]
    pub fn unknown() -> Self {
        Self {
            verdict: TravelVerdict::Unknown,
            distance_km: None,
            speed_kmh: None,
            elapsed_secs: None,
        }
    }
}

/// Pluggable backing store for the impossible-travel last-sighting
/// ledger (LOW-005).
///
/// Methods are intentionally synchronous — the [`RbaService`] hot path
/// (`evaluate`) is sync and is called from the IAM login flow without
/// blocking on async I/O. Concrete implementations that talk to async
/// backends (Postgres) bridge to the current Tokio runtime internally;
/// see [`crate::signals::travel_pg::PgTravelStore`].
///
/// [`RbaService`]: crate::service::RbaService
pub trait TravelStore: Send + Sync + std::fmt::Debug {
    /// Persist a successful login geo-fix for `(tenant, user)`. Acts as
    /// an upsert — later calls overwrite the row's `(lat, lon, at)`.
    fn record(&self, tenant_id: Uuid, user_id: Uuid, lat: f64, lon: f64, at: OffsetDateTime);

    /// Read the last sighting for `(tenant, user)` without mutating.
    /// Returns `None` when no prior sighting exists.
    #[must_use]
    fn last_sighting(&self, tenant_id: Uuid, user_id: Uuid) -> Option<LastSighting>;

    /// Evaluate a candidate login at `(lat, lon, at)` against the
    /// previously-recorded sighting for `(tenant, user)`. **Does not
    /// mutate** — callers invoke [`Self::record`] separately once the
    /// engine has committed to the decision.
    ///
    /// Returns [`ImpossibleTravelSignal::unknown`] when:
    /// * there is no prior sighting;
    /// * the candidate geo is `None` (private / unresolvable);
    ///
    /// or the [`TravelVerdict::Plausible`] sentinel when the elapsed
    /// time is below [`MIN_DWELL_SECS`] (same-session tail).
    ///
    /// Default impl uses [`Self::last_sighting`] + [`haversine_km`]; no
    /// implementor needs to override this unless it can compute the
    /// distance more efficiently server-side.
    #[must_use]
    fn evaluate(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        candidate_lat: Option<f64>,
        candidate_lon: Option<f64>,
        at: OffsetDateTime,
        max_speed_kmh: f64,
    ) -> ImpossibleTravelSignal {
        let Some(prev) = self.last_sighting(tenant_id, user_id) else {
            return ImpossibleTravelSignal::unknown();
        };
        let (Some(lat), Some(lon)) = (candidate_lat, candidate_lon) else {
            return ImpossibleTravelSignal::unknown();
        };

        let elapsed_secs = (at - prev.at).whole_seconds();
        if elapsed_secs < MIN_DWELL_SECS {
            return ImpossibleTravelSignal {
                verdict: TravelVerdict::Plausible,
                distance_km: Some(haversine_km(prev.lat, prev.lon, lat, lon)),
                speed_kmh: Some(0.0),
                elapsed_secs: Some(elapsed_secs),
            };
        }

        let distance_km = haversine_km(prev.lat, prev.lon, lat, lon);
        // elapsed_secs is at least MIN_DWELL_SECS (>= 5) here.
        #[allow(clippy::cast_precision_loss)]
        let hours = (elapsed_secs as f64) / 3_600.0;
        let speed_kmh = if hours > 0.0 {
            distance_km / hours
        } else {
            0.0
        };

        let verdict = if speed_kmh > max_speed_kmh {
            TravelVerdict::Impossible
        } else if speed_kmh > SUSPICIOUS_SPEED_KMH {
            TravelVerdict::Suspicious
        } else {
            TravelVerdict::Plausible
        };

        ImpossibleTravelSignal {
            verdict,
            distance_km: Some(distance_km),
            speed_kmh: Some(speed_kmh),
            elapsed_secs: Some(elapsed_secs),
        }
    }
}

/// In-memory backing store: one [`LastSighting`] per `(tenant, user)`.
///
/// Cheap to clone (`Arc<DashMap>` internally) and concurrency-safe.
/// Used in unit tests and the dev/in-memory build of `sx-monolith`.
/// Production deployments install [`crate::signals::travel_pg::PgTravelStore`]
/// behind the same [`TravelStore`] trait so a restart of `sx-monolith`
/// does not flush every user's last sighting.
#[derive(Debug, Clone, Default)]
pub struct MemTravelStore {
    rows: Arc<DashMap<String, LastSighting>>,
}

impl MemTravelStore {
    /// Build an empty in-memory tracker.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of rows currently held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    /// True when no rows are held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    fn key(tenant_id: Uuid, user_id: Uuid) -> String {
        format!("{tenant_id}|{user_id}")
    }
}

impl TravelStore for MemTravelStore {
    fn record(&self, tenant_id: Uuid, user_id: Uuid, lat: f64, lon: f64, at: OffsetDateTime) {
        self.rows
            .insert(Self::key(tenant_id, user_id), LastSighting { lat, lon, at });
    }

    fn last_sighting(&self, tenant_id: Uuid, user_id: Uuid) -> Option<LastSighting> {
        self.rows
            .get(&Self::key(tenant_id, user_id))
            .map(|r| r.value().clone())
    }
}

/// Back-compat alias.
///
/// Pre-LOW-005 callers built a `TravelTracker` directly. The concrete
/// type was renamed to [`MemTravelStore`] when the [`TravelStore`]
/// trait was introduced; the alias keeps the old name compiling
/// without source changes at every call site.
pub type TravelTracker = MemTravelStore;

/// Great-circle distance between two WGS-84 lat/lon points, in km.
///
/// Uses the haversine formula on a spherical Earth of radius
/// [`EARTH_RADIUS_KM`]. Inputs are decimal degrees.
#[must_use]
pub fn haversine_km(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
    let to_rad = std::f64::consts::PI / 180.0;
    let dlat = (lat2 - lat1) * to_rad;
    let dlon = (lon2 - lon1) * to_rad;
    let a = (dlat / 2.0).sin().powi(2)
        + (lat1 * to_rad).cos() * (lat2 * to_rad).cos() * (dlon / 2.0).sin().powi(2);
    let c = 2.0 * a.sqrt().min(1.0).asin();
    EARTH_RADIUS_KM * c
}

/// Score the impossible-travel signal.
#[must_use]
pub fn score(signal: &ImpossibleTravelSignal) -> i32 {
    match signal.verdict {
        TravelVerdict::Unknown => SCORE_UNKNOWN,
        TravelVerdict::Plausible => SCORE_PLAUSIBLE,
        TravelVerdict::Suspicious => SCORE_SUSPICIOUS,
        TravelVerdict::Impossible => SCORE_IMPOSSIBLE,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::float_cmp)]
mod tests {
    use super::*;
    use time::macros::datetime;
    use time::Duration;

    fn ts() -> OffsetDateTime {
        datetime!(2026-06-12 10:00:00 UTC)
    }

    #[test]
    fn haversine_zero_for_same_point() {
        let d = haversine_km(37.0902, -95.7129, 37.0902, -95.7129);
        assert!(d.abs() < 1e-6, "expected 0 km, got {d}");
    }

    #[test]
    fn haversine_matches_known_distance() {
        // London (51.5074, -0.1278) → Paris (48.8566, 2.3522) ≈ 343 km.
        let d = haversine_km(51.5074, -0.1278, 48.8566, 2.3522);
        assert!(
            (d - 343.0).abs() < 5.0,
            "expected ~343 km London→Paris, got {d}"
        );
    }

    #[test]
    fn haversine_matches_long_distance() {
        // US centroid (37.0902, -95.7129) → CN centroid (35.8617, 104.1954).
        // Spherical great-circle ≈ 11_650 km (a touch longer than the
        // 11_165 km figure you get from a WGS-84 ellipsoid, because the
        // haversine assumes a sphere). Allow ±50 km slack.
        let d = haversine_km(37.0902, -95.7129, 35.8617, 104.1954);
        assert!((d - 11_650.0).abs() < 50.0, "expected ~11_650 km, got {d}");
    }

    #[test]
    fn first_sighting_scores_unknown() {
        let t = MemTravelStore::new();
        let tenant = Uuid::new_v4();
        let user = Uuid::new_v4();
        let s = t.evaluate(
            tenant,
            user,
            Some(0.0),
            Some(0.0),
            ts(),
            DEFAULT_MAX_SPEED_KMH,
        );
        assert_eq!(s.verdict, TravelVerdict::Unknown);
        assert_eq!(score(&s), SCORE_UNKNOWN);
    }

    #[test]
    fn no_candidate_geo_scores_unknown() {
        let t = MemTravelStore::new();
        let tenant = Uuid::new_v4();
        let user = Uuid::new_v4();
        t.record(tenant, user, 51.5074, -0.1278, ts());
        let s = t.evaluate(
            tenant,
            user,
            None,
            None,
            ts() + Duration::hours(2),
            DEFAULT_MAX_SPEED_KMH,
        );
        assert_eq!(s.verdict, TravelVerdict::Unknown);
    }

    #[test]
    fn slow_travel_is_plausible() {
        let t = MemTravelStore::new();
        let tenant = Uuid::new_v4();
        let user = Uuid::new_v4();
        // Record London. Two hours later evaluate from Paris — speed
        // ~170 km/h, well below 200.
        t.record(tenant, user, 51.5074, -0.1278, ts());
        let s = t.evaluate(
            tenant,
            user,
            Some(48.8566),
            Some(2.3522),
            ts() + Duration::hours(2),
            DEFAULT_MAX_SPEED_KMH,
        );
        assert_eq!(
            s.verdict,
            TravelVerdict::Plausible,
            "speed={:?}",
            s.speed_kmh
        );
        assert_eq!(score(&s), SCORE_PLAUSIBLE);
    }

    #[test]
    fn suspicious_band_scores_thirty() {
        let t = MemTravelStore::new();
        let tenant = Uuid::new_v4();
        let user = Uuid::new_v4();
        // London → Paris in 30 minutes ⇒ ~686 km/h (between 200 and 900).
        t.record(tenant, user, 51.5074, -0.1278, ts());
        let s = t.evaluate(
            tenant,
            user,
            Some(48.8566),
            Some(2.3522),
            ts() + Duration::minutes(30),
            DEFAULT_MAX_SPEED_KMH,
        );
        assert_eq!(
            s.verdict,
            TravelVerdict::Suspicious,
            "speed={:?}",
            s.speed_kmh
        );
        assert_eq!(score(&s), SCORE_SUSPICIOUS);
    }

    #[test]
    fn impossible_travel_scores_max() {
        let t = MemTravelStore::new();
        let tenant = Uuid::new_v4();
        let user = Uuid::new_v4();
        // US → China centroids in 30 minutes ⇒ ~22_000 km/h, well over 900.
        t.record(tenant, user, 37.0902, -95.7129, ts());
        let s = t.evaluate(
            tenant,
            user,
            Some(35.8617),
            Some(104.1954),
            ts() + Duration::minutes(30),
            DEFAULT_MAX_SPEED_KMH,
        );
        assert_eq!(s.verdict, TravelVerdict::Impossible);
        assert_eq!(score(&s), SCORE_IMPOSSIBLE);
    }

    #[test]
    fn same_second_consecutive_logins_score_plausible() {
        let t = MemTravelStore::new();
        let tenant = Uuid::new_v4();
        let user = Uuid::new_v4();
        t.record(tenant, user, 37.0902, -95.7129, ts());
        // 1 second later from a far-away point: would be ∞ speed if we
        // didn't guard MIN_DWELL_SECS.
        let s = t.evaluate(
            tenant,
            user,
            Some(35.8617),
            Some(104.1954),
            ts() + Duration::seconds(1),
            DEFAULT_MAX_SPEED_KMH,
        );
        assert_eq!(s.verdict, TravelVerdict::Plausible);
    }

    #[test]
    fn record_overwrites_last_sighting() {
        let t = MemTravelStore::new();
        let tenant = Uuid::new_v4();
        let user = Uuid::new_v4();
        t.record(tenant, user, 0.0, 0.0, ts());
        t.record(tenant, user, 51.5074, -0.1278, ts() + Duration::hours(1));
        let last = t.last_sighting(tenant, user).expect("recorded");
        assert!((last.lat - 51.5074).abs() < 1e-6);
    }

    #[test]
    fn tracker_is_tenant_and_user_scoped() {
        let t = MemTravelStore::new();
        let t1 = Uuid::new_v4();
        let t2 = Uuid::new_v4();
        let u = Uuid::new_v4();
        t.record(t1, u, 37.0902, -95.7129, ts());
        assert!(t.last_sighting(t2, u).is_none());
    }

    #[test]
    fn verdict_strings_are_stable() {
        assert_eq!(TravelVerdict::Unknown.as_str(), "unknown");
        assert_eq!(TravelVerdict::Plausible.as_str(), "plausible");
        assert_eq!(TravelVerdict::Suspicious.as_str(), "suspicious");
        assert_eq!(TravelVerdict::Impossible.as_str(), "impossible");
    }

    #[test]
    fn travel_tracker_alias_is_mem_travel_store() {
        // LOW-005: TravelTracker is preserved as an alias so pre-LOW-005
        // callers keep compiling.
        let _alias: TravelTracker = MemTravelStore::new();
    }

    #[test]
    fn trait_object_delegates_to_inner_impl() {
        let store: Arc<dyn TravelStore> = Arc::new(MemTravelStore::new());
        let tenant = Uuid::new_v4();
        let user = Uuid::new_v4();
        store.record(tenant, user, 37.0902, -95.7129, ts());
        let s = store.evaluate(
            tenant,
            user,
            Some(35.8617),
            Some(104.1954),
            ts() + Duration::minutes(30),
            DEFAULT_MAX_SPEED_KMH,
        );
        assert_eq!(s.verdict, TravelVerdict::Impossible);
    }
}
