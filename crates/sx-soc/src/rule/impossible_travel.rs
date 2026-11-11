//! Impossible-travel detection rule.
//!
//! This module implements a *physical-plausibility* check on a stream of
//! authenticated logins. Given two successive [`LoginRecord`]s for the same
//! principal — a `prev`ious one and a `curr`ent one — it derives the implied
//! ground-speed required to traverse the great-circle distance between the
//! two coordinate pairs in the elapsed wall-clock interval. When the implied
//! speed exceeds an operator-supplied ceiling (`max_kmh`), the function
//! returns a [`TravelAnomaly`] describing the discrepancy.
//!
//! The detector is deliberately stateless and side-effect free; the
//! responsibility for sourcing the *previous* login lives behind the
//! [`LoginHistoryRepo`] trait, of which a tiny in-memory implementation
//! [`InMemoryLoginHistoryRepo`] is supplied for tests.
//!
//! # Coordinate system
//!
//! Latitude/longitude are expected in WGS-84 decimal degrees with the
//! conventional ranges (`lat ∈ [-90, 90]`, `lon ∈ [-180, 180]`). The
//! function does **not** validate ranges; callers (e.g. a `GeoIP` layer)
//! are expected to supply already-sanitized inputs.
//!
//! # Numerical model
//!
//! Distance is computed via the haversine formula
//!
//! ```text
//!   a = sin²(Δφ/2) + cos(φ₁) · cos(φ₂) · sin²(Δλ/2)
//!   c = 2 · atan2(√a, √(1−a))
//!   d = R · c
//! ```
//!
//! with `R = 6371.0088 km` (IUGG mean Earth radius). The haversine is
//! numerically well-conditioned for both very short and antipodal arcs,
//! so we use it across the whole range without falling back to the law
//! of cosines.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use time::OffsetDateTime;
use tokio::sync::Mutex;

use crate::error::SocError;

/// IUGG mean Earth radius in kilometres.
const EARTH_RADIUS_KM: f64 = 6371.0088;

/// One successful login event localized by `GeoIP` (or equivalent).
///
/// The geometric check itself only needs `(user_id, lat, lon, at)`. The
/// other fields exist for two reasons:
///
/// * `tenant_id` — multi-tenant deployments scope per-user history under
///   `(tenant_id, user_id)` so a tenant-A login never matches tenant-B
///   history (P2-007 acceptance criterion: "multi-tenant; per-user travel
///   history scoped by `tenant_id`").
/// * `source_ip` / `asn` — preserved on the record so the emitted SOC
///   finding can carry both endpoints, and so the corporate-VPN ASN
///   allowlist can suppress findings whose endpoints both sit inside the
///   tenant's known VPN egress pool.
///
/// Construction without tenant / IP / ASN context continues to work for
/// legacy tests via [`LoginRecord::new`]; multi-tenant production callers
/// should use [`LoginRecord::with_context`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LoginRecord {
    /// Stable user identifier (subject claim or internal id).
    pub user_id: String,
    /// Latitude in decimal degrees, WGS-84.
    pub lat: f64,
    /// Longitude in decimal degrees, WGS-84.
    pub lon: f64,
    /// Wall-clock time of the login, UTC.
    pub at: OffsetDateTime,
    /// Tenant scope. `None` is treated as "global" for the in-memory
    /// repo's key, which is appropriate for single-tenant tests; in
    /// production this should always be `Some`.
    #[serde(default)]
    pub tenant_id: Option<String>,
    /// Source IP of the login, captured for evidence and VPN-allowlist
    /// suppression.
    #[serde(default)]
    pub source_ip: Option<String>,
    /// Autonomous System Number for the source IP, used by the
    /// per-tenant corporate-VPN allowlist heuristic.
    #[serde(default)]
    pub asn: Option<u32>,
}

impl LoginRecord {
    /// Construct a login record from owned parts (back-compat: no tenant,
    /// IP, or ASN). New code should prefer [`Self::with_context`].
    #[must_use]
    pub fn new(user_id: impl Into<String>, lat: f64, lon: f64, at: OffsetDateTime) -> Self {
        Self {
            user_id: user_id.into(),
            lat,
            lon,
            at,
            tenant_id: None,
            source_ip: None,
            asn: None,
        }
    }

    /// Construct a multi-tenant login record carrying the source IP and
    /// ASN context required by the VPN-allowlist suppression rule.
    #[must_use]
    pub fn with_context(
        tenant_id: impl Into<String>,
        user_id: impl Into<String>,
        lat: f64,
        lon: f64,
        at: OffsetDateTime,
        source_ip: Option<String>,
        asn: Option<u32>,
    ) -> Self {
        Self {
            user_id: user_id.into(),
            lat,
            lon,
            at,
            tenant_id: Some(tenant_id.into()),
            source_ip,
            asn,
        }
    }
}

/// An impossible-travel anomaly: the geometric reasoning behind a fired
/// alert, suitable for embedding in [`crate::alert::Alert::description`]
/// or attaching as structured evidence.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TravelAnomaly {
    /// User whose two logins triggered the rule.
    pub user_id: String,
    /// Tenant whose policy was evaluated, if multi-tenant context was
    /// supplied on the current login. Inherited from `curr.tenant_id`.
    #[serde(default)]
    pub tenant_id: Option<String>,
    /// Great-circle distance between the two coordinates, in kilometres.
    pub distance_km: f64,
    /// Elapsed wall-clock seconds between `prev.at` and `curr.at`.
    pub elapsed_secs: f64,
    /// Implied average ground speed, kilometres per hour.
    pub computed_kmh: f64,
    /// Operator-supplied ceiling (the threshold that was exceeded).
    pub threshold_kmh: f64,
    /// The earlier login record, preserved for SOC evidence.
    #[serde(default)]
    pub prev: Option<LoginRecord>,
    /// The current login record, preserved for SOC evidence.
    #[serde(default)]
    pub curr: Option<LoginRecord>,
}

/// Evaluate a pair of login records for impossible travel.
///
/// Returns `Some(anomaly)` if and only if **both**
///
/// 1. `elapsed_secs > 0` (i.e. `curr.at > prev.at`); and
/// 2. the implied average ground speed strictly exceeds `max_kmh`.
///
/// Returns `None` otherwise — including when the elapsed time is zero
/// or negative (which avoids division by zero and rejects out-of-order
/// events).
#[must_use]
pub fn evaluate(prev: &LoginRecord, curr: &LoginRecord, max_kmh: f64) -> Option<TravelAnomaly> {
    let elapsed_secs = (curr.at - prev.at).as_seconds_f64();
    if elapsed_secs <= 0.0 {
        return None;
    }

    let distance_km = haversine_km(prev.lat, prev.lon, curr.lat, curr.lon);
    // hours = seconds / 3600; computed_kmh = km / hours
    let computed_kmh = distance_km / (elapsed_secs / 3600.0);

    if computed_kmh > max_kmh {
        Some(TravelAnomaly {
            user_id: curr.user_id.clone(),
            tenant_id: curr.tenant_id.clone(),
            distance_km,
            elapsed_secs,
            computed_kmh,
            threshold_kmh: max_kmh,
            prev: Some(prev.clone()),
            curr: Some(curr.clone()),
        })
    } else {
        None
    }
}

/// Outcome of an impossible-travel evaluation that takes a VPN allowlist
/// into account.
///
/// Both `Detected` and `Suppressed` carry the same [`TravelAnomaly`] —
/// the SOC pipeline emits a finding for the first and an audit-only row
/// for the second so an operator can later see "we *would* have alerted,
/// but the corporate-VPN heuristic suppressed it" without losing the
/// evidence.
#[derive(Debug, Clone, PartialEq)]
pub enum TravelDecision {
    /// No anomaly — either the elapsed time was non-positive or the
    /// computed speed sat at or below the threshold.
    None,
    /// Anomaly fired and should be forwarded to SOC sinks.
    Detected(TravelAnomaly),
    /// Anomaly would have fired but both endpoints sit inside the
    /// tenant's VPN egress allowlist; suppress the SOC emission but
    /// retain the evidence for audit.
    Suppressed(TravelAnomaly),
}

impl TravelDecision {
    /// Returns the wrapped anomaly for either firing or suppression, if any.
    #[must_use]
    pub const fn anomaly(&self) -> Option<&TravelAnomaly> {
        match self {
            Self::Detected(a) | Self::Suppressed(a) => Some(a),
            Self::None => None,
        }
    }

    /// `true` when a finding should be forwarded to SOC sinks.
    #[must_use]
    pub const fn is_detected(&self) -> bool {
        matches!(self, Self::Detected(_))
    }

    /// `true` when an anomaly was geometrically real but suppressed by
    /// the per-tenant VPN allowlist.
    #[must_use]
    pub const fn is_suppressed(&self) -> bool {
        matches!(self, Self::Suppressed(_))
    }
}

/// Evaluate a pair of login records against an optional per-tenant VPN
/// allowlist.
///
/// If [`evaluate`] would return `Some(anomaly)` AND both endpoints'
/// ASNs are present in `allowlist`, the result is
/// [`TravelDecision::Suppressed`]. Otherwise the wrapped anomaly is
/// returned as [`TravelDecision::Detected`]. When the underlying
/// geometric check declines (same time, same place, out-of-order), the
/// result is [`TravelDecision::None`].
#[must_use]
pub fn evaluate_with_allowlist(
    prev: &LoginRecord,
    curr: &LoginRecord,
    max_kmh: f64,
    allowlist: &TenantVpnAllowlist,
) -> TravelDecision {
    let Some(anomaly) = evaluate(prev, curr, max_kmh) else {
        return TravelDecision::None;
    };
    if both_endpoints_in_allowlist(prev, curr, allowlist) {
        TravelDecision::Suppressed(anomaly)
    } else {
        TravelDecision::Detected(anomaly)
    }
}

/// Return `true` when both records carry an ASN and *both* of those
/// ASNs are present in the supplied per-tenant allowlist. Missing ASN
/// or empty allowlist mean "no suppression".
fn both_endpoints_in_allowlist(
    prev: &LoginRecord,
    curr: &LoginRecord,
    allowlist: &TenantVpnAllowlist,
) -> bool {
    let (Some(prev_asn), Some(curr_asn)) = (prev.asn, curr.asn) else {
        return false;
    };
    allowlist.contains(prev_asn) && allowlist.contains(curr_asn)
}

/// Per-tenant set of ASNs treated as "corporate VPN egress".
///
/// When the impossible-travel geometric check fires AND both endpoints'
/// ASNs sit inside this set, the finding is suppressed (audit-only).
/// This implements the P2-007 acceptance criterion:
/// "if both IPs in known VPN egress list for tenant, suppress".
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TenantVpnAllowlist {
    asns: HashSet<u32>,
}

impl TenantVpnAllowlist {
    /// Empty allowlist (suppresses nothing).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert one ASN; returns `self` for builder-style chaining.
    #[must_use]
    pub fn with(mut self, asn: u32) -> Self {
        self.asns.insert(asn);
        self
    }

    /// Returns `true` when `asn` is on the allowlist.
    #[must_use]
    pub fn contains(&self, asn: u32) -> bool {
        self.asns.contains(&asn)
    }

    /// Number of ASNs on the allowlist.
    #[must_use]
    pub fn len(&self) -> usize {
        self.asns.len()
    }

    /// `true` when the allowlist is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.asns.is_empty()
    }
}

impl FromIterator<u32> for TenantVpnAllowlist {
    /// Build an allowlist from any iterator of ASNs.
    fn from_iter<I: IntoIterator<Item = u32>>(iter: I) -> Self {
        Self {
            asns: iter.into_iter().collect(),
        }
    }
}

/// Great-circle distance in kilometres between two `(lat, lon)` pairs.
///
/// Inputs are in decimal degrees; the function converts to radians
/// internally. Uses the haversine formula with the IUGG mean Earth radius.
#[must_use]
pub fn haversine_km(lat1_deg: f64, lon1_deg: f64, lat2_deg: f64, lon2_deg: f64) -> f64 {
    let lat1 = lat1_deg.to_radians();
    let lat2 = lat2_deg.to_radians();
    let d_lat = (lat2_deg - lat1_deg).to_radians();
    let d_lon = (lon2_deg - lon1_deg).to_radians();

    let sin_half_dlat = (d_lat / 2.0).sin();
    let sin_half_dlon = (d_lon / 2.0).sin();

    let a = sin_half_dlat.mul_add(
        sin_half_dlat,
        lat1.cos() * lat2.cos() * sin_half_dlon * sin_half_dlon,
    );
    // Clamp `a` defensively into [0, 1] to absorb FP drift near antipodes.
    let a = a.clamp(0.0, 1.0);
    let c = 2.0 * a.sqrt().atan2((1.0 - a).sqrt());
    EARTH_RADIUS_KM * c
}

/// Storage abstraction for the most-recent login per (tenant, user).
///
/// The trait is `async` so that production implementations (Redis,
/// Postgres, ...) can perform real I/O. For unit tests and the
/// in-process correlator path, [`InMemoryLoginHistoryRepo`] is provided.
///
/// ## Tenant scoping
///
/// Production multi-tenant deployments must NEVER mix tenants in this
/// store: a login by `user_id="alice"` under tenant A must never match
/// `user_id="alice"` under tenant B (which could even be a different
/// human). [`Self::last_login_for_tenant`] is the canonical API; the
/// legacy [`Self::last_login`] is kept for single-tenant tests and
/// implicitly maps to the "global" (no-tenant) bucket.
#[async_trait]
pub trait LoginHistoryRepo: Send + Sync {
    /// Return the most-recent login for `user_id`, or `None` if no prior
    /// login is on file. Treats the "no tenant" bucket; production
    /// callers should prefer [`Self::last_login_for_tenant`].
    async fn last_login(&self, user_id: &str) -> Result<Option<LoginRecord>, SocError>;

    /// Persist `rec` as the most-recent login for `(rec.tenant_id, rec.user_id)`.
    async fn record_login(&self, rec: &LoginRecord) -> Result<(), SocError>;

    /// Tenant-scoped lookup. Default delegates to [`Self::last_login`]
    /// when `tenant_id` is `None`; implementors should override to
    /// honour real tenant isolation.
    async fn last_login_for_tenant(
        &self,
        tenant_id: Option<&str>,
        user_id: &str,
    ) -> Result<Option<LoginRecord>, SocError> {
        // Default: ignore tenant. Real implementors override.
        let _ = tenant_id;
        self.last_login(user_id).await
    }
}

/// In-memory, single-process [`LoginHistoryRepo`] for tests and embedded
/// use. Each call to `record_login` overwrites the previous entry for
/// the same `(tenant_id, user_id)` key.
#[derive(Debug, Default)]
pub struct InMemoryLoginHistoryRepo {
    inner: Mutex<HashMap<(Option<String>, String), LoginRecord>>,
}

impl InMemoryLoginHistoryRepo {
    /// Build an empty repo.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl LoginHistoryRepo for InMemoryLoginHistoryRepo {
    async fn last_login(&self, user_id: &str) -> Result<Option<LoginRecord>, SocError> {
        let guard = self.inner.lock().await;
        Ok(guard.get(&(None, user_id.to_owned())).cloned())
    }

    async fn record_login(&self, rec: &LoginRecord) -> Result<(), SocError> {
        let key = (rec.tenant_id.clone(), rec.user_id.clone());
        let value = rec.clone();
        let mut guard = self.inner.lock().await;
        guard.insert(key, value);
        drop(guard);
        Ok(())
    }

    async fn last_login_for_tenant(
        &self,
        tenant_id: Option<&str>,
        user_id: &str,
    ) -> Result<Option<LoginRecord>, SocError> {
        let guard = self.inner.lock().await;
        Ok(guard
            .get(&(tenant_id.map(ToOwned::to_owned), user_id.to_owned()))
            .cloned())
    }
}

#[cfg(test)]
#[allow(
    clippy::float_cmp,
    clippy::unreadable_literal,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]
mod tests {
    use super::*;
    use time::Duration;

    fn ts(year: i32, month: u8, day: u8, h: u8, m: u8, s: u8) -> OffsetDateTime {
        let month = time::Month::try_from(month).expect("valid month");
        let date = time::Date::from_calendar_date(year, month, day).expect("valid date");
        let time = time::Time::from_hms(h, m, s).expect("valid time");
        date.with_time(time).assume_utc()
    }

    fn approx(actual: f64, expected: f64, tol: f64) -> bool {
        (actual - expected).abs() <= tol
    }

    // ---------- haversine ground truth ----------

    #[test]
    fn haversine_jakarta_to_singapore_is_about_900_km() {
        // Jakarta CGK (-6.1751, 106.8650) → Singapore SIN (1.3521, 103.8198)
        // Great-circle distance ≈ 902 km between the two airport coordinates;
        // the commonly cited "Jakarta–Singapore ≈ 880 km" figure refers to
        // the city centres and is within ~25 km of the airport pairing.
        let d = haversine_km(-6.1751, 106.8650, 1.3521, 103.8198);
        assert!(
            approx(d, 900.0, 25.0),
            "Jakarta→Singapore expected ≈900km (±25), got {d}"
        );
    }

    #[test]
    fn haversine_nyc_to_london_is_about_5570_km() {
        // New York JFK (40.6413, -73.7781) → London LHR (51.4700, -0.4543)
        // Published great-circle distance ≈ 5_540 km.
        let d = haversine_km(40.6413, -73.7781, 51.4700, -0.4543);
        assert!(
            approx(d, 5570.0, 50.0),
            "NYC→London expected ≈5570km, got {d}"
        );
    }

    #[test]
    fn haversine_identity_is_zero() {
        let d = haversine_km(37.7749, -122.4194, 37.7749, -122.4194);
        assert!(d.abs() < 1e-9, "identity distance must be 0, got {d}");
    }

    #[test]
    fn haversine_antipodal_is_about_half_circumference() {
        // (0, 0) and (0, 180) — antipodal along the equator: πR ≈ 20015 km.
        let d = haversine_km(0.0, 0.0, 0.0, 180.0);
        let expected = std::f64::consts::PI * EARTH_RADIUS_KM;
        assert!(
            approx(d, expected, 1e-6),
            "antipodal along equator expected {expected}, got {d}"
        );
    }

    #[test]
    fn haversine_pole_to_pole_is_about_half_circumference() {
        // North pole → south pole, also πR.
        let d = haversine_km(90.0, 0.0, -90.0, 0.0);
        let expected = std::f64::consts::PI * EARTH_RADIUS_KM;
        assert!(
            approx(d, expected, 1.0),
            "pole-to-pole expected {expected}, got {d}"
        );
    }

    // ---------- evaluate() behaviour ----------

    #[test]
    fn evaluate_same_location_same_time_returns_none() {
        let t = ts(2026, 6, 12, 10, 0, 0);
        let prev = LoginRecord::new("alice", 37.7749, -122.4194, t);
        let curr = LoginRecord::new("alice", 37.7749, -122.4194, t);
        assert!(evaluate(&prev, &curr, 800.0).is_none());
    }

    #[test]
    fn evaluate_zero_elapsed_returns_none_no_division_by_zero() {
        let t = ts(2026, 6, 12, 10, 0, 0);
        // Far apart, but elapsed = 0 → must not divide by zero.
        let prev = LoginRecord::new("alice", -6.1751, 106.8650, t);
        let curr = LoginRecord::new("alice", 1.3521, 103.8198, t);
        let out = evaluate(&prev, &curr, 800.0);
        assert!(out.is_none(), "elapsed=0 must yield None, got {out:?}");
    }

    #[test]
    fn evaluate_negative_elapsed_returns_none() {
        // Out-of-order events: curr is *before* prev.
        let earlier = ts(2026, 6, 12, 10, 0, 0);
        let later = ts(2026, 6, 12, 12, 0, 0);
        let prev = LoginRecord::new("alice", -6.1751, 106.8650, later);
        let curr = LoginRecord::new("alice", 1.3521, 103.8198, earlier);
        assert!(evaluate(&prev, &curr, 800.0).is_none());
    }

    #[test]
    fn evaluate_jakarta_to_london_in_one_hour_is_anomalous() {
        // ~11_700 km in 1h → ~11_700 km/h, far above commercial-jet ceiling.
        let prev = LoginRecord::new("alice", -6.1751, 106.8650, ts(2026, 6, 12, 10, 0, 0));
        let curr = LoginRecord::new("alice", 51.4700, -0.4543, ts(2026, 6, 12, 11, 0, 0));
        let anomaly = evaluate(&prev, &curr, 800.0).expect("must fire");
        assert_eq!(anomaly.user_id, "alice");
        assert_eq!(anomaly.threshold_kmh, 800.0);
        assert!(anomaly.elapsed_secs > 0.0);
        assert!(anomaly.distance_km > 10_000.0);
        assert!(anomaly.computed_kmh > 800.0);
    }

    #[test]
    fn evaluate_realistic_flight_under_threshold_is_none() {
        // Jakarta→Singapore over 2h = ~440 km/h → well under 800.
        let prev = LoginRecord::new("alice", -6.1751, 106.8650, ts(2026, 6, 12, 10, 0, 0));
        let curr = LoginRecord::new("alice", 1.3521, 103.8198, ts(2026, 6, 12, 12, 0, 0));
        assert!(evaluate(&prev, &curr, 800.0).is_none());
    }

    #[test]
    fn evaluate_at_threshold_exactly_returns_none() {
        // The predicate is strict-greater-than, so a speed at-or-below the
        // ceiling must NOT fire. We construct a journey of exactly 800 km
        // covered in exactly 1 hour, then add a 1 ms slack to absorb FP
        // round-off and confirm we sit *at* (or just under) the threshold.
        let dist = haversine_km(0.0, 0.0, 0.0, 7.194);
        // Solve elapsed such that dist / (elapsed/3600) <= 800.0.
        // Adding 0.001 s makes computed_kmh strictly less than 800.0 even
        // with f64 round-off in atan2/sqrt.
        let elapsed_secs = dist * 3600.0 / 800.0 + 0.001;
        let prev_t = ts(2026, 6, 12, 10, 0, 0);
        let curr_t = prev_t + Duration::seconds_f64(elapsed_secs);
        let prev = LoginRecord::new("alice", 0.0, 0.0, prev_t);
        let curr = LoginRecord::new("alice", 0.0, 7.194, curr_t);
        let out = evaluate(&prev, &curr, 800.0);
        assert!(
            out.is_none(),
            "speed at-or-below threshold must not fire, got {out:?}"
        );
    }

    #[test]
    fn evaluate_just_above_threshold_fires() {
        // Same geometry as above but shave 1 second off the elapsed time to
        // push computed_kmh just above the threshold.
        let dist = haversine_km(0.0, 0.0, 0.0, 7.194);
        let elapsed_secs = dist * 3600.0 / 800.0 - 1.0;
        let prev_t = ts(2026, 6, 12, 10, 0, 0);
        let curr_t = prev_t + Duration::seconds_f64(elapsed_secs);
        let prev = LoginRecord::new("alice", 0.0, 0.0, prev_t);
        let curr = LoginRecord::new("alice", 0.0, 7.194, curr_t);
        let anomaly = evaluate(&prev, &curr, 800.0).expect("must fire just above threshold");
        assert!(anomaly.computed_kmh > 800.0);
    }

    #[test]
    fn evaluate_antipodal_in_short_window_fires() {
        // (0,0) → (0,180): ~20015 km in 30 minutes → ~40030 km/h.
        let prev = LoginRecord::new("alice", 0.0, 0.0, ts(2026, 6, 12, 10, 0, 0));
        let curr = LoginRecord::new("alice", 0.0, 180.0, ts(2026, 6, 12, 10, 30, 0));
        let anomaly = evaluate(&prev, &curr, 800.0).expect("must fire");
        assert!(anomaly.distance_km > 19_000.0);
        assert!(anomaly.computed_kmh > 30_000.0);
    }

    #[test]
    fn travel_anomaly_carries_user_id_from_current_record() {
        // user_id is taken from `curr` so that re-keyed accounts surface
        // with their current identity.
        let prev = LoginRecord::new("old-alice", -6.1751, 106.8650, ts(2026, 6, 12, 10, 0, 0));
        let curr = LoginRecord::new("new-alice", 51.4700, -0.4543, ts(2026, 6, 12, 11, 0, 0));
        let anomaly = evaluate(&prev, &curr, 800.0).expect("must fire");
        assert_eq!(anomaly.user_id, "new-alice");
    }

    // ---------- LoginHistoryRepo (InMemory) ----------

    #[tokio::test]
    async fn in_memory_repo_round_trip() {
        let repo = InMemoryLoginHistoryRepo::new();
        let rec = LoginRecord::new("alice", 1.0, 2.0, ts(2026, 6, 12, 10, 0, 0));

        assert!(repo.last_login("alice").await.expect("ok").is_none());

        repo.record_login(&rec).await.expect("ok");

        let got = repo
            .last_login("alice")
            .await
            .expect("ok")
            .expect("present");
        assert_eq!(got, rec);
    }

    #[tokio::test]
    async fn in_memory_repo_overwrites_previous_entry() {
        let repo = InMemoryLoginHistoryRepo::new();
        let r1 = LoginRecord::new("alice", 1.0, 2.0, ts(2026, 6, 12, 10, 0, 0));
        let r2 = LoginRecord::new("alice", 3.0, 4.0, ts(2026, 6, 12, 11, 0, 0));
        repo.record_login(&r1).await.expect("ok");
        repo.record_login(&r2).await.expect("ok");

        let got = repo
            .last_login("alice")
            .await
            .expect("ok")
            .expect("present");
        assert_eq!(got, r2);
    }

    #[tokio::test]
    async fn in_memory_repo_isolates_users() {
        let repo = InMemoryLoginHistoryRepo::new();
        let alice = LoginRecord::new("alice", 1.0, 2.0, ts(2026, 6, 12, 10, 0, 0));
        let bob = LoginRecord::new("bob", 5.0, 6.0, ts(2026, 6, 12, 10, 0, 0));
        repo.record_login(&alice).await.expect("ok");
        repo.record_login(&bob).await.expect("ok");

        let got_alice = repo
            .last_login("alice")
            .await
            .expect("ok")
            .expect("present");
        let got_bob = repo.last_login("bob").await.expect("ok").expect("present");
        assert_eq!(got_alice, alice);
        assert_eq!(got_bob, bob);
    }

    // ---------- Tenant isolation ----------

    #[tokio::test]
    async fn in_memory_repo_isolates_same_user_across_tenants() {
        // Two distinct tenants log a user named "alice" — the entries
        // must not bleed across tenant boundaries.
        let repo = InMemoryLoginHistoryRepo::new();
        let a = LoginRecord::with_context(
            "tenant-a",
            "alice",
            -6.1751,
            106.8650,
            ts(2026, 6, 12, 10, 0, 0),
            Some("203.0.113.5".into()),
            Some(64500),
        );
        let b = LoginRecord::with_context(
            "tenant-b",
            "alice",
            40.7128,
            -74.0060,
            ts(2026, 6, 12, 10, 0, 0),
            Some("198.51.100.7".into()),
            Some(64501),
        );
        repo.record_login(&a).await.expect("ok");
        repo.record_login(&b).await.expect("ok");

        let got_a = repo
            .last_login_for_tenant(Some("tenant-a"), "alice")
            .await
            .expect("ok")
            .expect("present");
        let got_b = repo
            .last_login_for_tenant(Some("tenant-b"), "alice")
            .await
            .expect("ok")
            .expect("present");
        assert_eq!(got_a, a);
        assert_eq!(got_b, b);
        // Cross-tenant queries get nothing.
        let cross = repo
            .last_login_for_tenant(Some("tenant-c"), "alice")
            .await
            .expect("ok");
        assert!(cross.is_none());
    }

    // ---------- VPN allowlist suppression ----------

    fn jakarta() -> (f64, f64) {
        (-6.1751, 106.8650)
    }
    fn nyc() -> (f64, f64) {
        (40.7128, -74.0060)
    }

    #[test]
    fn jakarta_to_nyc_fifteen_minutes_apart_is_detected() {
        // P2-007 spec test: Jakarta → NYC, 15 minutes apart, must fire.
        // Great-circle ~16_000 km / 0.25 h = ~64_000 km/h, well above 800.
        let (jl, jo) = jakarta();
        let (nl, no) = nyc();
        let prev = LoginRecord::with_context(
            "tenant-x",
            "alice",
            jl,
            jo,
            ts(2026, 6, 12, 10, 0, 0),
            Some("203.0.113.5".into()),
            Some(64500),
        );
        let curr = LoginRecord::with_context(
            "tenant-x",
            "alice",
            nl,
            no,
            ts(2026, 6, 12, 10, 15, 0),
            Some("198.51.100.7".into()),
            Some(64501),
        );
        let allowlist = TenantVpnAllowlist::new();
        let decision = evaluate_with_allowlist(&prev, &curr, 800.0, &allowlist);
        let anomaly = decision.anomaly().expect("must carry anomaly");
        assert!(decision.is_detected(), "must fire, got {decision:?}");
        assert_eq!(anomaly.user_id, "alice");
        assert_eq!(anomaly.tenant_id.as_deref(), Some("tenant-x"));
        assert!(anomaly.computed_kmh > 800.0);
        assert!(anomaly.distance_km > 10_000.0);
        // Evidence: both IPs / ASNs preserved.
        let prev_ev = anomaly.prev.as_ref().expect("prev preserved");
        let curr_ev = anomaly.curr.as_ref().expect("curr preserved");
        assert_eq!(prev_ev.source_ip.as_deref(), Some("203.0.113.5"));
        assert_eq!(curr_ev.source_ip.as_deref(), Some("198.51.100.7"));
        assert_eq!(prev_ev.asn, Some(64500));
        assert_eq!(curr_ev.asn, Some(64501));
    }

    #[test]
    fn same_location_same_place_is_decision_none() {
        // P2-007 spec test: same login same place → no alert.
        let t = ts(2026, 6, 12, 10, 0, 0);
        let prev = LoginRecord::with_context(
            "tenant-x",
            "alice",
            37.7749,
            -122.4194,
            t,
            Some("203.0.113.5".into()),
            Some(64500),
        );
        // Same place, an hour later — speed = 0.
        let later = ts(2026, 6, 12, 11, 0, 0);
        let curr = LoginRecord::with_context(
            "tenant-x",
            "alice",
            37.7749,
            -122.4194,
            later,
            Some("203.0.113.5".into()),
            Some(64500),
        );
        let allowlist = TenantVpnAllowlist::new();
        let decision = evaluate_with_allowlist(&prev, &curr, 800.0, &allowlist);
        assert_eq!(decision, TravelDecision::None);
    }

    #[test]
    fn both_endpoints_in_vpn_allowlist_suppresses_finding() {
        // P2-007 spec test: VPN allowlist suppression. The geometry would
        // fire (Jakarta → NYC in 15 minutes), but both ASNs belong to the
        // tenant's corporate-VPN egress, so the decision is Suppressed.
        let (jl, jo) = jakarta();
        let (nl, no) = nyc();
        let prev = LoginRecord::with_context(
            "tenant-x",
            "alice",
            jl,
            jo,
            ts(2026, 6, 12, 10, 0, 0),
            Some("203.0.113.5".into()),
            Some(64500),
        );
        let curr = LoginRecord::with_context(
            "tenant-x",
            "alice",
            nl,
            no,
            ts(2026, 6, 12, 10, 15, 0),
            Some("198.51.100.7".into()),
            // Same corporate AS as `prev` — matches allowlist.
            Some(64500),
        );
        let allowlist = TenantVpnAllowlist::from_iter([64500_u32]);
        let decision = evaluate_with_allowlist(&prev, &curr, 800.0, &allowlist);
        assert!(decision.is_suppressed(), "must suppress, got {decision:?}");
        let anomaly = decision.anomaly().expect("evidence preserved");
        assert!(anomaly.computed_kmh > 800.0);
    }

    #[test]
    fn only_one_endpoint_in_allowlist_does_not_suppress() {
        // If only the previous login is on the corporate VPN but the
        // current one is from elsewhere, that's exactly the suspicious
        // pattern we want to surface — do NOT suppress.
        let (jl, jo) = jakarta();
        let (nl, no) = nyc();
        let prev = LoginRecord::with_context(
            "tenant-x",
            "alice",
            jl,
            jo,
            ts(2026, 6, 12, 10, 0, 0),
            Some("203.0.113.5".into()),
            Some(64500),
        );
        let curr = LoginRecord::with_context(
            "tenant-x",
            "alice",
            nl,
            no,
            ts(2026, 6, 12, 10, 15, 0),
            Some("198.51.100.7".into()),
            Some(64599), // not on allowlist
        );
        let allowlist = TenantVpnAllowlist::from_iter([64500_u32]);
        let decision = evaluate_with_allowlist(&prev, &curr, 800.0, &allowlist);
        assert!(
            decision.is_detected(),
            "must NOT suppress, got {decision:?}"
        );
    }

    #[test]
    fn missing_asn_means_no_suppression() {
        // Defensive: even an allowlist match can't apply when one
        // endpoint doesn't carry ASN evidence.
        let (jl, jo) = jakarta();
        let (nl, no) = nyc();
        let prev = LoginRecord::with_context(
            "tenant-x",
            "alice",
            jl,
            jo,
            ts(2026, 6, 12, 10, 0, 0),
            Some("203.0.113.5".into()),
            None,
        );
        let curr = LoginRecord::with_context(
            "tenant-x",
            "alice",
            nl,
            no,
            ts(2026, 6, 12, 10, 15, 0),
            Some("198.51.100.7".into()),
            Some(64500),
        );
        let allowlist = TenantVpnAllowlist::from_iter([64500_u32]);
        let decision = evaluate_with_allowlist(&prev, &curr, 800.0, &allowlist);
        assert!(decision.is_detected(), "missing ASN must not suppress");
    }

    #[test]
    fn tenant_vpn_allowlist_builder_apis() {
        let al = TenantVpnAllowlist::new().with(1).with(2).with(3);
        assert_eq!(al.len(), 3);
        assert!(al.contains(2));
        assert!(!al.contains(99));
        assert!(!al.is_empty());
        let empty = TenantVpnAllowlist::new();
        assert!(empty.is_empty());
    }
}
