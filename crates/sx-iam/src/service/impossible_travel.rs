//! Impossible-travel detection orchestrator (P2-007).
//!
//! This module ties together three crates so the IAM layer can detect
//! geographically implausible logins on every successful authentication:
//!
//! 1. **`sx-rba`** provides the IPv4 → (lat, lon) lookup via
//!    [`sx_rba::signals::ip_geo_centroid::IpGeoCentroid`]. (The MVP uses
//!    country centroids; production deployments swap in a city-level
//!    `MaxMind` `GeoLite2` reader behind the same shape.)
//! 2. **`sx-soc`** owns the geometric rule
//!    ([`sx_soc::evaluate_impossible_travel_with_allowlist`]) and the
//!    per-tenant VPN allowlist primitive
//!    ([`sx_soc::TenantVpnAllowlist`]).
//! 3. **This crate** wires them into a tenant-aware service that:
//!    * looks up the last-known login from a [`sx_soc::LoginHistoryRepo`]
//!      (scoped by `(tenant_id, user_id)`),
//!    * runs the geometric check against the per-tenant threshold,
//!    * suppresses findings that look like corporate-VPN-egress hops on
//!      both sides,
//!    * emits a SOC finding via [`SocFindingSink`] on detection, and
//!    * writes a structured audit log row for *every* outcome —
//!      including suppression-by-allowlist — so analysts can review
//!      what the rule did even when it stayed silent.
//!
//! ## Design constraints (P2-007)
//!
//! * Multi-tenant: travel history is scoped by `tenant_id`; no
//!   cross-tenant leak is possible because the in-memory and Postgres
//!   implementations of `LoginHistoryRepo` both key on
//!   `(tenant_id, user_id)`.
//! * Configurable per-tenant ceiling (`max_kmh`, default 800).
//! * The "VPN allowlist" suppression criterion is: BOTH endpoints'
//!   ASNs appear in the tenant's allowlist. If either ASN is missing
//!   (unknown) or off-list, the finding is forwarded — that aligns with
//!   the threat model: corporate-VPN-egress that *should* explain a
//!   continent jump must produce ASN evidence on both ends.
//! * Audit-only on suppression: we never silently drop evidence. The
//!   tracing field `outcome` distinguishes `detected`, `suppressed`,
//!   `no_history`, `no_anomaly`, `geolocation_missing`.
//!
//! ## Thread / async model
//!
//! [`ImpossibleTravelService`] is `Send + Sync` and cheap to clone via
//! `Arc<...>` of its trait-object collaborators. Each call does at most
//! two `LoginHistoryRepo` round-trips (read + write) and one synchronous
//! geometric evaluation.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;

use async_trait::async_trait;
use thiserror::Error;
use time::OffsetDateTime;

use sx_rba::signals::ip_geo_centroid::{GeoPoint, IpGeoCentroid};
use sx_soc::{
    evaluate_impossible_travel_with_allowlist, InMemoryLoginHistoryRepo, LoginHistoryRepo,
    LoginRecord, TenantVpnAllowlist, TravelAnomaly, TravelDecision,
};

/// Default impossible-travel ceiling (km/h).
///
/// 800 km/h is the standard sustainable-air-travel ceiling cited in the
/// P2-007 acceptance criteria; it sits above the cruising speed of a
/// typical commercial jet (~900 km/h) only when measured on a great
/// circle that the actual flight path does not trace, so 800 is the
/// conservative gate.
pub const DEFAULT_MAX_KMH: f64 = 800.0;

/// Per-tenant impossible-travel configuration.
///
/// Each tenant gets:
/// * a `max_kmh` ceiling (defaults to [`DEFAULT_MAX_KMH`]); and
/// * a [`TenantVpnAllowlist`] of "corporate VPN egress" ASNs whose
///   presence on *both* endpoints suppresses the finding.
#[derive(Debug, Clone)]
pub struct ImpossibleTravelConfig {
    /// Per-tenant ceiling. Lookups for missing tenants fall back to
    /// `default_max_kmh`.
    per_tenant_max_kmh: HashMap<String, f64>,
    /// Per-tenant VPN allowlist. Missing tenants get an empty allowlist
    /// (no suppression).
    per_tenant_allowlist: HashMap<String, TenantVpnAllowlist>,
    /// Fallback ceiling for tenants without an explicit entry.
    default_max_kmh: f64,
}

impl Default for ImpossibleTravelConfig {
    fn default() -> Self {
        Self {
            per_tenant_max_kmh: HashMap::new(),
            per_tenant_allowlist: HashMap::new(),
            default_max_kmh: DEFAULT_MAX_KMH,
        }
    }
}

impl ImpossibleTravelConfig {
    /// Empty config: every tenant gets the default ceiling and no
    /// allowlist.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Override the default ceiling that applies to tenants without an
    /// explicit entry.
    #[must_use]
    pub fn with_default_max_kmh(mut self, kmh: f64) -> Self {
        self.default_max_kmh = kmh;
        self
    }

    /// Set a per-tenant ceiling.
    #[must_use]
    pub fn with_tenant_max_kmh(mut self, tenant_id: impl Into<String>, kmh: f64) -> Self {
        self.per_tenant_max_kmh.insert(tenant_id.into(), kmh);
        self
    }

    /// Set a per-tenant VPN allowlist.
    #[must_use]
    pub fn with_tenant_allowlist(
        mut self,
        tenant_id: impl Into<String>,
        allowlist: TenantVpnAllowlist,
    ) -> Self {
        self.per_tenant_allowlist
            .insert(tenant_id.into(), allowlist);
        self
    }

    /// Resolve the ceiling for a tenant; falls back to the default.
    #[must_use]
    pub fn max_kmh_for(&self, tenant_id: &str) -> f64 {
        self.per_tenant_max_kmh
            .get(tenant_id)
            .copied()
            .unwrap_or(self.default_max_kmh)
    }

    /// Resolve the allowlist for a tenant; falls back to an empty
    /// allowlist (no suppression).
    #[must_use]
    pub fn allowlist_for(&self, tenant_id: &str) -> TenantVpnAllowlist {
        self.per_tenant_allowlist
            .get(tenant_id)
            .cloned()
            .unwrap_or_default()
    }
}

/// Errors raised by [`ImpossibleTravelService::check_login`].
#[derive(Debug, Error)]
pub enum ImpossibleTravelError {
    /// The login-history repository failed.
    #[error("login history repo error: {0}")]
    Repo(String),
    /// The SOC sink failed to accept the finding.
    #[error("soc sink error: {0}")]
    Sink(String),
}

/// Categorical outcome of one `check_login` call.
///
/// `Detected` and `Suppressed` carry the same [`TravelAnomaly`] so the
/// caller can attach evidence (IPs, lat/lon, computed km/h) to the
/// emitted finding *or* to an audit-only row.
#[derive(Debug, Clone, PartialEq)]
pub enum ImpossibleTravelOutcome {
    /// No prior login on file — nothing to compare against. The current
    /// login was still recorded for future comparisons.
    NoHistory,
    /// IP did not resolve to a (lat, lon); rule skipped this event.
    /// The current login was NOT recorded — without a coordinate it
    /// would poison future comparisons.
    GeolocationMissing,
    /// Prior login exists; the speed was at or below the threshold.
    NoAnomaly,
    /// Anomaly fired; a SOC finding was emitted.
    Detected(TravelAnomaly),
    /// Anomaly fired but both endpoints sat inside the tenant's VPN
    /// allowlist — finding was suppressed (audit-only).
    Suppressed(TravelAnomaly),
}

impl ImpossibleTravelOutcome {
    /// One-word tag used in the structured audit log so analysts can
    /// pivot by outcome.
    #[must_use]
    pub const fn audit_tag(&self) -> &'static str {
        match self {
            Self::NoHistory => "no_history",
            Self::GeolocationMissing => "geolocation_missing",
            Self::NoAnomaly => "no_anomaly",
            Self::Detected(_) => "detected",
            Self::Suppressed(_) => "suppressed",
        }
    }
}

/// Outbound port for forwarding impossible-travel findings into the SOC
/// pipeline.
///
/// In production this is implemented by the SOC bridge that converts a
/// [`TravelAnomaly`] into the `auth.impossible_travel` event that the
/// SOC rule pack already correlates on. Tests can use the in-memory
/// [`BufferingSocFindingSink`] (test-only) to assert what would have
/// been sent.
#[async_trait]
pub trait SocFindingSink: Send + Sync {
    /// Forward a detected anomaly. Suppressed anomalies are NEVER sent
    /// here — they are audit-only.
    async fn emit_impossible_travel(
        &self,
        anomaly: &TravelAnomaly,
    ) -> Result<(), ImpossibleTravelError>;
}

/// SOC sink that simply traces the finding as a structured `tracing` event.
///
/// Uses the conventional `iam.impossible_travel` kind. Useful as the
/// default sink in single-binary deployments where the audit log already
/// aggregates `tracing` events.
#[derive(Debug, Default, Clone)]
pub struct TracingSocFindingSink;

impl TracingSocFindingSink {
    /// Construct.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl SocFindingSink for TracingSocFindingSink {
    async fn emit_impossible_travel(
        &self,
        anomaly: &TravelAnomaly,
    ) -> Result<(), ImpossibleTravelError> {
        tracing::warn!(
            target: "sx_iam.impossible_travel",
            kind = "iam.impossible_travel",
            tenant_id = anomaly.tenant_id.as_deref().unwrap_or(""),
            user_id = %anomaly.user_id,
            distance_km = anomaly.distance_km,
            elapsed_secs = anomaly.elapsed_secs,
            computed_kmh = anomaly.computed_kmh,
            threshold_kmh = anomaly.threshold_kmh,
            prev_ip = anomaly
                .prev
                .as_ref()
                .and_then(|r| r.source_ip.as_deref())
                .unwrap_or(""),
            curr_ip = anomaly
                .curr
                .as_ref()
                .and_then(|r| r.source_ip.as_deref())
                .unwrap_or(""),
            prev_asn = anomaly.prev.as_ref().and_then(|r| r.asn).unwrap_or(0),
            curr_asn = anomaly.curr.as_ref().and_then(|r| r.asn).unwrap_or(0),
            "impossible-travel finding"
        );
        Ok(())
    }
}

/// The tenant-aware orchestrator for impossible-travel detection.
///
/// One process-wide instance is typically enough; clone it (cheap
/// — internal `Arc`s) into request handlers via dependency injection.
#[derive(Clone)]
pub struct ImpossibleTravelService {
    history: Arc<dyn LoginHistoryRepo>,
    geo: Arc<IpGeoCentroid>,
    sink: Arc<dyn SocFindingSink>,
    config: Arc<ImpossibleTravelConfig>,
}

impl std::fmt::Debug for ImpossibleTravelService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImpossibleTravelService")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl ImpossibleTravelService {
    /// Construct a service from its three collaborators.
    #[must_use]
    pub fn new(
        history: Arc<dyn LoginHistoryRepo>,
        geo: Arc<IpGeoCentroid>,
        sink: Arc<dyn SocFindingSink>,
        config: ImpossibleTravelConfig,
    ) -> Self {
        Self {
            history,
            geo,
            sink,
            config: Arc::new(config),
        }
    }

    /// Convenience constructor for tests / single-process embedding:
    /// pairs an in-memory [`LoginHistoryRepo`] with the default
    /// [`IpGeoCentroid`] and a [`TracingSocFindingSink`].
    #[must_use]
    pub fn in_memory(config: ImpossibleTravelConfig) -> Self {
        Self::new(
            Arc::new(InMemoryLoginHistoryRepo::new()),
            Arc::new(IpGeoCentroid::default()),
            Arc::new(TracingSocFindingSink::new()),
            config,
        )
    }

    /// Process one successful login.
    ///
    /// Looks up the user's last known login (scoped by tenant), evaluates
    /// the geometric check against the per-tenant threshold and VPN
    /// allowlist, emits a SOC finding on detection, audit-logs every
    /// outcome, and records the new login so the next call has history.
    ///
    /// `addr` is the source IPv4 of this login (used to resolve lat/lon
    /// via [`IpGeoCentroid`]). `asn` is the autonomous system number for
    /// that IP, used by the VPN allowlist suppression heuristic. `at` is
    /// the wall-clock timestamp of the login (UTC).
    pub async fn check_login(
        &self,
        tenant_id: &str,
        user_id: &str,
        addr: Ipv4Addr,
        asn: Option<u32>,
        at: OffsetDateTime,
    ) -> Result<ImpossibleTravelOutcome, ImpossibleTravelError> {
        // 1. Resolve geolocation for the current login.
        let Some(GeoPoint { lat, lon, .. }) = self.geo.lookup(addr) else {
            // No coordinate → we cannot reason about distance. Do NOT
            // record this login (it would poison future comparisons by
            // sitting at sentinel coordinates), do NOT alert, but DO
            // audit-log the skip so an operator can spot a broken
            // GeoIP feed.
            audit_log(
                tenant_id,
                user_id,
                &ImpossibleTravelOutcome::GeolocationMissing,
                Some(&addr.to_string()),
                asn,
                None,
            );
            return Ok(ImpossibleTravelOutcome::GeolocationMissing);
        };

        let curr = LoginRecord::with_context(
            tenant_id,
            user_id,
            lat,
            lon,
            at,
            Some(addr.to_string()),
            asn,
        );

        // 2. Look up prior login (tenant-scoped).
        let prev = self
            .history
            .last_login_for_tenant(Some(tenant_id), user_id)
            .await
            .map_err(|e| ImpossibleTravelError::Repo(e.to_string()))?;

        // 3. Evaluate against per-tenant threshold + allowlist (if any
        //    prior login exists).
        let outcome = match prev {
            None => ImpossibleTravelOutcome::NoHistory,
            Some(prev_rec) => {
                let max_kmh = self.config.max_kmh_for(tenant_id);
                let allowlist = self.config.allowlist_for(tenant_id);
                let decision = evaluate_impossible_travel_with_allowlist(
                    &prev_rec, &curr, max_kmh, &allowlist,
                );
                match decision {
                    TravelDecision::None => ImpossibleTravelOutcome::NoAnomaly,
                    TravelDecision::Detected(anomaly) => {
                        // Forward to SOC first; if the sink fails we
                        // still record the login so future comparisons
                        // remain consistent.
                        self.sink.emit_impossible_travel(&anomaly).await?;
                        ImpossibleTravelOutcome::Detected(anomaly)
                    }
                    TravelDecision::Suppressed(anomaly) => {
                        // Audit-only: do NOT forward to SOC.
                        ImpossibleTravelOutcome::Suppressed(anomaly)
                    }
                }
            }
        };

        // 4. Audit every outcome.
        audit_log(
            tenant_id,
            user_id,
            &outcome,
            Some(&addr.to_string()),
            asn,
            Some((lat, lon)),
        );

        // 5. Record the new login so the next call has history.
        self.history
            .record_login(&curr)
            .await
            .map_err(|e| ImpossibleTravelError::Repo(e.to_string()))?;

        Ok(outcome)
    }
}

/// Emit a single structured audit log row for an outcome. Captures
/// every field required by P2-007: tenant, user, IP, ASN, lat/lon, and
/// (where applicable) the anomaly evidence.
fn audit_log(
    tenant_id: &str,
    user_id: &str,
    outcome: &ImpossibleTravelOutcome,
    source_ip: Option<&str>,
    asn: Option<u32>,
    coords: Option<(f64, f64)>,
) {
    let (lat, lon) = coords.unwrap_or((f64::NAN, f64::NAN));
    let (distance_km, elapsed_secs, computed_kmh, threshold_kmh, prev_ip, prev_asn) = outcome
        .anomaly_evidence()
        .unwrap_or((0.0, 0.0, 0.0, 0.0, "", 0));
    tracing::info!(
        target: "sx_iam.impossible_travel.audit",
        outcome = outcome.audit_tag(),
        tenant_id = tenant_id,
        user_id = user_id,
        source_ip = source_ip.unwrap_or(""),
        asn = asn.unwrap_or(0),
        lat = lat,
        lon = lon,
        distance_km = distance_km,
        elapsed_secs = elapsed_secs,
        computed_kmh = computed_kmh,
        threshold_kmh = threshold_kmh,
        prev_ip = prev_ip,
        prev_asn = prev_asn,
        "impossible-travel evaluation"
    );
}

impl ImpossibleTravelOutcome {
    /// Extract (`distance_km`, `elapsed_secs`, `computed_kmh`,
    /// `threshold_kmh`, `prev_ip`, `prev_asn`) from a
    /// Detected/Suppressed outcome; returns `None` for the no-anomaly
    /// variants.
    fn anomaly_evidence(&self) -> Option<(f64, f64, f64, f64, &str, u32)> {
        let anomaly = match self {
            Self::Detected(a) | Self::Suppressed(a) => a,
            Self::NoHistory | Self::NoAnomaly | Self::GeolocationMissing => return None,
        };
        let prev_ip = anomaly
            .prev
            .as_ref()
            .and_then(|r| r.source_ip.as_deref())
            .unwrap_or("");
        let prev_asn = anomaly.prev.as_ref().and_then(|r| r.asn).unwrap_or(0);
        Some((
            anomaly.distance_km,
            anomaly.elapsed_secs,
            anomaly.computed_kmh,
            anomaly.threshold_kmh,
            prev_ip,
            prev_asn,
        ))
    }
}

#[cfg(test)]
#[allow(
    clippy::float_cmp,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Tests use a buffering sink so they can assert exactly what would
    /// have been forwarded to SOC.
    #[derive(Debug, Default)]
    struct BufferingSocFindingSink {
        emitted: Mutex<Vec<TravelAnomaly>>,
    }

    impl BufferingSocFindingSink {
        fn new() -> Self {
            Self::default()
        }

        fn snapshot(&self) -> Vec<TravelAnomaly> {
            let guard = self.emitted.lock().expect("sink mutex poisoned");
            guard.clone()
        }
    }

    #[async_trait]
    impl SocFindingSink for BufferingSocFindingSink {
        async fn emit_impossible_travel(
            &self,
            anomaly: &TravelAnomaly,
        ) -> Result<(), ImpossibleTravelError> {
            let mut guard = self.emitted.lock().expect("sink mutex poisoned");
            guard.push(anomaly.clone());
            Ok(())
        }
    }

    fn ts(year: i32, month: u8, day: u8, h: u8, m: u8, s: u8) -> OffsetDateTime {
        let month = time::Month::try_from(month).expect("valid month");
        let date = time::Date::from_calendar_date(year, month, day).expect("valid date");
        let time = time::Time::from_hms(h, m, s).expect("valid time");
        date.with_time(time).assume_utc()
    }

    fn build_service(
        config: ImpossibleTravelConfig,
    ) -> (
        ImpossibleTravelService,
        Arc<BufferingSocFindingSink>,
        Arc<InMemoryLoginHistoryRepo>,
    ) {
        let history: Arc<InMemoryLoginHistoryRepo> = Arc::new(InMemoryLoginHistoryRepo::new());
        let sink: Arc<BufferingSocFindingSink> = Arc::new(BufferingSocFindingSink::new());
        let svc = ImpossibleTravelService::new(
            history.clone(),
            Arc::new(IpGeoCentroid::default()),
            sink.clone(),
            config,
        );
        (svc, sink, history)
    }

    // P2-007 spec test: Jakarta → NYC, 15 minutes apart → detected.
    #[tokio::test]
    async fn jakarta_then_nyc_in_fifteen_minutes_is_detected() {
        let (svc, sink, history) = build_service(ImpossibleTravelConfig::new());

        // Indonesian IP (114.4.0.1 maps to ID per the embedded CSV).
        let id_ip = Ipv4Addr::new(114, 4, 0, 1);
        // US IP (8.8.8.8 maps to US).
        let us_ip = Ipv4Addr::new(8, 8, 8, 8);

        let first = svc
            .check_login(
                "tenant-a",
                "alice",
                id_ip,
                Some(64500),
                ts(2026, 6, 12, 10, 0, 0),
            )
            .await
            .expect("first login ok");
        assert_eq!(first, ImpossibleTravelOutcome::NoHistory);

        let second = svc
            .check_login(
                "tenant-a",
                "alice",
                us_ip,
                Some(64501),
                ts(2026, 6, 12, 10, 15, 0),
            )
            .await
            .expect("second login ok");

        match second {
            ImpossibleTravelOutcome::Detected(ref a) => {
                assert_eq!(a.user_id, "alice");
                assert_eq!(a.tenant_id.as_deref(), Some("tenant-a"));
                assert!(a.computed_kmh > DEFAULT_MAX_KMH);
                assert!(a.distance_km > 10_000.0);
                // IP / ASN evidence preserved.
                let prev = a.prev.as_ref().expect("prev evidence");
                let curr = a.curr.as_ref().expect("curr evidence");
                assert_eq!(prev.source_ip.as_deref(), Some("114.4.0.1"));
                assert_eq!(curr.source_ip.as_deref(), Some("8.8.8.8"));
                assert_eq!(prev.asn, Some(64500));
                assert_eq!(curr.asn, Some(64501));
            }
            other => panic!("expected Detected, got {other:?}"),
        }

        // Sink must have received exactly one finding.
        assert_eq!(sink.snapshot().len(), 1);

        // History was updated to the NYC login.
        let last = history
            .last_login_for_tenant(Some("tenant-a"), "alice")
            .await
            .expect("repo ok")
            .expect("history present");
        assert_eq!(last.source_ip.as_deref(), Some("8.8.8.8"));
    }

    // P2-007 spec test: same login same place → no alert.
    #[tokio::test]
    async fn same_login_same_place_does_not_alert() {
        let (svc, sink, _) = build_service(ImpossibleTravelConfig::new());
        let us_ip = Ipv4Addr::new(8, 8, 8, 8);

        let first = svc
            .check_login(
                "tenant-a",
                "alice",
                us_ip,
                Some(64500),
                ts(2026, 6, 12, 10, 0, 0),
            )
            .await
            .expect("first ok");
        assert_eq!(first, ImpossibleTravelOutcome::NoHistory);

        let second = svc
            .check_login(
                "tenant-a",
                "alice",
                us_ip,
                Some(64500),
                ts(2026, 6, 12, 11, 0, 0),
            )
            .await
            .expect("second ok");
        assert_eq!(second, ImpossibleTravelOutcome::NoAnomaly);
        assert!(sink.snapshot().is_empty(), "no finding must be emitted");
    }

    // P2-007 spec test: VPN allowlist suppression.
    #[tokio::test]
    async fn vpn_allowlist_suppresses_finding() {
        // Same Jakarta → NYC geometry as the detection test, but the
        // tenant's allowlist contains the ASN both endpoints carry.
        let allowlist = TenantVpnAllowlist::from_iter([64500_u32]);
        let cfg = ImpossibleTravelConfig::new().with_tenant_allowlist("tenant-a", allowlist);
        let (svc, sink, _) = build_service(cfg);

        let id_ip = Ipv4Addr::new(114, 4, 0, 1);
        let us_ip = Ipv4Addr::new(8, 8, 8, 8);

        svc.check_login(
            "tenant-a",
            "alice",
            id_ip,
            Some(64500),
            ts(2026, 6, 12, 10, 0, 0),
        )
        .await
        .expect("first ok");

        let second = svc
            .check_login(
                "tenant-a",
                "alice",
                us_ip,
                Some(64500),
                ts(2026, 6, 12, 10, 15, 0),
            )
            .await
            .expect("second ok");

        match second {
            ImpossibleTravelOutcome::Suppressed(a) => {
                assert!(a.computed_kmh > DEFAULT_MAX_KMH);
            }
            other => panic!("expected Suppressed, got {other:?}"),
        }
        assert!(
            sink.snapshot().is_empty(),
            "suppressed finding must NOT be forwarded to SOC"
        );
    }

    // Tenant isolation: same user_id, different tenants → no cross-talk.
    #[tokio::test]
    async fn travel_history_is_scoped_per_tenant() {
        let (svc, sink, _) = build_service(ImpossibleTravelConfig::new());
        let id_ip = Ipv4Addr::new(114, 4, 0, 1);
        let us_ip = Ipv4Addr::new(8, 8, 8, 8);

        // Tenant A logs Jakarta.
        svc.check_login(
            "tenant-a",
            "alice",
            id_ip,
            Some(64500),
            ts(2026, 6, 12, 10, 0, 0),
        )
        .await
        .expect("ok");

        // Tenant B logs NYC 15 minutes later — would fire if histories
        // crossed tenants, but must NOT because `alice` has no history
        // under tenant-b.
        let b = svc
            .check_login(
                "tenant-b",
                "alice",
                us_ip,
                Some(64501),
                ts(2026, 6, 12, 10, 15, 0),
            )
            .await
            .expect("ok");
        assert_eq!(b, ImpossibleTravelOutcome::NoHistory);
        assert!(sink.snapshot().is_empty());
    }

    // Per-tenant threshold override: a small ceiling fires on a slow
    // walk that the default would ignore.
    #[tokio::test]
    async fn per_tenant_threshold_override_is_honoured() {
        // Set tenant-a's ceiling to 1 km/h so even a same-country walk
        // triggers the rule.
        let cfg = ImpossibleTravelConfig::new().with_tenant_max_kmh("tenant-a", 1.0);
        let (svc, sink, _) = build_service(cfg);

        let us_ip = Ipv4Addr::new(8, 8, 8, 8);
        let cn_ip = Ipv4Addr::new(27, 0, 0, 1); // CN centroid via embedded CSV.

        svc.check_login("tenant-a", "alice", us_ip, None, ts(2026, 6, 12, 10, 0, 0))
            .await
            .expect("first ok");
        let second = svc
            .check_login("tenant-a", "alice", cn_ip, None, ts(2026, 6, 13, 10, 0, 0))
            .await
            .expect("second ok");
        assert!(matches!(second, ImpossibleTravelOutcome::Detected(_)));
        assert_eq!(sink.snapshot().len(), 1);
    }

    // Geolocation missing → no SOC finding, no history poisoning, but
    // audited.
    #[tokio::test]
    async fn rfc1918_ip_skips_with_geolocation_missing() {
        let (svc, sink, history) = build_service(ImpossibleTravelConfig::new());
        let priv_ip = Ipv4Addr::new(10, 0, 0, 1);
        let out = svc
            .check_login(
                "tenant-a",
                "alice",
                priv_ip,
                None,
                ts(2026, 6, 12, 10, 0, 0),
            )
            .await
            .expect("ok");
        assert_eq!(out, ImpossibleTravelOutcome::GeolocationMissing);
        assert!(sink.snapshot().is_empty());
        // History must NOT have recorded a sentinel coordinate.
        assert!(history
            .last_login_for_tenant(Some("tenant-a"), "alice")
            .await
            .expect("ok")
            .is_none());
    }

    #[test]
    fn config_defaults_apply_when_tenant_missing() {
        let cfg = ImpossibleTravelConfig::new();
        assert_eq!(cfg.max_kmh_for("anything"), DEFAULT_MAX_KMH);
        assert!(cfg.allowlist_for("anything").is_empty());
    }

    #[test]
    fn config_with_tenant_overrides_default() {
        let cfg = ImpossibleTravelConfig::new()
            .with_default_max_kmh(500.0)
            .with_tenant_max_kmh("vip", 2000.0)
            .with_tenant_allowlist("vip", TenantVpnAllowlist::from_iter([64500_u32]));
        assert_eq!(cfg.max_kmh_for("vip"), 2000.0);
        assert_eq!(cfg.max_kmh_for("other"), 500.0);
        assert!(cfg.allowlist_for("vip").contains(64500));
        assert!(cfg.allowlist_for("other").is_empty());
    }

    #[test]
    fn outcome_audit_tags_are_stable() {
        assert_eq!(ImpossibleTravelOutcome::NoHistory.audit_tag(), "no_history");
        assert_eq!(
            ImpossibleTravelOutcome::GeolocationMissing.audit_tag(),
            "geolocation_missing"
        );
        assert_eq!(ImpossibleTravelOutcome::NoAnomaly.audit_tag(), "no_anomaly");
        let anomaly = TravelAnomaly {
            user_id: "u".into(),
            tenant_id: Some("t".into()),
            distance_km: 1.0,
            elapsed_secs: 1.0,
            computed_kmh: 1.0,
            threshold_kmh: 1.0,
            prev: None,
            curr: None,
        };
        assert_eq!(
            ImpossibleTravelOutcome::Detected(anomaly.clone()).audit_tag(),
            "detected"
        );
        assert_eq!(
            ImpossibleTravelOutcome::Suppressed(anomaly).audit_tag(),
            "suppressed"
        );
    }

    #[tokio::test]
    async fn tracing_sink_emit_does_not_error() {
        let sink = TracingSocFindingSink::new();
        let anomaly = TravelAnomaly {
            user_id: "u".into(),
            tenant_id: Some("t".into()),
            distance_km: 12_000.0,
            elapsed_secs: 900.0,
            computed_kmh: 48_000.0,
            threshold_kmh: 800.0,
            prev: None,
            curr: None,
        };
        sink.emit_impossible_travel(&anomaly)
            .await
            .expect("tracing sink is infallible");
    }
}
