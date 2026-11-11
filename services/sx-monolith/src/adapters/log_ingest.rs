//! OCSF log-ingest adapter.
//!
//! Wraps [`sx_log_ingest::LogIngestService`] (in-memory ring buffer +
//! parser registry) behind [`sx_api::port::LogIngestPort`]. The port hands
//! out the [`crate::view::log_ingest_view::OcsfEventView`] projection so
//! the API crate keeps the wire shape decoupled from the canonical
//! `sx_log_ingest::OcsfEvent`.
//!
//! Also wraps [`sx_log_ingest::rate_limit::RateLimiter`] behind
//! [`sx_api::port::LogRateLimitPort`] (MED-001) so the `/v1/logs/ingest`
//! controller can enforce per-tenant token-bucket limits and the
//! `/v1/admin/log-ingest/tiers/{tenant_id}` admin endpoint can mutate
//! per-tenant tier assignments.
//!
//! Future iterations will plug a ClickHouse-backed implementation behind
//! the same trait without touching the controller or HTTP surface.

use std::sync::Arc;

use async_trait::async_trait;
use sx_api::port::{
    LogIngestError, LogIngestPort, LogRateLimitDecision, LogRateLimitError, LogRateLimitPort,
    LogRateLimitTierSnapshot,
};
use sx_api::view::log_ingest_view::{ObservableView, OcsfEventView, OcsfMetadataView};
use sx_config::schema::log_ingest::LogIngestRateLimitConfig;
use sx_log_ingest::rate_limit::{RateDecision, RateLimiter, Tier, TierRates, TierRatesTable};
use sx_log_ingest::{LogIngestService, OcsfEvent};

/// Bundle returned to the composition root.
pub(crate) struct LogIngestBundle {
    /// HTTP-facing log-ingest port — registered on `AppState::log_ingest`.
    pub log_ingest: Arc<dyn LogIngestPort>,
    /// HTTP-facing rate-limiter port — registered on
    /// `AppState::log_rate_limit`. MED-001.
    pub log_rate_limit: Arc<dyn LogRateLimitPort>,
}

/// Build the in-memory log-ingest adapter pre-loaded with the three
/// built-in OCSF parsers (CloudTrail, RFC 5424 syslog, Suricata EVE)
/// plus the per-tenant token-bucket limiter seeded from the supplied
/// `sx-config` schema (MED-001).
pub(crate) fn build(cfg: &LogIngestRateLimitConfig) -> LogIngestBundle {
    let table = TierRatesTable::new(
        TierRates::new(cfg.free.per_sec_rate, cfg.free.burst),
        TierRates::new(cfg.pro.per_sec_rate, cfg.pro.burst),
        TierRates::new(cfg.enterprise.per_sec_rate, cfg.enterprise.burst),
    );
    // `check_invariants` (called by the config loader) already
    // restricted this to one of {free, pro, enterprise}; fall back to
    // free defensively so a future schema bug cannot panic the boot.
    let default_tier = Tier::parse(&cfg.default_tier).unwrap_or(Tier::Free);
    let limiter = Arc::new(RateLimiter::new(table, default_tier));
    LogIngestBundle {
        log_ingest: Arc::new(LogIngestAdapter::new(LogIngestService::with_builtins())),
        log_rate_limit: Arc::new(LogRateLimitAdapter::new(Arc::clone(&limiter))),
    }
}

/// Concrete adapter — delegates to the underlying ring-buffer service and
/// projects [`OcsfEvent`] into [`OcsfEventView`] on the listing side.
#[derive(Debug, Clone)]
pub(crate) struct LogIngestAdapter {
    service: LogIngestService,
}

impl LogIngestAdapter {
    /// Wrap the supplied service.
    pub(crate) const fn new(service: LogIngestService) -> Self {
        Self { service }
    }

    /// Project a canonical OCSF event onto the wire DTO.
    fn project(event: OcsfEvent) -> OcsfEventView {
        OcsfEventView {
            class_uid: event.class_uid,
            category_uid: event.category_uid,
            time: event.time,
            severity_id: event.severity_id,
            raw: event.raw,
            metadata: OcsfMetadataView {
                version: event.metadata.version,
                product: event.metadata.product,
                source_type: event.metadata.source_type,
                tenant_id: event.metadata.tenant_id,
            },
            observables: event
                .observables
                .into_iter()
                .map(|o| ObservableView {
                    name: o.name,
                    kind: o.kind,
                    value: o.value,
                })
                .collect(),
        }
    }
}

#[async_trait]
impl LogIngestPort for LogIngestAdapter {
    async fn ingest_one(
        &self,
        tenant_id: &str,
        source: &str,
        payload: &str,
    ) -> Result<(), LogIngestError> {
        self.service
            .ingest_one(tenant_id, source, payload)
            .await
            .map_err(map_err)
    }

    async fn list(
        &self,
        tenant_id: &str,
        limit: usize,
    ) -> Result<Vec<OcsfEventView>, LogIngestError> {
        let items = self.service.list(tenant_id, limit).await.map_err(map_err)?;
        Ok(items.into_iter().map(Self::project).collect())
    }
}

/// Translate a [`sx_log_ingest::LogIngestError`] onto the API port surface.
fn map_err(err: sx_log_ingest::LogIngestError) -> LogIngestError {
    match err {
        sx_log_ingest::LogIngestError::UnknownSource(s) => LogIngestError::UnknownSource(s),
        sx_log_ingest::LogIngestError::Parser(p) => LogIngestError::Invalid(p.to_string()),
        sx_log_ingest::LogIngestError::Internal(m) => LogIngestError::Internal(m),
    }
}

// ---------------------------------------------------------------------------
// MED-001 — per-tenant rate-limiter adapter
// ---------------------------------------------------------------------------

/// Adapter wrapping a shared [`RateLimiter`] (process-memory token
/// buckets) behind the synchronous [`LogRateLimitPort`] trait the API
/// crate consumes.
#[derive(Debug, Clone)]
pub(crate) struct LogRateLimitAdapter {
    limiter: Arc<RateLimiter>,
}

impl LogRateLimitAdapter {
    pub(crate) const fn new(limiter: Arc<RateLimiter>) -> Self {
        Self { limiter }
    }

    fn project(decision: RateDecision) -> LogRateLimitDecision {
        match decision {
            RateDecision::Allowed {
                limit,
                remaining,
                reset_at_unix_secs,
            } => LogRateLimitDecision {
                allowed: true,
                limit,
                remaining,
                reset_at_unix_secs,
                retry_after_secs: 0,
            },
            RateDecision::Throttled {
                retry_after_secs,
                limit,
                remaining,
                reset_at_unix_secs,
            } => LogRateLimitDecision {
                allowed: false,
                limit,
                remaining,
                reset_at_unix_secs,
                retry_after_secs,
            },
        }
    }
}

impl LogRateLimitPort for LogRateLimitAdapter {
    fn try_acquire(&self, tenant_id: &str, endpoint: &str) -> LogRateLimitDecision {
        Self::project(self.limiter.try_acquire(tenant_id, endpoint))
    }

    fn set_tier(
        &self,
        tenant_id: &str,
        tier: &str,
        override_rate_per_sec: Option<u32>,
    ) -> Result<LogRateLimitTierSnapshot, LogRateLimitError> {
        let parsed =
            Tier::parse(tier).ok_or_else(|| LogRateLimitError::InvalidTier(tier.into()))?;
        if let Some(rate) = override_rate_per_sec {
            if rate == 0 {
                return Err(LogRateLimitError::InvalidOverride(
                    "override_rate_per_sec must be > 0".into(),
                ));
            }
        }
        let rates = self
            .limiter
            .set_tier(tenant_id, parsed, override_rate_per_sec);
        Ok(LogRateLimitTierSnapshot {
            per_sec_rate: rates.per_sec_rate,
            burst: rates.burst,
        })
    }

    fn tier_of(&self, tenant_id: &str) -> (String, Option<u32>) {
        let tier = self.limiter.tier_of(tenant_id);
        let override_rate = self.limiter.override_rate_of(tenant_id);
        (tier.as_str().to_owned(), override_rate)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const TENANT: &str = "01010101-0101-0101-0101-010101010101";
    const CT: &str = r#"{
        "eventTime": "2026-06-12T10:30:01Z",
        "eventSource": "ec2.amazonaws.com",
        "eventName": "RunInstances",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "203.0.113.5"
    }"#;

    #[tokio::test]
    async fn adapter_ingest_then_list_round_trip_projects_view() {
        let bundle = build(&LogIngestRateLimitConfig::default());
        bundle
            .log_ingest
            .ingest_one(TENANT, "cloudtrail", CT)
            .await
            .unwrap();
        let items = bundle.log_ingest.list(TENANT, 10).await.unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].class_uid, 6003);
        assert_eq!(items[0].metadata.tenant_id, TENANT);
        assert_eq!(items[0].metadata.source_type, "cloudtrail");
        assert!(items[0]
            .observables
            .iter()
            .any(|o| o.name == "src_ip" && o.kind == "ip" && o.value == "203.0.113.5"));
    }

    #[tokio::test]
    async fn adapter_unknown_source_maps_to_unknown_source_variant() {
        let bundle = build(&LogIngestRateLimitConfig::default());
        let err = bundle
            .log_ingest
            .ingest_one(TENANT, "no-such-source", "{}")
            .await
            .unwrap_err();
        assert!(matches!(err, LogIngestError::UnknownSource(s) if s == "no-such-source"));
    }

    #[tokio::test]
    async fn adapter_malformed_payload_maps_to_invalid() {
        let bundle = build(&LogIngestRateLimitConfig::default());
        let err = bundle
            .log_ingest
            .ingest_one(TENANT, "cloudtrail", "{not json")
            .await
            .unwrap_err();
        assert!(matches!(err, LogIngestError::Invalid(_)));
    }

    #[tokio::test]
    async fn adapter_list_for_empty_tenant_returns_empty() {
        let bundle = build(&LogIngestRateLimitConfig::default());
        let items = bundle.log_ingest.list("nobody", 10).await.unwrap();
        assert!(items.is_empty());
    }

    #[tokio::test]
    async fn rate_limit_adapter_admits_then_throttles_when_bucket_drained() {
        // Tiny burst so we can exhaust the bucket in a unit test.
        let cfg = LogIngestRateLimitConfig {
            free: sx_config::schema::log_ingest::TierRateConfig {
                per_sec_rate: 1,
                burst: 2,
            },
            ..LogIngestRateLimitConfig::default()
        };
        let bundle = build(&cfg);
        // Admit twice (burst=2).
        let a = bundle.log_rate_limit.try_acquire(TENANT, "/v1/logs/ingest");
        let b = bundle.log_rate_limit.try_acquire(TENANT, "/v1/logs/ingest");
        assert!(a.allowed && b.allowed);
        // Third call within the same instant should throttle.
        let c = bundle.log_rate_limit.try_acquire(TENANT, "/v1/logs/ingest");
        assert!(!c.allowed);
        assert_eq!(c.limit, 2);
        assert_eq!(c.remaining, 0);
        assert!(c.retry_after_secs >= 1);
    }

    #[tokio::test]
    async fn rate_limit_adapter_set_tier_returns_new_rates() {
        let bundle = build(&LogIngestRateLimitConfig::default());
        let snap = bundle
            .log_rate_limit
            .set_tier(TENANT, "enterprise", None)
            .expect("enterprise tier must be valid");
        assert_eq!(snap.per_sec_rate, 10_000);
        assert_eq!(snap.burst, 20_000);
        let (tier, override_rate) = bundle.log_rate_limit.tier_of(TENANT);
        assert_eq!(tier, "enterprise");
        assert!(override_rate.is_none());
    }

    #[tokio::test]
    async fn rate_limit_adapter_set_tier_with_override_scales_burst() {
        let bundle = build(&LogIngestRateLimitConfig::default());
        let snap = bundle
            .log_rate_limit
            .set_tier(TENANT, "free", Some(5_000))
            .expect("override must apply");
        assert_eq!(snap.per_sec_rate, 5_000);
        // Free tier burst shape is 2x — override preserves the shape.
        assert_eq!(snap.burst, 10_000);
        let (_, override_rate) = bundle.log_rate_limit.tier_of(TENANT);
        assert_eq!(override_rate, Some(5_000));
    }

    #[tokio::test]
    async fn rate_limit_adapter_rejects_unknown_tier() {
        let bundle = build(&LogIngestRateLimitConfig::default());
        let err = bundle
            .log_rate_limit
            .set_tier(TENANT, "ultra", None)
            .expect_err("unknown tier must reject");
        assert!(matches!(err, LogRateLimitError::InvalidTier(t) if t == "ultra"));
    }

    #[tokio::test]
    async fn rate_limit_adapter_rejects_zero_override() {
        let bundle = build(&LogIngestRateLimitConfig::default());
        let err = bundle
            .log_rate_limit
            .set_tier(TENANT, "free", Some(0))
            .expect_err("zero override must reject");
        assert!(matches!(err, LogRateLimitError::InvalidOverride(_)));
    }

    #[test]
    fn project_preserves_all_fields() {
        let ev = OcsfEvent::new(
            6003,
            6,
            "2026-06-12T10:30:01Z",
            sx_log_ingest::Severity::Medium,
            "raw",
            sx_log_ingest::OcsfMetadata::new("AWS CloudTrail", "cloudtrail"),
        );
        let view = LogIngestAdapter::project(ev);
        assert_eq!(view.class_uid, 6003);
        assert_eq!(view.category_uid, 6);
        assert_eq!(view.severity_id, 3);
        assert_eq!(view.metadata.source_type, "cloudtrail");
    }
}
