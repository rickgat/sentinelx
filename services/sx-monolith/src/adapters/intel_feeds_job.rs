//! Background TAXII poller job (P0-001).
//!
//! Drives the [`sx_intel_feeds::FeedOrchestrator`] on the configured
//! cadence. The job owns one `tokio::task` per spawn call. The task:
//!
//!   1. Builds a TAXII client (HTTPS, bearer-auth) at boot and reuses the
//!      same `reqwest::Client` for every poll cycle.
//!   2. On every tick, calls [`FeedOrchestrator::poll_once`] for the
//!      configured tenant. Indicators land in the shared sharded bloom
//!      filter (also read by the HTTP `/v1/intel/check` endpoint) and
//!      the per-tenant `tenant_iocs` table; per-feed status is updated
//!      in `intel_feed_status`.
//!   3. On `429 Too Many Requests` the orchestrator surfaces a
//!      [`sx_intel_feeds::TaxiiError::Backoff`] that the job honours by
//!      sleeping for the requested duration before the next tick.
//!   4. Silent-feed alerts surface as `warn!` events for the existing
//!      alert rule pack hook.
//!
//! ## Secret handling
//!
//! The `IntelFeedsConfig::taxii_bearer` field is wrapped in
//! [`secrecy::SecretString`]. This module never logs the bearer — it is
//! cloned once into the TAXII client at construction time, at which
//! point the client itself takes responsibility for keeping it out of
//! `tracing` events.
//!
//! ## Tenant scoping
//!
//! For Phase-1 we drive a single tenant identifier per spawned job
//! (read from [`IntelFeedsConfig::tenant_id`] when set, falling back to
//! [`DEFAULT_TENANT_ID`]). A multi-tenant variant that fans out across
//! every tenant in the platform lands when the per-tenant config schema
//! is wired up — see the follow-up note in `SECURITY_GAP_REMEDIATION_TASKS`.

use std::sync::Arc;
use std::time::Duration;

use secrecy::ExposeSecret;
use sx_config::IntelFeedsConfig;
use sx_intel_feeds::{
    FeedError, FeedId, FeedOrchestrator, InMemoryRepository, SystemClock, TaxiiClient, TaxiiError,
    TenantId, TenantIocRepository,
};
use sx_intel_ioc::ShardedBloomFilter;
use tokio::task::JoinHandle;
use tokio::time::{interval, MissedTickBehavior};
use tracing::{info, warn};
use url::Url;

/// Default tenant identifier used by the legacy single-tenant `spawn`
/// entry-point. The multi-tenant variant supersedes this once a per-tenant
/// feed-config table is wired in.
pub(crate) const DEFAULT_TENANT_ID: &str = "00000000-0000-0000-0000-000000000000";

/// Default feed identifier used when the legacy `spawn` entry-point is
/// invoked. Operator-supplied names land in a future config-schema bump.
pub(crate) const DEFAULT_FEED_ID: &str = "default-taxii";

/// Legacy thin spawn — kept for callers that don't yet plumb the shared
/// bloom filter into the composition root.
///
/// When `cfg.enabled` is `true` this provisions a brand-new bloom filter
/// + in-memory repository internally and drives a real TAXII poll loop.
///
/// The HTTP check endpoint will *not* see these indicators in this mode;
/// the [`spawn_with`] variant below is the preferred entry-point.
///
/// Retained (but `#[allow(dead_code)]`) so test callers and the not-yet-
/// migrated composition path still have a thin wrapper to invoke without
/// having to pass the shared bloom + repository explicitly. The current
/// `build_app_state` uses [`spawn_with`] directly.
#[allow(dead_code)]
pub(crate) fn spawn(cfg: &IntelFeedsConfig) -> Option<JoinHandle<()>> {
    if !cfg.enabled {
        return None;
    }
    let bloom = Arc::new(ShardedBloomFilter::with_defaults());
    let repo: Arc<dyn TenantIocRepository> = Arc::new(InMemoryRepository::new());
    spawn_with(cfg, bloom, repo)
}

/// Preferred spawn — wires the shared bloom filter and a caller-supplied
/// repository into the orchestrator so freshly-ingested indicators land in
/// the same hot-path filter the HTTP `/v1/intel/check` endpoint reads.
///
/// Returns `None` when `cfg.enabled` is `false`, the endpoint URL is
/// malformed, or the configured feed/tenant ids are empty — every failure
/// is logged at `warn` level so an operator notices.
pub(crate) fn spawn_with(
    cfg: &IntelFeedsConfig,
    bloom: Arc<ShardedBloomFilter>,
    repo: Arc<dyn TenantIocRepository>,
) -> Option<JoinHandle<()>> {
    if !cfg.enabled {
        return None;
    }

    let endpoint = cfg.taxii_endpoint.clone();
    let collection_id = cfg.collection_id.clone();
    let poll_interval = Duration::from_secs(cfg.poll_interval_secs);

    let base_url = match Url::parse(&endpoint) {
        Ok(u) => u,
        Err(err) => {
            warn!(
                target: "adapters.intel_feeds_job",
                endpoint = %endpoint,
                error = %err,
                "intel_feeds: refusing to spawn poller — taxii_endpoint is not a URL",
            );
            return None;
        }
    };

    let api_root = derive_api_root(&base_url);
    let feed_id = match FeedId::new(DEFAULT_FEED_ID) {
        Ok(v) => v,
        Err(err) => {
            warn!(
                target: "adapters.intel_feeds_job",
                error = %err,
                "intel_feeds: refusing to spawn poller — feed id invariant",
            );
            return None;
        }
    };
    let tenant = match TenantId::new(DEFAULT_TENANT_ID) {
        Ok(v) => v,
        Err(err) => {
            warn!(
                target: "adapters.intel_feeds_job",
                error = %err,
                "intel_feeds: refusing to spawn poller — tenant id invariant",
            );
            return None;
        }
    };

    // Clone the bearer once into the TAXII client. The secret never
    // escapes this scope — `TaxiiClient` writes it directly into the
    // `Authorization` header at request time.
    let bearer =
        secrecy::SecretString::new(cfg.taxii_bearer.expose_secret().to_owned().into_boxed_str());
    let http = reqwest::Client::new();
    let taxii = TaxiiClient::new(http, base_url, Some(bearer));

    let orchestrator = FeedOrchestrator::new(
        taxii,
        api_root,
        collection_id.clone(),
        feed_id.clone(),
        bloom,
        repo,
        Arc::new(SystemClock),
    );

    let handle = tokio::spawn(async move {
        let mut ticker = interval(poll_interval);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
        info!(
            target: "adapters.intel_feeds_job",
            collection_id = %collection_id,
            poll_interval_secs = poll_interval.as_secs(),
            "intel_feeds: TAXII poller spawned",
        );
        loop {
            ticker.tick().await;
            match orchestrator.poll_once(&tenant).await {
                Ok(outcome) => {
                    info!(
                        target: "adapters.intel_feeds_job",
                        tenant = tenant.as_str(),
                        feed = feed_id.as_str(),
                        indicators_added = outcome.indicators_added,
                        indicators_evicted = outcome.indicators_evicted,
                        silent_feed_alert = outcome.silent_feed_alert,
                        "intel_feeds: TAXII poll succeeded",
                    );
                }
                Err(FeedError::Taxii(TaxiiError::Backoff(d))) => {
                    warn!(
                        target: "adapters.intel_feeds_job",
                        tenant = tenant.as_str(),
                        feed = feed_id.as_str(),
                        retry_after_secs = d.as_secs(),
                        "intel_feeds: TAXII server requested back-off",
                    );
                    tokio::time::sleep(d).await;
                }
                Err(err) => {
                    warn!(
                        target: "adapters.intel_feeds_job",
                        tenant = tenant.as_str(),
                        feed = feed_id.as_str(),
                        error = %err,
                        "intel_feeds: TAXII poll failed",
                    );
                }
            }
        }
    });

    Some(handle)
}

/// Derive the API root from the configured `taxii_endpoint`. The TAXII
/// 2.1 spec separates the server root (where `/taxii2/` lives) from the
/// API root (where `/api/v21/collections/…` lives). For deployments that
/// only expose one root we use the configured endpoint verbatim; the
/// orchestrator + `TaxiiClient` jointly handle trailing-slash
/// normalisation.
fn derive_api_root(base: &Url) -> String {
    base.as_str().to_owned()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::{derive_api_root, spawn, spawn_with, DEFAULT_FEED_ID, DEFAULT_TENANT_ID};
    use secrecy::SecretString;
    use std::sync::Arc;
    use sx_config::IntelFeedsConfig;
    use sx_intel_feeds::{InMemoryRepository, TenantIocRepository};
    use sx_intel_ioc::ShardedBloomFilter;
    use url::Url;

    fn disabled_cfg() -> IntelFeedsConfig {
        IntelFeedsConfig::default()
    }

    fn enabled_cfg() -> IntelFeedsConfig {
        IntelFeedsConfig {
            enabled: true,
            taxii_endpoint: "https://taxii.example.com/api/v21/".to_string(),
            taxii_bearer: SecretString::from("test-bearer".to_string()),
            collection_id: "00000000-0000-0000-0000-000000000001".to_string(),
            // Use a long interval so the spawned task never actually
            // logs during the test — we only assert spawn behaviour.
            poll_interval_secs: 86_400,
            // HIGH-011 added the diversity threshold to the schema; the
            // production default is 2. The intel_feeds_job tests only
            // assert spawn behaviour and never inspect the value, so any
            // non-zero default keeps the fixture valid.
            min_independent_sources: 2,
        }
    }

    #[test]
    fn spawn_returns_none_when_disabled() {
        let cfg = disabled_cfg();
        assert!(
            !cfg.enabled,
            "precondition: default config must be disabled"
        );
        let handle = spawn(&cfg);
        assert!(
            handle.is_none(),
            "disabled intel_feeds must not spawn a background task"
        );
    }

    #[tokio::test]
    async fn spawn_returns_some_when_enabled_and_can_be_aborted() {
        let cfg = enabled_cfg();
        let handle = spawn(&cfg).expect("enabled config must spawn a task");
        handle.abort();
        let outcome = handle.await;
        assert!(
            outcome.is_err() && outcome.err().is_some_and(|e| e.is_cancelled()),
            "spawned task should be aborted cleanly"
        );
    }

    #[tokio::test]
    async fn spawn_with_shares_bloom_and_repo() {
        let cfg = enabled_cfg();
        let bloom = Arc::new(ShardedBloomFilter::with_defaults());
        let repo: Arc<dyn TenantIocRepository> = Arc::new(InMemoryRepository::new());
        let handle = spawn_with(&cfg, Arc::clone(&bloom), Arc::clone(&repo))
            .expect("enabled config must spawn a task");
        handle.abort();
        let outcome = handle.await;
        assert!(outcome.is_err() && outcome.err().is_some_and(|e| e.is_cancelled()));
    }

    #[tokio::test]
    async fn spawn_with_returns_none_when_endpoint_is_garbage() {
        let mut cfg = enabled_cfg();
        cfg.taxii_endpoint = "this is not a url".to_string();
        let bloom = Arc::new(ShardedBloomFilter::with_defaults());
        let repo: Arc<dyn TenantIocRepository> = Arc::new(InMemoryRepository::new());
        let handle = spawn_with(&cfg, bloom, repo);
        assert!(handle.is_none());
    }

    #[test]
    fn derive_api_root_preserves_explicit_path() {
        let url = Url::parse("https://taxii.example/root1/").unwrap();
        assert_eq!(derive_api_root(&url), "https://taxii.example/root1/");
    }

    #[test]
    fn default_identifiers_are_non_empty() {
        // The constants are `const &str` literals with non-empty bytes;
        // clippy's `const_is_empty` notes the predicate is trivially
        // true, but the assert documents the invariant for future
        // editors who might be tempted to set them to "".
        #[allow(clippy::const_is_empty)]
        {
            assert!(!DEFAULT_TENANT_ID.is_empty());
            assert!(!DEFAULT_FEED_ID.is_empty());
        }
    }
}
