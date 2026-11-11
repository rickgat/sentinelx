//! Background polling, per-tenant credential resolution, rate-limiting,
//! and audit logging for the commercial intel feed adapters
//! (`Mandiant`, `CrowdStrike`).
//!
//! ## Responsibilities
//!
//! * Resolve per-tenant credentials from a [`sx_secrets::SecretsProvider`]
//!   using a documented path convention. Plaintext credentials never
//!   leave `SecretString` and are never logged.
//! * Throttle each vendor according to its published RPM ceiling via the
//!   shared [`crate::rate_limit::TokenBucket`].
//! * Run a background poll cycle on a configurable cadence
//!   (`intel_feeds.commercial_poll_interval_secs`) and emit structured
//!   audit events per cycle: provider, tenant, success / failure with
//!   HTTP code, and indicator count. **Credential content is never
//!   included in any audit field.**
//!
//! ## Secrets path convention
//!
//! For tenant `T` and provider `P`, the [`TenantCredentialStore`] looks
//! up keys under `tenants/{T}/intel/{P}/...`:
//!
//! | Provider     | Paths                                                                 |
//! |--------------|-----------------------------------------------------------------------|
//! | `mandiant`   | `tenants/{T}/intel/mandiant/api_key` *or* `client_id`+`client_secret` |
//! | `crowdstrike`| `tenants/{T}/intel/crowdstrike/client_id` + `client_secret`           |
//!
//! Callers may override the path layout via
//! [`TenantCredentialStore::with_path_prefix`]. The store reads each
//! key as a [`secrecy::SecretString`] and assembles a vendor config; it
//! never logs the resolved values.
//!
//! ## Rate-limit defaults
//!
//! | Vendor       | RPM | Refill window |
//! |--------------|-----|---------------|
//! | `mandiant`   | 60  | 60 s          |
//! | `crowdstrike`| 100 | 60 s          |

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use secrecy::SecretString;
use time::OffsetDateTime;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use sx_secrets::{SecretsError, SecretsProvider};

use crate::commercial::{CommercialIntelFeed, EnrichedIndicator, IntelError};
use crate::crowdstrike::{CrowdStrikeCloud, CrowdStrikeConfig, CrowdStrikeFeed};
use crate::mandiant::{MandiantAuth, MandiantConfig, MandiantFeed};
use crate::rate_limit::TokenBucket;

/// Mandiant published rate ceiling: 60 requests per minute.
pub const MANDIANT_RPM: u32 = 60;
/// `CrowdStrike` published rate ceiling: 100 requests per minute.
pub const CROWDSTRIKE_RPM: u32 = 100;
/// Refill window the per-vendor token buckets use (one minute).
pub const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);

/// Default polling cadence in seconds — 1 h. Mirrors
/// `intel_feeds.commercial_poll_interval_secs` in the global config.
pub const DEFAULT_COMMERCIAL_POLL_INTERVAL_SECS: u64 = 3_600;

/// Default sx-secrets path prefix. Tenant id and provider key are
/// concatenated underneath this root: `{prefix}/{tenant}/{provider}/{key}`.
pub const DEFAULT_SECRETS_PREFIX: &str = "tenants";

/// Errors surfaced by the commercial scheduler stack.
#[derive(Debug, thiserror::Error)]
pub enum CommercialSchedulerError {
    /// Secret lookup failed in the underlying [`SecretsProvider`].
    #[error("secrets lookup failed for {tenant}/{provider}: {source}")]
    Secret {
        /// Tenant the lookup was scoped to.
        tenant: String,
        /// Provider id (`"mandiant"` / `"crowdstrike"`).
        provider: &'static str,
        /// Underlying secrets error.
        #[source]
        source: SecretsError,
    },
    /// The looked-up credentials were missing or syntactically invalid for
    /// the requested provider (e.g. empty string, wrong shape).
    #[error("credentials for {tenant}/{provider} are missing or invalid")]
    MissingCredentials {
        /// Tenant the lookup was scoped to.
        tenant: String,
        /// Provider id.
        provider: &'static str,
    },
    /// Adapter construction failed (config rejected).
    #[error("adapter construction failed for {provider}: {source}")]
    Adapter {
        /// Provider id.
        provider: &'static str,
        /// Wrapped adapter error.
        #[source]
        source: IntelError,
    },
}

/// Structured audit event describing one poll-cycle attempt.
///
/// The variants are deliberately small and serialisable — the
/// integration layer (typically a thin wrapper around `sx-audit`) is
/// responsible for persisting them. **Credentials must never be added to
/// this struct.**
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommercialAuditEvent {
    /// A poll cycle completed successfully.
    PollSucceeded {
        /// Tenant the poll ran for.
        tenant: String,
        /// Provider id (`"mandiant"` / `"crowdstrike"`).
        provider: &'static str,
        /// Number of indicators (post-dedup) handed off downstream.
        indicators: usize,
        /// When the poll completed.
        completed_at: OffsetDateTime,
    },
    /// A poll cycle failed. `http_status` is populated when the failure
    /// surfaced as an HTTP error; `None` for transport / decode errors.
    PollFailed {
        /// Tenant the poll ran for.
        tenant: String,
        /// Provider id.
        provider: &'static str,
        /// HTTP status code (when applicable).
        http_status: Option<u16>,
        /// Short, redacted reason string. **Never contains credentials.**
        reason: String,
        /// When the failure was observed.
        completed_at: OffsetDateTime,
    },
}

/// Sink the scheduler emits per-cycle audit events into. Implementations
/// typically forward to `sx-audit`; the in-memory variant
/// [`InMemoryAuditSink`] exists for tests.
#[async_trait]
pub trait CommercialAuditSink: Send + Sync {
    /// Record an audit event. Implementations MUST be non-blocking from
    /// the caller's perspective: any persistence work should happen in a
    /// background task or use an async I/O path.
    async fn record(&self, event: CommercialAuditEvent);
}

/// Process-local sink used by tests. Cheap to clone — interior storage
/// is shared via [`Arc<Mutex<...>>`].
#[derive(Debug, Default, Clone)]
pub struct InMemoryAuditSink {
    events: Arc<Mutex<Vec<CommercialAuditEvent>>>,
}

impl InMemoryAuditSink {
    /// Create an empty sink.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot the events recorded so far.
    pub async fn snapshot(&self) -> Vec<CommercialAuditEvent> {
        self.events.lock().await.clone()
    }
}

#[async_trait]
impl CommercialAuditSink for InMemoryAuditSink {
    async fn record(&self, event: CommercialAuditEvent) {
        self.events.lock().await.push(event);
    }
}

/// Per-tenant credential resolver backed by a [`SecretsProvider`].
///
/// The store does not cache — caching belongs in a [`SecretsProvider`]
/// decorator (e.g. `sx_secrets::CachedProvider`). This avoids stale
/// reads after rotation while still letting callers opt into caching at
/// the provider layer.
#[derive(Clone)]
pub struct TenantCredentialStore<P> {
    secrets: P,
    prefix: String,
}

impl<P> std::fmt::Debug for TenantCredentialStore<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TenantCredentialStore")
            .field("prefix", &self.prefix)
            .finish_non_exhaustive()
    }
}

impl<P: SecretsProvider> TenantCredentialStore<P> {
    /// Construct against the default `tenants/` path prefix.
    pub fn new(secrets: P) -> Self {
        Self {
            secrets,
            prefix: DEFAULT_SECRETS_PREFIX.to_string(),
        }
    }

    /// Override the path prefix. Useful for tenants that share a
    /// multi-mount Vault layout.
    #[must_use]
    pub fn with_path_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.prefix = prefix.into();
        self
    }

    fn path(&self, tenant: &str, provider: &'static str, key: &str) -> String {
        format!("{}/{}/intel/{}/{}", self.prefix, tenant, provider, key)
    }

    async fn try_get(
        &self,
        tenant: &str,
        provider: &'static str,
        key: &str,
    ) -> Result<Option<SecretString>, CommercialSchedulerError> {
        let path = self.path(tenant, provider, key);
        match self.secrets.get(&path).await {
            Ok(v) => Ok(Some(v)),
            Err(SecretsError::NotFound(_)) => Ok(None),
            Err(e) => Err(CommercialSchedulerError::Secret {
                tenant: tenant.to_string(),
                provider,
                source: e,
            }),
        }
    }

    /// Build a [`MandiantConfig`] for `tenant`, preferring `OAuth2`
    /// credentials when both are present. Returns
    /// [`CommercialSchedulerError::MissingCredentials`] when neither an
    /// API key nor an `OAuth2` pair is available.
    pub async fn mandiant_config(
        &self,
        tenant: &str,
        base_url: Option<String>,
    ) -> Result<MandiantConfig, CommercialSchedulerError> {
        use secrecy::ExposeSecret;
        const PROVIDER: &str = "mandiant";
        let client_id = self.try_get(tenant, PROVIDER, "client_id").await?;
        let client_secret = self.try_get(tenant, PROVIDER, "client_secret").await?;
        let base = base_url.unwrap_or_else(|| "https://api.intelligence.mandiant.com".to_string());
        if let (Some(id), Some(secret)) = (client_id, client_secret) {
            return Ok(MandiantConfig {
                enabled: true,
                auth: MandiantAuth::OAuth2 {
                    client_id: id.expose_secret().to_string(),
                    client_secret: secret,
                },
                base_url: base,
            });
        }
        if let Some(api_key) = self.try_get(tenant, PROVIDER, "api_key").await? {
            return Ok(MandiantConfig {
                enabled: true,
                auth: MandiantAuth::ApiKey { api_key },
                base_url: base,
            });
        }
        Err(CommercialSchedulerError::MissingCredentials {
            tenant: tenant.to_string(),
            provider: PROVIDER,
        })
    }

    /// Build a [`CrowdStrikeConfig`] for `tenant`. The Falcon cloud is a
    /// non-secret routing decision and is supplied by the caller.
    pub async fn crowdstrike_config(
        &self,
        tenant: &str,
        cloud: CrowdStrikeCloud,
    ) -> Result<CrowdStrikeConfig, CommercialSchedulerError> {
        use secrecy::ExposeSecret;
        const PROVIDER: &str = "crowdstrike";
        let client_id = self
            .try_get(tenant, PROVIDER, "client_id")
            .await?
            .ok_or_else(|| CommercialSchedulerError::MissingCredentials {
                tenant: tenant.to_string(),
                provider: PROVIDER,
            })?;
        let client_secret = self
            .try_get(tenant, PROVIDER, "client_secret")
            .await?
            .ok_or_else(|| CommercialSchedulerError::MissingCredentials {
                tenant: tenant.to_string(),
                provider: PROVIDER,
            })?;
        Ok(CrowdStrikeConfig {
            enabled: true,
            client_id: client_id.expose_secret().to_string(),
            client_secret,
            cloud,
        })
    }
}

/// Wraps a [`CommercialIntelFeed`] with a shared [`TokenBucket`] so that
/// every concurrent fetcher for a given vendor respects the published
/// RPM ceiling. Cheap to clone.
#[derive(Debug, Clone)]
pub struct RateLimitedFeed<F> {
    inner: F,
    bucket: TokenBucket,
}

impl<F: CommercialIntelFeed> RateLimitedFeed<F> {
    /// Wrap `inner` with `bucket`.
    pub const fn new(inner: F, bucket: TokenBucket) -> Self {
        Self { inner, bucket }
    }
}

#[async_trait]
impl<F: CommercialIntelFeed> CommercialIntelFeed for RateLimitedFeed<F> {
    fn provider_id(&self) -> &'static str {
        self.inner.provider_id()
    }

    async fn fetch_since(
        &self,
        since: OffsetDateTime,
    ) -> Result<Vec<EnrichedIndicator>, IntelError> {
        // One token per fetch — fetchers may then paginate internally
        // and burn additional API calls; this matches the existing NVD
        // pattern where the bucket gates the start of a fetch sweep.
        self.bucket.acquire().await;
        self.inner.fetch_since(since).await
    }
}

/// Tenant + provider routing entry used by [`CommercialFeedsScheduler`].
///
/// Each entry pins a tenant to a single provider; tenants subscribed to
/// both Mandiant and `CrowdStrike` appear as two entries.
#[derive(Debug, Clone)]
pub struct TenantFeedTarget {
    /// Tenant identifier (UUID, slug, …).
    pub tenant: String,
    /// Which provider to poll.
    pub provider: ProviderKind,
}

/// Provider routing tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderKind {
    /// Mandiant Advantage Threat Intelligence.
    Mandiant,
    /// `CrowdStrike` Falcon Intel.
    CrowdStrike(CrowdStrikeCloud),
}

impl ProviderKind {
    /// Stable provider id for metrics / audit attribution.
    #[must_use]
    pub const fn provider_id(self) -> &'static str {
        match self {
            Self::Mandiant => "mandiant",
            Self::CrowdStrike(_) => "crowdstrike",
        }
    }
}

/// Downstream sink for enriched indicators. The scheduler hands off all
/// indicators from a successful poll cycle in one batch.
#[async_trait]
pub trait IndicatorSink: Send + Sync {
    /// Persist a batch of indicators tagged with the originating tenant
    /// and provider. Implementations are expected to dedupe at their own
    /// layer (e.g. keyed by `(kind, value, tenant)`).
    async fn ingest(
        &self,
        tenant: &str,
        provider: &'static str,
        indicators: Vec<EnrichedIndicator>,
    );
}

/// Test/diagnostic sink that just accumulates everything in memory.
/// Test-only row stored inside [`InMemoryIndicatorSink`].
pub type StoredIndicatorRow = (String, &'static str, EnrichedIndicator);

/// Test/diagnostic sink that just accumulates everything in memory.
#[derive(Debug, Default, Clone)]
pub struct InMemoryIndicatorSink {
    inner: Arc<Mutex<Vec<StoredIndicatorRow>>>,
}

impl InMemoryIndicatorSink {
    /// Empty sink.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot all ingested indicators.
    pub async fn snapshot(&self) -> Vec<StoredIndicatorRow> {
        self.inner.lock().await.clone()
    }
}

#[async_trait]
impl IndicatorSink for InMemoryIndicatorSink {
    async fn ingest(
        &self,
        tenant: &str,
        provider: &'static str,
        indicators: Vec<EnrichedIndicator>,
    ) {
        let mut guard = self.inner.lock().await;
        for ind in indicators {
            guard.push((tenant.to_string(), provider, ind));
        }
    }
}

/// Deduplicates a batch of indicators by `(kind, value)`, keeping the
/// first occurrence and folding subsequent sources into its `sources`
/// vec. Stable order so tests can assert deterministic output.
#[must_use]
pub fn dedupe_indicators(batch: Vec<EnrichedIndicator>) -> Vec<EnrichedIndicator> {
    use std::collections::HashMap;
    let mut index: HashMap<(String, String), usize> = HashMap::new();
    let mut out: Vec<EnrichedIndicator> = Vec::with_capacity(batch.len());
    for ind in batch {
        let key = (format!("{:?}", ind.kind), ind.value.clone());
        if let Some(&idx) = index.get(&key) {
            // Safety: `idx` is always derived from `out.len()` at the
            // time of insertion and `out` is push-only, so it cannot
            // refer to an out-of-range slot. We still defensively use
            // `get_mut` to keep clippy happy.
            if let Some(existing) = out.get_mut(idx) {
                // Merge sources, preserving order, no duplicates.
                for src in &ind.sources {
                    if !existing.sources.contains(src) {
                        existing.sources.push(src.clone());
                    }
                }
                // Earliest first_seen / latest last_seen wins.
                if ind.first_seen < existing.first_seen {
                    existing.first_seen = ind.first_seen;
                }
                if ind.last_seen > existing.last_seen {
                    existing.last_seen = ind.last_seen;
                }
            }
        } else {
            index.insert(key, out.len());
            out.push(ind);
        }
    }
    out
}

/// Orchestrates polling for every (tenant, provider) target on the
/// configured interval.
pub struct CommercialFeedsScheduler<C, S, A> {
    creds: TenantCredentialStore<C>,
    sink: S,
    audit: A,
    mandiant_bucket: TokenBucket,
    crowdstrike_bucket: TokenBucket,
    poll_interval: Duration,
    targets: Vec<TenantFeedTarget>,
    http: reqwest::Client,
    mandiant_base_override: Option<String>,
    crowdstrike_base_override: Option<url::Url>,
}

impl<C, S, A> std::fmt::Debug for CommercialFeedsScheduler<C, S, A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CommercialFeedsScheduler")
            .field("poll_interval", &self.poll_interval)
            .field("targets", &self.targets.len())
            .finish_non_exhaustive()
    }
}

impl<C, S, A> CommercialFeedsScheduler<C, S, A>
where
    C: SecretsProvider + Clone + 'static,
    S: IndicatorSink + 'static,
    A: CommercialAuditSink + 'static,
{
    /// Build a scheduler with default per-vendor rate buckets and the
    /// default 1 h poll interval.
    pub fn new(
        creds: TenantCredentialStore<C>,
        sink: S,
        audit: A,
        targets: Vec<TenantFeedTarget>,
    ) -> Self {
        Self {
            creds,
            sink,
            audit,
            mandiant_bucket: TokenBucket::new(MANDIANT_RPM, RATE_LIMIT_WINDOW),
            crowdstrike_bucket: TokenBucket::new(CROWDSTRIKE_RPM, RATE_LIMIT_WINDOW),
            poll_interval: Duration::from_secs(DEFAULT_COMMERCIAL_POLL_INTERVAL_SECS),
            targets,
            http: reqwest::Client::new(),
            mandiant_base_override: None,
            crowdstrike_base_override: None,
        }
    }

    /// Override the poll interval. Honoured on the next loop iteration.
    #[must_use]
    pub const fn with_poll_interval(mut self, interval: Duration) -> Self {
        self.poll_interval = interval;
        self
    }

    /// Override the Mandiant base URL (tests inject the `wiremock` URL
    /// here).
    #[must_use]
    pub fn with_mandiant_base(mut self, base: impl Into<String>) -> Self {
        self.mandiant_base_override = Some(base.into());
        self
    }

    /// Override the `CrowdStrike` base URL (tests inject the `wiremock`
    /// URL here).
    #[must_use]
    pub fn with_crowdstrike_base(mut self, base: url::Url) -> Self {
        self.crowdstrike_base_override = Some(base);
        self
    }

    /// Replace the Mandiant rate-limit bucket. Defaults to 60 rpm.
    #[must_use]
    pub fn with_mandiant_bucket(mut self, bucket: TokenBucket) -> Self {
        self.mandiant_bucket = bucket;
        self
    }

    /// Replace the `CrowdStrike` rate-limit bucket. Defaults to 100 rpm.
    #[must_use]
    pub fn with_crowdstrike_bucket(mut self, bucket: TokenBucket) -> Self {
        self.crowdstrike_bucket = bucket;
        self
    }

    /// Run a single poll cycle for every target. Returns the count of
    /// successful pulls. Errors for individual targets are converted
    /// into [`CommercialAuditEvent::PollFailed`] events and do **not**
    /// abort the cycle.
    pub async fn run_once(&self, since: OffsetDateTime) -> usize {
        let mut successes = 0usize;
        for target in &self.targets {
            match self.poll_one(target, since).await {
                Ok(count) => {
                    successes += 1;
                    self.audit
                        .record(CommercialAuditEvent::PollSucceeded {
                            tenant: target.tenant.clone(),
                            provider: target.provider.provider_id(),
                            indicators: count,
                            completed_at: OffsetDateTime::now_utc(),
                        })
                        .await;
                    info!(
                        target: "sx_intel_feeds::commercial_scheduler",
                        tenant = %target.tenant,
                        provider = target.provider.provider_id(),
                        indicators = count,
                        "commercial intel poll succeeded",
                    );
                }
                Err(e) => {
                    let (status, reason) = classify_error(&e);
                    self.audit
                        .record(CommercialAuditEvent::PollFailed {
                            tenant: target.tenant.clone(),
                            provider: target.provider.provider_id(),
                            http_status: status,
                            reason: reason.clone(),
                            completed_at: OffsetDateTime::now_utc(),
                        })
                        .await;
                    warn!(
                        target: "sx_intel_feeds::commercial_scheduler",
                        tenant = %target.tenant,
                        provider = target.provider.provider_id(),
                        http_status = ?status,
                        reason = %reason,
                        "commercial intel poll failed",
                    );
                }
            }
        }
        successes
    }

    /// Spawn the polling loop. Returns immediately; the loop runs until
    /// `cancel` resolves. Each tick calls [`Self::run_once`] with the
    /// current high-water mark (initialized at `start_since`).
    pub fn spawn_loop(
        self: Arc<Self>,
        start_since: OffsetDateTime,
        mut cancel: tokio::sync::watch::Receiver<bool>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut since = start_since;
            loop {
                let _ = self.run_once(since).await;
                since = OffsetDateTime::now_utc();
                tokio::select! {
                    () = tokio::time::sleep(self.poll_interval) => {},
                    res = cancel.changed() => {
                        if res.is_err() || *cancel.borrow() {
                            debug!(target: "sx_intel_feeds::commercial_scheduler", "shutdown signalled");
                            return;
                        }
                    }
                }
            }
        })
    }

    async fn poll_one(
        &self,
        target: &TenantFeedTarget,
        since: OffsetDateTime,
    ) -> Result<usize, PollError> {
        let indicators = match target.provider {
            ProviderKind::Mandiant => self.poll_mandiant(&target.tenant, since).await?,
            ProviderKind::CrowdStrike(cloud) => {
                self.poll_crowdstrike(&target.tenant, cloud, since).await?
            }
        };
        let deduped = dedupe_indicators(indicators);
        let count = deduped.len();
        self.sink
            .ingest(&target.tenant, target.provider.provider_id(), deduped)
            .await;
        Ok(count)
    }

    async fn poll_mandiant(
        &self,
        tenant: &str,
        since: OffsetDateTime,
    ) -> Result<Vec<EnrichedIndicator>, PollError> {
        let cfg = self
            .creds
            .mandiant_config(tenant, self.mandiant_base_override.clone())
            .await
            .map_err(PollError::Cred)?;
        let feed = MandiantFeed::with_http(self.http.clone(), cfg).map_err(PollError::Intel)?;
        let limited = RateLimitedFeed::new(feed, self.mandiant_bucket.clone());
        limited.fetch_since(since).await.map_err(PollError::Intel)
    }

    async fn poll_crowdstrike(
        &self,
        tenant: &str,
        cloud: CrowdStrikeCloud,
        since: OffsetDateTime,
    ) -> Result<Vec<EnrichedIndicator>, PollError> {
        let cfg = self
            .creds
            .crowdstrike_config(tenant, cloud)
            .await
            .map_err(PollError::Cred)?;
        let feed = CrowdStrikeFeed::with_http_and_base(
            self.http.clone(),
            cfg,
            self.crowdstrike_base_override.clone(),
        )
        .map_err(PollError::Intel)?;
        let limited = RateLimitedFeed::new(feed, self.crowdstrike_bucket.clone());
        limited.fetch_since(since).await.map_err(PollError::Intel)
    }
}

#[derive(Debug)]
enum PollError {
    Cred(CommercialSchedulerError),
    Intel(IntelError),
}

/// Map an internal error into an `(http_status, redacted_reason)` pair
/// suitable for the audit log. Credentials never appear in the reason.
fn classify_error(err: &PollError) -> (Option<u16>, String) {
    match err {
        PollError::Cred(c) => match c {
            CommercialSchedulerError::MissingCredentials { .. } => {
                (None, "missing credentials".to_string())
            }
            CommercialSchedulerError::Secret { .. } => (None, "secrets backend error".to_string()),
            CommercialSchedulerError::Adapter { .. } => {
                (None, "adapter construction failed".to_string())
            }
        },
        PollError::Intel(i) => match i {
            IntelError::Status { status, .. } => (Some(*status), format!("http {status}")),
            IntelError::Unauthorized { .. } => (Some(401), "unauthorized".to_string()),
            IntelError::Http(_) => (None, "transport error".to_string()),
            IntelError::Decode { .. } => (None, "decode error".to_string()),
            IntelError::Config(_) => (None, "config error".to_string()),
            IntelError::Url(_) => (None, "url error".to_string()),
        },
    }
}

impl<C, S, A> CommercialFeedsScheduler<C, S, A> {
    /// Expose the audit sink reference for diagnostic / shutdown tooling.
    pub const fn audit(&self) -> &A {
        &self.audit
    }

    /// Expose the indicator sink reference for diagnostic / shutdown
    /// tooling.
    pub const fn sink(&self) -> &S {
        &self.sink
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::expect_used
)]
mod tests {
    use super::*;
    use crate::commercial::Tlp;
    use crate::indicator::{HashKind, IndicatorKind};
    use secrecy::ExposeSecret;
    use serde_json::json;
    use wiremock::matchers::{body_string_contains, header, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn put(provider: &InMemoryProviderHandle, key: &str, value: &str) {
        provider
            .inner
            .0
            .lock()
            .unwrap()
            .insert(key.to_string(), value.to_string());
    }

    /// Minimal blocking-mutex map to avoid pulling `tokio::sync` into the
    /// test path twice; we use a plain `std::sync::Mutex` here.
    #[derive(Default)]
    struct StdMap(std::sync::Mutex<std::collections::HashMap<String, String>>);

    #[derive(Clone)]
    struct InMemoryProviderHandle {
        inner: Arc<StdMap>,
    }

    impl InMemoryProviderHandle {
        fn new() -> Self {
            Self {
                inner: Arc::new(StdMap::default()),
            }
        }
    }

    #[async_trait]
    impl SecretsProvider for InMemoryProviderHandle {
        async fn get(&self, p: &str) -> Result<SecretString, SecretsError> {
            let guard = self.inner.0.lock().unwrap();
            guard
                .get(p)
                .map(|v| SecretString::new(v.clone().into_boxed_str()))
                .ok_or_else(|| SecretsError::NotFound(p.to_string()))
        }

        async fn put(&self, p: &str, v: SecretString) -> Result<(), SecretsError> {
            self.inner
                .0
                .lock()
                .unwrap()
                .insert(p.to_string(), v.expose_secret().to_string());
            Ok(())
        }
    }

    #[tokio::test]
    async fn credential_store_prefers_oauth2_for_mandiant() {
        let provider = InMemoryProviderHandle::new();
        put(&provider, "tenants/acme/intel/mandiant/client_id", "id-1");
        put(
            &provider,
            "tenants/acme/intel/mandiant/client_secret",
            "sec-1",
        );
        put(
            &provider,
            "tenants/acme/intel/mandiant/api_key",
            "key-fallback",
        );
        let store = TenantCredentialStore::new(provider);
        let cfg = store.mandiant_config("acme", None).await.unwrap();
        assert!(matches!(cfg.auth, MandiantAuth::OAuth2 { .. }));
    }

    #[tokio::test]
    async fn credential_store_falls_back_to_api_key_for_mandiant() {
        let provider = InMemoryProviderHandle::new();
        put(&provider, "tenants/acme/intel/mandiant/api_key", "key-only");
        let store = TenantCredentialStore::new(provider);
        let cfg = store.mandiant_config("acme", None).await.unwrap();
        assert!(matches!(cfg.auth, MandiantAuth::ApiKey { .. }));
    }

    #[tokio::test]
    async fn credential_store_missing_returns_error() {
        let provider = InMemoryProviderHandle::new();
        let store = TenantCredentialStore::new(provider);
        let err = store.mandiant_config("acme", None).await.unwrap_err();
        assert!(matches!(
            err,
            CommercialSchedulerError::MissingCredentials { .. }
        ));
        let err = store
            .crowdstrike_config("acme", CrowdStrikeCloud::Us1)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            CommercialSchedulerError::MissingCredentials { .. }
        ));
    }

    #[tokio::test]
    async fn credential_store_crowdstrike_needs_both_id_and_secret() {
        let provider = InMemoryProviderHandle::new();
        put(&provider, "tenants/acme/intel/crowdstrike/client_id", "id");
        let store = TenantCredentialStore::new(provider);
        let err = store
            .crowdstrike_config("acme", CrowdStrikeCloud::Us1)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            CommercialSchedulerError::MissingCredentials { .. }
        ));
    }

    fn make_indicator(value: &str, source: &str) -> EnrichedIndicator {
        EnrichedIndicator {
            kind: IndicatorKind::Domain,
            value: value.to_string(),
            tlp: Tlp::Amber,
            confidence: Some(80),
            sources: vec![source.to_string()],
            first_seen: OffsetDateTime::UNIX_EPOCH,
            last_seen: OffsetDateTime::UNIX_EPOCH,
            ttp_refs: vec![],
        }
    }

    #[test]
    fn dedupe_collapses_same_value_across_sources() {
        let batch = vec![
            make_indicator("evil.example", "mandiant"),
            make_indicator("evil.example", "crowdstrike"),
            make_indicator("other.example", "mandiant"),
            EnrichedIndicator {
                kind: IndicatorKind::FileHash(HashKind::Sha256),
                value: "abc".to_string(),
                tlp: Tlp::Amber,
                confidence: None,
                sources: vec!["mandiant".into()],
                first_seen: OffsetDateTime::UNIX_EPOCH,
                last_seen: OffsetDateTime::UNIX_EPOCH,
                ttp_refs: vec![],
            },
        ];
        let out = dedupe_indicators(batch);
        assert_eq!(out.len(), 3);
        // Sources are merged on the surviving entry.
        let evil = out.iter().find(|i| i.value == "evil.example").unwrap();
        assert!(evil.sources.contains(&"mandiant".to_string()));
        assert!(evil.sources.contains(&"crowdstrike".to_string()));
    }

    #[tokio::test(start_paused = true)]
    async fn rate_limited_feed_serializes_through_token_bucket() {
        use std::sync::atomic::{AtomicU32, Ordering};

        struct CountingFeed {
            n: Arc<AtomicU32>,
        }
        #[async_trait]
        impl CommercialIntelFeed for CountingFeed {
            fn provider_id(&self) -> &'static str {
                "mandiant"
            }
            async fn fetch_since(
                &self,
                _since: OffsetDateTime,
            ) -> Result<Vec<EnrichedIndicator>, IntelError> {
                self.n.fetch_add(1, Ordering::SeqCst);
                Ok(vec![])
            }
        }

        let counter = Arc::new(AtomicU32::new(0));
        let inner = CountingFeed { n: counter.clone() };
        let bucket = TokenBucket::new(2, Duration::from_secs(2));
        let feed = RateLimitedFeed::new(inner, bucket);

        // First two fetches consume the burst immediately, third sleeps.
        let start = tokio::time::Instant::now();
        feed.fetch_since(OffsetDateTime::UNIX_EPOCH).await.unwrap();
        feed.fetch_since(OffsetDateTime::UNIX_EPOCH).await.unwrap();
        feed.fetch_since(OffsetDateTime::UNIX_EPOCH).await.unwrap();
        let waited = tokio::time::Instant::now().duration_since(start);
        assert!(
            waited >= Duration::from_millis(900),
            "expected ~1s wait, got {waited:?}"
        );
        assert_eq!(counter.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn scheduler_emits_success_audit_on_clean_poll() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/oauth2/token"))
            .and(body_string_contains("grant_type=client_credentials"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "tok-x",
                "expires_in": 1800
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/intel/queries/indicators/v1"))
            .and(header("authorization", "Bearer tok-x"))
            .and(query_param("limit", "5000"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "resources": [
                    {
                        "type": "domain",
                        "indicator": "evil.example",
                        "malicious_confidence": "high",
                        "published_date": 1_717_200_000_i64,
                        "last_updated": 1_717_200_000_i64
                    }
                ],
                "meta": {"pagination": {"offset": 0, "limit": 5000, "total": 1}}
            })))
            .mount(&server)
            .await;

        let provider = InMemoryProviderHandle::new();
        put(
            &provider,
            "tenants/acme/intel/crowdstrike/client_id",
            "cs-id",
        );
        put(
            &provider,
            "tenants/acme/intel/crowdstrike/client_secret",
            "cs-sec",
        );
        let store = TenantCredentialStore::new(provider);
        let sink = InMemoryIndicatorSink::new();
        let audit = InMemoryAuditSink::new();

        let scheduler = CommercialFeedsScheduler::new(
            store,
            sink.clone(),
            audit.clone(),
            vec![TenantFeedTarget {
                tenant: "acme".to_string(),
                provider: ProviderKind::CrowdStrike(CrowdStrikeCloud::Us1),
            }],
        )
        .with_crowdstrike_base(url::Url::parse(&server.uri()).unwrap());

        let ok = scheduler.run_once(OffsetDateTime::UNIX_EPOCH).await;
        assert_eq!(ok, 1);
        let events = audit.snapshot().await;
        assert_eq!(events.len(), 1);
        assert!(matches!(
            events[0],
            CommercialAuditEvent::PollSucceeded { ref tenant, provider: "crowdstrike", indicators: 1, .. } if tenant == "acme"
        ));
        let stored = sink.snapshot().await;
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].0, "acme");
        assert_eq!(stored[0].1, "crowdstrike");
    }

    #[tokio::test]
    async fn scheduler_records_http_status_on_failure() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/oauth2/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "tok-x",
                "expires_in": 1800
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/intel/queries/indicators/v1"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;

        let provider = InMemoryProviderHandle::new();
        put(
            &provider,
            "tenants/acme/intel/crowdstrike/client_id",
            "cs-id",
        );
        put(
            &provider,
            "tenants/acme/intel/crowdstrike/client_secret",
            "cs-sec",
        );
        let store = TenantCredentialStore::new(provider);
        let sink = InMemoryIndicatorSink::new();
        let audit = InMemoryAuditSink::new();

        let scheduler = CommercialFeedsScheduler::new(
            store,
            sink,
            audit.clone(),
            vec![TenantFeedTarget {
                tenant: "acme".to_string(),
                provider: ProviderKind::CrowdStrike(CrowdStrikeCloud::Us1),
            }],
        )
        .with_crowdstrike_base(url::Url::parse(&server.uri()).unwrap());

        let ok = scheduler.run_once(OffsetDateTime::UNIX_EPOCH).await;
        assert_eq!(ok, 0);
        let events = audit.snapshot().await;
        assert_eq!(events.len(), 1);
        match &events[0] {
            CommercialAuditEvent::PollFailed {
                http_status,
                reason,
                provider,
                ..
            } => {
                assert_eq!(*http_status, Some(503));
                assert!(reason.contains("503"));
                assert_eq!(*provider, "crowdstrike");
                // Never echo credentials into the audit reason.
                assert!(!reason.contains("cs-sec"));
                assert!(!reason.contains("cs-id"));
            }
            CommercialAuditEvent::PollSucceeded { .. } => {
                panic!("expected PollFailed, got PollSucceeded")
            }
        }
    }

    #[tokio::test]
    async fn scheduler_missing_credentials_is_recorded_as_failure() {
        let provider = InMemoryProviderHandle::new();
        let store = TenantCredentialStore::new(provider);
        let sink = InMemoryIndicatorSink::new();
        let audit = InMemoryAuditSink::new();

        let scheduler = CommercialFeedsScheduler::new(
            store,
            sink,
            audit.clone(),
            vec![TenantFeedTarget {
                tenant: "no-such-tenant".to_string(),
                provider: ProviderKind::Mandiant,
            }],
        );
        let ok = scheduler.run_once(OffsetDateTime::UNIX_EPOCH).await;
        assert_eq!(ok, 0);
        let events = audit.snapshot().await;
        assert_eq!(events.len(), 1);
        match &events[0] {
            CommercialAuditEvent::PollFailed {
                http_status,
                reason,
                ..
            } => {
                assert!(http_status.is_none());
                assert!(reason.contains("missing"));
            }
            CommercialAuditEvent::PollSucceeded { .. } => {
                panic!("expected PollFailed, got PollSucceeded")
            }
        }
    }
}
