//! Real HTTP-backed providers for the `EPSS`, `CISA` `KEV`, and `NVD CVE`
//! intel feeds.
//!
//! All providers share a single [`reqwest::Client`] supplied by the caller,
//! so connection pooling and TLS state are reused across all outbound HTTP
//! work in the monolith.
//!
//! ## `EPSS` — [`FirstEpssProvider`]
//!
//! Looks each `CVE` up via the public `FIRST.org` `EPSS` endpoint
//! (`https://api.first.org/data/v1/epss?cve=CVE-YYYY-NNNN`). A `404` or an
//! empty `data` array becomes `Ok(None)`. All other transport failures map
//! to [`RiskError::Provider`].
//!
//! ## `KEV` — [`CisaKevProvider`]
//!
//! Downloads the full `CISA` "Known Exploited Vulnerabilities" catalogue once
//! and caches the set of `cveID` strings behind a [`tokio::sync::RwLock`].
//! Lookups are then `O(1)` `HashSet` hits. The cache is refreshed lazily after
//! [`KEV_CACHE_TTL`] elapses; that constant matches the documented refresh
//! cadence of the upstream feed.
//!
//! ## `NVD CVE` — [`NvdCveProvider`]
//!
//! Resolves the canonical CVSS envelope (v3.1 / v4.0) and an English
//! description for a given CVE id via the `NVD` REST API
//! (`https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=…`). Successful
//! lookups are cached behind a [`tokio::sync::RwLock`] keyed on the
//! upper-cased CVE id for [`NVD_CACHE_TTL`]. Misses (`Ok(None)`) are
//! deliberately NOT cached so a transient `NVD` outage can recover without
//! poisoning the cache.

use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use serde_json::Value;
use sx_core::value_object::{cvss::CvssScore, epss::EpssScore, ids::CveId};
use sx_risk::error::RiskError;
use sx_risk::service::{EpssProvider, KevProvider};
use tokio::sync::RwLock;
use tokio::time::Instant;

/// Public `FIRST.org` `EPSS` query endpoint.
const EPSS_BASE_URL: &str = "https://api.first.org/data/v1/epss";

/// Public `CISA` `KEV` catalogue JSON.
const KEV_FEED_URL: &str =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

/// `User-Agent` advertised on every outbound intel request.
const USER_AGENT: &str = "SentinelX-Intel/0.1 (+https://sentinelx.example.invalid)";

/// Per-request timeout for intel feed fetches.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Documented upstream refresh cadence of the `CISA` `KEV` feed.
const KEV_CACHE_TTL: Duration = Duration::from_secs(6 * 60 * 60);

/// Public `NVD` REST API endpoint (CVE 2.0 schema).
const NVD_BASE_URL: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";

/// `NVD` lookup cache TTL. The `NVD` data set is mutable but slow-changing;
/// 24 hours is the published guidance for clients that do not subscribe to
/// the `lastModStartDate` delta endpoint.
const NVD_CACHE_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// Container holding all intel providers as trait objects.
#[derive(Debug, Clone)]
pub(crate) struct IntelBundle {
    /// Concrete `EPSS` adapter.
    pub epss: Arc<dyn EpssProvider>,
    /// Concrete `KEV` adapter.
    pub kev: Arc<dyn KevProvider>,
    /// Concrete `NVD CVE` lookup adapter.
    pub cve: Arc<dyn CveLookup>,
}

/// Build a bundle of HTTP-backed intel providers sharing `http_client`.
pub(crate) fn build(http_client: reqwest::Client) -> IntelBundle {
    let epss = Arc::new(FirstEpssProvider::new(http_client.clone()));
    let kev = Arc::new(CisaKevProvider::new(http_client.clone()));
    let cve = Arc::new(NvdCveProvider::new(http_client));
    IntelBundle { epss, kev, cve }
}

// ----- EPSS --------------------------------------------------------------

/// `EPSS` adapter backed by the public `FIRST.org` API.
#[derive(Debug, Clone)]
pub(crate) struct FirstEpssProvider {
    client: reqwest::Client,
}

impl FirstEpssProvider {
    /// Construct a provider that reuses the caller-supplied `client`.
    pub(crate) const fn new(client: reqwest::Client) -> Self {
        Self { client }
    }
}

#[async_trait]
impl EpssProvider for FirstEpssProvider {
    async fn fetch(&self, cve: &CveId) -> Result<Option<EpssScore>, RiskError> {
        let response = self
            .client
            .get(EPSS_BASE_URL)
            .query(&[("cve", cve.as_str())])
            .header(reqwest::header::USER_AGENT, USER_AGENT)
            .timeout(REQUEST_TIMEOUT)
            .send()
            .await
            .map_err(|e| {
                tracing::warn!(error = %e, cve = cve.as_str(), "epss.http.failed");
                RiskError::provider(format!("epss: request failed: {e}"))
            })?;

        let status = response.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !status.is_success() {
            tracing::warn!(status = %status, cve = cve.as_str(), "epss.http.status");
            return Err(RiskError::provider(format!("epss: HTTP status {status}")));
        }

        let envelope: Value = response.json().await.map_err(|e| {
            tracing::warn!(error = %e, cve = cve.as_str(), "epss.json.failed");
            RiskError::provider(format!("epss: malformed JSON: {e}"))
        })?;

        let Some(row) = envelope
            .get("data")
            .and_then(Value::as_array)
            .and_then(|rows| rows.first())
        else {
            return Ok(None);
        };

        let epss_raw = row
            .get("epss")
            .and_then(Value::as_str)
            .ok_or_else(|| RiskError::provider("epss: missing 'epss' field".to_string()))?;
        let percentile_raw = row
            .get("percentile")
            .and_then(Value::as_str)
            .ok_or_else(|| RiskError::provider("epss: missing 'percentile' field".to_string()))?;

        let probability = parse_unit("epss", epss_raw)?;
        let percentile = parse_unit("percentile", percentile_raw)?;

        EpssScore::new(probability, percentile)
            .map(Some)
            .map_err(|e| RiskError::provider(format!("epss: invalid score: {e}")))
    }
}

fn parse_unit(label: &str, raw: &str) -> Result<f32, RiskError> {
    raw.parse::<f32>()
        .map_err(|e| RiskError::provider(format!("epss: invalid {label} '{raw}': {e}")))
}

// ----- KEV ---------------------------------------------------------------

/// `CISA` `KEV` adapter with an in-memory, TTL-bounded `HashSet` cache.
#[derive(Debug)]
pub(crate) struct CisaKevProvider {
    client: reqwest::Client,
    cache: RwLock<KevCache>,
}

#[derive(Debug)]
struct KevCache {
    fetched_at: Option<Instant>,
    ids: HashSet<String>,
}

impl KevCache {
    fn is_fresh(&self) -> bool {
        self.fetched_at.is_some_and(|t| t.elapsed() < KEV_CACHE_TTL)
    }
}

impl CisaKevProvider {
    /// Construct a provider that reuses the caller-supplied `client`.
    pub(crate) fn new(client: reqwest::Client) -> Self {
        Self {
            client,
            cache: RwLock::new(KevCache {
                fetched_at: None,
                ids: HashSet::new(),
            }),
        }
    }

    /// Refresh the cache from the upstream feed.
    async fn refresh(&self) -> Result<(), RiskError> {
        let response = self
            .client
            .get(KEV_FEED_URL)
            .header(reqwest::header::USER_AGENT, USER_AGENT)
            .timeout(REQUEST_TIMEOUT)
            .send()
            .await
            .map_err(|e| {
                tracing::warn!(error = %e, "kev.http.failed");
                RiskError::provider(format!("kev: request failed: {e}"))
            })?;

        let status = response.status();
        if !status.is_success() {
            tracing::warn!(status = %status, "kev.http.status");
            return Err(RiskError::provider(format!("kev: HTTP status {status}")));
        }

        let catalog: Value = response.json().await.map_err(|e| {
            tracing::warn!(error = %e, "kev.json.failed");
            RiskError::provider(format!("kev: malformed JSON: {e}"))
        })?;

        let vulns = catalog
            .get("vulnerabilities")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                RiskError::provider("kev: missing 'vulnerabilities' array".to_string())
            })?;

        let ids: HashSet<String> = vulns
            .iter()
            .filter_map(|v| v.get("cveID").and_then(Value::as_str))
            .map(str::to_ascii_uppercase)
            .filter(|s| !s.is_empty())
            .collect();

        let count = ids.len();
        let mut guard = self.cache.write().await;
        guard.fetched_at = Some(Instant::now());
        guard.ids = ids;
        tracing::info!(count, "kev.cache.refreshed");
        Ok(())
    }
}

#[async_trait]
impl KevProvider for CisaKevProvider {
    async fn is_known_exploited(&self, cve: &CveId) -> Result<bool, RiskError> {
        // Fast path: cache is fresh, so we only take a read lock.
        {
            let guard = self.cache.read().await;
            if guard.is_fresh() {
                return Ok(guard.ids.contains(cve.as_str()));
            }
        }

        // Slow path: refresh under the write lock — `refresh` itself
        // takes the write lock, so release ours first.
        self.refresh().await?;

        let guard = self.cache.read().await;
        Ok(guard.ids.contains(cve.as_str()))
    }
}

// ----- NVD CVE -----------------------------------------------------------

/// CVE detail returned by [`CveLookup::fetch`].
///
/// `description` is captured today so future phases (finding enrichment,
/// SSVC narrative) can surface it without re-querying NVD.
#[derive(Debug, Clone)]
pub(crate) struct CveDetail {
    /// CVSS envelope (v3 and/or v4) sourced from the upstream feed.
    pub cvss: CvssScore,
    /// English description of the vulnerability, if upstream provides one.
    #[allow(dead_code)]
    pub description: Option<String>,
}

/// Port for resolving CVE metadata (CVSS + description) by id.
///
/// Implementations are expected to be idempotent and side-effect free
/// other than transient I/O + caching.
#[async_trait]
pub(crate) trait CveLookup: Send + Sync + std::fmt::Debug {
    /// Fetch the [`CveDetail`] for `cve`.
    ///
    /// Returns `Ok(None)` when the upstream feed reports the CVE is
    /// unknown (HTTP 404 or an empty `vulnerabilities` array).
    async fn fetch(&self, cve: &CveId) -> Result<Option<CveDetail>, RiskError>;
}

/// `NVD` `CVE` adapter with an in-memory, TTL-bounded `HashMap` cache.
#[derive(Debug)]
pub(crate) struct NvdCveProvider {
    client: reqwest::Client,
    cache: RwLock<HashMap<String, (Instant, CveDetail)>>,
}

impl NvdCveProvider {
    /// Construct a provider that reuses the caller-supplied `client`.
    pub(crate) fn new(client: reqwest::Client) -> Self {
        Self {
            client,
            cache: RwLock::new(HashMap::new()),
        }
    }

    /// Try to return a fresh cached entry for `key`.
    async fn cached(&self, key: &str) -> Option<CveDetail> {
        let guard = self.cache.read().await;
        guard.get(key).and_then(|(at, detail)| {
            if at.elapsed() < NVD_CACHE_TTL {
                Some(detail.clone())
            } else {
                None
            }
        })
    }

    /// Insert `detail` into the cache under `key`.
    async fn insert(&self, key: String, detail: CveDetail) {
        let mut guard = self.cache.write().await;
        guard.insert(key, (Instant::now(), detail));
    }
}

#[async_trait]
impl CveLookup for NvdCveProvider {
    async fn fetch(&self, cve: &CveId) -> Result<Option<CveDetail>, RiskError> {
        let key = cve.as_str().to_ascii_uppercase();

        if let Some(hit) = self.cached(&key).await {
            return Ok(Some(hit));
        }

        let response = self
            .client
            .get(NVD_BASE_URL)
            .query(&[("cveId", key.as_str())])
            .header(reqwest::header::USER_AGENT, USER_AGENT)
            .timeout(REQUEST_TIMEOUT)
            .send()
            .await
            .map_err(|e| {
                tracing::warn!(error = %e, cve = key.as_str(), "nvd.http.failed");
                RiskError::provider(format!("nvd: request failed: {e}"))
            })?;

        let status = response.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !status.is_success() {
            tracing::warn!(status = %status, cve = key.as_str(), "nvd.http.status");
            return Err(RiskError::provider(format!("nvd: HTTP status {status}")));
        }

        let envelope: Value = response.json().await.map_err(|e| {
            tracing::warn!(error = %e, cve = key.as_str(), "nvd.json.failed");
            RiskError::provider(format!("nvd: malformed JSON: {e}"))
        })?;

        let Some(first) = envelope
            .get("vulnerabilities")
            .and_then(Value::as_array)
            .and_then(|rows| rows.first())
        else {
            return Ok(None);
        };

        let Some(cve_obj) = first.get("cve") else {
            return Ok(None);
        };

        let detail = match parse_cve_detail(cve_obj) {
            Ok(Some(d)) => d,
            Ok(None) => return Ok(None),
            Err(e) => return Err(e),
        };

        self.insert(key, detail.clone()).await;
        Ok(Some(detail))
    }
}

/// Parse the `cve` object returned by the `NVD` API into a [`CveDetail`].
///
/// Returns `Ok(None)` when the upstream entry exists but carries no usable
/// CVSS data (which the caller treats as "unknown" for scoring purposes).
fn parse_cve_detail(cve_obj: &Value) -> Result<Option<CveDetail>, RiskError> {
    let metrics = cve_obj.get("metrics");

    let v4 = metrics
        .and_then(|m| m.get("cvssMetricV40"))
        .and_then(Value::as_array)
        .and_then(|rows| rows.first())
        .and_then(|row| row.get("cvssData"))
        .and_then(|d| d.get("baseScore"))
        .and_then(Value::as_f64)
        .and_then(f64_to_f32);

    let v3 = metrics
        .and_then(|m| m.get("cvssMetricV31"))
        .and_then(Value::as_array)
        .and_then(|rows| rows.first())
        .and_then(|row| row.get("cvssData"))
        .and_then(|d| d.get("baseScore"))
        .and_then(Value::as_f64)
        .and_then(f64_to_f32);

    if v3.is_none() && v4.is_none() {
        return Ok(None);
    }

    let cvss = CvssScore::new(v3, v4)
        .map_err(|e| RiskError::provider(format!("nvd: invalid CVSS: {e}")))?;

    let description = cve_obj
        .get("descriptions")
        .and_then(Value::as_array)
        .and_then(|rows| {
            rows.iter().find_map(|row| {
                let lang = row.get("lang").and_then(Value::as_str)?;
                if lang.eq_ignore_ascii_case("en") {
                    row.get("value").and_then(Value::as_str).map(str::to_owned)
                } else {
                    None
                }
            })
        });

    Ok(Some(CveDetail { cvss, description }))
}

/// Narrow an upstream `f64` baseScore to the `f32` accepted by
/// [`CvssScore`]. Non-finite or out-of-band values are filtered upstream.
fn f64_to_f32(v: f64) -> Option<f32> {
    if v.is_finite() && (0.0..=10.0).contains(&v) {
        // Range is checked above; the as-cast is precision-only — safe.
        #[allow(clippy::cast_possible_truncation)]
        Some(v as f32)
    } else {
        None
    }
}
