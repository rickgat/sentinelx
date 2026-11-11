//! `CrowdStrike` Falcon Intel adapter.
//!
//! Implements [`crate::commercial::CommercialIntelFeed`] against the
//! Falcon `intel/queries/indicators/v1` endpoint, with `OAuth2`
//! `client_credentials` token exchange.
//!
//! ## Auth flow
//!
//! 1. `POST {base}/oauth2/token` with
//!    `Content-Type: application/x-www-form-urlencoded` and a body of
//!    `client_id=...&client_secret=...&grant_type=client_credentials`.
//! 2. Response body: `{ "access_token": "...", "expires_in": 1800, ... }`.
//! 3. Token is cached in-memory for 25 minutes (Falcon issues 30-minute
//!    tokens; we refresh 5 minutes early to avoid clock-skew expiry
//!    mid-request).
//! 4. If a fetch returns `401`, we drop the cached token and retry once
//!    with a freshly-minted one.
//!
//! ## Endpoint
//!
//! `GET {base}/intel/queries/indicators/v1?filter=last_updated:>{epoch}`
//! plus optional `offset`+`limit` for pagination. The response is a JSON
//! envelope with a `resources` array of indicator records.
//!
//! ## Opt-in
//!
//! Same pattern as Mandiant: [`CrowdStrikeFeed::new`] returns
//! [`IntelError::Config`] unless `enabled` is `true` and credentials are
//! present.

use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::{Client, StatusCode};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use time::OffsetDateTime;
use tokio::sync::Mutex;
use tracing::{debug, warn};
use url::Url;

use crate::commercial::{CommercialIntelFeed, EnrichedIndicator, IntelError, Tlp};
use crate::indicator::{HashKind, IndicatorKind};

/// Stable provider tag.
pub const PROVIDER_ID: &str = "crowdstrike";

/// Token lifetime we honour, regardless of `expires_in`. Falcon returns
/// 1800 (30 min) tokens; we cache for 25 min to leave a refresh margin.
const TOKEN_CACHE_TTL: Duration = Duration::from_secs(25 * 60);
const PAGE_LIMIT: u32 = 5_000;
const MAX_PAGES: u32 = 500;

/// `CrowdStrike` Falcon cloud the tenant is provisioned in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrowdStrikeCloud {
    /// `https://api.crowdstrike.com` (US-1).
    Us1,
    /// `https://api.us-2.crowdstrike.com` (US-2).
    Us2,
    /// `https://api.eu-1.crowdstrike.com` (EU-1).
    Eu1,
}

impl CrowdStrikeCloud {
    /// Return the API base URL for this cloud.
    #[must_use]
    pub const fn base_url(self) -> &'static str {
        match self {
            Self::Us1 => "https://api.crowdstrike.com",
            Self::Us2 => "https://api.us-2.crowdstrike.com",
            Self::Eu1 => "https://api.eu-1.crowdstrike.com",
        }
    }
}

/// Configuration for [`CrowdStrikeFeed`]. Per-tenant; never persisted
/// with the client secret in plaintext.
#[derive(Debug, Clone)]
pub struct CrowdStrikeConfig {
    /// Adapter must be opted-in by setting this to `true`.
    pub enabled: bool,
    /// `OAuth2` client id (public-ish, but kept structured for parity).
    pub client_id: String,
    /// `OAuth2` client secret. Wrapped in [`SecretString`].
    pub client_secret: SecretString,
    /// Cloud the tenant uses.
    pub cloud: CrowdStrikeCloud,
}

impl Default for CrowdStrikeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            client_id: String::new(),
            client_secret: SecretString::new(String::new().into_boxed_str()),
            cloud: CrowdStrikeCloud::Us1,
        }
    }
}

#[derive(Debug)]
struct CachedToken {
    bearer: SecretString,
    expires_at: Instant,
}

/// `CrowdStrike` Falcon Intel adapter.
///
/// Clones share the token cache via [`Arc<Mutex<...>>`]. Cloning is
/// cheap; do it freely.
#[derive(Debug, Clone)]
pub struct CrowdStrikeFeed {
    http: Client,
    base_url: Url,
    client_id: String,
    client_secret: SecretString,
    token: Arc<Mutex<Option<CachedToken>>>,
}

impl CrowdStrikeFeed {
    /// Build a feed using a fresh `reqwest::Client` against the
    /// configured cloud.
    pub fn new(cfg: CrowdStrikeConfig) -> Result<Self, IntelError> {
        Self::with_http_and_base(Client::new(), cfg, None)
    }

    /// Build a feed against a caller-supplied HTTP client *and* a
    /// caller-supplied base URL. Tests inject a `wiremock::MockServer`
    /// URL here; production code passes `None` to derive from
    /// [`CrowdStrikeCloud::base_url`].
    pub fn with_http_and_base(
        http: Client,
        cfg: CrowdStrikeConfig,
        base_url_override: Option<Url>,
    ) -> Result<Self, IntelError> {
        if !cfg.enabled {
            return Err(IntelError::Config(
                "crowdstrike.enabled must be true".to_string(),
            ));
        }
        if cfg.client_id.trim().is_empty() {
            return Err(IntelError::Config(
                "crowdstrike.client_id must be non-empty".to_string(),
            ));
        }
        if cfg.client_secret.expose_secret().is_empty() {
            return Err(IntelError::Config(
                "crowdstrike.client_secret must be non-empty".to_string(),
            ));
        }
        let base_url = match base_url_override {
            Some(u) => u,
            None => Url::parse(cfg.cloud.base_url())
                .map_err(|e| IntelError::Url(format!("crowdstrike cloud base URL: {e}")))?,
        };
        Ok(Self {
            http,
            base_url,
            client_id: cfg.client_id,
            client_secret: cfg.client_secret,
            token: Arc::new(Mutex::new(None)),
        })
    }

    async fn cached_or_fresh_token(&self) -> Result<SecretString, IntelError> {
        {
            let guard = self.token.lock().await;
            if let Some(cached) = guard.as_ref() {
                if cached.expires_at > Instant::now() {
                    return Ok(SecretString::new(
                        cached.bearer.expose_secret().to_string().into_boxed_str(),
                    ));
                }
            }
        }
        self.refresh_token().await
    }

    async fn refresh_token(&self) -> Result<SecretString, IntelError> {
        let url = self
            .base_url
            .join("/oauth2/token")
            .map_err(|e| IntelError::Url(format!("/oauth2/token: {e}")))?;
        let form = [
            ("client_id", self.client_id.as_str()),
            ("client_secret", self.client_secret.expose_secret()),
            ("grant_type", "client_credentials"),
        ];
        debug!(
            target: "sx_intel_feeds::crowdstrike",
            vendor = PROVIDER_ID,
            "requesting fresh oauth2 token",
        );
        let resp = self
            .http
            .post(url)
            .header(
                reqwest::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .header(reqwest::header::ACCEPT, "application/json")
            .form(&form)
            .send()
            .await
            .map_err(IntelError::Http)?;
        let status = resp.status();
        if !status.is_success() {
            if matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN) {
                return Err(IntelError::Unauthorized {
                    vendor: PROVIDER_ID,
                });
            }
            return Err(IntelError::Status {
                vendor: PROVIDER_ID,
                status: status.as_u16(),
            });
        }
        let body: TokenResponse = resp
            .json()
            .await
            .map_err(|e| IntelError::decode(PROVIDER_ID, e))?;
        if body.access_token.is_empty() {
            return Err(IntelError::decode(
                PROVIDER_ID,
                "oauth2 response missing access_token",
            ));
        }
        let bearer = SecretString::new(body.access_token.clone().into_boxed_str());
        {
            let mut guard = self.token.lock().await;
            *guard = Some(CachedToken {
                bearer: SecretString::new(body.access_token.into_boxed_str()),
                expires_at: Instant::now() + TOKEN_CACHE_TTL,
            });
        }
        Ok(bearer)
    }

    async fn invalidate_token(&self) {
        let mut guard = self.token.lock().await;
        *guard = None;
    }

    fn auth_headers(bearer: &SecretString) -> Result<HeaderMap, IntelError> {
        let mut headers = HeaderMap::new();
        let val = format!("Bearer {}", bearer.expose_secret());
        let mut hv = HeaderValue::from_str(&val).map_err(|_| {
            IntelError::Config("crowdstrike bearer contains invalid header bytes".to_string())
        })?;
        hv.set_sensitive(true);
        headers.insert(reqwest::header::AUTHORIZATION, hv);
        headers.insert(
            reqwest::header::ACCEPT,
            HeaderValue::from_static("application/json"),
        );
        Ok(headers)
    }

    fn build_url(&self, since: OffsetDateTime, offset: u32) -> Result<Url, IntelError> {
        let mut url = self
            .base_url
            .join("/intel/queries/indicators/v1")
            .map_err(|e| IntelError::Url(format!("indicators path: {e}")))?;
        let epoch = since.unix_timestamp();
        let filter = format!("last_updated:>{epoch}");
        {
            let mut q = url.query_pairs_mut();
            q.append_pair("filter", &filter);
            q.append_pair("limit", &PAGE_LIMIT.to_string());
            if offset > 0 {
                q.append_pair("offset", &offset.to_string());
            }
        }
        Ok(url)
    }

    async fn fetch_page(
        &self,
        bearer: &SecretString,
        since: OffsetDateTime,
        offset: u32,
    ) -> Result<reqwest::Response, IntelError> {
        let url = self.build_url(since, offset)?;
        let headers = Self::auth_headers(bearer)?;
        debug!(
            target: "sx_intel_feeds::crowdstrike",
            vendor = PROVIDER_ID,
            offset,
            "fetching indicator page",
        );
        self.http
            .get(url)
            .headers(headers)
            .send()
            .await
            .map_err(IntelError::Http)
    }
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    #[serde(default)]
    access_token: String,
    #[serde(default)]
    #[allow(dead_code)]
    expires_in: u64,
    #[serde(default)]
    #[allow(dead_code)]
    token_type: String,
}

#[derive(Debug, Deserialize, Default)]
struct IndicatorEnvelope {
    #[serde(default)]
    resources: Vec<RawIndicator>,
    #[serde(default)]
    meta: Option<MetaBlock>,
}

#[derive(Debug, Deserialize, Default)]
struct MetaBlock {
    #[serde(default)]
    pagination: Option<PaginationBlock>,
}

#[derive(Debug, Deserialize, Default)]
struct PaginationBlock {
    #[serde(default)]
    #[allow(dead_code)]
    offset: Option<u32>,
    #[serde(default)]
    limit: Option<u32>,
    #[serde(default)]
    total: Option<u64>,
}

#[derive(Debug, Deserialize, Default)]
struct RawIndicator {
    #[serde(default, rename = "type")]
    kind: Option<String>,
    #[serde(default)]
    indicator: Option<String>,
    #[serde(default)]
    malicious_confidence: Option<String>,
    #[serde(default)]
    published_date: Option<i64>,
    #[serde(default)]
    last_updated: Option<i64>,
    #[serde(default)]
    actors: Vec<String>,
    #[serde(default)]
    malware_families: Vec<String>,
    #[serde(default)]
    kill_chains: Vec<String>,
    #[serde(default)]
    labels: Vec<RawLabel>,
}

#[derive(Debug, Deserialize, Default)]
struct RawLabel {
    #[serde(default)]
    name: Option<String>,
}

#[async_trait]
impl CommercialIntelFeed for CrowdStrikeFeed {
    fn provider_id(&self) -> &'static str {
        PROVIDER_ID
    }

    async fn fetch_since(
        &self,
        since: OffsetDateTime,
    ) -> Result<Vec<EnrichedIndicator>, IntelError> {
        let mut out = Vec::new();
        let mut offset: u32 = 0;
        let mut retried_auth = false;
        let mut bearer = self.cached_or_fresh_token().await?;
        for _ in 0..MAX_PAGES {
            let resp = self.fetch_page(&bearer, since, offset).await?;
            let status = resp.status();
            if status == StatusCode::UNAUTHORIZED && !retried_auth {
                debug!(
                    target: "sx_intel_feeds::crowdstrike",
                    vendor = PROVIDER_ID,
                    "401 received; refreshing token and retrying once",
                );
                self.invalidate_token().await;
                bearer = self.refresh_token().await?;
                retried_auth = true;
                continue;
            }
            if !status.is_success() {
                if matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN) {
                    return Err(IntelError::Unauthorized {
                        vendor: PROVIDER_ID,
                    });
                }
                return Err(IntelError::Status {
                    vendor: PROVIDER_ID,
                    status: status.as_u16(),
                });
            }
            // Reset retry flag after any successful page so a later 401
            // (e.g. token expiry during a long paginated walk) gets one
            // more refresh attempt.
            retried_auth = false;
            let envelope: IndicatorEnvelope = resp
                .json()
                .await
                .map_err(|e| IntelError::decode(PROVIDER_ID, e))?;
            let returned = u32::try_from(envelope.resources.len()).unwrap_or(u32::MAX);
            for raw in envelope.resources {
                if let Some(ind) = map_indicator(raw) {
                    out.push(ind);
                } else {
                    warn!(
                        target: "sx_intel_feeds::crowdstrike",
                        vendor = PROVIDER_ID,
                        "skipping unrecognised indicator shape",
                    );
                }
            }
            // Pagination: advance offset by what we just received.
            // Stop when fewer than page_limit rows came back, or when
            // meta.pagination.total says we are at the end.
            let limit = envelope
                .meta
                .as_ref()
                .and_then(|m| m.pagination.as_ref())
                .and_then(|p| p.limit)
                .unwrap_or(PAGE_LIMIT);
            let total = envelope
                .meta
                .as_ref()
                .and_then(|m| m.pagination.as_ref())
                .and_then(|p| p.total);
            if returned == 0 || returned < limit {
                return Ok(out);
            }
            offset = offset.saturating_add(returned);
            if let Some(total) = total {
                if u64::from(offset) >= total {
                    return Ok(out);
                }
            }
        }
        warn!(
            target: "sx_intel_feeds::crowdstrike",
            vendor = PROVIDER_ID,
            max_pages = MAX_PAGES,
            "pagination loop ceiling hit; returning accumulated indicators",
        );
        Ok(out)
    }
}

fn map_indicator(raw: RawIndicator) -> Option<EnrichedIndicator> {
    let value = raw.indicator?;
    let kind = map_kind(raw.kind.as_deref(), &value)?;
    let confidence = raw.malicious_confidence.as_deref().and_then(map_confidence);
    let first_seen = raw
        .published_date
        .and_then(|s| OffsetDateTime::from_unix_timestamp(s).ok())
        .unwrap_or(OffsetDateTime::UNIX_EPOCH);
    let last_seen = raw
        .last_updated
        .and_then(|s| OffsetDateTime::from_unix_timestamp(s).ok())
        .unwrap_or(first_seen);
    let mut ttp_refs = Vec::with_capacity(
        raw.actors.len() + raw.malware_families.len() + raw.kill_chains.len() + raw.labels.len(),
    );
    for actor in raw.actors {
        ttp_refs.push(format!("actor:{actor}"));
    }
    for fam in raw.malware_families {
        ttp_refs.push(format!("malware:{fam}"));
    }
    for kc in raw.kill_chains {
        ttp_refs.push(format!("kill_chain:{kc}"));
    }
    for label in raw.labels {
        if let Some(name) = label.name {
            // Falcon labels are e.g. "MitreATTCK/T1059.001" — keep verbatim.
            ttp_refs.push(name);
        }
    }
    Some(EnrichedIndicator {
        kind,
        value,
        // Falcon does not return TLP per-indicator; default to Amber per
        // contractual default.
        tlp: Tlp::Amber,
        confidence,
        sources: vec![PROVIDER_ID.to_string()],
        first_seen,
        last_seen,
        ttp_refs,
    })
}

fn map_kind(kind: Option<&str>, value: &str) -> Option<IndicatorKind> {
    let raw = kind?.to_ascii_lowercase();
    match raw.as_str() {
        "ip_address" | "ipv4" => Some(IndicatorKind::Ipv4),
        "ipv6" => Some(IndicatorKind::Ipv6),
        "domain" => Some(IndicatorKind::Domain),
        "url" => Some(IndicatorKind::Url),
        "email_address" | "email" => Some(IndicatorKind::Email),
        "hash_md5" | "md5" => Some(IndicatorKind::FileHash(HashKind::Md5)),
        "hash_sha1" | "sha1" => Some(IndicatorKind::FileHash(HashKind::Sha1)),
        "hash_sha256" | "sha256" => Some(IndicatorKind::FileHash(HashKind::Sha256)),
        "host" => infer_host_kind(value),
        _ => None,
    }
}

fn map_confidence(raw: &str) -> Option<u8> {
    match raw.to_ascii_lowercase().as_str() {
        "high" => Some(90),
        "medium" => Some(60),
        "low" => Some(30),
        "unverified" => Some(10),
        _ => None,
    }
}

fn infer_host_kind(value: &str) -> Option<IndicatorKind> {
    if value.parse::<std::net::Ipv4Addr>().is_ok() {
        Some(IndicatorKind::Ipv4)
    } else if value.parse::<std::net::Ipv6Addr>().is_ok() {
        Some(IndicatorKind::Ipv6)
    } else if value.contains('.') {
        Some(IndicatorKind::Domain)
    } else {
        None
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
    use serde_json::json;
    use std::sync::atomic::{AtomicU32, Ordering};
    use wiremock::matchers::{body_string_contains, header, method, path, query_param};
    use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

    fn cfg_for(server: &MockServer) -> (CrowdStrikeConfig, Url) {
        let cfg = CrowdStrikeConfig {
            enabled: true,
            client_id: "cs-client".to_string(),
            client_secret: SecretString::new("cs-secret".to_string().into_boxed_str()),
            cloud: CrowdStrikeCloud::Us1,
        };
        let url = Url::parse(&server.uri()).unwrap();
        (cfg, url)
    }

    #[test]
    fn rejects_disabled_config() {
        let cfg = CrowdStrikeConfig {
            enabled: false,
            client_id: "id".to_string(),
            client_secret: SecretString::new("s".to_string().into_boxed_str()),
            cloud: CrowdStrikeCloud::Us1,
        };
        assert!(matches!(
            CrowdStrikeFeed::new(cfg).unwrap_err(),
            IntelError::Config(_)
        ));
    }

    #[test]
    fn rejects_empty_credentials() {
        let cfg = CrowdStrikeConfig {
            enabled: true,
            client_id: String::new(),
            client_secret: SecretString::new("s".to_string().into_boxed_str()),
            cloud: CrowdStrikeCloud::Us1,
        };
        assert!(matches!(
            CrowdStrikeFeed::new(cfg).unwrap_err(),
            IntelError::Config(_)
        ));
        let cfg = CrowdStrikeConfig {
            enabled: true,
            client_id: "id".to_string(),
            client_secret: SecretString::new(String::new().into_boxed_str()),
            cloud: CrowdStrikeCloud::Us1,
        };
        assert!(matches!(
            CrowdStrikeFeed::new(cfg).unwrap_err(),
            IntelError::Config(_)
        ));
    }

    #[test]
    fn cloud_base_urls_resolve() {
        assert!(CrowdStrikeCloud::Us1.base_url().contains("api.crowdstrike"));
        assert!(CrowdStrikeCloud::Us2.base_url().contains("us-2"));
        assert!(CrowdStrikeCloud::Eu1.base_url().contains("eu-1"));
    }

    #[tokio::test]
    async fn token_is_cached_across_multiple_fetches() {
        let server = MockServer::start().await;
        // Token endpoint should be hit exactly once.
        Mock::given(method("POST"))
            .and(path("/oauth2/token"))
            .and(body_string_contains("grant_type=client_credentials"))
            .and(body_string_contains("client_id=cs-client"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "tok-1",
                "expires_in": 1800,
                "token_type": "bearer"
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/intel/queries/indicators/v1"))
            .and(header("authorization", "Bearer tok-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "resources": [],
                "meta": {"pagination": {"offset": 0, "limit": 5000, "total": 0}}
            })))
            .expect(2)
            .mount(&server)
            .await;

        let (cfg, base) = cfg_for(&server);
        let feed = CrowdStrikeFeed::with_http_and_base(Client::new(), cfg, Some(base)).unwrap();
        let since = OffsetDateTime::UNIX_EPOCH;
        let _ = feed.fetch_since(since).await.unwrap();
        let _ = feed.fetch_since(since).await.unwrap();
    }

    #[tokio::test]
    async fn filter_param_uses_unix_epoch_of_since() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/oauth2/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "tok-1",
                "expires_in": 1800
            })))
            .mount(&server)
            .await;
        // 2024-06-01T00:00:00Z == 1717200000
        Mock::given(method("GET"))
            .and(path("/intel/queries/indicators/v1"))
            .and(query_param("filter", "last_updated:>1717200000"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "resources": [
                    {
                        "type": "domain",
                        "indicator": "evil.example",
                        "malicious_confidence": "high",
                        "published_date": 1_700_000_000_i64,
                        "last_updated": 1_717_200_000_i64,
                        "actors": ["FANCY_BEAR"],
                        "malware_families": ["x-loader"],
                        "labels": [{"name": "MitreATTCK/T1071.001"}]
                    }
                ],
                "meta": {"pagination": {"offset": 0, "limit": 5000, "total": 1}}
            })))
            .expect(1)
            .mount(&server)
            .await;
        let (cfg, base) = cfg_for(&server);
        let feed = CrowdStrikeFeed::with_http_and_base(Client::new(), cfg, Some(base)).unwrap();
        let since = OffsetDateTime::from_unix_timestamp(1_717_200_000).unwrap();
        let inds = feed.fetch_since(since).await.unwrap();
        assert_eq!(inds.len(), 1);
        assert_eq!(inds[0].kind, IndicatorKind::Domain);
        assert_eq!(inds[0].value, "evil.example");
        assert_eq!(inds[0].confidence, Some(90));
        assert!(inds[0].ttp_refs.iter().any(|t| t == "MitreATTCK/T1071.001"));
        assert!(inds[0].ttp_refs.iter().any(|t| t == "actor:FANCY_BEAR"));
    }

    /// Custom responder that returns 401 on the first GET and 200
    /// thereafter — exercises the single-retry-after-refresh path.
    struct FlakyAuth {
        gets: AtomicU32,
        ok_body: serde_json::Value,
    }

    impl Respond for FlakyAuth {
        fn respond(&self, _req: &Request) -> ResponseTemplate {
            let n = self.gets.fetch_add(1, Ordering::SeqCst);
            if n == 0 {
                ResponseTemplate::new(401)
            } else {
                ResponseTemplate::new(200).set_body_json(self.ok_body.clone())
            }
        }
    }

    #[tokio::test]
    async fn fetch_retries_once_after_401_with_fresh_token() {
        let server = MockServer::start().await;
        // Two token mints: initial + post-401 refresh.
        Mock::given(method("POST"))
            .and(path("/oauth2/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "tok-fresh",
                "expires_in": 1800
            })))
            .expect(2)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/intel/queries/indicators/v1"))
            .respond_with(FlakyAuth {
                gets: AtomicU32::new(0),
                ok_body: json!({
                    "resources": [],
                    "meta": {"pagination": {"offset": 0, "limit": 5000, "total": 0}}
                }),
            })
            .expect(2)
            .mount(&server)
            .await;

        let (cfg, base) = cfg_for(&server);
        let feed = CrowdStrikeFeed::with_http_and_base(Client::new(), cfg, Some(base)).unwrap();
        let inds = feed.fetch_since(OffsetDateTime::UNIX_EPOCH).await.unwrap();
        assert!(inds.is_empty());
    }

    #[tokio::test]
    async fn decode_error_path_surfaces_decode_variant() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/oauth2/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "tok-1",
                "expires_in": 1800
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/intel/queries/indicators/v1"))
            .respond_with(ResponseTemplate::new(200).set_body_string("not json at all"))
            .mount(&server)
            .await;

        let (cfg, base) = cfg_for(&server);
        let feed = CrowdStrikeFeed::with_http_and_base(Client::new(), cfg, Some(base)).unwrap();
        let err = feed
            .fetch_since(OffsetDateTime::UNIX_EPOCH)
            .await
            .unwrap_err();
        match err {
            IntelError::Decode { vendor, .. } => assert_eq!(vendor, PROVIDER_ID),
            other => panic!("expected Decode, got {other:?}"),
        }
    }
}
