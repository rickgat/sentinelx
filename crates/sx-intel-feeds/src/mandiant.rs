//! Mandiant Advantage Threat Intelligence adapter.
//!
//! Implements [`crate::commercial::CommercialIntelFeed`] against the
//! Mandiant v4 indicator API. The adapter is intentionally schema-light:
//! we extract the documented fields we promise downstream
//! ([`EnrichedIndicator`]) and ignore everything else, so vendor schema
//! drift does not break ingestion.
//!
//! ## Auth modes
//!
//! Two flavours are supported via [`MandiantAuth`]:
//!
//! * [`MandiantAuth::ApiKey`] — legacy single-header auth (`X-Auth-Token`
//!   + `X-App-Name`) for tenants still on the FireEye-era keys.
//! * [`MandiantAuth::OAuth2`] — current Mandiant Advantage `OAuth2`
//!   client-credentials flow against
//!   `POST /token` (form-encoded `grant_type=client_credentials` with
//!   `Authorization: Basic <base64(client_id:client_secret)>`). Tokens are
//!   cached in-memory until ~5 minutes before expiry; a 401 on the
//!   indicator endpoint triggers exactly one refresh-and-retry.
//!
//! Both modes route through the same [`CommercialIntelFeed::fetch_since`]
//! surface and produce identical [`EnrichedIndicator`] output.
//!
//! ## Endpoint
//!
//! `GET {base_url}/v4/indicator?last_modified_since={iso8601}` with
//! optional `next` cursor for pagination. The API may surface the cursor
//! either as a `next` field in the JSON envelope or as a separate
//! pagination block — we accept both shapes.
//!
//! ## Opt-in
//!
//! [`MandiantFeed::new`] returns [`IntelError::Config`] if `enabled` is
//! false or credentials are missing. Callers must therefore explicitly
//! opt-in per tenant before any network traffic is issued.

use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::{Client, StatusCode};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tokio::sync::Mutex;
use tracing::{debug, warn};
use url::Url;

use crate::commercial::{CommercialIntelFeed, EnrichedIndicator, IntelError, Tlp};
use crate::indicator::{HashKind, IndicatorKind};

/// Stable provider tag for metrics, source attribution, and error
/// surfaces.
pub const PROVIDER_ID: &str = "mandiant";

const DEFAULT_BASE_URL: &str = "https://api.intelligence.mandiant.com";
/// Legacy FireEye-era base URL. Exposed for tenants migrating their old
/// API keys without changing endpoints simultaneously; not used by the
/// default config.
pub const LEGACY_FIREEYE_BASE_URL: &str = "https://api.intelligence.fireeye.com";
const APP_NAME: &str = "sentinelx";
/// Defensive cap on pagination — Mandiant occasionally returns cursors
/// that point back at themselves; this prevents infinite loops.
const MAX_PAGES: u32 = 500;
/// Token lifetime we honour for `OAuth2` caching. Mandiant Advantage
/// returns ~14 400 s (4 h) tokens; we cache for slightly less to leave a
/// refresh margin and survive small clock skew.
const OAUTH_TOKEN_CACHE_TTL: Duration = Duration::from_secs(60 * 60 * 3);

/// How [`MandiantFeed`] authenticates against the Mandiant API.
#[derive(Debug, Clone)]
pub enum MandiantAuth {
    /// Legacy `X-Auth-Token` API-key auth (FireEye-era tenants).
    ApiKey {
        /// The API key. Wrapped in [`SecretString`] so it is never
        /// `Debug`-printed or `Display`-logged.
        api_key: SecretString,
    },
    /// `OAuth2` client-credentials flow against `POST /token`.
    OAuth2 {
        /// `OAuth2` client id (issued by Mandiant Advantage).
        client_id: String,
        /// `OAuth2` client secret. Wrapped in [`SecretString`].
        client_secret: SecretString,
    },
}

impl MandiantAuth {
    fn validate(&self) -> Result<(), IntelError> {
        match self {
            Self::ApiKey { api_key } => {
                if api_key.expose_secret().is_empty() {
                    return Err(IntelError::Config(
                        "mandiant.api_key must be non-empty".to_string(),
                    ));
                }
            }
            Self::OAuth2 {
                client_id,
                client_secret,
            } => {
                if client_id.trim().is_empty() {
                    return Err(IntelError::Config(
                        "mandiant.client_id must be non-empty".to_string(),
                    ));
                }
                if client_secret.expose_secret().is_empty() {
                    return Err(IntelError::Config(
                        "mandiant.client_secret must be non-empty".to_string(),
                    ));
                }
            }
        }
        Ok(())
    }
}

/// Configuration for [`MandiantFeed`]. Per-tenant; never persisted with
/// credential material in plaintext (caller must encrypt at rest, e.g.
/// via `sx-secrets`).
#[derive(Debug, Clone)]
pub struct MandiantConfig {
    /// Whether the adapter is enabled for this tenant. Must be `true`
    /// for [`MandiantFeed::new`] to succeed.
    pub enabled: bool,
    /// Authentication mode.
    pub auth: MandiantAuth,
    /// Override base URL. Defaults to
    /// `https://api.intelligence.mandiant.com`. Tests inject the
    /// `wiremock` server URL here.
    pub base_url: String,
}

impl MandiantConfig {
    /// Construct an API-key config. Convenience for callers migrating off
    /// the legacy FireEye-era keys.
    #[must_use]
    pub fn api_key(api_key: SecretString) -> Self {
        Self {
            enabled: true,
            auth: MandiantAuth::ApiKey { api_key },
            base_url: DEFAULT_BASE_URL.to_string(),
        }
    }

    /// Construct an `OAuth2` client-credentials config.
    #[must_use]
    pub fn oauth2(client_id: impl Into<String>, client_secret: SecretString) -> Self {
        Self {
            enabled: true,
            auth: MandiantAuth::OAuth2 {
                client_id: client_id.into(),
                client_secret,
            },
            base_url: DEFAULT_BASE_URL.to_string(),
        }
    }
}

impl Default for MandiantConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            auth: MandiantAuth::ApiKey {
                api_key: SecretString::new(String::new().into_boxed_str()),
            },
            base_url: DEFAULT_BASE_URL.to_string(),
        }
    }
}

#[derive(Debug)]
struct CachedOAuthToken {
    bearer: SecretString,
    expires_at: Instant,
}

/// Mandiant indicator-feed adapter.
///
/// Construct via [`MandiantFeed::new`] (which validates the config) or
/// [`MandiantFeed::with_http`] (tests). Cheap to clone — interior
/// `Arc`-shaped state shares the OAuth token cache across clones.
#[derive(Debug, Clone)]
pub struct MandiantFeed {
    http: Client,
    base_url: Url,
    auth: MandiantAuth,
    oauth_token: Arc<Mutex<Option<CachedOAuthToken>>>,
}

impl MandiantFeed {
    /// Build a feed against the configured (or default) base URL using a
    /// fresh `reqwest::Client`.
    pub fn new(cfg: MandiantConfig) -> Result<Self, IntelError> {
        Self::with_http(Client::new(), cfg)
    }

    /// Build a feed using a caller-supplied HTTP client. Used by tests
    /// against a `wiremock::MockServer` URL.
    pub fn with_http(http: Client, cfg: MandiantConfig) -> Result<Self, IntelError> {
        if !cfg.enabled {
            return Err(IntelError::Config(
                "mandiant.enabled must be true".to_string(),
            ));
        }
        cfg.auth.validate()?;
        let base_str = if cfg.base_url.is_empty() {
            DEFAULT_BASE_URL.to_string()
        } else {
            cfg.base_url
        };
        let base_url =
            Url::parse(&base_str).map_err(|e| IntelError::Url(format!("base_url: {e}")))?;
        Ok(Self {
            http,
            base_url,
            auth: cfg.auth,
            oauth_token: Arc::new(Mutex::new(None)),
        })
    }

    async fn auth_headers(&self) -> Result<HeaderMap, IntelError> {
        let mut headers = HeaderMap::new();
        match &self.auth {
            MandiantAuth::ApiKey { api_key } => {
                let mut token = HeaderValue::from_str(api_key.expose_secret()).map_err(|_| {
                    IntelError::Config("mandiant.api_key contains invalid header bytes".to_string())
                })?;
                token.set_sensitive(true);
                headers.insert("X-Auth-Token", token);
                headers.insert("X-App-Name", HeaderValue::from_static(APP_NAME));
            }
            MandiantAuth::OAuth2 { .. } => {
                let bearer = self.cached_or_fresh_token().await?;
                let val = format!("Bearer {}", bearer.expose_secret());
                let mut hv = HeaderValue::from_str(&val).map_err(|_| {
                    IntelError::Config("mandiant bearer contains invalid header bytes".to_string())
                })?;
                hv.set_sensitive(true);
                headers.insert(reqwest::header::AUTHORIZATION, hv);
                headers.insert("X-App-Name", HeaderValue::from_static(APP_NAME));
            }
        }
        headers.insert(
            reqwest::header::ACCEPT,
            HeaderValue::from_static("application/json"),
        );
        Ok(headers)
    }

    async fn cached_or_fresh_token(&self) -> Result<SecretString, IntelError> {
        {
            let guard = self.oauth_token.lock().await;
            if let Some(cached) = guard.as_ref() {
                if cached.expires_at > Instant::now() {
                    return Ok(SecretString::new(
                        cached.bearer.expose_secret().to_string().into_boxed_str(),
                    ));
                }
            }
        }
        self.refresh_oauth_token().await
    }

    async fn refresh_oauth_token(&self) -> Result<SecretString, IntelError> {
        let MandiantAuth::OAuth2 {
            client_id,
            client_secret,
        } = &self.auth
        else {
            return Err(IntelError::Config(
                "mandiant: refresh_oauth_token invoked on non-OAuth2 auth".to_string(),
            ));
        };
        let url = self
            .base_url
            .join("/token")
            .map_err(|e| IntelError::Url(format!("/token: {e}")))?;
        let creds = format!("{}:{}", client_id, client_secret.expose_secret());
        let basic = BASE64.encode(creds);
        debug!(
            target: "sx_intel_feeds::mandiant",
            vendor = PROVIDER_ID,
            "requesting fresh oauth2 token",
        );
        let resp = self
            .http
            .post(url)
            .header(reqwest::header::AUTHORIZATION, format!("Basic {basic}"))
            .header(
                reqwest::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .header(reqwest::header::ACCEPT, "application/json")
            .body("grant_type=client_credentials")
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
        let ttl = body.expires_in.map_or(OAUTH_TOKEN_CACHE_TTL, |s| {
            Duration::from_secs(s.saturating_sub(300))
        });
        {
            let mut guard = self.oauth_token.lock().await;
            *guard = Some(CachedOAuthToken {
                bearer: SecretString::new(body.access_token.into_boxed_str()),
                expires_at: Instant::now() + ttl,
            });
        }
        Ok(bearer)
    }

    async fn invalidate_oauth_token(&self) {
        let mut guard = self.oauth_token.lock().await;
        *guard = None;
    }

    /// Returns `true` when this feed is configured for `OAuth2` client
    /// credentials (and therefore supports refresh-on-401 retry). Used by
    /// the fetch loop to decide whether to retry after a 401.
    const fn uses_oauth(&self) -> bool {
        matches!(self.auth, MandiantAuth::OAuth2 { .. })
    }

    fn build_url(&self, since: OffsetDateTime, next: Option<&str>) -> Result<Url, IntelError> {
        let mut url = self
            .base_url
            .join("/v4/indicator")
            .map_err(|e| IntelError::Url(format!("indicator path: {e}")))?;
        let since_iso = since
            .format(&Rfc3339)
            .map_err(|e| IntelError::Config(format!("since timestamp format: {e}")))?;
        {
            let mut q = url.query_pairs_mut();
            q.append_pair("last_modified_since", &since_iso);
            if let Some(cursor) = next {
                q.append_pair("next", cursor);
            }
        }
        Ok(url)
    }
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    #[serde(default)]
    access_token: String,
    #[serde(default)]
    expires_in: Option<u64>,
    #[serde(default)]
    #[allow(dead_code)]
    token_type: Option<String>,
}

/// Wire envelope. Mandiant returns an `indicators` array plus a `next`
/// cursor either at the top level or inside a `pagination` block — we
/// accept both shapes via two optional fields.
#[derive(Debug, Deserialize, Default)]
struct IndicatorEnvelope {
    #[serde(default)]
    indicators: Vec<RawIndicator>,
    #[serde(default)]
    next: Option<String>,
    #[serde(default)]
    pagination: Option<PaginationBlock>,
}

#[derive(Debug, Deserialize, Default)]
struct PaginationBlock {
    #[serde(default)]
    next: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct RawIndicator {
    #[serde(default, rename = "type")]
    kind: Option<String>,
    #[serde(default)]
    value: Option<String>,
    #[serde(default)]
    confidence: Option<u8>,
    #[serde(default)]
    tlp: Option<String>,
    #[serde(default)]
    first_seen: Option<String>,
    #[serde(default)]
    last_seen: Option<String>,
    #[serde(default)]
    last_updated: Option<String>,
    #[serde(default)]
    attributed_associations: Vec<Association>,
    #[serde(default)]
    mitre_attack_techniques: Vec<MitreTechnique>,
}

#[derive(Debug, Deserialize, Default)]
struct Association {
    #[serde(default, rename = "type")]
    kind: Option<String>,
    #[serde(default)]
    name: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct MitreTechnique {
    #[serde(default)]
    id: Option<String>,
}

#[async_trait]
impl CommercialIntelFeed for MandiantFeed {
    fn provider_id(&self) -> &'static str {
        PROVIDER_ID
    }

    async fn fetch_since(
        &self,
        since: OffsetDateTime,
    ) -> Result<Vec<EnrichedIndicator>, IntelError> {
        let mut out = Vec::new();
        let mut cursor: Option<String> = None;
        let mut retried_auth = false;
        for _ in 0..MAX_PAGES {
            let url = self.build_url(since, cursor.as_deref())?;
            let headers = self.auth_headers().await?;
            debug!(
                target: "sx_intel_feeds::mandiant",
                vendor = PROVIDER_ID,
                "fetching indicator page",
            );
            let resp = self
                .http
                .get(url)
                .headers(headers)
                .send()
                .await
                .map_err(IntelError::Http)?;
            let status = resp.status();
            if status == StatusCode::UNAUTHORIZED && self.uses_oauth() && !retried_auth {
                debug!(
                    target: "sx_intel_feeds::mandiant",
                    vendor = PROVIDER_ID,
                    "401 received; refreshing oauth2 token and retrying once",
                );
                self.invalidate_oauth_token().await;
                self.refresh_oauth_token().await?;
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
            // Reset retry flag on success — token may expire later in a
            // long paginated walk, give it one more refresh attempt.
            retried_auth = false;
            let envelope: IndicatorEnvelope = resp
                .json()
                .await
                .map_err(|e| IntelError::decode(PROVIDER_ID, e))?;
            for raw in envelope.indicators {
                match map_indicator(raw) {
                    Some(ind) => out.push(ind),
                    None => {
                        // Skip silently — schema-light approach lets us
                        // tolerate vendor drift without aborting the
                        // whole fetch.
                        warn!(
                            target: "sx_intel_feeds::mandiant",
                            vendor = PROVIDER_ID,
                            "skipping unrecognised indicator shape",
                        );
                    }
                }
            }
            let next_cursor = envelope
                .next
                .or_else(|| envelope.pagination.and_then(|p| p.next));
            match next_cursor {
                Some(c) if !c.is_empty() => cursor = Some(c),
                _ => return Ok(out),
            }
        }
        warn!(
            target: "sx_intel_feeds::mandiant",
            vendor = PROVIDER_ID,
            max_pages = MAX_PAGES,
            "pagination loop ceiling hit; returning accumulated indicators",
        );
        Ok(out)
    }
}

fn map_indicator(raw: RawIndicator) -> Option<EnrichedIndicator> {
    let value = raw.value?;
    let kind = map_kind(raw.kind.as_deref(), &value)?;
    let tlp = raw.tlp.as_deref().map_or(Tlp::Amber, Tlp::parse_lenient);
    let first_seen = parse_ts(raw.first_seen.as_deref()).unwrap_or_else(epoch);
    let last_seen = parse_ts(raw.last_seen.as_deref())
        .or_else(|| parse_ts(raw.last_updated.as_deref()))
        .unwrap_or(first_seen);
    let mut ttp_refs = Vec::new();
    for t in raw.mitre_attack_techniques {
        if let Some(id) = t.id {
            ttp_refs.push(id);
        }
    }
    for a in raw.attributed_associations {
        if let (Some(name), Some(kind)) = (a.name, a.kind) {
            // Capture e.g. "threat-actor:FIN7" verbatim.
            ttp_refs.push(format!("{kind}:{name}"));
        }
    }
    Some(EnrichedIndicator {
        kind,
        value,
        tlp,
        confidence: raw.confidence,
        sources: vec![PROVIDER_ID.to_string()],
        first_seen,
        last_seen,
        ttp_refs,
    })
}

fn map_kind(kind: Option<&str>, value: &str) -> Option<IndicatorKind> {
    let raw = kind?.to_ascii_lowercase();
    match raw.as_str() {
        "ipv4" | "ipv4-addr" => Some(IndicatorKind::Ipv4),
        "ipv6" | "ipv6-addr" => Some(IndicatorKind::Ipv6),
        "fqdn" | "domain" | "domain-name" => Some(IndicatorKind::Domain),
        "url" => Some(IndicatorKind::Url),
        "email" | "email-addr" => Some(IndicatorKind::Email),
        "md5" => Some(IndicatorKind::FileHash(HashKind::Md5)),
        "sha1" | "sha-1" => Some(IndicatorKind::FileHash(HashKind::Sha1)),
        "sha256" | "sha-256" => Some(IndicatorKind::FileHash(HashKind::Sha256)),
        "fqdn-or-ip" | "host" => infer_host_kind(value),
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

fn parse_ts(raw: Option<&str>) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(raw?, &Rfc3339).ok()
}

const fn epoch() -> OffsetDateTime {
    OffsetDateTime::UNIX_EPOCH
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
    use wiremock::matchers::{header, method, path, query_param, query_param_is_missing};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn cfg_for(server: &MockServer) -> MandiantConfig {
        MandiantConfig {
            enabled: true,
            auth: MandiantAuth::ApiKey {
                api_key: SecretString::new("super-secret-mandiant".to_string().into_boxed_str()),
            },
            base_url: server.uri(),
        }
    }

    fn oauth_cfg_for(server: &MockServer) -> MandiantConfig {
        MandiantConfig {
            enabled: true,
            auth: MandiantAuth::OAuth2 {
                client_id: "mand-client".to_string(),
                client_secret: SecretString::new("mand-secret".to_string().into_boxed_str()),
            },
            base_url: server.uri(),
        }
    }

    #[test]
    fn rejects_disabled_config() {
        let cfg = MandiantConfig {
            enabled: false,
            auth: MandiantAuth::ApiKey {
                api_key: SecretString::new("k".to_string().into_boxed_str()),
            },
            base_url: DEFAULT_BASE_URL.to_string(),
        };
        let err = MandiantFeed::new(cfg).unwrap_err();
        assert!(matches!(err, IntelError::Config(_)));
    }

    #[test]
    fn rejects_empty_api_key() {
        let cfg = MandiantConfig {
            enabled: true,
            auth: MandiantAuth::ApiKey {
                api_key: SecretString::new(String::new().into_boxed_str()),
            },
            base_url: DEFAULT_BASE_URL.to_string(),
        };
        let err = MandiantFeed::new(cfg).unwrap_err();
        assert!(matches!(err, IntelError::Config(_)));
    }

    #[test]
    fn rejects_empty_oauth_credentials() {
        let cfg = MandiantConfig {
            enabled: true,
            auth: MandiantAuth::OAuth2 {
                client_id: String::new(),
                client_secret: SecretString::new("s".to_string().into_boxed_str()),
            },
            base_url: DEFAULT_BASE_URL.to_string(),
        };
        assert!(matches!(
            MandiantFeed::new(cfg).unwrap_err(),
            IntelError::Config(_)
        ));
        let cfg = MandiantConfig {
            enabled: true,
            auth: MandiantAuth::OAuth2 {
                client_id: "id".to_string(),
                client_secret: SecretString::new(String::new().into_boxed_str()),
            },
            base_url: DEFAULT_BASE_URL.to_string(),
        };
        assert!(matches!(
            MandiantFeed::new(cfg).unwrap_err(),
            IntelError::Config(_)
        ));
    }

    #[tokio::test]
    async fn fetch_since_sends_auth_headers() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v4/indicator"))
            .and(header("X-Auth-Token", "super-secret-mandiant"))
            .and(header("X-App-Name", APP_NAME))
            .and(query_param("last_modified_since", "2024-06-01T00:00:00Z"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "indicators": [
                    {
                        "type": "fqdn",
                        "value": "evil.example",
                        "confidence": 80,
                        "tlp": "amber",
                        "first_seen": "2024-05-01T00:00:00Z",
                        "last_seen": "2024-06-01T00:00:00Z",
                        "mitre_attack_techniques": [{"id": "T1071.001"}]
                    }
                ]
            })))
            .expect(1)
            .mount(&server)
            .await;

        let feed = MandiantFeed::with_http(Client::new(), cfg_for(&server)).unwrap();
        let since = OffsetDateTime::parse("2024-06-01T00:00:00Z", &Rfc3339).unwrap();
        let inds = feed.fetch_since(since).await.unwrap();
        assert_eq!(inds.len(), 1);
        assert_eq!(inds[0].kind, IndicatorKind::Domain);
        assert_eq!(inds[0].value, "evil.example");
        assert_eq!(inds[0].tlp, Tlp::Amber);
        assert_eq!(inds[0].confidence, Some(80));
        assert_eq!(inds[0].sources, vec!["mandiant".to_string()]);
        assert!(inds[0].ttp_refs.contains(&"T1071.001".to_string()));
    }

    #[tokio::test]
    async fn fetch_since_paginates() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v4/indicator"))
            .and(query_param_is_missing("next"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "indicators": [
                    {
                        "type": "ipv4",
                        "value": "198.51.100.7",
                        "confidence": 60
                    }
                ],
                "next": "cursor-2"
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v4/indicator"))
            .and(query_param("next", "cursor-2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "indicators": [
                    {
                        "type": "sha256",
                        "value": "a".repeat(64),
                        "confidence": 90
                    }
                ]
            })))
            .expect(1)
            .mount(&server)
            .await;

        let feed = MandiantFeed::with_http(Client::new(), cfg_for(&server)).unwrap();
        let since = OffsetDateTime::UNIX_EPOCH;
        let inds = feed.fetch_since(since).await.unwrap();
        assert_eq!(inds.len(), 2);
        assert_eq!(inds[0].kind, IndicatorKind::Ipv4);
        assert_eq!(inds[1].kind, IndicatorKind::FileHash(HashKind::Sha256));
    }

    #[tokio::test]
    async fn fetch_since_surfaces_decode_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v4/indicator"))
            .respond_with(ResponseTemplate::new(200).set_body_string("definitely not json"))
            .mount(&server)
            .await;
        let feed = MandiantFeed::with_http(Client::new(), cfg_for(&server)).unwrap();
        let err = feed
            .fetch_since(OffsetDateTime::UNIX_EPOCH)
            .await
            .unwrap_err();
        match err {
            IntelError::Decode { vendor, .. } => assert_eq!(vendor, PROVIDER_ID),
            other => panic!("expected Decode, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn fetch_since_401_maps_to_unauthorized() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v4/indicator"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&server)
            .await;
        let feed = MandiantFeed::with_http(Client::new(), cfg_for(&server)).unwrap();
        let err = feed
            .fetch_since(OffsetDateTime::UNIX_EPOCH)
            .await
            .unwrap_err();
        assert!(matches!(err, IntelError::Unauthorized { vendor } if vendor == PROVIDER_ID));
    }

    #[tokio::test]
    async fn oauth2_fetch_caches_token_across_pages() {
        let server = MockServer::start().await;
        // Expected client_credentials body + HTTP Basic header. We do not
        // assert the exact base64 here because reqwest already escapes it.
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "mand-tok-1",
                "expires_in": 14400,
                "token_type": "bearer"
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v4/indicator"))
            .and(header("authorization", "Bearer mand-tok-1"))
            .and(header("X-App-Name", APP_NAME))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "indicators": [
                    {
                        "type": "ipv4",
                        "value": "203.0.113.7",
                        "confidence": 70
                    }
                ]
            })))
            .expect(2)
            .mount(&server)
            .await;

        let feed = MandiantFeed::with_http(Client::new(), oauth_cfg_for(&server)).unwrap();
        let since = OffsetDateTime::UNIX_EPOCH;
        let inds = feed.fetch_since(since).await.unwrap();
        assert_eq!(inds.len(), 1);
        // Second call must reuse the cached token — token endpoint still
        // only hit once.
        let inds2 = feed.fetch_since(since).await.unwrap();
        assert_eq!(inds2.len(), 1);
    }

    /// First GET to indicator returns 401, then a subsequent token-refresh
    /// happens and the retry succeeds. Exercises the OAuth `retried_auth`
    /// path.
    #[tokio::test]
    async fn oauth2_refreshes_on_401_and_retries_once() {
        use std::sync::atomic::{AtomicU32, Ordering};
        use wiremock::{Request, Respond};

        struct FlakyOAuth {
            gets: AtomicU32,
        }
        impl Respond for FlakyOAuth {
            fn respond(&self, _req: &Request) -> ResponseTemplate {
                let n = self.gets.fetch_add(1, Ordering::SeqCst);
                if n == 0 {
                    ResponseTemplate::new(401)
                } else {
                    ResponseTemplate::new(200).set_body_json(json!({
                        "indicators": [
                            {"type": "ipv4", "value": "198.51.100.7", "confidence": 50}
                        ]
                    }))
                }
            }
        }

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "mand-tok-fresh",
                "expires_in": 14400
            })))
            .expect(2)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v4/indicator"))
            .respond_with(FlakyOAuth {
                gets: AtomicU32::new(0),
            })
            .expect(2)
            .mount(&server)
            .await;

        let feed = MandiantFeed::with_http(Client::new(), oauth_cfg_for(&server)).unwrap();
        let inds = feed.fetch_since(OffsetDateTime::UNIX_EPOCH).await.unwrap();
        assert_eq!(inds.len(), 1);
    }

    #[test]
    fn legacy_fireeye_base_url_constant_is_exposed() {
        // Sanity check the legacy constant is reachable so callers
        // migrating off the FireEye keys can opt into it explicitly.
        assert!(LEGACY_FIREEYE_BASE_URL.contains("fireeye"));
    }
}
