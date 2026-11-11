//! Minimal TAXII 2.1 client (P0-001 MVP slice).
//!
//! This module exposes only the *core* client primitives the upcoming feed
//! orchestrator will call into:
//!
//! 1. [`TaxiiClient::discover`] — `GET {base}/taxii2/`, returns
//!    [`TaxiiDiscovery`] (server metadata + API roots).
//! 2. [`TaxiiClient::list_collections`] — `GET {api_root}/api/v21/collections/`,
//!    returns one page of [`TaxiiCollection`] entries.
//! 3. [`TaxiiClient::get_objects`] — `GET {api_root}/api/v21/collections/{id}/objects/`
//!    with optional `added_after` query parameter, returns one page of
//!    raw STIX [`TaxiiObjects`] (objects + pagination cursors).
//!
//! ## Out of scope (this slice)
//!
//! Feed orchestration, indicator persistence, tenant context propagation,
//! multi-page streaming, and monolith adapter wiring intentionally do
//! **not** live here — they land in the next Phase-2 slice.
//!
//! ## Auth
//!
//! Authentication is optional bearer token. When supplied it is wrapped in
//! [`secrecy::SecretString`], emitted as `Authorization: Bearer …` on every
//! request, and never logged — `set_sensitive(true)` is asserted on the
//! header value so `reqwest`'s tracing redacts it.
//!
//! ## Rate limiting
//!
//! On HTTP `429 Too Many Requests` the client parses the `Retry-After`
//! response header and surfaces [`TaxiiError::Backoff`] carrying the
//! resolved [`std::time::Duration`] so the caller decides whether to sleep
//! and retry. The client itself does *not* sleep or retry.

use std::sync::Arc;
use std::time::Duration;

use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, AUTHORIZATION, RETRY_AFTER};
use reqwest::{Client, StatusCode};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use thiserror::Error;
use tracing::debug;
use url::Url;

/// TAXII 2.1 media type advertised on `Accept` and required by the spec.
const TAXII_MEDIA_TYPE: &str = "application/taxii+json;version=2.1";

/// Default fallback when a `429` response omits a parseable `Retry-After`.
const DEFAULT_BACKOFF: Duration = Duration::from_secs(1);

/// Errors surfaced by [`TaxiiClient`] operations.
#[derive(Debug, Error)]
pub enum TaxiiError {
    /// Transport-layer failure (DNS, TLS, timeout, connection reset, …).
    #[error("TAXII network error: {0}")]
    Network(#[source] reqwest::Error),
    /// Response body could not be decoded as the expected JSON shape.
    #[error("TAXII decode error: {0}")]
    Decode(#[source] serde_json::Error),
    /// Server returned a non-2xx, non-429 status. The 429 case is reported
    /// separately as [`TaxiiError::Backoff`].
    #[error("TAXII server returned status {status}")]
    BadResponse {
        /// HTTP status code returned by the server.
        status: StatusCode,
    },
    /// Server returned `429 Too Many Requests`. Carries the duration the
    /// caller should wait before retrying, parsed from `Retry-After` (or a
    /// safe default when the header is absent / unparseable).
    #[error("TAXII rate-limited, retry after {0:?}")]
    Backoff(Duration),
    /// The supplied base URL or computed path could not be parsed.
    #[error("TAXII URL error: {0}")]
    Url(#[from] url::ParseError),
}

/// Discovery document returned by `GET /taxii2/`.
///
/// Mirrors the TAXII 2.1 spec ¶4.1 fields. All fields default to empty so
/// that minor server-side omissions do not break clients.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct TaxiiDiscovery {
    /// Human-readable title of the TAXII server.
    #[serde(default)]
    pub title: String,
    /// Optional long-form description.
    #[serde(default)]
    pub description: Option<String>,
    /// Optional contact information (free-form, may be an email or URL).
    #[serde(default)]
    pub contact: Option<String>,
    /// The default API root URL, when the server advertises one.
    #[serde(default)]
    pub default: Option<String>,
    /// All API root URLs the server exposes.
    #[serde(default)]
    pub api_roots: Vec<String>,
}

/// A single TAXII 2.1 collection descriptor.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct TaxiiCollection {
    /// Collection identifier (typically a UUID).
    pub id: String,
    /// Human-readable title.
    #[serde(default)]
    pub title: String,
    /// Optional collection description.
    #[serde(default)]
    pub description: Option<String>,
    /// Whether the caller may read objects from this collection.
    #[serde(default)]
    pub can_read: bool,
    /// Whether the caller may push objects into this collection.
    #[serde(default)]
    pub can_write: bool,
    /// Media types this collection accepts/produces.
    #[serde(default)]
    pub media_types: Vec<String>,
}

/// A single page of STIX objects from a TAXII collection.
///
/// Pagination state is carried inline: when [`Self::more`] is `true`, the
/// caller should re-issue [`TaxiiClient::get_objects`] passing
/// [`Self::next`] as a future cursor (cursor support is wired up in the
/// next slice — this MVP exposes the values verbatim).
#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Default)]
pub struct TaxiiObjects {
    /// Raw STIX 2.1 SDOs / SROs verbatim from the server. Decoding into
    /// concrete `Indicator`s is the parser's job, not this client's.
    #[serde(default)]
    pub objects: Vec<serde_json::Value>,
    /// `true` when more pages are available.
    #[serde(default)]
    pub more: bool,
    /// Opaque pagination cursor (when `more=true`).
    #[serde(default)]
    pub next: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CollectionsEnvelope {
    #[serde(default)]
    collections: Vec<TaxiiCollection>,
}

/// TAXII 2.1 client core.
///
/// Cheap to clone — holds a `reqwest::Client` (itself an `Arc` internally),
/// a parsed base URL, and an optional [`SecretString`] bearer token wrapped
/// in [`Arc`] for cheap propagation across tasks.
#[derive(Debug, Clone)]
pub struct TaxiiClient {
    http: Client,
    base_url: Url,
    bearer: Option<Arc<SecretString>>,
}

impl TaxiiClient {
    /// Construct a new TAXII client.
    ///
    /// `base_url` is the TAXII server origin (e.g. `https://taxii.example/`);
    /// the trailing slash is enforced internally so callers can supply
    /// either form. `bearer` is optional — anonymous TAXII servers exist
    /// and the spec only mandates auth when the server requires it.
    pub fn new(http: Client, base_url: Url, bearer: Option<SecretString>) -> Self {
        let mut base_url = base_url;
        ensure_trailing_slash(&mut base_url);
        Self {
            http,
            base_url,
            bearer: bearer.map(Arc::new),
        }
    }

    fn auth_headers(&self) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(ACCEPT, HeaderValue::from_static(TAXII_MEDIA_TYPE));
        if let Some(token) = &self.bearer {
            let raw = format!("Bearer {}", token.expose_secret());
            if let Ok(mut v) = HeaderValue::from_str(&raw) {
                v.set_sensitive(true);
                headers.insert(AUTHORIZATION, v);
            }
        }
        headers
    }

    /// Fetch the TAXII discovery document from `{base}/taxii2/`.
    pub async fn discover(&self) -> Result<TaxiiDiscovery, TaxiiError> {
        let url = self.base_url.join("taxii2/")?;
        debug!(%url, "TAXII discover");
        let resp = self
            .http
            .get(url)
            .headers(self.auth_headers())
            .send()
            .await
            .map_err(TaxiiError::Network)?;
        let bytes = ensure_ok(resp).await?;
        serde_json::from_slice(&bytes).map_err(TaxiiError::Decode)
    }

    /// List collections under the given API root.
    ///
    /// `api_root` must be an absolute URL — one of the values returned by
    /// [`TaxiiDiscovery::api_roots`] or [`TaxiiDiscovery::default`].
    ///
    /// Returns *one* page of collections. Pagination is intentionally not
    /// followed by this MVP — that lands in the orchestrator slice.
    pub async fn list_collections(
        &self,
        api_root: &str,
    ) -> Result<Vec<TaxiiCollection>, TaxiiError> {
        let url = build_collections_url(api_root)?;
        debug!(%url, "TAXII list_collections");
        let resp = self
            .http
            .get(url)
            .headers(self.auth_headers())
            .send()
            .await
            .map_err(TaxiiError::Network)?;
        let bytes = ensure_ok(resp).await?;
        let env: CollectionsEnvelope =
            serde_json::from_slice(&bytes).map_err(TaxiiError::Decode)?;
        Ok(env.collections)
    }

    /// Fetch one page of STIX objects from `{api_root}/api/v21/collections/{id}/objects/`.
    ///
    /// `since`, when set, is forwarded verbatim as the `added_after` query
    /// parameter — TAXII expects RFC 3339 / ISO 8601, and the caller owns
    /// formatting (so we do not depend on a `time` formatter here).
    pub async fn get_objects(
        &self,
        api_root: &str,
        collection_id: &str,
        since: Option<&str>,
    ) -> Result<TaxiiObjects, TaxiiError> {
        let url = build_objects_url(api_root, collection_id, since)?;
        debug!(%url, "TAXII get_objects");
        let resp = self
            .http
            .get(url)
            .headers(self.auth_headers())
            .send()
            .await
            .map_err(TaxiiError::Network)?;
        let bytes = ensure_ok(resp).await?;
        serde_json::from_slice(&bytes).map_err(TaxiiError::Decode)
    }
}

/// Validate response status, capturing 429 as [`TaxiiError::Backoff`] and
/// returning the raw body bytes on 2xx. All other non-success codes map to
/// [`TaxiiError::BadResponse`].
async fn ensure_ok(resp: reqwest::Response) -> Result<Vec<u8>, TaxiiError> {
    let status = resp.status();
    if status.is_success() {
        let buf = resp.bytes().await.map_err(TaxiiError::Network)?;
        return Ok(buf.to_vec());
    }
    if status == StatusCode::TOO_MANY_REQUESTS {
        let wait = parse_retry_after(resp.headers().get(RETRY_AFTER));
        return Err(TaxiiError::Backoff(wait));
    }
    Err(TaxiiError::BadResponse { status })
}

/// Parse a `Retry-After` header value. TAXII (HTTP) allows two forms:
/// integer "delta-seconds" or an HTTP-date. For the MVP we honour
/// delta-seconds and fall back to [`DEFAULT_BACKOFF`] for anything else —
/// the next slice will plumb through `httpdate` if it proves necessary.
fn parse_retry_after(value: Option<&HeaderValue>) -> Duration {
    let Some(v) = value else {
        return DEFAULT_BACKOFF;
    };
    let Ok(s) = v.to_str() else {
        return DEFAULT_BACKOFF;
    };
    s.trim()
        .parse::<u64>()
        .map_or(DEFAULT_BACKOFF, Duration::from_secs)
}

fn ensure_trailing_slash(url: &mut Url) {
    if !url.path().ends_with('/') {
        let new_path = format!("{}/", url.path());
        url.set_path(&new_path);
    }
}

fn build_collections_url(api_root: &str) -> Result<Url, TaxiiError> {
    let mut base = Url::parse(api_root)?;
    ensure_trailing_slash(&mut base);
    Ok(base.join("api/v21/collections/")?)
}

fn build_objects_url(
    api_root: &str,
    collection_id: &str,
    since: Option<&str>,
) -> Result<Url, TaxiiError> {
    let mut base = Url::parse(api_root)?;
    ensure_trailing_slash(&mut base);
    let path = format!("api/v21/collections/{collection_id}/objects/");
    let mut url = base.join(&path)?;
    if let Some(after) = since {
        url.query_pairs_mut().append_pair("added_after", after);
    }
    Ok(url)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;
    use serde_json::json;
    use wiremock::matchers::{header, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn token() -> SecretString {
        SecretString::new("super-secret-bearer".to_owned().into_boxed_str())
    }

    fn client_for(server: &MockServer) -> TaxiiClient {
        let base = Url::parse(&server.uri()).unwrap();
        TaxiiClient::new(reqwest::Client::new(), base, Some(token()))
    }

    #[tokio::test]
    async fn discovery_happy_path_returns_typed_document() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/taxii2/"))
            .and(header("authorization", "Bearer super-secret-bearer"))
            .and(header("accept", TAXII_MEDIA_TYPE))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "title": "Mock TAXII",
                "description": "fixture server",
                "contact": "ops@example.invalid",
                "default": "https://example.invalid/api1/",
                "api_roots": ["https://example.invalid/api1/"],
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = client_for(&server);
        let disco = client.discover().await.unwrap();
        assert_eq!(disco.title, "Mock TAXII");
        assert_eq!(disco.description.as_deref(), Some("fixture server"));
        assert_eq!(disco.contact.as_deref(), Some("ops@example.invalid"));
        assert_eq!(disco.api_roots.len(), 1);
    }

    #[tokio::test]
    async fn discovery_unauthorized_maps_to_bad_response_401() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/taxii2/"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&server)
            .await;

        let client = client_for(&server);
        let err = client.discover().await.unwrap_err();
        match err {
            TaxiiError::BadResponse { status } => {
                assert_eq!(status, StatusCode::UNAUTHORIZED);
            }
            other => panic!("expected BadResponse(401), got {other:?}"),
        }
    }

    #[tokio::test]
    async fn rate_limited_429_surfaces_backoff_from_retry_after() {
        let server = MockServer::start().await;
        let api_root = format!("{}/root/", server.uri());

        Mock::given(method("GET"))
            .and(path("/root/api/v21/collections/"))
            .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "7"))
            .mount(&server)
            .await;

        let client = client_for(&server);
        let err = client.list_collections(&api_root).await.unwrap_err();
        match err {
            TaxiiError::Backoff(d) => assert_eq!(d, Duration::from_secs(7)),
            other => panic!("expected Backoff, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn get_objects_paginated_more_true_returns_cursor() {
        let server = MockServer::start().await;
        let api_root = format!("{}/root/", server.uri());

        Mock::given(method("GET"))
            .and(path("/root/api/v21/collections/col-7/objects/"))
            .and(query_param("added_after", "2024-06-01T00:00:00Z"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "objects": [
                    { "type": "indicator", "id": "indicator--1" },
                    { "type": "indicator", "id": "indicator--2" }
                ],
                "more": true,
                "next": "cursor-xyz",
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = client_for(&server);
        let page = client
            .get_objects(&api_root, "col-7", Some("2024-06-01T00:00:00Z"))
            .await
            .unwrap();
        assert_eq!(page.objects.len(), 2);
        assert!(page.more);
        assert_eq!(page.next.as_deref(), Some("cursor-xyz"));
    }

    #[tokio::test]
    async fn discovery_invalid_json_maps_to_decode_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/taxii2/"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/taxii+json;version=2.1")
                    .set_body_string("{not-valid-json"),
            )
            .mount(&server)
            .await;

        let client = client_for(&server);
        let err = client.discover().await.unwrap_err();
        assert!(
            matches!(err, TaxiiError::Decode(_)),
            "expected Decode, got {err:?}"
        );
    }
}
