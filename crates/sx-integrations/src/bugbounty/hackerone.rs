//! HackerOne REST connector.
//!
//! ## Auth
//!
//! HackerOne's API authenticates with HTTP Basic auth where the username
//! is the API user identifier and the password is the API token. The
//! header is rebuilt on every request so a future rotation of `api_token`
//! is observed without extra plumbing.
//!
//! ## Endpoint shape
//!
//! Pushing a `SentinelX` finding to a program is modeled as an *internal
//! activity comment* — never as a public report. HackerOne exposes
//! internal activity creation under:
//!
//! * `POST /v1/programs/{handle}/internal_notes` (production endpoint
//!   path; kept behind a constant so a follow-up wire revision is a
//!   one-line change).
//!
//! The wire payload follows the JSON:API convention HackerOne uses:
//! `{"data": {"type": "internal-note", "attributes": { … }}}`.

use std::fmt;

use async_trait::async_trait;
use base64::Engine;
use reqwest::{Client, StatusCode, Url};
use secrecy::{ExposeSecret, SecretString};
use serde_json::json;
use tracing::{debug, warn};

use super::connector::{
    is_pushable, BugBountyConnector, BugBountyKind, ConnectorError, HackerOneCredentials,
    PushOutcome, TriagedFinding,
};

/// Default base URL for the HackerOne API.
pub const HACKERONE_BASE_URL: &str = "https://api.hackerone.com/v1/";

/// HackerOne REST connector.
///
/// Clone-able because every field is cheap: the [`Client`] is internally
/// reference-counted, the base URL is a [`Url`], and the credentials are
/// a [`SecretString`].
#[derive(Clone)]
pub struct HackerOneConnector {
    http: Client,
    base_url: Url,
    api_username: String,
    api_token: SecretString,
}

impl fmt::Debug for HackerOneConnector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HackerOneConnector")
            .field("base_url", &self.base_url.as_str())
            .field("api_username", &self.api_username)
            .field("api_token", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl HackerOneConnector {
    /// Construct a HackerOne connector with the default base URL.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectorError::Format`] if [`HACKERONE_BASE_URL`] cannot
    /// be parsed.
    pub fn new(http: Client, creds: HackerOneCredentials) -> Result<Self, ConnectorError> {
        let base_url = Url::parse(HACKERONE_BASE_URL).map_err(ConnectorError::format)?;
        Ok(Self::with_base_url(http, base_url, creds))
    }

    /// Construct a HackerOne connector with a caller-supplied base URL.
    /// Used by integration tests against a mock server.
    #[must_use]
    pub fn with_base_url(http: Client, base_url: Url, creds: HackerOneCredentials) -> Self {
        Self {
            http,
            base_url,
            api_username: creds.api_username,
            api_token: creds.api_token,
        }
    }

    /// Build the `Authorization: Basic …` header value.
    fn basic_auth_header(&self) -> SecretString {
        let raw = format!("{}:{}", self.api_username, self.api_token.expose_secret());
        let encoded = base64::engine::general_purpose::STANDARD.encode(raw.as_bytes());
        SecretString::from(format!("Basic {encoded}"))
    }
}

#[async_trait]
impl BugBountyConnector for HackerOneConnector {
    fn kind(&self) -> BugBountyKind {
        BugBountyKind::HackerOne
    }

    async fn push_internal_note(
        &self,
        finding: &TriagedFinding,
    ) -> Result<PushOutcome, ConnectorError> {
        if !is_pushable(finding.severity) {
            return Err(ConnectorError::BelowSeverityFloor(finding.severity));
        }

        // Use `programs/{handle}/internal_notes` — the program handle is
        // url-path-safe by definition (HackerOne enforces it on the
        // platform side), so we splice it in directly.
        let endpoint = self
            .base_url
            .join(&format!(
                "programs/{}/internal_notes",
                finding.program_handle
            ))
            .map_err(ConnectorError::format)?;

        // JSON:API envelope. `visibility: "internal"` is a defence-in-depth
        // flag — the endpoint itself never produces a researcher-visible
        // artefact, but we include the flag explicitly so a future endpoint
        // revision that *would* default to "public" still produces the
        // intended internal-only note.
        let body = json!({
            "data": {
                "type": "internal-note",
                "attributes": {
                    "title": finding.title,
                    "body": finding.description,
                    "severity_rating": finding.severity.label(),
                    "visibility": "internal",
                    "source": "sentinelx",
                    "tenant_id": finding.tenant_id,
                    "finding_id": finding.id,
                }
            }
        });

        debug!(
            target: "sx_integrations::bugbounty::hackerone",
            program = %finding.program_handle,
            severity = finding.severity.label(),
            "pushing hackerone internal note"
        );

        let auth = self.basic_auth_header();
        let resp = self
            .http
            .post(endpoint)
            .header(reqwest::header::AUTHORIZATION, auth.expose_secret())
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header(reqwest::header::ACCEPT, "application/json")
            .json(&body)
            .send()
            .await?;

        let status = resp.status();
        if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
            warn!(
                target: "sx_integrations::bugbounty::hackerone",
                %status,
                "hackerone rejected internal note"
            );
            return Err(ConnectorError::Unauthorized);
        }
        if status == StatusCode::TOO_MANY_REQUESTS {
            let retry_after_secs = resp
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.trim().parse::<u64>().ok());
            return Err(ConnectorError::RateLimited { retry_after_secs });
        }
        if !status.is_success() {
            let body_text = resp.text().await.unwrap_or_default();
            return Err(ConnectorError::Format(format!(
                "hackerone returned {status}: {body_text}"
            )));
        }

        // JSON:API success body: `{"data": {"id": "...", "links": {"self": "..."}}}`.
        let value: serde_json::Value = resp.json().await.unwrap_or_else(|_| json!({}));
        let upstream_id = value
            .pointer("/data/id")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned);
        let url = value
            .pointer("/data/links/self")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned);
        Ok(PushOutcome { upstream_id, url })
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::expect_used,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;
    use crate::siem::Severity;
    use serde_json::json;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn creds() -> HackerOneCredentials {
        HackerOneCredentials {
            api_username: "ops-api".into(),
            api_token: SecretString::from("h1-token-shhh".to_owned()),
        }
    }

    fn connector_for(server: &MockServer) -> HackerOneConnector {
        let base = Url::parse(&format!("{}/", server.uri())).unwrap();
        HackerOneConnector::with_base_url(Client::new(), base, creds())
    }

    fn expected_basic_auth() -> String {
        let raw = "ops-api:h1-token-shhh";
        let encoded = base64::engine::general_purpose::STANDARD.encode(raw.as_bytes());
        format!("Basic {encoded}")
    }

    fn high_finding() -> TriagedFinding {
        TriagedFinding {
            id: "f-7".into(),
            tenant_id: "t-1".into(),
            program_handle: "acme".into(),
            severity: Severity::High,
            title: "RCE in /upload".into(),
            description: "Server-side template injection".into(),
        }
    }

    #[tokio::test]
    async fn push_internal_note_success_returns_outcome() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/programs/acme/internal_notes"))
            .and(header("authorization", expected_basic_auth().as_str()))
            .and(header("content-type", "application/json"))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "data": {
                    "id": "1000042",
                    "type": "internal-note",
                    "links": { "self": "https://api.hackerone.com/v1/internal_notes/1000042" }
                }
            })))
            .expect(1)
            .mount(&server)
            .await;

        let c = connector_for(&server);
        let outcome = c.push_internal_note(&high_finding()).await.unwrap();
        assert_eq!(outcome.upstream_id.as_deref(), Some("1000042"));
        assert_eq!(
            outcome.url.as_deref(),
            Some("https://api.hackerone.com/v1/internal_notes/1000042")
        );
    }

    #[tokio::test]
    async fn push_below_floor_short_circuits_without_hitting_api() {
        let server = MockServer::start().await;
        // No mock mounted — if we hit the API, the call fails.
        let c = connector_for(&server);
        let mut low = high_finding();
        low.severity = Severity::Medium;
        let err = c.push_internal_note(&low).await.unwrap_err();
        assert!(matches!(err, ConnectorError::BelowSeverityFloor(_)));
    }

    #[tokio::test]
    async fn unauthorized_maps_to_unauthorized() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/programs/acme/internal_notes"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&server)
            .await;
        let c = connector_for(&server);
        let err = c.push_internal_note(&high_finding()).await.unwrap_err();
        assert!(matches!(err, ConnectorError::Unauthorized));
    }

    #[tokio::test]
    async fn rate_limit_propagates_retry_after() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/programs/acme/internal_notes"))
            .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "12"))
            .mount(&server)
            .await;
        let c = connector_for(&server);
        let err = c.push_internal_note(&high_finding()).await.unwrap_err();
        match err {
            ConnectorError::RateLimited { retry_after_secs } => {
                assert_eq!(retry_after_secs, Some(12));
            }
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn server_error_maps_to_format() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/programs/acme/internal_notes"))
            .respond_with(ResponseTemplate::new(500).set_body_string("oops"))
            .mount(&server)
            .await;
        let c = connector_for(&server);
        let err = c.push_internal_note(&high_finding()).await.unwrap_err();
        match err {
            ConnectorError::Format(msg) => assert!(msg.contains("500")),
            other => panic!("expected Format, got {other:?}"),
        }
    }

    #[test]
    fn debug_redacts_api_token() {
        let c = HackerOneConnector::new(Client::new(), creds()).unwrap();
        let dbg = format!("{c:?}");
        assert!(dbg.contains("ops-api"));
        assert!(!dbg.contains("h1-token-shhh"), "leaked: {dbg}");
        assert!(dbg.contains("<redacted>"));
        // Basic-auth base64 must not leak either.
        assert!(!dbg.contains(&expected_basic_auth()));
    }

    #[test]
    fn connector_kind_is_hackerone() {
        let c = HackerOneConnector::new(Client::new(), creds()).unwrap();
        assert_eq!(c.kind(), BugBountyKind::HackerOne);
    }
}
