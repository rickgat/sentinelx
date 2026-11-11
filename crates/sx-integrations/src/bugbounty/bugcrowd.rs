//! Bugcrowd REST connector.
//!
//! ## Auth
//!
//! Bugcrowd authenticates with a bearer API token under the
//! `Authorization: Token <token>` scheme (Bugcrowd's documented format).
//! The header is rebuilt on every request so credential rotation is
//! observed immediately.
//!
//! ## Endpoint shape
//!
//! Pushing a `SentinelX` finding to a program is modeled as an *internal
//! note* attached to the program's engagement brief — never as a
//! researcher-visible submission. Bugcrowd exposes internal notes under:
//!
//! * `POST /v2/programs/{handle}/internal_notes`.
//!
//! Bugcrowd uses JSON:API for its v2 endpoints; we wrap the payload in
//! the canonical `{"data": {"type": "internal_note", "attributes": …}}`
//! envelope.

use std::fmt;

use async_trait::async_trait;
use reqwest::{Client, StatusCode, Url};
use secrecy::{ExposeSecret, SecretString};
use serde_json::json;
use tracing::{debug, warn};

use super::connector::{
    is_pushable, BugBountyConnector, BugBountyKind, BugcrowdCredentials, ConnectorError,
    PushOutcome, TriagedFinding,
};

/// Default base URL for the Bugcrowd API.
pub const BUGCROWD_BASE_URL: &str = "https://api.bugcrowd.com/v2/";

/// Bugcrowd REST connector.
#[derive(Clone)]
pub struct BugcrowdConnector {
    http: Client,
    base_url: Url,
    api_token: SecretString,
}

impl fmt::Debug for BugcrowdConnector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BugcrowdConnector")
            .field("base_url", &self.base_url.as_str())
            .field("api_token", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl BugcrowdConnector {
    /// Construct a Bugcrowd connector with the default base URL.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectorError::Format`] if [`BUGCROWD_BASE_URL`] cannot
    /// be parsed.
    pub fn new(http: Client, creds: BugcrowdCredentials) -> Result<Self, ConnectorError> {
        let base_url = Url::parse(BUGCROWD_BASE_URL).map_err(ConnectorError::format)?;
        Ok(Self::with_base_url(http, base_url, creds))
    }

    /// Construct a Bugcrowd connector with a caller-supplied base URL.
    #[must_use]
    pub fn with_base_url(http: Client, base_url: Url, creds: BugcrowdCredentials) -> Self {
        Self {
            http,
            base_url,
            api_token: creds.api_token,
        }
    }

    /// Build the `Authorization: Token …` header.
    fn token_header(&self) -> SecretString {
        SecretString::from(format!("Token {}", self.api_token.expose_secret()))
    }
}

#[async_trait]
impl BugBountyConnector for BugcrowdConnector {
    fn kind(&self) -> BugBountyKind {
        BugBountyKind::Bugcrowd
    }

    async fn push_internal_note(
        &self,
        finding: &TriagedFinding,
    ) -> Result<PushOutcome, ConnectorError> {
        if !is_pushable(finding.severity) {
            return Err(ConnectorError::BelowSeverityFloor(finding.severity));
        }

        let endpoint = self
            .base_url
            .join(&format!(
                "programs/{}/internal_notes",
                finding.program_handle
            ))
            .map_err(ConnectorError::format)?;

        let body = json!({
            "data": {
                "type": "internal_note",
                "attributes": {
                    "title": finding.title,
                    "body": finding.description,
                    "severity": finding.severity.label(),
                    "visibility": "internal",
                    "source": "sentinelx",
                    "tenant_id": finding.tenant_id,
                    "finding_id": finding.id,
                }
            }
        });

        debug!(
            target: "sx_integrations::bugbounty::bugcrowd",
            program = %finding.program_handle,
            severity = finding.severity.label(),
            "pushing bugcrowd internal note"
        );

        let auth = self.token_header();
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
                target: "sx_integrations::bugbounty::bugcrowd",
                %status,
                "bugcrowd rejected internal note"
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
                "bugcrowd returned {status}: {body_text}"
            )));
        }

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

    fn creds() -> BugcrowdCredentials {
        BugcrowdCredentials {
            api_token: SecretString::from("bc-token-shhh".to_owned()),
        }
    }

    fn connector_for(server: &MockServer) -> BugcrowdConnector {
        let base = Url::parse(&format!("{}/", server.uri())).unwrap();
        BugcrowdConnector::with_base_url(Client::new(), base, creds())
    }

    fn high_finding() -> TriagedFinding {
        TriagedFinding {
            id: "f-7".into(),
            tenant_id: "t-1".into(),
            program_handle: "acme".into(),
            severity: Severity::Critical,
            title: "Auth bypass on /admin".into(),
            description: "Header-tampering bypasses RBAC".into(),
        }
    }

    #[tokio::test]
    async fn push_internal_note_success_returns_outcome() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/programs/acme/internal_notes"))
            .and(header("authorization", "Token bc-token-shhh"))
            .and(header("content-type", "application/json"))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "data": {
                    "id": "00000000-aaaa-bbbb-cccc-111111111111",
                    "type": "internal_note",
                    "links": { "self": "https://api.bugcrowd.com/v2/internal_notes/00000000-aaaa-bbbb-cccc-111111111111" }
                }
            })))
            .expect(1)
            .mount(&server)
            .await;

        let c = connector_for(&server);
        let outcome = c.push_internal_note(&high_finding()).await.unwrap();
        assert_eq!(
            outcome.upstream_id.as_deref(),
            Some("00000000-aaaa-bbbb-cccc-111111111111")
        );
        assert!(outcome.url.is_some());
    }

    #[tokio::test]
    async fn push_below_floor_short_circuits_without_hitting_api() {
        let server = MockServer::start().await;
        let c = connector_for(&server);
        let mut low = high_finding();
        low.severity = Severity::Low;
        let err = c.push_internal_note(&low).await.unwrap_err();
        assert!(matches!(err, ConnectorError::BelowSeverityFloor(_)));
    }

    #[tokio::test]
    async fn unauthorized_maps_to_unauthorized() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/programs/acme/internal_notes"))
            .respond_with(ResponseTemplate::new(403))
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
            .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "60"))
            .mount(&server)
            .await;
        let c = connector_for(&server);
        let err = c.push_internal_note(&high_finding()).await.unwrap_err();
        match err {
            ConnectorError::RateLimited { retry_after_secs } => {
                assert_eq!(retry_after_secs, Some(60));
            }
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    #[test]
    fn debug_redacts_api_token() {
        let c = BugcrowdConnector::new(Client::new(), creds()).unwrap();
        let dbg = format!("{c:?}");
        assert!(!dbg.contains("bc-token-shhh"), "leaked: {dbg}");
        assert!(dbg.contains("<redacted>"));
    }

    #[test]
    fn connector_kind_is_bugcrowd() {
        let c = BugcrowdConnector::new(Client::new(), creds()).unwrap();
        assert_eq!(c.kind(), BugBountyKind::Bugcrowd);
    }
}
