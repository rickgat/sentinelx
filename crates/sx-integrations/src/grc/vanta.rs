//! Vanta REST connector.
//!
//! ## Auth
//!
//! Vanta exposes a bearer-token API key per workspace. Customers mint
//! the key in the Vanta admin console under *Connections → API Keys*.
//! The key is forwarded as `Authorization: Bearer <key>` on every
//! request and never logged.
//!
//! ## Endpoints (MVP shape)
//!
//! Vanta's API is organised under `https://api.vanta.com`. For this MVP
//! we model two upsert endpoints that match the GRC connector surface:
//!
//! * `POST /v1/evidence/upsert` — push a single
//!   [`ComplianceEvidence`] record.
//! * `POST /v1/findings/upsert` — push a single
//!   [`FindingState`] record.
//!
//! The exact production endpoint paths are kept behind constants so a
//! follow-up rev (when the real Vanta API contract is locked) is a
//! one-line change. The handler shape (Bearer auth, JSON payload,
//! `201` / `200` success codes, `429` → backoff) is already
//! production-shaped.

use std::fmt;

use async_trait::async_trait;
use reqwest::{Client, StatusCode, Url};
use secrecy::{ExposeSecret, SecretString};
use serde_json::json;
use tracing::{debug, warn};

use super::connector::{
    ComplianceEvidence, ConnectorError, FindingState, GrcConnector, GrcKind, PushOutcome,
    VantaCredentials,
};

/// Default base URL for the Vanta API.
pub const VANTA_BASE_URL: &str = "https://api.vanta.com/";

/// Path appended to the base URL for evidence upserts.
const EVIDENCE_PATH: &str = "v1/evidence/upsert";

/// Path appended to the base URL for finding upserts.
const FINDINGS_PATH: &str = "v1/findings/upsert";

/// Vanta REST connector.
///
/// Clone-able because every field is cheap: the [`Client`] is internally
/// reference-counted, the base URL is a [`Url`], and the credentials are
/// a [`SecretString`].
#[derive(Clone)]
pub struct VantaConnector {
    http: Client,
    base_url: Url,
    api_key: SecretString,
}

impl fmt::Debug for VantaConnector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VantaConnector")
            .field("base_url", &self.base_url.as_str())
            .field("api_key", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl VantaConnector {
    /// Construct a Vanta connector with the default base URL.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectorError::Format`] if [`VANTA_BASE_URL`] cannot be
    /// parsed (which should be impossible at runtime — this is a
    /// defence-in-depth guard).
    pub fn new(http: Client, creds: VantaCredentials) -> Result<Self, ConnectorError> {
        let base_url = Url::parse(VANTA_BASE_URL).map_err(ConnectorError::format)?;
        Ok(Self::with_base_url(http, base_url, creds))
    }

    /// Construct a Vanta connector with a caller-supplied base URL.
    ///
    /// Used by integration tests against a mock server.
    #[must_use]
    pub fn with_base_url(http: Client, base_url: Url, creds: VantaCredentials) -> Self {
        Self {
            http,
            base_url,
            api_key: creds.api_key,
        }
    }

    /// Internal helper: build the bearer header. Returned as a
    /// [`SecretString`] so it can be passed to the HTTP client without
    /// materialising into a `Debug`-able owned string anywhere.
    fn bearer_header(&self) -> SecretString {
        SecretString::from(format!("Bearer {}", self.api_key.expose_secret()))
    }

    /// POST `body` to `endpoint` and translate the response.
    async fn post_json(
        &self,
        endpoint: Url,
        body: &serde_json::Value,
    ) -> Result<PushOutcome, ConnectorError> {
        let auth = self.bearer_header();
        let resp = self
            .http
            .post(endpoint)
            .header(reqwest::header::AUTHORIZATION, auth.expose_secret())
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header(reqwest::header::ACCEPT, "application/json")
            .json(body)
            .send()
            .await?;

        let status = resp.status();
        if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
            warn!(
                target: "sx_integrations::grc::vanta",
                %status,
                "vanta rejected upsert"
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
                "vanta returned {status}: {body_text}"
            )));
        }

        // The MVP wire contract returns `{ "id": "...", "url": "..." }`
        // on success. Both fields are optional — we project them into a
        // `PushOutcome` and surface anything missing as `None`.
        let value: serde_json::Value = resp.json().await.unwrap_or_else(|_| json!({}));
        Ok(PushOutcome {
            upstream_id: value
                .get("id")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned),
            url: value
                .get("url")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned),
        })
    }
}

#[async_trait]
impl GrcConnector for VantaConnector {
    fn kind(&self) -> GrcKind {
        GrcKind::Vanta
    }

    async fn push_evidence(
        &self,
        evidence: &ComplianceEvidence,
    ) -> Result<PushOutcome, ConnectorError> {
        let endpoint = self
            .base_url
            .join(EVIDENCE_PATH)
            .map_err(ConnectorError::format)?;

        let body = json!({
            "evidence_id": evidence.id,
            "tenant_id": evidence.tenant_id,
            "framework": evidence.framework,
            "control_id": evidence.control_id,
            "finding_ref": evidence.finding_ref,
            "observation_ref": evidence.observation_ref,
            "collected_at": evidence.collected_at,
        });

        debug!(
            target: "sx_integrations::grc::vanta",
            framework = %evidence.framework,
            control_id = %evidence.control_id,
            "pushing vanta evidence"
        );

        self.post_json(endpoint, &body).await
    }

    async fn push_finding(&self, finding: &FindingState) -> Result<PushOutcome, ConnectorError> {
        let endpoint = self
            .base_url
            .join(FINDINGS_PATH)
            .map_err(ConnectorError::format)?;

        let body = json!({
            "finding_id": finding.id,
            "tenant_id": finding.tenant_id,
            "severity": finding.severity,
            "status": finding.status,
            "title": finding.title,
            "description": finding.description,
            "first_seen": finding.first_seen,
            "last_seen": finding.last_seen,
        });

        debug!(
            target: "sx_integrations::grc::vanta",
            severity = %finding.severity,
            status = %finding.status,
            "pushing vanta finding"
        );

        self.post_json(endpoint, &body).await
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
    use serde_json::json;
    use wiremock::matchers::{body_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn creds() -> VantaCredentials {
        VantaCredentials {
            api_key: SecretString::from("vanta-key-shhh".to_owned()),
        }
    }

    fn connector_for(server: &MockServer) -> VantaConnector {
        let base = Url::parse(&format!("{}/", server.uri())).unwrap();
        VantaConnector::with_base_url(Client::new(), base, creds())
    }

    fn evidence() -> ComplianceEvidence {
        ComplianceEvidence {
            id: "ev-1".into(),
            tenant_id: "t-1".into(),
            framework: "soc2".into(),
            control_id: "CC6.1".into(),
            finding_ref: "f-7".into(),
            observation_ref: "obs-3".into(),
            collected_at: "2027-01-01T00:00:00Z".into(),
        }
    }

    fn finding() -> FindingState {
        FindingState {
            id: "f-9".into(),
            tenant_id: "t-1".into(),
            severity: "high".into(),
            status: "open".into(),
            title: "Unpatched RCE".into(),
            description: "CVE-2027-0001 unpatched".into(),
            first_seen: "2027-01-01T00:00:00Z".into(),
            last_seen: "2027-01-02T00:00:00Z".into(),
        }
    }

    #[tokio::test]
    async fn push_evidence_posts_expected_shape() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/evidence/upsert"))
            .and(header("authorization", "Bearer vanta-key-shhh"))
            .and(header("content-type", "application/json"))
            .and(body_json(json!({
                "evidence_id": "ev-1",
                "tenant_id": "t-1",
                "framework": "soc2",
                "control_id": "CC6.1",
                "finding_ref": "f-7",
                "observation_ref": "obs-3",
                "collected_at": "2027-01-01T00:00:00Z",
            })))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "id": "vanta-ev-42",
                "url": "https://api.vanta.com/v1/evidence/vanta-ev-42",
            })))
            .expect(1)
            .mount(&server)
            .await;

        let c = connector_for(&server);
        let outcome = c.push_evidence(&evidence()).await.unwrap();
        assert_eq!(outcome.upstream_id.as_deref(), Some("vanta-ev-42"));
        assert_eq!(
            outcome.url.as_deref(),
            Some("https://api.vanta.com/v1/evidence/vanta-ev-42")
        );
    }

    #[tokio::test]
    async fn push_finding_posts_expected_shape() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/findings/upsert"))
            .and(header("authorization", "Bearer vanta-key-shhh"))
            .and(body_json(json!({
                "finding_id": "f-9",
                "tenant_id": "t-1",
                "severity": "high",
                "status": "open",
                "title": "Unpatched RCE",
                "description": "CVE-2027-0001 unpatched",
                "first_seen": "2027-01-01T00:00:00Z",
                "last_seen": "2027-01-02T00:00:00Z",
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": "vanta-find-7",
            })))
            .expect(1)
            .mount(&server)
            .await;

        let c = connector_for(&server);
        let outcome = c.push_finding(&finding()).await.unwrap();
        assert_eq!(outcome.upstream_id.as_deref(), Some("vanta-find-7"));
        assert!(outcome.url.is_none());
    }

    #[tokio::test]
    async fn unauthorized_maps_to_unauthorized() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/evidence/upsert"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&server)
            .await;
        let c = connector_for(&server);
        let err = c.push_evidence(&evidence()).await.unwrap_err();
        assert!(matches!(err, ConnectorError::Unauthorized));
    }

    #[tokio::test]
    async fn rate_limit_propagates_retry_after() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/findings/upsert"))
            .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "37"))
            .mount(&server)
            .await;
        let c = connector_for(&server);
        let err = c.push_finding(&finding()).await.unwrap_err();
        match err {
            ConnectorError::RateLimited { retry_after_secs } => {
                assert_eq!(retry_after_secs, Some(37));
            }
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn server_error_maps_to_format() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/evidence/upsert"))
            .respond_with(ResponseTemplate::new(500).set_body_string("oops"))
            .mount(&server)
            .await;
        let c = connector_for(&server);
        let err = c.push_evidence(&evidence()).await.unwrap_err();
        match err {
            ConnectorError::Format(msg) => assert!(msg.contains("500")),
            other => panic!("expected Format, got {other:?}"),
        }
    }

    #[test]
    fn debug_redacts_api_key() {
        let c = VantaConnector::new(
            Client::new(),
            VantaCredentials {
                api_key: SecretString::from("super-secret-vanta".to_owned()),
            },
        )
        .unwrap();
        let dbg = format!("{c:?}");
        assert!(!dbg.contains("super-secret-vanta"), "leaked: {dbg}");
        assert!(dbg.contains("<redacted>"));
    }

    #[test]
    fn connector_kind_is_vanta() {
        let c = VantaConnector::new(Client::new(), creds()).unwrap();
        assert_eq!(c.kind(), GrcKind::Vanta);
    }
}
