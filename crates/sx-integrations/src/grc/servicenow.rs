//! `ServiceNow` REST connector.
//!
//! ## Auth
//!
//! Operators provide their `ServiceNow` instance URL plus a basic-auth
//! user/password pair. The `Authorization: Basic <base64>` header is
//! rebuilt on every request and the password is wrapped in
//! [`secrecy::SecretString`].
//!
//! ## Endpoints
//!
//! `ServiceNow` stores incidents in the `incident` table; the REST
//! interface exposes them under `/api/now/table/incident`. Both
//! evidence and finding pushes from `SentinelX` materialise as
//! incidents in the GRC pipeline — the connector tags them with a
//! `sx-` `correlation_id` so duplicates collapse upstream.

use std::fmt;

use async_trait::async_trait;
use base64::Engine;
use reqwest::{Client, StatusCode, Url};
use secrecy::{ExposeSecret, SecretString};
use serde_json::json;
use tracing::{debug, warn};

use super::connector::{
    ComplianceEvidence, ConnectorError, FindingState, GrcConnector, GrcKind, PushOutcome,
    ServiceNowCredentials,
};

/// Path appended to the instance URL for the incident table.
const INCIDENT_PATH: &str = "api/now/table/incident";

/// `ServiceNow` REST connector.
#[derive(Clone)]
pub struct ServiceNowConnector {
    http: Client,
    instance_url: Url,
    user: String,
    password: SecretString,
}

impl fmt::Debug for ServiceNowConnector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServiceNowConnector")
            .field("instance_url", &self.instance_url.as_str())
            .field("user", &self.user)
            .field("password", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl ServiceNowConnector {
    /// Construct a new `ServiceNow` connector.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectorError::Format`] when `instance_url` is not a
    /// well-formed URL.
    pub fn new(http: Client, creds: ServiceNowCredentials) -> Result<Self, ConnectorError> {
        // Ensure a trailing slash so `Url::join` correctly appends the
        // table path. Without it `join` treats the last path segment as
        // a peer instead of a parent.
        let mut url_str = creds.instance_url;
        if !url_str.ends_with('/') {
            url_str.push('/');
        }
        let instance_url = Url::parse(&url_str).map_err(ConnectorError::format)?;
        Ok(Self {
            http,
            instance_url,
            user: creds.user,
            password: creds.password,
        })
    }

    /// Build the `Authorization: Basic …` header value.
    fn basic_auth_header(&self) -> SecretString {
        let raw = format!("{}:{}", self.user, self.password.expose_secret());
        let encoded = base64::engine::general_purpose::STANDARD.encode(raw.as_bytes());
        SecretString::from(format!("Basic {encoded}"))
    }

    async fn post_incident(&self, body: &serde_json::Value) -> Result<PushOutcome, ConnectorError> {
        let endpoint = self
            .instance_url
            .join(INCIDENT_PATH)
            .map_err(ConnectorError::format)?;

        let auth = self.basic_auth_header();
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
                target: "sx_integrations::grc::servicenow",
                %status,
                "servicenow rejected incident push"
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
                "servicenow returned {status}: {body_text}"
            )));
        }

        // `ServiceNow`'s table API returns `{ "result": { "sys_id": "...", "number": "..." } }`.
        let value: serde_json::Value = resp.json().await.unwrap_or_else(|_| json!({}));
        let result = value.get("result").cloned().unwrap_or_else(|| json!({}));
        Ok(PushOutcome {
            upstream_id: result
                .get("sys_id")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned),
            url: result
                .get("number")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned),
        })
    }
}

#[async_trait]
impl GrcConnector for ServiceNowConnector {
    fn kind(&self) -> GrcKind {
        GrcKind::ServiceNow
    }

    async fn push_evidence(
        &self,
        evidence: &ComplianceEvidence,
    ) -> Result<PushOutcome, ConnectorError> {
        let body = json!({
            "short_description": format!(
                "SentinelX compliance evidence {} / {}",
                evidence.framework, evidence.control_id
            ),
            "description": format!(
                "Evidence for finding {} (observation {})",
                evidence.finding_ref, evidence.observation_ref
            ),
            "category": "compliance",
            "correlation_id": format!("sx-evidence-{}", evidence.id),
            "u_tenant_id": evidence.tenant_id,
            "u_framework": evidence.framework,
            "u_control_id": evidence.control_id,
            "u_collected_at": evidence.collected_at,
        });
        debug!(
            target: "sx_integrations::grc::servicenow",
            framework = %evidence.framework,
            control_id = %evidence.control_id,
            "pushing servicenow incident (evidence)"
        );
        self.post_incident(&body).await
    }

    async fn push_finding(&self, finding: &FindingState) -> Result<PushOutcome, ConnectorError> {
        let body = json!({
            "short_description": finding.title,
            "description": finding.description,
            "category": "security",
            "severity": map_severity(&finding.severity),
            "state": map_status(&finding.status),
            "correlation_id": format!("sx-finding-{}", finding.id),
            "u_tenant_id": finding.tenant_id,
            "u_first_seen": finding.first_seen,
            "u_last_seen": finding.last_seen,
        });
        debug!(
            target: "sx_integrations::grc::servicenow",
            severity = %finding.severity,
            status = %finding.status,
            "pushing servicenow incident (finding)"
        );
        self.post_incident(&body).await
    }
}

/// Map the `SentinelX` severity scale onto `ServiceNow`'s `1..=4` enum.
fn map_severity(s: &str) -> u8 {
    match s {
        "critical" => 1,
        "high" => 2,
        "medium" => 3,
        _ => 4,
    }
}

/// Map the `SentinelX` finding status onto `ServiceNow` incident state.
///
/// 1=New, 2=In Progress, 6=Resolved, 7=Closed — kept as numbers because
/// `ServiceNow`'s table API consumes the integer column directly.
fn map_status(s: &str) -> u8 {
    match s {
        "triaged" => 2,
        "accepted" => 6,
        "closed" => 7,
        // "open" + unknown both map to `1` (New).
        _ => 1,
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
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn creds_for(url: &str) -> ServiceNowCredentials {
        ServiceNowCredentials {
            instance_url: url.to_owned(),
            user: "ops".to_owned(),
            password: SecretString::from("password-shh".to_owned()),
        }
    }

    fn expected_basic_auth() -> String {
        let raw = "ops:password-shh";
        let encoded = base64::engine::general_purpose::STANDARD.encode(raw.as_bytes());
        format!("Basic {encoded}")
    }

    #[tokio::test]
    async fn push_finding_targets_incident_table() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/now/table/incident"))
            .and(header("authorization", expected_basic_auth().as_str()))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "result": {
                    "sys_id": "abc123",
                    "number": "INC0001234",
                }
            })))
            .expect(1)
            .mount(&server)
            .await;

        let creds = creds_for(&server.uri());
        let c = ServiceNowConnector::new(Client::new(), creds).unwrap();
        let outcome = c
            .push_finding(&super::super::FindingState {
                id: "f-1".into(),
                tenant_id: "t-1".into(),
                severity: "high".into(),
                status: "open".into(),
                title: "T".into(),
                description: "D".into(),
                first_seen: "2027-01-01T00:00:00Z".into(),
                last_seen: "2027-01-02T00:00:00Z".into(),
            })
            .await
            .unwrap();
        assert_eq!(outcome.upstream_id.as_deref(), Some("abc123"));
        assert_eq!(outcome.url.as_deref(), Some("INC0001234"));
    }

    #[tokio::test]
    async fn push_evidence_targets_incident_table() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/now/table/incident"))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "result": { "sys_id": "ev-sys", "number": "INC0009999" }
            })))
            .expect(1)
            .mount(&server)
            .await;
        let creds = creds_for(&server.uri());
        let c = ServiceNowConnector::new(Client::new(), creds).unwrap();
        let outcome = c
            .push_evidence(&super::super::ComplianceEvidence {
                id: "e".into(),
                tenant_id: "t".into(),
                framework: "soc2".into(),
                control_id: "CC6.1".into(),
                finding_ref: "f".into(),
                observation_ref: "o".into(),
                collected_at: "2027-01-01T00:00:00Z".into(),
            })
            .await
            .unwrap();
        assert_eq!(outcome.upstream_id.as_deref(), Some("ev-sys"));
    }

    #[tokio::test]
    async fn unauthorized_maps_to_unauthorized() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/now/table/incident"))
            .respond_with(ResponseTemplate::new(403))
            .mount(&server)
            .await;
        let creds = creds_for(&server.uri());
        let c = ServiceNowConnector::new(Client::new(), creds).unwrap();
        let err = c
            .push_finding(&super::super::FindingState {
                id: "f-1".into(),
                tenant_id: "t-1".into(),
                severity: "low".into(),
                status: "open".into(),
                title: "T".into(),
                description: "D".into(),
                first_seen: "2027-01-01T00:00:00Z".into(),
                last_seen: "2027-01-02T00:00:00Z".into(),
            })
            .await
            .unwrap_err();
        assert!(matches!(err, ConnectorError::Unauthorized));
    }

    #[test]
    fn severity_mapping_is_stable() {
        assert_eq!(map_severity("critical"), 1);
        assert_eq!(map_severity("high"), 2);
        assert_eq!(map_severity("medium"), 3);
        assert_eq!(map_severity("low"), 4);
        assert_eq!(map_severity("info"), 4);
        assert_eq!(map_severity("???"), 4);
    }

    #[test]
    fn status_mapping_is_stable() {
        assert_eq!(map_status("open"), 1);
        assert_eq!(map_status("triaged"), 2);
        assert_eq!(map_status("accepted"), 6);
        assert_eq!(map_status("closed"), 7);
        assert_eq!(map_status("???"), 1);
    }

    #[test]
    fn debug_redacts_password() {
        let creds = creds_for("https://acme.service-now.com");
        let c = ServiceNowConnector::new(Client::new(), creds).unwrap();
        let dbg = format!("{c:?}");
        assert!(!dbg.contains("password-shh"), "leaked: {dbg}");
        assert!(dbg.contains("<redacted>"));
        assert!(dbg.contains("acme.service-now.com"));
    }
}
