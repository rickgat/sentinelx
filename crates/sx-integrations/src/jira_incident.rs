//! Jira Cloud REST API v3 incident-sink adapter (TOP5-#5).
//!
//! This adapter implements [`IncidentSinkPort`] for Atlassian Jira
//! Cloud. It is distinct from the simpler [`crate::jira::JiraClient`]
//! used by the legacy "file an issue for a finding" code path: this one
//! consumes the full [`IncidentEvent`] envelope and stamps every
//! enrichment field (CVSS / CWE / MITRE / compliance) into Atlassian
//! Document Format (ADF) on the issue body, plus a code block carrying
//! the raw finding JSON for downstream automation.
//!
//! ## Endpoint
//!
//! `POST <base_url>/rest/api/3/issue` — Atlassian Cloud's standard
//! issue-create API. See <https://developer.atlassian.com/cloud/jira/platform/rest/v3/api-group-issues/#api-rest-api-3-issue-post>.
//!
//! ## Authentication
//!
//! Two stable modes (see [`JiraAuth`]):
//!
//! * [`JiraAuth::BasicAuth`] — `email + api_token`, encoded as HTTP
//!   Basic. The canonical Atlassian Cloud flow.
//! * [`JiraAuth::Bearer`] — OAuth 2.0 (3LO) bearer token. The token
//!   exchange itself runs outside SentinelX; we replay the bearer on
//!   every outbound request.
//!
//! The credential is wrapped in [`SecretString`] so it never appears in
//! `Debug` output, panic messages, or `tracing` spans.
//!
//! ## Severity mapping
//!
//! Mirrors the legacy [`crate::jira`] table:
//!
//! | SentinelX  | Jira label              | Priority hint |
//! |------------|-------------------------|---------------|
//! | `Info`     | `sx-severity-info`      | `Lowest`      |
//! | `Low`      | `sx-severity-low`       | `Low`         |
//! | `Medium`   | `sx-severity-medium`    | `Medium`      |
//! | `High`     | `sx-severity-high`      | `High`        |
//! | `Critical` | `sx-severity-critical`  | `Highest`     |
//!
//! ## Error taxonomy
//!
//! Maps Jira HTTP responses onto the shared [`IncidentSinkError`]
//! variants. See the inline comments on [`JiraIncidentSink::emit`] for
//! the per-status rules.

use std::fmt;

use async_trait::async_trait;
use base64::Engine;
use reqwest::{Client, StatusCode, Url};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use serde_json::{json, Value};
use sx_core::value_object::severity::Severity;
use tracing::{debug, warn};

use crate::incident_sink::{
    parse_retry_after_secs, EmissionReceipt, IncidentEvent, IncidentSinkError, IncidentSinkPort,
};

/// Issue-creation endpoint path, appended to the configured base URL.
const ISSUE_PATH: &str = "rest/api/3/issue";

/// Cap on the size of the vendor error body captured into
/// [`IncidentSinkError::BadGateway::body`]. Jira occasionally returns
/// large stack-trace bodies on `5xx`; we keep enough to diagnose without
/// flooding the log pipeline.
const MAX_VENDOR_BODY_BYTES: usize = 4096;

/// Authentication strategy for the Jira incident sink.
///
/// Mirrors the `JiraAuthKind` config enum in
/// [`sx_config::schema::integrations`]: the monolith composition root
/// constructs one of these variants from the on-disk config block.
pub enum JiraAuth {
    /// `email + api_token`, encoded as HTTP Basic. The canonical
    /// Atlassian Cloud "I want to script Jira from a CLI" path.
    BasicAuth {
        /// Atlassian Cloud account email.
        email: String,
        /// Atlassian Cloud API token.
        api_token: SecretString,
    },
    /// OAuth 2.0 (3LO) bearer access token. Token exchange runs
    /// out-of-band; we replay the bearer on every outbound call.
    Bearer {
        /// OAuth 2.0 (3LO) bearer access token.
        token: SecretString,
    },
}

impl fmt::Debug for JiraAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BasicAuth { email, .. } => f
                .debug_struct("JiraAuth::BasicAuth")
                .field("email", email)
                .field("api_token", &"<redacted>")
                .finish_non_exhaustive(),
            Self::Bearer { .. } => f
                .debug_struct("JiraAuth::Bearer")
                .field("token", &"<redacted>")
                .finish_non_exhaustive(),
        }
    }
}

/// Jira Cloud incident-sink adapter.
///
/// Construct one per Jira project — different tenants targeting
/// different projects can share a single underlying [`reqwest::Client`]
/// but each gets their own sink with their own credentials + project
/// key. The sink itself is `Send + Sync`; share it via `Arc` from the
/// composition root.
pub struct JiraIncidentSink {
    http: Client,
    base_url: Url,
    project_key: String,
    issue_type: String,
    auth: JiraAuth,
    external_id_custom_field: Option<String>,
}

impl fmt::Debug for JiraIncidentSink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JiraIncidentSink")
            .field("base_url", &self.base_url.as_str())
            .field("project_key", &self.project_key)
            .field("issue_type", &self.issue_type)
            .field("auth", &self.auth)
            .field("external_id_custom_field", &self.external_id_custom_field)
            .finish_non_exhaustive()
    }
}

impl JiraIncidentSink {
    /// Construct a new sink.
    ///
    /// `base_url` is the Atlassian Cloud site root, e.g.
    /// `https://acme.atlassian.net/`. `project_key` is the Jira project
    /// the sink files issues under (e.g. `SEC`). `issue_type` is the
    /// Jira issue type name (typically `Task`).
    #[must_use]
    pub const fn new(
        http: Client,
        base_url: Url,
        project_key: String,
        issue_type: String,
        auth: JiraAuth,
        external_id_custom_field: Option<String>,
    ) -> Self {
        Self {
            http,
            base_url,
            project_key,
            issue_type,
            auth,
            external_id_custom_field,
        }
    }

    /// Build the `Authorization` header value for the current auth
    /// strategy. Held inside a [`SecretString`] so the rendered value
    /// never materialises into a `Debug`-able owned string elsewhere.
    fn authorization_header(&self) -> SecretString {
        match &self.auth {
            JiraAuth::BasicAuth { email, api_token } => {
                let raw = format!("{}:{}", email, api_token.expose_secret());
                let encoded = base64::engine::general_purpose::STANDARD.encode(raw.as_bytes());
                SecretString::from(format!("Basic {encoded}"))
            }
            JiraAuth::Bearer { token } => {
                SecretString::from(format!("Bearer {}", token.expose_secret()))
            }
        }
    }

    /// Compose the Jira REST v3 issue-create body for `event`.
    ///
    /// The description is encoded as Atlassian Document Format (ADF) so
    /// the issue renders cleanly in the Jira UI:
    ///
    /// * One paragraph carrying the rendered description text.
    /// * One structured paragraph listing CVSS / CWE / MITRE /
    ///   compliance summaries.
    /// * One code block containing the full enrichment payload as JSON
    ///   so downstream automation can pull the structured data back out
    ///   without parsing prose.
    fn build_payload(&self, event: &IncidentEvent) -> Value {
        let label = severity_label(event.severity);
        let priority = severity_priority_hint(event.severity);

        let enrichment_blob = serde_json::to_string_pretty(&event).unwrap_or_else(|_| {
            // serde_json::to_string_pretty only fails on type-system
            // mismatches (Map<u32, ...> etc.); our event uses only safe
            // types so falling back to a marker keeps the panic-free
            // contract intact.
            "{\"warning\": \"failed to serialise enrichment\"}".to_owned()
        });

        // ADF description: prose + enrichment summary + JSON code block.
        let description_adf = json!({
            "type": "doc",
            "version": 1,
            "content": [
                {
                    "type": "paragraph",
                    "content": [
                        { "type": "text", "text": event.description.clone() }
                    ]
                },
                {
                    "type": "paragraph",
                    "content": [
                        { "type": "text", "text": render_enrichment_summary(event) }
                    ]
                },
                {
                    "type": "codeBlock",
                    "attrs": { "language": "json" },
                    "content": [
                        { "type": "text", "text": enrichment_blob }
                    ]
                }
            ]
        });

        let mut fields = serde_json::Map::new();
        fields.insert("project".to_owned(), json!({ "key": self.project_key }));
        fields.insert("issuetype".to_owned(), json!({ "name": self.issue_type }));
        fields.insert("summary".to_owned(), Value::String(event.title.clone()));
        fields.insert(
            "labels".to_owned(),
            json!([label, format!("sx-tenant-{}", event.tenant_id)]),
        );
        fields.insert("priority".to_owned(), json!({ "name": priority }));
        fields.insert("description".to_owned(), description_adf);

        // Idempotency hook: stamp the SentinelX finding id on the
        // configured custom field if both the field id and the finding
        // are present. Operators query that field downstream to dedupe.
        if let (Some(cf), Some(digest)) = (
            self.external_id_custom_field.as_deref(),
            event.finding.as_ref(),
        ) {
            fields.insert(
                cf.to_owned(),
                Value::String(format!("{}::{}", event.tenant_id, digest.id)),
            );
        }

        json!({ "fields": fields })
    }
}

/// Minimal projection of the Jira `POST /rest/api/3/issue` response.
///
/// The Jira API returns `id`, `key`, and `self`; only the human-readable
/// key and the canonical `self` URL are surfaced into the
/// [`EmissionReceipt`]. The numeric `id` is deliberately not captured —
/// downstream consumers query by key, never id.
#[derive(Debug, Deserialize)]
struct JiraIssueResponse {
    key: String,
    #[serde(default, rename = "self")]
    self_url: Option<String>,
}

#[async_trait]
impl IncidentSinkPort for JiraIncidentSink {
    async fn emit(&self, event: &IncidentEvent) -> Result<EmissionReceipt, IncidentSinkError> {
        let endpoint = self
            .base_url
            .join(ISSUE_PATH)
            .map_err(IncidentSinkError::schema)?;

        let body = self.build_payload(event);

        debug!(
            target: "sx_integrations::jira_incident",
            project = %self.project_key,
            tenant = %event.tenant_id,
            severity = %event.severity,
            "emitting jira incident"
        );

        let auth = self.authorization_header();
        let resp = self
            .http
            .post(endpoint.clone())
            .header(reqwest::header::AUTHORIZATION, auth.expose_secret())
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header(reqwest::header::ACCEPT, "application/json")
            .json(&body)
            .send()
            .await?;

        let status = resp.status();

        if status == StatusCode::UNAUTHORIZED {
            warn!(target: "sx_integrations::jira_incident", "jira returned 401");
            return Err(IncidentSinkError::Unauthenticated);
        }
        if status == StatusCode::FORBIDDEN {
            warn!(target: "sx_integrations::jira_incident", "jira returned 403");
            return Err(IncidentSinkError::Unauthorised);
        }
        if status == StatusCode::TOO_MANY_REQUESTS {
            let retry_after = parse_retry_after_secs(
                resp.headers()
                    .get(reqwest::header::RETRY_AFTER)
                    .and_then(|v| v.to_str().ok()),
            );
            return Err(IncidentSinkError::RateLimited { retry_after });
        }
        if !status.is_success() {
            let body_text = resp.text().await.unwrap_or_default();
            let truncated = truncate_body(&body_text);
            // 4xx (other than 401/403/429) → schema mismatch (bad
            // project key, missing required field). 5xx → upstream
            // outage. Both surface as BadGateway since either is "the
            // vendor wouldn't accept this", and the caller will retry
            // identically.
            return Err(IncidentSinkError::BadGateway {
                status: status.as_u16(),
                body: truncated,
            });
        }

        let parsed: JiraIssueResponse = resp.json().await?;
        let external_url = parsed.self_url.clone().unwrap_or_else(|| {
            // Fall back to the browse URL when Jira's `self` field is
            // missing (the API guarantees it but defensive coding is
            // cheap).
            let mut browse = self.base_url.clone();
            browse.set_path(&format!("browse/{}", parsed.key));
            browse.to_string()
        });

        Ok(EmissionReceipt {
            external_id: parsed.key,
            external_url,
        })
    }

    fn name(&self) -> &'static str {
        "jira"
    }
}

/// Map a [`Severity`] to its Jira label.
#[must_use]
pub fn severity_label(sev: Severity) -> String {
    format!("sx-severity-{sev}")
}

/// Map a [`Severity`] to a Jira priority name hint.
#[must_use]
pub const fn severity_priority_hint(sev: Severity) -> &'static str {
    match sev {
        Severity::Info => "Lowest",
        Severity::Low => "Low",
        Severity::Medium => "Medium",
        Severity::High => "High",
        Severity::Critical => "Highest",
    }
}

/// Truncate a vendor response body to [`MAX_VENDOR_BODY_BYTES`].
fn truncate_body(body: &str) -> String {
    if body.len() <= MAX_VENDOR_BODY_BYTES {
        body.to_owned()
    } else {
        // Slice on a char boundary by taking the longest prefix ≤ cap.
        let mut end = MAX_VENDOR_BODY_BYTES;
        while !body.is_char_boundary(end) {
            end -= 1;
        }
        let mut s = body[..end].to_owned();
        s.push_str("…[truncated]");
        s
    }
}

/// One-line summary of the enrichment envelope, embedded in the ADF
/// description so analysts can eyeball the key fields without opening
/// the JSON code block.
fn render_enrichment_summary(event: &IncidentEvent) -> String {
    let cvss = event
        .cvss
        .as_ref()
        .map_or_else(|| "n/a".to_owned(), |c| format!("{:.1}", c.base_score));
    let cwe = if event.cwe.is_empty() {
        "none".to_owned()
    } else {
        event
            .cwe
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    };
    let attack = if event.mitre_attack.is_empty() {
        "none".to_owned()
    } else {
        event
            .mitre_attack
            .iter()
            .map(|t| t.technique.clone())
            .collect::<Vec<_>>()
            .join(", ")
    };
    format!(
        "Severity: {} | CVSS: {} | CWE: {} | MITRE ATT&CK: {}",
        event.severity, cvss, cwe, attack
    )
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::expect_used,
    clippy::indexing_slicing
)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::incident_sink::{FindingDigest, IncidentKind};
    use sx_core::value_object::compliance::ComplianceTags;
    use wiremock::matchers::{body_partial_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn basic_auth_sink(server: &MockServer) -> JiraIncidentSink {
        let base = Url::parse(&format!("{}/", server.uri())).unwrap();
        JiraIncidentSink::new(
            reqwest::Client::new(),
            base,
            "SEC".to_owned(),
            "Task".to_owned(),
            JiraAuth::BasicAuth {
                email: "ops@example.com".to_owned(),
                api_token: SecretString::from("jira-token".to_owned()),
            },
            Some("customfield_10042".to_owned()),
        )
    }

    fn event(kind: IncidentKind, severity: Severity) -> IncidentEvent {
        IncidentEvent {
            kind,
            severity,
            tenant_id: "t-1".to_owned(),
            title: "[SentinelX] Critical SQLi at /login".to_owned(),
            description: "Detected SQLi via blind boolean payload.".to_owned(),
            finding: Some(FindingDigest {
                id: "f-1".to_owned(),
                asset_id: "a-1".to_owned(),
                status: "open".to_owned(),
                cve_id: Some("CVE-2024-1234".to_owned()),
            }),
            cvss: None,
            cwe: Vec::new(),
            mitre_attack: Vec::new(),
            compliance: ComplianceTags::default(),
            source_url: Some("https://sentinelx.example.invalid/findings/f-1".to_owned()),
        }
    }

    fn expected_basic_auth_header() -> String {
        let raw = "ops@example.com:jira-token";
        let encoded = base64::engine::general_purpose::STANDARD.encode(raw.as_bytes());
        format!("Basic {encoded}")
    }

    #[tokio::test]
    async fn happy_path_returns_receipt_with_jira_key() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/rest/api/3/issue"))
            .and(header(
                "authorization",
                expected_basic_auth_header().as_str(),
            ))
            .and(header("content-type", "application/json"))
            .and(body_partial_json(json!({
                "fields": {
                    "project": { "key": "SEC" },
                    "issuetype": { "name": "Task" },
                    "summary": "[SentinelX] Critical SQLi at /login"
                }
            })))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "id": "10042",
                "key": "SEC-7",
                "self": "https://acme.atlassian.net/rest/api/3/issue/10042"
            })))
            .expect(1)
            .mount(&server)
            .await;

        let sink = basic_auth_sink(&server);
        let receipt = sink
            .emit(&event(IncidentKind::FindingEmitted, Severity::Critical))
            .await
            .unwrap();
        assert_eq!(receipt.external_id, "SEC-7");
        assert!(!receipt.external_url.is_empty());
    }

    #[tokio::test]
    async fn unauthorised_401_maps_to_unauthenticated() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/rest/api/3/issue"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&server)
            .await;

        let sink = basic_auth_sink(&server);
        let err = sink
            .emit(&event(IncidentKind::FindingEmitted, Severity::High))
            .await
            .unwrap_err();
        assert!(matches!(err, IncidentSinkError::Unauthenticated));
    }

    #[tokio::test]
    async fn forbidden_403_maps_to_unauthorised() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/rest/api/3/issue"))
            .respond_with(ResponseTemplate::new(403))
            .mount(&server)
            .await;

        let sink = basic_auth_sink(&server);
        let err = sink
            .emit(&event(IncidentKind::PlaybookTriggered, Severity::High))
            .await
            .unwrap_err();
        assert!(matches!(err, IncidentSinkError::Unauthorised));
    }

    #[tokio::test]
    async fn rate_limited_429_returns_retry_after() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/rest/api/3/issue"))
            .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "13"))
            .mount(&server)
            .await;

        let sink = basic_auth_sink(&server);
        let err = sink
            .emit(&event(IncidentKind::FindingEmitted, Severity::Critical))
            .await
            .unwrap_err();
        match err {
            IncidentSinkError::RateLimited { retry_after } => {
                assert_eq!(retry_after, Some(Duration::from_secs(13)));
            }
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn server_error_5xx_maps_to_bad_gateway() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/rest/api/3/issue"))
            .respond_with(ResponseTemplate::new(503).set_body_string("upstream outage"))
            .mount(&server)
            .await;

        let sink = basic_auth_sink(&server);
        let err = sink
            .emit(&event(IncidentKind::AuditChainBreak, Severity::High))
            .await
            .unwrap_err();
        match err {
            IncidentSinkError::BadGateway { status, body } => {
                assert_eq!(status, 503);
                assert!(body.contains("upstream outage"));
            }
            other => panic!("expected BadGateway, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn bearer_auth_header_renders_correctly() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/rest/api/3/issue"))
            .and(header("authorization", "Bearer bearer-token-XYZ"))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "id": "10042",
                "key": "SEC-8",
                "self": "https://acme.atlassian.net/rest/api/3/issue/10042"
            })))
            .expect(1)
            .mount(&server)
            .await;

        let base = Url::parse(&format!("{}/", server.uri())).unwrap();
        let sink = JiraIncidentSink::new(
            reqwest::Client::new(),
            base,
            "SEC".to_owned(),
            "Task".to_owned(),
            JiraAuth::Bearer {
                token: SecretString::from("bearer-token-XYZ".to_owned()),
            },
            None,
        );
        let receipt = sink
            .emit(&event(IncidentKind::FindingEmitted, Severity::Critical))
            .await
            .unwrap();
        assert_eq!(receipt.external_id, "SEC-8");
    }

    #[tokio::test]
    async fn payload_includes_severity_label_and_priority() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/rest/api/3/issue"))
            .and(body_partial_json(json!({
                "fields": {
                    "priority": { "name": "Highest" },
                    "labels": ["sx-severity-critical", "sx-tenant-t-1"]
                }
            })))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "id": "1", "key": "SEC-1"
            })))
            .expect(1)
            .mount(&server)
            .await;

        let sink = basic_auth_sink(&server);
        sink.emit(&event(IncidentKind::FindingEmitted, Severity::Critical))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn payload_stamps_external_id_custom_field_when_configured() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/rest/api/3/issue"))
            .and(body_partial_json(json!({
                "fields": { "customfield_10042": "t-1::f-1" }
            })))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "id": "1", "key": "SEC-9"
            })))
            .expect(1)
            .mount(&server)
            .await;

        let sink = basic_auth_sink(&server);
        sink.emit(&event(IncidentKind::FindingEmitted, Severity::Critical))
            .await
            .unwrap();
    }

    #[test]
    fn debug_impl_redacts_basic_auth_token() {
        let sink = JiraIncidentSink::new(
            reqwest::Client::new(),
            Url::parse("https://acme.atlassian.net/").unwrap(),
            "SEC".to_owned(),
            "Task".to_owned(),
            JiraAuth::BasicAuth {
                email: "ops@example.com".to_owned(),
                api_token: SecretString::from("super-secret-token".to_owned()),
            },
            None,
        );
        let dbg = format!("{sink:?}");
        assert!(dbg.contains("ops@example.com"));
        assert!(
            !dbg.contains("super-secret-token"),
            "token leaked in Debug: {dbg}"
        );
    }

    #[test]
    fn debug_impl_redacts_bearer_token() {
        let sink = JiraIncidentSink::new(
            reqwest::Client::new(),
            Url::parse("https://acme.atlassian.net/").unwrap(),
            "SEC".to_owned(),
            "Task".to_owned(),
            JiraAuth::Bearer {
                token: SecretString::from("super-secret-bearer".to_owned()),
            },
            None,
        );
        let dbg = format!("{sink:?}");
        assert!(
            !dbg.contains("super-secret-bearer"),
            "bearer leaked in Debug: {dbg}"
        );
    }

    #[test]
    fn severity_label_mapping_is_stable() {
        assert_eq!(severity_label(Severity::Info), "sx-severity-info");
        assert_eq!(severity_label(Severity::Low), "sx-severity-low");
        assert_eq!(severity_label(Severity::Medium), "sx-severity-medium");
        assert_eq!(severity_label(Severity::High), "sx-severity-high");
        assert_eq!(severity_label(Severity::Critical), "sx-severity-critical");
    }

    #[test]
    fn severity_priority_hint_mapping_is_stable() {
        assert_eq!(severity_priority_hint(Severity::Info), "Lowest");
        assert_eq!(severity_priority_hint(Severity::Low), "Low");
        assert_eq!(severity_priority_hint(Severity::Medium), "Medium");
        assert_eq!(severity_priority_hint(Severity::High), "High");
        assert_eq!(severity_priority_hint(Severity::Critical), "Highest");
    }

    #[test]
    fn truncate_body_keeps_short_bodies_intact() {
        let s = "short";
        assert_eq!(truncate_body(s), s);
    }

    #[test]
    fn truncate_body_truncates_long_bodies_with_marker() {
        let s = "a".repeat(MAX_VENDOR_BODY_BYTES + 100);
        let out = truncate_body(&s);
        assert!(out.len() < s.len());
        assert!(out.ends_with("…[truncated]"));
    }
}
