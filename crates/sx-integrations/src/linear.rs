//! Linear GraphQL incident-sink adapter (TOP5-#5-FU2).
//!
//! This adapter implements [`IncidentSinkPort`] for Linear's single
//! GraphQL endpoint. It mirrors the Jira / PagerDuty MVP shape: stamp the
//! full [`IncidentEvent`] envelope (CVSS / CWE / MITRE / compliance) into
//! the issue body, surface the vendor-side primary identifier on the
//! returned [`EmissionReceipt`].
//!
//! ## Endpoint
//!
//! `POST https://api.linear.app/graphql` — Linear exposes a single
//! GraphQL endpoint and the operation is selected by the request body's
//! `query` field. We send the documented `IssueCreate` mutation.
//!
//! See <https://developers.linear.app/docs/graphql/working-with-the-graphql-api>
//! for the canonical contract.
//!
//! ## Authentication
//!
//! Linear's docs use a raw API key in the `Authorization` header — the
//! token travels verbatim, **without** a `Bearer ` prefix (unlike most
//! OAuth-based REST APIs). OAuth 2.0 is out of scope for the MVP and
//! tracked separately.
//!
//! The credential is wrapped in [`SecretString`] so it never appears in
//! `Debug` output, panic messages, or `tracing` spans.
//!
//! ## Severity mapping
//!
//! Linear's priority enum is fixed by the API (`0 = No priority`, `1 =
//! Urgent`, `2 = High`, `3 = Medium`, `4 = Low`). We map:
//!
//! | SentinelX  | Linear priority           |
//! |------------|---------------------------|
//! | `Critical` | `1` (Urgent)              |
//! | `High`     | `2` (High)                |
//! | `Medium`   | `3` (Medium)              |
//! | `Low`      | `4` (Low)                 |
//! | `Info`     | `0` (No priority)         |
//!
//! ## Error taxonomy
//!
//! Linear returns `200 OK` even on auth / rate-limit failures and signals
//! the problem in the GraphQL `errors[]` array's `extensions.code`. We
//! map:
//!
//! * `extensions.code == "AUTHENTICATION_ERROR"` → [`IncidentSinkError::Unauthenticated`].
//! * `extensions.code == "RATELIMITED"` → [`IncidentSinkError::RateLimited`] with a
//!   fixed 60-second backoff (Linear documents a 60-second sliding window
//!   default and does not expose a `Retry-After` equivalent on the
//!   GraphQL surface).
//! * Other GraphQL errors → [`IncidentSinkError::Schema`].
//! * HTTP 5xx → [`IncidentSinkError::BadGateway`].

use std::fmt;
use std::time::Duration;

use async_trait::async_trait;
use reqwest::{Client, StatusCode, Url};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use serde_json::{json, Value};
use sx_core::value_object::severity::Severity;
use tracing::{debug, warn};

use crate::incident_sink::{EmissionReceipt, IncidentEvent, IncidentSinkError, IncidentSinkPort};

/// Default Linear GraphQL endpoint. Operators override this for tests or
/// for a local mock fixture.
pub const DEFAULT_API_URL: &str = "https://api.linear.app/graphql";

/// Cap on the size of the vendor error body captured into
/// [`IncidentSinkError::BadGateway::body`]. Linear's GraphQL responses are
/// modest in practice; we keep enough to diagnose without flooding logs.
const MAX_VENDOR_BODY_BYTES: usize = 4096;

/// Sliding-window default Linear documents when rate-limiting GraphQL
/// callers. Linear does not surface a `Retry-After` header on the GraphQL
/// surface, so we backoff for a fixed minute and let upstream retry the
/// emission.
const LINEAR_RATE_LIMIT_BACKOFF_SECS: u64 = 60;

/// The full `IssueCreate` mutation we send to Linear. Defined as a
/// constant so the wiremock integration tests can assert that the
/// outbound body contains the exact string the API expects.
pub const ISSUE_CREATE_MUTATION: &str =
    "mutation IssueCreate($input: IssueCreateInput!) { issueCreate(input: $input) { success issue { id identifier url } } }";

/// Linear GraphQL incident-sink adapter.
///
/// Construct one per Linear team — different teams (or different tenants
/// targeting different teams) each get their own sink instance, sharing
/// the workspace-wide [`reqwest::Client`] for connection pooling. The
/// sink itself is `Send + Sync`; share it via `Arc` from the composition
/// root.
pub struct LinearIncidentSink {
    http: Client,
    api_url: Url,
    api_key: SecretString,
    team_id: String,
    label_ids: Vec<String>,
}

impl fmt::Debug for LinearIncidentSink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LinearIncidentSink")
            .field("api_url", &self.api_url.as_str())
            .field("api_key", &"<redacted>")
            .field("team_id", &self.team_id)
            .field("label_ids", &self.label_ids)
            .finish_non_exhaustive()
    }
}

impl LinearIncidentSink {
    /// Construct a new sink. `api_url` is typically [`DEFAULT_API_URL`]
    /// but can be overridden for a wiremock fixture; `api_key` is the raw
    /// Linear API key (not prefixed with `Bearer `); `team_id` is the
    /// Linear team UUID the sink files issues under; `label_ids` is an
    /// optional list of label UUIDs to attach to every issue.
    #[must_use]
    pub const fn new(
        http: Client,
        api_url: Url,
        api_key: SecretString,
        team_id: String,
        label_ids: Vec<String>,
    ) -> Self {
        Self {
            http,
            api_url,
            api_key,
            team_id,
            label_ids,
        }
    }

    /// Build the GraphQL request body for `event`.
    ///
    /// The description is composed as Markdown — Linear renders Markdown
    /// natively in its issue view, so this gives operators a clean
    /// summary, the enrichment block, and a fenced JSON code block
    /// carrying the raw event payload for downstream automation.
    fn build_payload(&self, event: &IncidentEvent) -> Value {
        let priority = severity_priority(event.severity);

        let enrichment_blob = serde_json::to_string_pretty(&event).unwrap_or_else(|_| {
            // serde_json::to_string_pretty only fails on type-system
            // mismatches; falling back to a marker keeps the panic-free
            // contract intact.
            "{\"warning\": \"failed to serialise enrichment\"}".to_owned()
        });

        let description = format!(
            "{prose}\n\n**Enrichment**\n\n{summary}\n\n```json\n{blob}\n```",
            prose = event.description,
            summary = render_enrichment_summary(event),
            blob = enrichment_blob,
        );

        let mut input = serde_json::Map::new();
        input.insert("teamId".to_owned(), Value::String(self.team_id.clone()));
        input.insert("title".to_owned(), Value::String(event.title.clone()));
        input.insert("description".to_owned(), Value::String(description));
        input.insert("priority".to_owned(), json!(priority));
        if !self.label_ids.is_empty() {
            input.insert(
                "labelIds".to_owned(),
                Value::Array(
                    self.label_ids
                        .iter()
                        .map(|s| Value::String(s.clone()))
                        .collect(),
                ),
            );
        }

        json!({
            "query": ISSUE_CREATE_MUTATION,
            "variables": { "input": Value::Object(input) }
        })
    }
}

/// Top-level shape of a Linear GraphQL response. The API returns
/// `data` + `errors` per the GraphQL spec; `errors` is non-empty even on
/// `200 OK` when the operation failed.
#[derive(Debug, Deserialize)]
struct GraphQlResponse {
    #[serde(default)]
    data: Option<IssueCreateData>,
    #[serde(default)]
    errors: Vec<GraphQlError>,
}

/// The `data` envelope on a successful `IssueCreate` response.
#[derive(Debug, Deserialize)]
struct IssueCreateData {
    #[serde(rename = "issueCreate")]
    issue_create: Option<IssueCreatePayload>,
}

/// The `issueCreate` mutation payload — `success` plus the created
/// issue's id / identifier / url.
#[derive(Debug, Deserialize)]
struct IssueCreatePayload {
    #[serde(default)]
    success: bool,
    #[serde(default)]
    issue: Option<IssueNode>,
}

/// Minimal projection of a Linear `Issue` node — we surface the
/// human-readable identifier (`SEC-42`) on the receipt and fall back to
/// the opaque id when the identifier is missing.
#[derive(Debug, Deserialize)]
struct IssueNode {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    identifier: Option<String>,
    #[serde(default)]
    url: Option<String>,
}

/// One GraphQL error entry. We key off `extensions.code` to map onto our
/// shared [`IncidentSinkError`] taxonomy.
#[derive(Debug, Deserialize)]
struct GraphQlError {
    #[serde(default)]
    message: String,
    #[serde(default)]
    extensions: Option<GraphQlErrorExtensions>,
}

/// Linear surfaces failure classification under `extensions.code`. We
/// only consume the `code` field; the rest of the structure is opaque to
/// us and varies by error kind.
#[derive(Debug, Deserialize)]
struct GraphQlErrorExtensions {
    #[serde(default)]
    code: Option<String>,
}

#[async_trait]
impl IncidentSinkPort for LinearIncidentSink {
    async fn emit(&self, event: &IncidentEvent) -> Result<EmissionReceipt, IncidentSinkError> {
        let body = self.build_payload(event);

        debug!(
            target: "sx_integrations::linear",
            team = %self.team_id,
            tenant = %event.tenant_id,
            severity = %event.severity,
            "emitting linear incident"
        );

        let resp = self
            .http
            .post(self.api_url.clone())
            .header(reqwest::header::AUTHORIZATION, self.api_key.expose_secret())
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header(reqwest::header::ACCEPT, "application/json")
            .json(&body)
            .send()
            .await?;

        let status = resp.status();

        // Linear's GraphQL surface returns 200 OK on both success and
        // most failure modes (auth / rate-limit / validation), and
        // reserves non-2xx for transport / infrastructure failures. Map
        // those eagerly so the body parser only ever sees a real GraphQL
        // envelope.
        if status == StatusCode::UNAUTHORIZED {
            warn!(target: "sx_integrations::linear", "linear returned 401");
            return Err(IncidentSinkError::Unauthenticated);
        }
        if status == StatusCode::FORBIDDEN {
            warn!(target: "sx_integrations::linear", "linear returned 403");
            return Err(IncidentSinkError::Unauthorised);
        }
        if status == StatusCode::TOO_MANY_REQUESTS {
            return Err(IncidentSinkError::RateLimited {
                retry_after: Some(Duration::from_secs(LINEAR_RATE_LIMIT_BACKOFF_SECS)),
            });
        }
        if !status.is_success() {
            let body_text = resp.text().await.unwrap_or_default();
            let truncated = truncate_body(&body_text);
            return Err(IncidentSinkError::BadGateway {
                status: status.as_u16(),
                body: truncated,
            });
        }

        let parsed: GraphQlResponse = resp.json().await?;

        // GraphQL errors travel inside the 200 OK envelope. Inspect the
        // first error's extensions.code to decide which IncidentSinkError
        // variant to surface; fall back to `Schema` for unknown codes.
        if let Some(err) = parsed.errors.first() {
            let code = err
                .extensions
                .as_ref()
                .and_then(|e| e.code.as_deref())
                .unwrap_or("");
            return Err(match code {
                "AUTHENTICATION_ERROR" => {
                    warn!(target: "sx_integrations::linear", "linear GraphQL authentication error");
                    IncidentSinkError::Unauthenticated
                }
                "RATELIMITED" => IncidentSinkError::RateLimited {
                    retry_after: Some(Duration::from_secs(LINEAR_RATE_LIMIT_BACKOFF_SECS)),
                },
                _ => IncidentSinkError::Schema(format!("Linear GraphQL: {}", err.message)),
            });
        }

        let payload = parsed.data.and_then(|d| d.issue_create).ok_or_else(|| {
            IncidentSinkError::Schema("Linear: missing issueCreate payload".into())
        })?;
        if !payload.success {
            return Err(IncidentSinkError::Schema(
                "Linear: issueCreate returned success=false".into(),
            ));
        }
        let issue = payload
            .issue
            .ok_or_else(|| IncidentSinkError::Schema("Linear: missing issue node".into()))?;

        // Prefer the human-readable identifier (`SEC-42`) on the receipt
        // — that's what operators type into Linear search. Fall back to
        // the opaque uuid when (in theory) Linear ever omits the
        // identifier.
        let external_id = issue.identifier.clone().or(issue.id).ok_or_else(|| {
            IncidentSinkError::Schema("Linear: issue node missing id+identifier".into())
        })?;
        let external_url = issue.url.unwrap_or_else(|| {
            // Linear's canonical issue URL format is opaque to us when
            // the API omits `url`; fall back to a search-friendly
            // placeholder containing the identifier so operators can
            // still find the issue manually.
            format!("https://linear.app/?issue={external_id}")
        });

        Ok(EmissionReceipt {
            external_id,
            external_url,
        })
    }

    fn name(&self) -> &'static str {
        "linear"
    }
}

/// Map a SentinelX [`Severity`] to Linear's fixed priority enum.
///
/// Linear's priority scale is `0 = No priority`, `1 = Urgent`, `2 =
/// High`, `3 = Medium`, `4 = Low`. We deliberately map `Info` to `0`
/// (No priority) rather than `4` (Low) so analysts can filter the high
/// queue without seeing informational noise.
#[must_use]
pub const fn severity_priority(sev: Severity) -> u8 {
    match sev {
        Severity::Critical => 1,
        Severity::High => 2,
        Severity::Medium => 3,
        Severity::Low => 4,
        Severity::Info => 0,
    }
}

/// One-line summary of the enrichment envelope, embedded in the Markdown
/// description so analysts see the key fields without expanding the JSON
/// code block.
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

fn truncate_body(body: &str) -> String {
    if body.len() <= MAX_VENDOR_BODY_BYTES {
        body.to_owned()
    } else {
        let mut end = MAX_VENDOR_BODY_BYTES;
        while !body.is_char_boundary(end) {
            end -= 1;
        }
        let mut s = body[..end].to_owned();
        s.push_str("…[truncated]");
        s
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
    use std::time::Duration;

    use super::*;
    use crate::incident_sink::{FindingDigest, IncidentKind};
    use sx_core::value_object::compliance::ComplianceTags;
    use wiremock::matchers::{body_partial_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn sink_for(server: &MockServer) -> LinearIncidentSink {
        let url = Url::parse(&format!("{}/graphql", server.uri())).unwrap();
        LinearIncidentSink::new(
            reqwest::Client::new(),
            url,
            SecretString::from("linear-api-key".to_owned()),
            "team-uuid".to_owned(),
            vec!["label-uuid-1".to_owned()],
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

    #[tokio::test]
    async fn happy_path_returns_receipt_with_linear_identifier() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/graphql"))
            .and(header("authorization", "linear-api-key"))
            .and(header("content-type", "application/json"))
            .and(body_partial_json(json!({
                "query": ISSUE_CREATE_MUTATION,
                "variables": {
                    "input": {
                        "teamId": "team-uuid",
                        "title": "[SentinelX] Critical SQLi at /login",
                        "priority": 1,
                        "labelIds": ["label-uuid-1"]
                    }
                }
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": {
                    "issueCreate": {
                        "success": true,
                        "issue": {
                            "id": "abc123",
                            "identifier": "SEC-42",
                            "url": "https://linear.app/acme/issue/SEC-42"
                        }
                    }
                }
            })))
            .expect(1)
            .mount(&server)
            .await;

        let sink = sink_for(&server);
        let receipt = sink
            .emit(&event(IncidentKind::FindingEmitted, Severity::Critical))
            .await
            .unwrap();
        assert_eq!(receipt.external_id, "SEC-42");
        assert_eq!(receipt.external_url, "https://linear.app/acme/issue/SEC-42");
    }

    #[tokio::test]
    async fn graphql_authentication_error_maps_to_unauthenticated() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/graphql"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "errors": [
                    {
                        "message": "bad key",
                        "extensions": { "code": "AUTHENTICATION_ERROR" }
                    }
                ]
            })))
            .mount(&server)
            .await;

        let sink = sink_for(&server);
        let err = sink
            .emit(&event(IncidentKind::FindingEmitted, Severity::High))
            .await
            .unwrap_err();
        assert!(matches!(err, IncidentSinkError::Unauthenticated));
    }

    #[tokio::test]
    async fn graphql_ratelimited_maps_to_rate_limited_with_60s_backoff() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/graphql"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "errors": [
                    {
                        "message": "slow down",
                        "extensions": { "code": "RATELIMITED" }
                    }
                ]
            })))
            .mount(&server)
            .await;

        let sink = sink_for(&server);
        let err = sink
            .emit(&event(IncidentKind::FindingEmitted, Severity::Critical))
            .await
            .unwrap_err();
        match err {
            IncidentSinkError::RateLimited { retry_after } => {
                assert_eq!(retry_after, Some(Duration::from_secs(60)));
            }
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn graphql_other_error_maps_to_schema() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/graphql"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "errors": [
                    {
                        "message": "team not found",
                        "extensions": { "code": "INVALID_INPUT" }
                    }
                ]
            })))
            .mount(&server)
            .await;

        let sink = sink_for(&server);
        let err = sink
            .emit(&event(IncidentKind::FindingEmitted, Severity::Medium))
            .await
            .unwrap_err();
        match err {
            IncidentSinkError::Schema(msg) => {
                assert!(msg.contains("Linear GraphQL"), "got: {msg}");
                assert!(msg.contains("team not found"), "got: {msg}");
            }
            other => panic!("expected Schema, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn http_5xx_maps_to_bad_gateway() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/graphql"))
            .respond_with(ResponseTemplate::new(503).set_body_string("upstream outage"))
            .mount(&server)
            .await;

        let sink = sink_for(&server);
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
    async fn http_429_maps_to_rate_limited_with_60s_backoff() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/graphql"))
            .respond_with(ResponseTemplate::new(429))
            .mount(&server)
            .await;

        let sink = sink_for(&server);
        let err = sink
            .emit(&event(IncidentKind::FindingEmitted, Severity::Critical))
            .await
            .unwrap_err();
        match err {
            IncidentSinkError::RateLimited { retry_after } => {
                assert_eq!(retry_after, Some(Duration::from_secs(60)));
            }
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn body_shape_matches_issue_create_mutation_and_variables() {
        // Explicit body-shape assertion: the posted JSON must carry the
        // exact mutation string and the canonical variables.input fields
        // (teamId, title, priority).
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/graphql"))
            .and(body_partial_json(json!({
                "query": ISSUE_CREATE_MUTATION,
                "variables": {
                    "input": {
                        "teamId": "team-uuid",
                        "title": "[SentinelX] Critical SQLi at /login",
                        "priority": 1
                    }
                }
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": {
                    "issueCreate": {
                        "success": true,
                        "issue": { "id": "x", "identifier": "SEC-1", "url": "https://linear.app/x" }
                    }
                }
            })))
            .expect(1)
            .mount(&server)
            .await;

        let sink = sink_for(&server);
        sink.emit(&event(IncidentKind::FindingEmitted, Severity::Critical))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn success_false_surfaces_as_schema_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/graphql"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": {
                    "issueCreate": {
                        "success": false,
                        "issue": null
                    }
                }
            })))
            .mount(&server)
            .await;

        let sink = sink_for(&server);
        let err = sink
            .emit(&event(IncidentKind::FindingEmitted, Severity::Medium))
            .await
            .unwrap_err();
        assert!(matches!(err, IncidentSinkError::Schema(_)));
    }

    #[test]
    fn severity_priority_mapping_is_stable() {
        assert_eq!(severity_priority(Severity::Critical), 1);
        assert_eq!(severity_priority(Severity::High), 2);
        assert_eq!(severity_priority(Severity::Medium), 3);
        assert_eq!(severity_priority(Severity::Low), 4);
        assert_eq!(severity_priority(Severity::Info), 0);
    }

    #[test]
    fn debug_impl_redacts_api_key() {
        let sink = LinearIncidentSink::new(
            reqwest::Client::new(),
            Url::parse(DEFAULT_API_URL).unwrap(),
            SecretString::from("super-secret-linear-key".to_owned()),
            "team-uuid".to_owned(),
            Vec::new(),
        );
        let dbg = format!("{sink:?}");
        assert!(
            !dbg.contains("super-secret-linear-key"),
            "key leaked in Debug: {dbg}"
        );
        assert!(dbg.contains("<redacted>"));
    }

    #[test]
    fn truncate_body_keeps_short_bodies_intact() {
        assert_eq!(truncate_body("short"), "short");
    }

    #[test]
    fn truncate_body_truncates_long_bodies_with_marker() {
        let s = "a".repeat(MAX_VENDOR_BODY_BYTES + 100);
        let out = truncate_body(&s);
        assert!(out.len() < s.len());
        assert!(out.ends_with("…[truncated]"));
    }
}
