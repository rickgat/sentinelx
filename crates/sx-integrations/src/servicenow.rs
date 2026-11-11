//! ServiceNow Table API incident-sink adapter (TOP5-#5-FU1).
//!
//! Implements [`IncidentSinkPort`] for the ServiceNow Table API
//! (`POST <base_url>/api/now/table/incident`). Mirrors the
//! [`crate::jira_incident`] / [`crate::pagerduty`] shape: vendor adapter
//! consumes an [`IncidentEvent`], emits a vendor-side record, returns an
//! [`EmissionReceipt`] carrying the `sys_id` and the canonical
//! `nav_to.do` navigation URL.
//!
//! ## Endpoint
//!
//! `POST {base_url}/api/now/table/incident` — ServiceNow's standard
//! Table API for the `incident` table. See
//! <https://developer.servicenow.com/dev.do#!/reference/api/utah/rest/c_TableAPI>
//! for the canonical contract.
//!
//! ## Authentication
//!
//! HTTP Basic — `Authorization: Basic base64(user:password)`. The MVP
//! does not implement OAuth (`TOP5-#5-FU1` scope explicitly limits us to
//! basic auth); operators that need OAuth track it as a future
//! enhancement on this ticket.
//!
//! The password is wrapped in [`SecretString`] so it never appears in
//! `Debug` output, panic messages, or `tracing` spans.
//!
//! ## ITIL severity mapping
//!
//! ServiceNow tracks two independent dimensions: `impact` (business
//! impact) and `urgency` (time-criticality), each on a 1..=3 scale (1
//! highest, 3 lowest). The incident `priority` is derived server-side
//! from the impact × urgency matrix. We map SentinelX [`Severity`] per
//! ITIL Service Operation guidance:
//!
//! | SentinelX  | impact | urgency |
//! |------------|--------|---------|
//! | `Critical` |   1    |   1     |
//! | `High`     |   1    |   2     |
//! | `Medium`   |   2    |   3     |
//! | `Low`      |   3    |   3     |
//! | `Info`     |   3    |   4     |
//!
//! `Info` maps `urgency = 4` to model an explicitly *non-urgent*
//! informational drop, even though ServiceNow's default OOB choice list
//! ends at 3 — operators that have not extended the choice list will see
//! ServiceNow snap the value to 3 on insert, which still preserves the
//! ordering.
//!
//! ## Idempotency
//!
//! Every event carries a `correlation_id` of the shape
//! `{tenant_id}:{finding_id|synthetic-kind-key}`. ServiceNow's
//! `correlation_id` column is the canonical operator-side dedup key —
//! retries from the SentinelX side surface a duplicate-correlation
//! warning rather than spawning multiple incidents.
//!
//! ## Error taxonomy
//!
//! Maps Table API responses onto the shared [`IncidentSinkError`]:
//!
//! * `401` → [`IncidentSinkError::Unauthenticated`].
//! * `403` → [`IncidentSinkError::Unauthorised`].
//! * `429` → [`IncidentSinkError::RateLimited`] (parses `Retry-After`).
//! * `>= 500` (or other non-2xx) → [`IncidentSinkError::BadGateway`].

use std::fmt;

use async_trait::async_trait;
use base64::Engine;
use reqwest::{Client, StatusCode, Url};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use serde_json::Value;
use sx_core::value_object::severity::Severity;
use tracing::{debug, warn};

use crate::incident_sink::{
    parse_retry_after_secs, EmissionReceipt, IncidentEvent, IncidentKind, IncidentSinkError,
    IncidentSinkPort,
};

/// Table API incident-create endpoint path, appended to the configured
/// base URL.
const INCIDENT_PATH: &str = "api/now/table/incident";

/// Cap on the size of the vendor error body captured into
/// [`IncidentSinkError::BadGateway::body`].
const MAX_VENDOR_BODY_BYTES: usize = 4096;

/// Constant `category` value stamped on every emitted incident. The MVP
/// has a single category; operators that want per-event category mapping
/// extend this in a follow-up.
const SERVICENOW_CATEGORY: &str = "security";

/// ServiceNow Table API incident-sink adapter.
///
/// Construct one per ServiceNow instance — different tenants targeting
/// different instances each get their own sink, and the monolith
/// composition root registers the subset the operator has enabled.
/// `Send + Sync`; share via `Arc<dyn IncidentSinkPort>`.
pub struct ServiceNowIncidentSink {
    http: Client,
    base_url: Url,
    user: String,
    password: SecretString,
    assignment_group: Option<String>,
}

impl fmt::Debug for ServiceNowIncidentSink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServiceNowIncidentSink")
            .field("base_url", &self.base_url.as_str())
            .field("user", &self.user)
            .field("password", &"<redacted>")
            .field("assignment_group", &self.assignment_group)
            .finish_non_exhaustive()
    }
}

impl ServiceNowIncidentSink {
    /// Construct a new sink.
    ///
    /// `base_url` is the ServiceNow instance root, e.g.
    /// `https://acme.service-now.com/`. `user` + `password` are the basic
    /// auth credentials (typically a dedicated ServiceNow integration
    /// user with the `itil` role). `assignment_group` is the optional
    /// `sys_id` of the group that should pick the incident up — when
    /// `None` ServiceNow's default assignment rules run.
    #[must_use]
    pub const fn new(
        http: Client,
        base_url: Url,
        user: String,
        password: SecretString,
        assignment_group: Option<String>,
    ) -> Self {
        Self {
            http,
            base_url,
            user,
            password,
            assignment_group,
        }
    }

    /// Render the `Authorization: Basic ...` header value. Held inside a
    /// [`SecretString`] so the rendered value never materialises into a
    /// `Debug`-able owned string elsewhere.
    fn authorization_header(&self) -> SecretString {
        let raw = format!("{}:{}", self.user, self.password.expose_secret());
        let encoded = base64::engine::general_purpose::STANDARD.encode(raw.as_bytes());
        SecretString::from(format!("Basic {encoded}"))
    }

    /// Compose the Table API incident-create body for `event`.
    ///
    /// Stamps:
    /// * `short_description` ← `event.title`.
    /// * `description` ← rendered prose + an enrichment summary block
    ///   (CVSS / CWE / MITRE ATT&CK / compliance) so analysts see the key
    ///   fields without opening the full JSON.
    /// * `impact` + `urgency` ← ITIL mapping from `event.severity`.
    /// * `category` ← constant `"security"`.
    /// * `assignment_group` ← config pass-through (omitted when `None`).
    /// * `correlation_id` ← `{tenant_id}:{finding_id|synthetic-key}`.
    fn build_payload(&self, event: &IncidentEvent) -> Value {
        let (impact, urgency) = severity_impact_urgency(event.severity);

        let mut body = serde_json::Map::new();
        body.insert(
            "short_description".to_owned(),
            Value::String(truncate_short_description(&event.title)),
        );
        body.insert(
            "description".to_owned(),
            Value::String(render_description(event)),
        );
        body.insert("impact".to_owned(), Value::from(u64::from(impact)));
        body.insert("urgency".to_owned(), Value::from(u64::from(urgency)));
        body.insert(
            "category".to_owned(),
            Value::String(SERVICENOW_CATEGORY.to_owned()),
        );
        body.insert(
            "correlation_id".to_owned(),
            Value::String(derive_correlation_id(event)),
        );
        if let Some(group) = self.assignment_group.as_deref() {
            body.insert(
                "assignment_group".to_owned(),
                Value::String(group.to_owned()),
            );
        }

        Value::Object(body)
    }

    /// Build the canonical browser navigation URL for an incident given
    /// its `sys_id`. ServiceNow's standard pattern is
    /// `<base>/nav_to.do?uri=/incident.do?sys_id=<sys_id>`.
    fn navigation_url(&self, sys_id: &str) -> String {
        // We deliberately build the URL by string concatenation rather
        // than `Url::set_path` + `set_query`, because ServiceNow's
        // `nav_to.do?uri=` value embeds a literal `?` inside the query
        // string — the only way `Url`'s percent-encoding logic preserves
        // that shape is to feed it the raw, hand-encoded string.
        let mut url = self.base_url.to_string();
        if !url.ends_with('/') {
            url.push('/');
        }
        url.push_str("nav_to.do?uri=/incident.do?sys_id=");
        url.push_str(sys_id);
        url
    }
}

/// Minimal projection of the Table API `POST /api/now/table/incident`
/// response. ServiceNow returns the inserted row under `result`; we only
/// surface `sys_id` (vendor-side primary identifier) and the
/// human-readable `number` (e.g. `INC0010023`) — `number` is preferred
/// for `EmissionReceipt.external_id` when present because that is what
/// operators see in the UI; we fall back to `sys_id` when the field is
/// absent (the spec guarantees both but defensive coding is cheap).
#[derive(Debug, Deserialize)]
struct ServiceNowInsertResponse {
    result: ServiceNowInsertResult,
}

#[derive(Debug, Deserialize)]
struct ServiceNowInsertResult {
    #[serde(default)]
    sys_id: Option<String>,
    #[serde(default)]
    number: Option<String>,
}

#[async_trait]
impl IncidentSinkPort for ServiceNowIncidentSink {
    async fn emit(&self, event: &IncidentEvent) -> Result<EmissionReceipt, IncidentSinkError> {
        let endpoint = self
            .base_url
            .join(INCIDENT_PATH)
            .map_err(IncidentSinkError::schema)?;

        let body = self.build_payload(event);

        debug!(
            target: "sx_integrations::servicenow",
            tenant = %event.tenant_id,
            severity = %event.severity,
            "emitting servicenow incident"
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
            warn!(target: "sx_integrations::servicenow", "servicenow returned 401");
            return Err(IncidentSinkError::Unauthenticated);
        }
        if status == StatusCode::FORBIDDEN {
            warn!(target: "sx_integrations::servicenow", "servicenow returned 403");
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
            // 4xx (other than 401/403/429) plus 5xx all collapse onto
            // `BadGateway` — they share the "the vendor wouldn't accept
            // this; retry identically" treatment the fan-out applies.
            return Err(IncidentSinkError::BadGateway {
                status: status.as_u16(),
                body: truncated,
            });
        }

        let parsed: ServiceNowInsertResponse = resp.json().await?;
        let sys_id = parsed.result.sys_id.unwrap_or_default();
        if sys_id.is_empty() {
            return Err(IncidentSinkError::schema(
                "servicenow response missing result.sys_id",
            ));
        }
        let external_url = self.navigation_url(&sys_id);
        let external_id = parsed.result.number.unwrap_or(sys_id);

        Ok(EmissionReceipt {
            external_id,
            external_url,
        })
    }

    fn name(&self) -> &'static str {
        "servicenow"
    }
}

/// Map a SentinelX [`Severity`] to its `(impact, urgency)` ITIL pair.
///
/// See the table in the module-level docs for the rationale.
#[must_use]
pub const fn severity_impact_urgency(sev: Severity) -> (u8, u8) {
    match sev {
        Severity::Critical => (1, 1),
        Severity::High => (1, 2),
        Severity::Medium => (2, 3),
        Severity::Low => (3, 3),
        Severity::Info => (3, 4),
    }
}

/// Derive a deterministic correlation id from an [`IncidentEvent`].
///
/// Shape: `{tenant_id}:{finding_id}` when the event carries a finding;
/// `{tenant_id}:sx-{kind}-{title}` for playbook + audit-break events so
/// distinct events stay distinct on the operator side. ServiceNow's
/// `correlation_id` column is its canonical dedup key — retries with the
/// same value land on the same incident.
fn derive_correlation_id(event: &IncidentEvent) -> String {
    event.finding.as_ref().map_or_else(
        || {
            let kind = match event.kind {
                IncidentKind::FindingEmitted => "finding",
                IncidentKind::PlaybookTriggered => "playbook",
                IncidentKind::AuditChainBreak => "audit-break",
            };
            format!("{}:sx-{}-{}", event.tenant_id, kind, event.title)
        },
        |digest| format!("{}:{}", event.tenant_id, digest.id),
    )
}

/// Render the long-form description: the event prose followed by a
/// human-readable enrichment summary (CVSS / CWE / MITRE / compliance).
/// ServiceNow's `description` column renders the value as plain text —
/// markdown-ish formatting is fine but does not get parsed.
fn render_description(event: &IncidentEvent) -> String {
    use std::fmt::Write as _;

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
    let compliance = format!("{:?}", event.compliance);

    let mut out = String::with_capacity(event.description.len() + 256);
    out.push_str(&event.description);
    out.push_str("\n\n---\nSentinelX enrichment\n");
    // `writeln!` into a String never fails — the `_ =` discards the
    // `Result` cleanly without dragging the `expect`/`unwrap` clippy
    // lints into the call chain.
    let _ = writeln!(out, "- Severity: {}", event.severity);
    let _ = writeln!(out, "- CVSS: {cvss}");
    let _ = writeln!(out, "- CWE: {cwe}");
    let _ = writeln!(out, "- MITRE ATT&CK: {attack}");
    let _ = writeln!(out, "- Compliance: {compliance}");
    if let Some(src) = event.source_url.as_ref() {
        let _ = writeln!(out, "- SentinelX link: {src}");
    }
    out
}

/// ServiceNow's `short_description` column is a `string(160)`. We trim
/// preemptively rather than risk a 400.
fn truncate_short_description(s: &str) -> String {
    const SHORT_DESCRIPTION_CAP: usize = 160;
    if s.len() <= SHORT_DESCRIPTION_CAP {
        s.to_owned()
    } else {
        let mut end = SHORT_DESCRIPTION_CAP;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        s[..end].to_owned()
    }
}

/// Truncate a vendor response body to [`MAX_VENDOR_BODY_BYTES`].
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
    use crate::incident_sink::FindingDigest;
    use serde_json::json;
    use sx_core::value_object::compliance::ComplianceTags;
    use wiremock::matchers::{body_partial_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn sink_for(server: &MockServer) -> ServiceNowIncidentSink {
        let base = Url::parse(&format!("{}/", server.uri())).unwrap();
        ServiceNowIncidentSink::new(
            reqwest::Client::new(),
            base,
            "sx-integration".to_owned(),
            SecretString::from("snow-password".to_owned()),
            Some("group-sys-id-1234".to_owned()),
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
        let raw = "sx-integration:snow-password";
        let encoded = base64::engine::general_purpose::STANDARD.encode(raw.as_bytes());
        format!("Basic {encoded}")
    }

    #[tokio::test]
    async fn happy_path_returns_receipt_with_servicenow_number_and_nav_url() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/now/table/incident"))
            .and(header(
                "authorization",
                expected_basic_auth_header().as_str(),
            ))
            .and(header("content-type", "application/json"))
            .and(body_partial_json(json!({
                "short_description": "[SentinelX] Critical SQLi at /login",
                "category": "security",
                "impact": 1,
                "urgency": 1,
                "assignment_group": "group-sys-id-1234",
                "correlation_id": "t-1:f-1"
            })))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "result": {
                    "sys_id": "abc123def456",
                    "number": "INC0010023"
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
        // `number` is preferred for `external_id` when present (matches
        // the value operators see in the UI).
        assert_eq!(receipt.external_id, "INC0010023");
        assert!(
            receipt
                .external_url
                .contains("nav_to.do?uri=/incident.do?sys_id=abc123def456"),
            "external_url missing nav pattern: {}",
            receipt.external_url
        );
    }

    #[tokio::test]
    async fn happy_path_falls_back_to_sys_id_when_number_absent() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/now/table/incident"))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "result": { "sys_id": "INC0010023" }
            })))
            .expect(1)
            .mount(&server)
            .await;

        let sink = sink_for(&server);
        let receipt = sink
            .emit(&event(IncidentKind::FindingEmitted, Severity::Critical))
            .await
            .unwrap();
        assert_eq!(receipt.external_id, "INC0010023");
        assert!(receipt
            .external_url
            .contains("nav_to.do?uri=/incident.do?sys_id=INC0010023"));
    }

    #[tokio::test]
    async fn unauthorised_401_maps_to_unauthenticated() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/now/table/incident"))
            .respond_with(ResponseTemplate::new(401))
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
    async fn forbidden_403_maps_to_unauthorised() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/now/table/incident"))
            .respond_with(ResponseTemplate::new(403))
            .mount(&server)
            .await;

        let sink = sink_for(&server);
        let err = sink
            .emit(&event(IncidentKind::PlaybookTriggered, Severity::High))
            .await
            .unwrap_err();
        assert!(matches!(err, IncidentSinkError::Unauthorised));
    }

    #[tokio::test]
    async fn rate_limited_429_returns_retry_after_30s() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/now/table/incident"))
            .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "30"))
            .mount(&server)
            .await;

        let sink = sink_for(&server);
        let err = sink
            .emit(&event(IncidentKind::FindingEmitted, Severity::Critical))
            .await
            .unwrap_err();
        match err {
            IncidentSinkError::RateLimited { retry_after } => {
                assert_eq!(retry_after, Some(Duration::from_secs(30)));
            }
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn server_error_5xx_maps_to_bad_gateway() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/now/table/incident"))
            .respond_with(ResponseTemplate::new(503).set_body_string("snow outage"))
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
                assert!(body.contains("snow outage"));
            }
            other => panic!("expected BadGateway, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn payload_stamps_impact_urgency_for_high_severity() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/now/table/incident"))
            .and(body_partial_json(json!({
                "category": "security",
                "impact": 1,
                "urgency": 2
            })))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "result": { "sys_id": "x" }
            })))
            .expect(1)
            .mount(&server)
            .await;

        let sink = sink_for(&server);
        sink.emit(&event(IncidentKind::FindingEmitted, Severity::High))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn payload_omits_assignment_group_when_unset() {
        let server = MockServer::start().await;
        // Match any POST and capture the body to assert it does NOT
        // include `assignment_group`.
        Mock::given(method("POST"))
            .and(path("/api/now/table/incident"))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "result": { "sys_id": "x" }
            })))
            .expect(1)
            .mount(&server)
            .await;

        let base = Url::parse(&format!("{}/", server.uri())).unwrap();
        let sink = ServiceNowIncidentSink::new(
            reqwest::Client::new(),
            base,
            "sx-integration".to_owned(),
            SecretString::from("snow-password".to_owned()),
            None,
        );
        sink.emit(&event(IncidentKind::FindingEmitted, Severity::Critical))
            .await
            .unwrap();
        // No assertion possible on absent field via body_partial_json;
        // the build_payload unit test below covers the omission.
        let payload = sink.build_payload(&event(IncidentKind::FindingEmitted, Severity::Critical));
        assert!(
            payload.get("assignment_group").is_none(),
            "assignment_group must be omitted when config is None"
        );
    }

    #[tokio::test]
    async fn missing_sys_id_in_response_maps_to_schema_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/now/table/incident"))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "result": { "number": "INC0010023" }
            })))
            .mount(&server)
            .await;

        let sink = sink_for(&server);
        let err = sink
            .emit(&event(IncidentKind::FindingEmitted, Severity::Critical))
            .await
            .unwrap_err();
        match err {
            IncidentSinkError::Schema(msg) => {
                assert!(msg.contains("sys_id"), "expected sys_id in error: {msg}");
            }
            other => panic!("expected Schema, got {other:?}"),
        }
    }

    #[test]
    fn severity_impact_urgency_matches_itil_table() {
        assert_eq!(severity_impact_urgency(Severity::Critical), (1, 1));
        assert_eq!(severity_impact_urgency(Severity::High), (1, 2));
        assert_eq!(severity_impact_urgency(Severity::Medium), (2, 3));
        assert_eq!(severity_impact_urgency(Severity::Low), (3, 3));
        assert_eq!(severity_impact_urgency(Severity::Info), (3, 4));
    }

    #[test]
    fn correlation_id_uses_finding_id_when_present() {
        let id = derive_correlation_id(&event(IncidentKind::FindingEmitted, Severity::Critical));
        assert_eq!(id, "t-1:f-1");
    }

    #[test]
    fn correlation_id_for_playbook_uses_kind_and_title() {
        let mut e = event(IncidentKind::PlaybookTriggered, Severity::High);
        e.finding = None;
        let id = derive_correlation_id(&e);
        assert!(id.starts_with("t-1:sx-playbook-"));
        assert!(id.contains("Critical SQLi at /login"));
    }

    #[test]
    fn debug_impl_redacts_password() {
        let sink = ServiceNowIncidentSink::new(
            reqwest::Client::new(),
            Url::parse("https://acme.service-now.com/").unwrap(),
            "sx-integration".to_owned(),
            SecretString::from("super-secret-password".to_owned()),
            None,
        );
        let dbg = format!("{sink:?}");
        assert!(dbg.contains("sx-integration"));
        assert!(
            !dbg.contains("super-secret-password"),
            "password leaked in Debug: {dbg}"
        );
        assert!(dbg.contains("<redacted>"));
    }

    #[test]
    fn truncate_short_description_caps_at_160_chars() {
        let s = "a".repeat(500);
        let out = truncate_short_description(&s);
        assert_eq!(out.len(), 160);
    }

    #[test]
    fn truncate_short_description_keeps_short_strings_intact() {
        assert_eq!(truncate_short_description("short"), "short");
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

    #[test]
    fn navigation_url_includes_sys_id_and_nav_path() {
        let sink = ServiceNowIncidentSink::new(
            reqwest::Client::new(),
            Url::parse("https://acme.service-now.com/").unwrap(),
            "u".to_owned(),
            SecretString::from("p".to_owned()),
            None,
        );
        let url = sink.navigation_url("abc123");
        assert_eq!(
            url,
            "https://acme.service-now.com/nav_to.do?uri=/incident.do?sys_id=abc123"
        );
    }
}
