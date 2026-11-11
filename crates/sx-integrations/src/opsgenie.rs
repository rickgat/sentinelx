//! Opsgenie Alerts API v2 incident-sink adapter (TOP5-#5-FU3).
//!
//! Mirrors [`crate::pagerduty`] for Atlassian Opsgenie. Opsgenie's
//! `POST /v2/alerts` endpoint is the natural analogue of PagerDuty's
//! `enqueue` — a single REST call mints an alert that on-call rotations
//! and escalation policies hang off.
//!
//! ## Endpoint
//!
//! `POST {api_url}/v2/alerts`. The default `api_url` is
//! `https://api.opsgenie.com`; operators on the EU residency plan
//! override it to `https://api.eu.opsgenie.com`. The endpoint is
//! configurable so wiremock tests can target a local mock server.
//!
//! See <https://docs.opsgenie.com/docs/alert-api> for the canonical
//! Alerts API v2 contract.
//!
//! ## Authentication
//!
//! Integration-key auth via the `Authorization: GenieKey <api_key>`
//! header — note the `GenieKey ` prefix (NOT `Bearer`). The key is wrapped
//! in [`SecretString`] so the value never reaches `Debug` output, panics,
//! or tracing spans.
//!
//! ## Severity mapping
//!
//! Opsgenie has a five-band priority scale (`P1..P5`) that lines up 1:1
//! with SentinelX's [`Severity`]:
//!
//! | SentinelX  | Opsgenie |
//! |------------|----------|
//! | `Critical` | `P1`     |
//! | `High`     | `P2`     |
//! | `Medium`   | `P3`     |
//! | `Low`      | `P4`     |
//! | `Info`     | `P5`     |
//!
//! Unlike PagerDuty (whose lowest band is `info`, collapsing `Low` and
//! `Info`), Opsgenie preserves the full SentinelX severity ladder.
//!
//! ## Idempotency
//!
//! Every alert carries an `alias` derived from `(tenant_id, finding.id)`
//! (or a deterministic kind-specific string for non-finding events).
//! Opsgenie uses alias as the dedup key — re-sending the same event
//! collapses onto the existing open alert.
//!
//! ## Error taxonomy
//!
//! Maps Alerts API v2 responses onto the shared [`IncidentSinkError`].
//! `202 Accepted` is the documented success status; Opsgenie returns a
//! `data.requestId` rather than a stable URL, so the receipt's
//! `external_url` is a best-effort search link
//! (`https://app.opsgenie.com/alert/list?query=alias:<alias>`).

use std::fmt::{self, Write as _};

use async_trait::async_trait;
use reqwest::{Client, StatusCode, Url};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use serde_json::{json, Value};
use sx_core::value_object::severity::Severity;
use tracing::{debug, warn};

use crate::incident_sink::{
    parse_retry_after_secs, EmissionReceipt, IncidentEvent, IncidentKind, IncidentSinkError,
    IncidentSinkPort,
};

/// Default Opsgenie Alerts API host (US datacentre). Operators on the EU
/// residency plan override this to `https://api.eu.opsgenie.com`.
pub const DEFAULT_API_URL: &str = "https://api.opsgenie.com";

/// Default `Retry-After` fallback when Opsgenie returns 429 without a
/// header value. 60 seconds matches the vendor's published rate-limit
/// guidance.
const DEFAULT_RATE_LIMIT_RETRY_SECS: u64 = 60;

/// Cap on the size of the vendor error body captured into
/// [`IncidentSinkError::BadGateway::body`].
const MAX_VENDOR_BODY_BYTES: usize = 2048;

/// Opsgenie alert priority values (`P1..P5`).
///
/// Distinct enum (rather than a bare `&'static str`) so the conversion
/// table lives in one place and unit tests can lock down the mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpsgeniePriority {
    /// Highest priority. Maps from SentinelX `Critical`.
    P1,
    /// Maps from SentinelX `High`.
    P2,
    /// Maps from SentinelX `Medium`.
    P3,
    /// Maps from SentinelX `Low`.
    P4,
    /// Lowest priority. Maps from SentinelX `Info`.
    P5,
}

impl OpsgeniePriority {
    /// Convert a SentinelX [`Severity`] into the matching Opsgenie
    /// priority. The full five-band ladder is preserved 1:1.
    #[must_use]
    pub const fn from_sx_severity(sev: Severity) -> Self {
        match sev {
            Severity::Critical => Self::P1,
            Severity::High => Self::P2,
            Severity::Medium => Self::P3,
            Severity::Low => Self::P4,
            Severity::Info => Self::P5,
        }
    }

    /// Wire form (the upper-case `P1..P5` value the Alerts API expects).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::P1 => "P1",
            Self::P2 => "P2",
            Self::P3 => "P3",
            Self::P4 => "P4",
            Self::P5 => "P5",
        }
    }
}

/// Opsgenie Alerts API v2 incident-sink adapter.
///
/// Construct one per integration key — different Opsgenie teams (e.g.
/// "engineering on-call", "security incident response") each get their
/// own sink instance, and the monolith fan-out registers any subset that
/// the operator has enabled.
pub struct OpsgenieIncidentSink {
    http: Client,
    alerts_url: Url,
    api_key: SecretString,
    source_override: Option<String>,
}

impl fmt::Debug for OpsgenieIncidentSink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpsgenieIncidentSink")
            .field("alerts_url", &self.alerts_url.as_str())
            .field("api_key", &"<redacted>")
            .field("source_override", &self.source_override)
            .finish_non_exhaustive()
    }
}

impl OpsgenieIncidentSink {
    /// Construct a new sink. `alerts_url` is the full Alerts API v2
    /// endpoint (typically `<api_url>/v2/alerts`). `api_key` is the
    /// per-integration shared secret. When `source_override` is `Some`,
    /// every event uses that value as `source`; when `None`, the emitting
    /// tenant id travels in `source` so Opsgenie's alert-list filters
    /// work per tenant.
    #[must_use]
    pub const fn new(
        http: Client,
        alerts_url: Url,
        api_key: SecretString,
        source_override: Option<String>,
    ) -> Self {
        Self {
            http,
            alerts_url,
            api_key,
            source_override,
        }
    }

    /// Compose the Alerts API v2 create-alert body for `event`.
    fn build_payload(&self, event: &IncidentEvent) -> (Value, String) {
        let alias = derive_alias(event);
        let source = self
            .source_override
            .clone()
            .unwrap_or_else(|| event.tenant_id.clone());
        let priority = OpsgeniePriority::from_sx_severity(event.severity);

        let description = render_description(event);
        let details = build_details(event);

        let mut body = serde_json::Map::new();
        body.insert(
            "message".to_owned(),
            Value::String(truncate_message(&event.title)),
        );
        body.insert("description".to_owned(), Value::String(description));
        body.insert("alias".to_owned(), Value::String(alias.clone()));
        body.insert(
            "priority".to_owned(),
            Value::String(priority.as_str().to_owned()),
        );
        body.insert("source".to_owned(), Value::String(source));
        body.insert(
            "tags".to_owned(),
            json!(["sentinelx", kind_tag(event.kind)]),
        );
        body.insert("details".to_owned(), Value::Object(details));

        (Value::Object(body), alias)
    }
}

/// Minimal projection of the Alerts API v2 create-alert response.
///
/// Opsgenie returns a wrapping object — `{ result, took, requestId }` —
/// where `requestId` carries through as `data.requestId` once the alert
/// is asynchronously materialised. We accept both shapes (top-level and
/// `data.requestId`) for forward compatibility.
#[derive(Debug, Deserialize)]
struct CreateAlertResponse {
    #[serde(default, rename = "requestId")]
    request_id: Option<String>,
    #[serde(default)]
    data: Option<CreateAlertData>,
    #[serde(default)]
    result: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CreateAlertData {
    #[serde(default, rename = "requestId")]
    request_id: Option<String>,
}

/// Minimal projection of an Opsgenie error response.
#[derive(Debug, Deserialize)]
struct OpsgenieErrorBody {
    #[serde(default)]
    message: Option<String>,
}

#[async_trait]
impl IncidentSinkPort for OpsgenieIncidentSink {
    async fn emit(&self, event: &IncidentEvent) -> Result<EmissionReceipt, IncidentSinkError> {
        let (body, alias) = self.build_payload(event);

        debug!(
            target: "sx_integrations::opsgenie",
            tenant = %event.tenant_id,
            severity = %event.severity,
            "emitting opsgenie alert"
        );

        let auth_header = format!("GenieKey {}", self.api_key.expose_secret());

        let resp = self
            .http
            .post(self.alerts_url.clone())
            .header(reqwest::header::AUTHORIZATION, auth_header)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header(reqwest::header::ACCEPT, "application/json")
            .json(&body)
            .send()
            .await?;

        let status = resp.status();

        if status == StatusCode::UNAUTHORIZED {
            warn!(target: "sx_integrations::opsgenie", "opsgenie returned 401");
            return Err(IncidentSinkError::Unauthenticated);
        }
        if status == StatusCode::FORBIDDEN {
            warn!(target: "sx_integrations::opsgenie", "opsgenie returned 403");
            return Err(IncidentSinkError::Unauthorised);
        }
        if status == StatusCode::TOO_MANY_REQUESTS {
            let retry_after = parse_retry_after_secs(
                resp.headers()
                    .get(reqwest::header::RETRY_AFTER)
                    .and_then(|v| v.to_str().ok()),
            )
            .or_else(|| {
                Some(std::time::Duration::from_secs(
                    DEFAULT_RATE_LIMIT_RETRY_SECS,
                ))
            });
            return Err(IncidentSinkError::RateLimited { retry_after });
        }
        if status == StatusCode::UNPROCESSABLE_ENTITY {
            let body_text = resp.text().await.unwrap_or_default();
            let message = serde_json::from_str::<OpsgenieErrorBody>(&body_text)
                .ok()
                .and_then(|b| b.message)
                .unwrap_or_else(|| truncate_body(&body_text));
            return Err(IncidentSinkError::Schema(message));
        }
        // Opsgenie returns 202 Accepted on success. Treat any 2xx as
        // success to stay tolerant of future protocol tweaks.
        if !status.is_success() {
            let body_text = resp.text().await.unwrap_or_default();
            let truncated = truncate_body(&body_text);
            return Err(IncidentSinkError::BadGateway {
                status: status.as_u16(),
                body: truncated,
            });
        }

        let parsed: CreateAlertResponse = resp.json().await?;
        let request_id = parsed
            .data
            .as_ref()
            .and_then(|d| d.request_id.clone())
            .or_else(|| parsed.request_id.clone())
            .unwrap_or_else(|| alias.clone());

        // Opsgenie does NOT return a stable browser URL on the create
        // response (alerts materialise asynchronously). The canonical
        // "view alerts with this alias" search URL is the best we can do
        // synchronously; the dashboard contract treats `external_url` as
        // a best-effort deep-link.
        let external_url = format!("https://app.opsgenie.com/alert/list?query=alias:{alias}");

        debug!(
            target: "sx_integrations::opsgenie",
            request_id = %request_id,
            alias = %alias,
            result = parsed.result.as_deref().unwrap_or("Request will be processed"),
            "opsgenie create-alert accepted"
        );

        Ok(EmissionReceipt {
            external_id: request_id,
            external_url,
        })
    }

    fn name(&self) -> &'static str {
        "opsgenie"
    }
}

/// Derive a deterministic alias from an [`IncidentEvent`].
///
/// Opsgenie collapses repeated create-alert calls with the same alias
/// onto the existing open alert. Stable per `(tenant_id, finding.id)` so
/// re-emissions of the same finding never spawn multiple alerts; for
/// non-finding events the alias embeds the kind + title so distinct
/// events stay distinct.
fn derive_alias(event: &IncidentEvent) -> String {
    event.finding.as_ref().map_or_else(
        || {
            let kind = kind_tag(event.kind);
            format!("sx::{}::{}::{}", event.tenant_id, kind, event.title)
        },
        |digest| format!("sx::{}::finding::{}", event.tenant_id, digest.id),
    )
}

/// Map an [`IncidentKind`] to a short, stable tag for the alert's `tags`
/// array (also embedded in non-finding aliases).
const fn kind_tag(kind: IncidentKind) -> &'static str {
    match kind {
        IncidentKind::FindingEmitted => "finding",
        IncidentKind::PlaybookTriggered => "playbook",
        IncidentKind::AuditChainBreak => "audit-break",
    }
}

/// Render a long-form description that combines the human-readable
/// description with a structured CVSS / CWE / MITRE / compliance block.
/// Opsgenie surfaces `description` verbatim in the alert UI; we keep the
/// extra metadata both here (for humans) and in `details` (for filters /
/// integrations).
fn render_description(event: &IncidentEvent) -> String {
    let mut out = String::with_capacity(event.description.len() + 256);
    out.push_str(&event.description);
    out.push_str("\n\n---\n");
    if let Some(cvss) = event.cvss.as_ref() {
        // `writeln!` into a `String` is infallible.
        let _ = writeln!(out, "CVSS v3.1 base score: {:.1}", cvss.base_score);
    }
    if !event.cwe.is_empty() {
        let joined: Vec<String> = event.cwe.iter().map(ToString::to_string).collect();
        let _ = writeln!(out, "CWE: {}", joined.join(", "));
    }
    if !event.mitre_attack.is_empty() {
        let joined: Vec<String> = event
            .mitre_attack
            .iter()
            .map(|m| m.technique.clone())
            .collect();
        let _ = writeln!(out, "MITRE ATT&CK: {}", joined.join(", "));
    }
    let nist = nist_joined(event, ", ");
    if !nist.is_empty() {
        let _ = writeln!(out, "NIST 800-53: {nist}");
    }
    out
}

/// Join the event's NIST 800-53 control ids with `sep`.
fn nist_joined(event: &IncidentEvent, sep: &str) -> String {
    event
        .compliance
        .nist_800_53
        .iter()
        .map(|c| c.as_str().to_owned())
        .collect::<Vec<_>>()
        .join(sep)
}

/// Build the structured `details` object Opsgenie exposes verbatim in
/// the alert's "Extra Properties" panel and in alert-list filter
/// expressions. All values are stringified — Opsgenie's details schema
/// only stores string→string pairs.
fn build_details(event: &IncidentEvent) -> serde_json::Map<String, Value> {
    let mut details = serde_json::Map::new();
    details.insert(
        "tenant_id".to_owned(),
        Value::String(event.tenant_id.clone()),
    );
    details.insert(
        "kind".to_owned(),
        Value::String(kind_tag(event.kind).to_owned()),
    );
    if let Some(cvss) = event.cvss.as_ref() {
        details.insert(
            "cvss_base_score".to_owned(),
            Value::String(format!("{:.1}", cvss.base_score)),
        );
    }
    if !event.cwe.is_empty() {
        let joined = event
            .cwe
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",");
        details.insert("cwe".to_owned(), Value::String(joined));
    }
    if !event.mitre_attack.is_empty() {
        let joined = event
            .mitre_attack
            .iter()
            .map(|m| m.technique.clone())
            .collect::<Vec<_>>()
            .join(",");
        details.insert("mitre".to_owned(), Value::String(joined));
    }
    let nist = nist_joined(event, ",");
    if !nist.is_empty() {
        details.insert("compliance_nist_800_53".to_owned(), Value::String(nist));
    }
    if let Some(finding) = event.finding.as_ref() {
        details.insert("finding_id".to_owned(), Value::String(finding.id.clone()));
        details.insert(
            "asset_id".to_owned(),
            Value::String(finding.asset_id.clone()),
        );
        details.insert(
            "finding_status".to_owned(),
            Value::String(finding.status.clone()),
        );
        if let Some(cve) = finding.cve_id.as_ref() {
            details.insert("cve_id".to_owned(), Value::String(cve.clone()));
        }
    }
    if let Some(url) = event.source_url.as_ref() {
        details.insert("source_url".to_owned(), Value::String(url.clone()));
    }
    details
}

/// Opsgenie caps `message` at 130 characters. We trim preemptively
/// rather than risk a 422.
fn truncate_message(s: &str) -> String {
    const OPSGENIE_MESSAGE_CAP: usize = 130;
    if s.len() <= OPSGENIE_MESSAGE_CAP {
        s.to_owned()
    } else {
        let mut end = OPSGENIE_MESSAGE_CAP;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        s[..end].to_owned()
    }
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
    use crate::incident_sink::FindingDigest;
    use sx_core::value_object::compliance::ComplianceTags;
    use wiremock::matchers::{body_partial_json, header, method, path};
    use wiremock::{Mock, MockServer, Request, ResponseTemplate};

    fn sink_for(server: &MockServer) -> OpsgenieIncidentSink {
        let url = Url::parse(&format!("{}/v2/alerts", server.uri())).unwrap();
        OpsgenieIncidentSink::new(
            reqwest::Client::new(),
            url,
            SecretString::from("og-api-key".to_owned()),
            None,
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
    async fn happy_path_returns_receipt_with_request_id() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v2/alerts"))
            .and(header("authorization", "GenieKey og-api-key"))
            .and(header("content-type", "application/json"))
            .and(body_partial_json(json!({
                "alias": "sx::t-1::finding::f-1",
                "priority": "P1",
                "source": "t-1",
                "tags": ["sentinelx", "finding"]
            })))
            .respond_with(ResponseTemplate::new(202).set_body_json(json!({
                "result": "Request will be processed",
                "took": 0.302,
                "requestId": "43a29c5c-3dbf-4fa4-9c26-f4f71023e120"
            })))
            .expect(1)
            .mount(&server)
            .await;

        let sink = sink_for(&server);
        let receipt = sink
            .emit(&event(IncidentKind::FindingEmitted, Severity::Critical))
            .await
            .unwrap();
        assert_eq!(receipt.external_id, "43a29c5c-3dbf-4fa4-9c26-f4f71023e120");
        assert!(receipt.external_url.contains("alias:sx::t-1::finding::f-1"));
    }

    #[tokio::test]
    async fn unauthorised_401_maps_to_unauthenticated() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v2/alerts"))
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
            .and(path("/v2/alerts"))
            .respond_with(ResponseTemplate::new(403))
            .mount(&server)
            .await;

        let sink = sink_for(&server);
        let err = sink
            .emit(&event(IncidentKind::FindingEmitted, Severity::High))
            .await
            .unwrap_err();
        assert!(matches!(err, IncidentSinkError::Unauthorised));
    }

    #[tokio::test]
    async fn rate_limited_429_parses_retry_after_45s() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v2/alerts"))
            .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "45"))
            .mount(&server)
            .await;

        let sink = sink_for(&server);
        let err = sink
            .emit(&event(IncidentKind::FindingEmitted, Severity::Critical))
            .await
            .unwrap_err();
        match err {
            IncidentSinkError::RateLimited { retry_after } => {
                assert_eq!(retry_after, Some(Duration::from_secs(45)));
            }
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn rate_limited_429_without_header_defaults_to_60s() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v2/alerts"))
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
    async fn unprocessable_422_maps_to_schema_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v2/alerts"))
            .respond_with(ResponseTemplate::new(422).set_body_json(json!({
                "message": "alias too long",
                "took": 0.001
            })))
            .mount(&server)
            .await;

        let sink = sink_for(&server);
        let err = sink
            .emit(&event(IncidentKind::FindingEmitted, Severity::High))
            .await
            .unwrap_err();
        match err {
            IncidentSinkError::Schema(msg) => {
                assert!(msg.contains("alias too long"), "got: {msg}");
            }
            other => panic!("expected Schema, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn server_error_5xx_maps_to_bad_gateway() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v2/alerts"))
            .respond_with(ResponseTemplate::new(500).set_body_string("upstream nope"))
            .mount(&server)
            .await;

        let sink = sink_for(&server);
        let err = sink
            .emit(&event(IncidentKind::AuditChainBreak, Severity::High))
            .await
            .unwrap_err();
        match err {
            IncidentSinkError::BadGateway { status, body } => {
                assert_eq!(status, 500);
                assert!(body.contains("upstream nope"));
            }
            other => panic!("expected BadGateway, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn payload_priority_maps_high_to_p2() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v2/alerts"))
            .and(body_partial_json(json!({
                "priority": "P2"
            })))
            .respond_with(ResponseTemplate::new(202).set_body_json(json!({
                "result": "ok",
                "took": 0.1,
                "requestId": "x"
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
    async fn body_shape_contains_message_priority_alias_and_sentinelx_tag() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v2/alerts"))
            .respond_with(ResponseTemplate::new(202).set_body_json(json!({
                "result": "ok",
                "took": 0.1,
                "requestId": "x"
            })))
            .expect(1)
            .mount(&server)
            .await;

        let sink = sink_for(&server);
        sink.emit(&event(IncidentKind::FindingEmitted, Severity::Critical))
            .await
            .unwrap();

        let requests: Vec<Request> = server.received_requests().await.unwrap_or_default();
        assert_eq!(requests.len(), 1);
        let body: Value = serde_json::from_slice(&requests[0].body).unwrap();
        // `message` present and matches the event title.
        assert_eq!(
            body["message"].as_str().unwrap(),
            "[SentinelX] Critical SQLi at /login"
        );
        // `priority` is one of the P1..P5 ladder.
        let prio = body["priority"].as_str().unwrap();
        assert!(
            matches!(prio, "P1" | "P2" | "P3" | "P4" | "P5"),
            "priority not in ladder: {prio}"
        );
        // `alias` present and finding-id based.
        assert_eq!(body["alias"].as_str().unwrap(), "sx::t-1::finding::f-1");
        // `tags` contains "sentinelx".
        let tags = body["tags"].as_array().unwrap();
        assert!(tags.iter().any(|t| t.as_str() == Some("sentinelx")));
    }

    #[tokio::test]
    async fn source_override_appears_in_payload() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v2/alerts"))
            .and(body_partial_json(json!({
                "source": "custom-source"
            })))
            .respond_with(ResponseTemplate::new(202).set_body_json(json!({
                "result": "ok",
                "took": 0.1,
                "requestId": "x"
            })))
            .expect(1)
            .mount(&server)
            .await;

        let url = Url::parse(&format!("{}/v2/alerts", server.uri())).unwrap();
        let sink = OpsgenieIncidentSink::new(
            reqwest::Client::new(),
            url,
            SecretString::from("og-api-key".to_owned()),
            Some("custom-source".to_owned()),
        );
        sink.emit(&event(IncidentKind::FindingEmitted, Severity::Critical))
            .await
            .unwrap();
    }

    #[test]
    fn severity_mapping_is_one_to_one() {
        assert_eq!(
            OpsgeniePriority::from_sx_severity(Severity::Critical),
            OpsgeniePriority::P1
        );
        assert_eq!(
            OpsgeniePriority::from_sx_severity(Severity::High),
            OpsgeniePriority::P2
        );
        assert_eq!(
            OpsgeniePriority::from_sx_severity(Severity::Medium),
            OpsgeniePriority::P3
        );
        assert_eq!(
            OpsgeniePriority::from_sx_severity(Severity::Low),
            OpsgeniePriority::P4
        );
        assert_eq!(
            OpsgeniePriority::from_sx_severity(Severity::Info),
            OpsgeniePriority::P5
        );
    }

    #[test]
    fn alias_uses_finding_id_when_present() {
        let key = derive_alias(&event(IncidentKind::FindingEmitted, Severity::Critical));
        assert_eq!(key, "sx::t-1::finding::f-1");
    }

    #[test]
    fn alias_for_playbook_uses_kind_and_title() {
        let mut e = event(IncidentKind::PlaybookTriggered, Severity::High);
        e.finding = None;
        let key = derive_alias(&e);
        assert!(key.starts_with("sx::t-1::playbook::"));
        assert!(key.contains("Critical SQLi at /login"));
    }

    #[test]
    fn debug_impl_redacts_api_key() {
        let url = Url::parse("https://api.opsgenie.com/v2/alerts").unwrap();
        let sink = OpsgenieIncidentSink::new(
            reqwest::Client::new(),
            url,
            SecretString::from("super-secret-og-key".to_owned()),
            None,
        );
        let dbg = format!("{sink:?}");
        assert!(
            !dbg.contains("super-secret-og-key"),
            "api key leaked in Debug: {dbg}"
        );
        assert!(dbg.contains("<redacted>"));
    }

    #[test]
    fn truncate_message_caps_at_130_chars() {
        let s = "a".repeat(500);
        let out = truncate_message(&s);
        assert_eq!(out.len(), 130);
    }

    #[test]
    fn truncate_message_keeps_short_strings_intact() {
        assert_eq!(truncate_message("short"), "short");
    }
}
