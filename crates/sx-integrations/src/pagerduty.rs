//! PagerDuty Events API v2 incident-sink adapter (TOP5-#5).
//!
//! This adapter implements [`IncidentSinkPort`] for PagerDuty's Events
//! API v2 — the "trigger an incident" endpoint that on-call rotations
//! and escalation policies hang off.
//!
//! ## Endpoint
//!
//! `POST https://events.pagerduty.com/v2/enqueue` (or the EU residency
//! variant `https://events.eu.pagerduty.com/v2/enqueue`). The endpoint
//! is configurable so wiremock tests can target a local mock server.
//!
//! See <https://developer.pagerduty.com/api-reference/368ae3d938c9e-send-an-event>
//! for the canonical Events API v2 contract.
//!
//! ## Authentication
//!
//! Single-credential model: each PagerDuty service has one or more
//! "Events API v2" integrations, each minting a `routing_key` (a
//! 32-character hex/alphanumeric token). The routing key travels in the
//! request body — there is no HTTP `Authorization` header. We wrap it
//! in [`SecretString`] so the value never reaches `Debug` output,
//! panics, or tracing spans.
//!
//! ## Severity mapping
//!
//! The Events API v2 has its own fixed severity scale (`critical |
//! error | warning | info`) — distinct from SentinelX's five-band
//! [`Severity`]. We collapse:
//!
//! | SentinelX  | PagerDuty   |
//! |------------|-------------|
//! | `Critical` | `critical`  |
//! | `High`     | `error`     |
//! | `Medium`   | `warning`   |
//! | `Low`      | `info`      |
//! | `Info`     | `info`      |
//!
//! `Low` and `Info` both collapse to PagerDuty `info` because the
//! upstream API does not have a distinct lowest band.
//!
//! ## Idempotency
//!
//! Every `trigger` event carries a `dedup_key` derived from the
//! `(tenant_id, finding.id)` pair (or a deterministic kind-specific
//! string for non-finding events). PagerDuty uses this key to collapse
//! repeated triggers into a single open incident — re-sending the same
//! event is safe.
//!
//! ## Error taxonomy
//!
//! Maps Events API v2 responses onto the shared [`IncidentSinkError`].
//! `202 Accepted` is the documented success status.

use std::fmt;

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

/// Default PagerDuty Events API v2 endpoint (US datacentre). Operators
/// on the EU residency plan override this to
/// `https://events.eu.pagerduty.com/v2/enqueue`.
pub const DEFAULT_EVENTS_URL: &str = "https://events.pagerduty.com/v2/enqueue";

/// Cap on the size of the vendor error body captured into
/// [`IncidentSinkError::BadGateway::body`].
const MAX_VENDOR_BODY_BYTES: usize = 2048;

/// PagerDuty Events API v2 severity values.
///
/// Distinct from SentinelX's five-band [`Severity`]; the conversion
/// table lives on [`PagerDutySeverity::from_sx_severity`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PagerDutySeverity {
    /// Highest severity. Maps from SentinelX `Critical`.
    Critical,
    /// Error severity. Maps from SentinelX `High`.
    Error,
    /// Warning severity. Maps from SentinelX `Medium`.
    Warning,
    /// Informational. Maps from SentinelX `Low` and `Info` (the Events
    /// API has no distinct lowest band).
    Info,
}

impl PagerDutySeverity {
    /// Convert a SentinelX [`Severity`] into the matching PagerDuty
    /// Events API v2 severity. The MVP collapses `Info` and `Low` onto
    /// `info` because the upstream API does not have a distinct lowest
    /// band.
    #[must_use]
    pub const fn from_sx_severity(sev: Severity) -> Self {
        match sev {
            Severity::Critical => Self::Critical,
            Severity::High => Self::Error,
            Severity::Medium => Self::Warning,
            Severity::Low | Severity::Info => Self::Info,
        }
    }

    /// Wire form (lower-case enum value the Events API expects).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::Error => "error",
            Self::Warning => "warning",
            Self::Info => "info",
        }
    }
}

/// PagerDuty Events API v2 incident-sink adapter.
///
/// Construct one per integration key — different PagerDuty services
/// (e.g. one for "engineering on-call", one for "security incident
/// response") each get their own sink instance, and the monolith
/// fan-out registers any subset that the operator has enabled.
pub struct PagerDutyIncidentSink {
    http: Client,
    events_url: Url,
    routing_key: SecretString,
    source_override: Option<String>,
}

impl fmt::Debug for PagerDutyIncidentSink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PagerDutyIncidentSink")
            .field("events_url", &self.events_url.as_str())
            .field("routing_key", &"<redacted>")
            .field("source_override", &self.source_override)
            .finish_non_exhaustive()
    }
}

impl PagerDutyIncidentSink {
    /// Construct a new sink. `events_url` is the full Events API v2
    /// endpoint (typically [`DEFAULT_EVENTS_URL`] or the EU variant).
    /// `routing_key` is the per-integration shared secret. When
    /// `source_override` is `Some`, every event uses that value as
    /// `payload.source`; when `None`, the emitting tenant's id travels
    /// in `payload.source` so PagerDuty's incident-search filters work
    /// per tenant.
    #[must_use]
    pub const fn new(
        http: Client,
        events_url: Url,
        routing_key: SecretString,
        source_override: Option<String>,
    ) -> Self {
        Self {
            http,
            events_url,
            routing_key,
            source_override,
        }
    }

    /// Compose the Events API v2 trigger body for `event`.
    fn build_payload(&self, event: &IncidentEvent) -> Value {
        let dedup_key = derive_dedup_key(event);
        let source = self
            .source_override
            .clone()
            .unwrap_or_else(|| event.tenant_id.clone());
        let pd_severity = PagerDutySeverity::from_sx_severity(event.severity);

        // Structured enrichment object — PagerDuty surfaces this in the
        // incident's "Custom Details" panel without further parsing.
        let custom_details = json!({
            "kind": serde_json::to_value(event.kind).unwrap_or(Value::Null),
            "tenant_id": event.tenant_id,
            "title": event.title,
            "description": event.description,
            "finding": event.finding,
            "cvss": event.cvss,
            "cwe": event.cwe,
            "mitre_attack": event.mitre_attack,
            "compliance": event.compliance,
            "source_url": event.source_url,
        });

        let mut payload = serde_json::Map::new();
        payload.insert(
            "summary".to_owned(),
            Value::String(truncate_summary(&event.title)),
        );
        payload.insert("source".to_owned(), Value::String(source));
        payload.insert(
            "severity".to_owned(),
            Value::String(pd_severity.as_str().to_owned()),
        );
        payload.insert(
            "component".to_owned(),
            Value::String("sentinelx".to_owned()),
        );
        payload.insert(
            "class".to_owned(),
            Value::String(kind_class(event.kind).to_owned()),
        );
        payload.insert("custom_details".to_owned(), custom_details);

        let mut body = serde_json::Map::new();
        body.insert(
            "routing_key".to_owned(),
            Value::String(self.routing_key.expose_secret().to_owned()),
        );
        body.insert(
            "event_action".to_owned(),
            Value::String("trigger".to_owned()),
        );
        body.insert("dedup_key".to_owned(), Value::String(dedup_key));
        body.insert("payload".to_owned(), Value::Object(payload));

        if let Some(url) = event.source_url.as_ref() {
            body.insert(
                "links".to_owned(),
                json!([{ "href": url, "text": "SentinelX dashboard" }]),
            );
        }

        Value::Object(body)
    }
}

/// Minimal projection of the Events API v2 `enqueue` response.
#[derive(Debug, Deserialize)]
struct EnqueueResponse {
    #[serde(default)]
    dedup_key: Option<String>,
    #[serde(default)]
    message: Option<String>,
}

#[async_trait]
impl IncidentSinkPort for PagerDutyIncidentSink {
    async fn emit(&self, event: &IncidentEvent) -> Result<EmissionReceipt, IncidentSinkError> {
        let body = self.build_payload(event);

        debug!(
            target: "sx_integrations::pagerduty",
            tenant = %event.tenant_id,
            severity = %event.severity,
            "emitting pagerduty incident"
        );

        let resp = self
            .http
            .post(self.events_url.clone())
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header(reqwest::header::ACCEPT, "application/json")
            .json(&body)
            .send()
            .await?;

        let status = resp.status();

        if status == StatusCode::UNAUTHORIZED {
            warn!(target: "sx_integrations::pagerduty", "pagerduty returned 401");
            return Err(IncidentSinkError::Unauthenticated);
        }
        if status == StatusCode::FORBIDDEN {
            warn!(target: "sx_integrations::pagerduty", "pagerduty returned 403");
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
        // PagerDuty Events API v2 returns 202 Accepted on success. We
        // treat any 2xx as success to stay tolerant of future protocol
        // tweaks.
        if !status.is_success() {
            let body_text = resp.text().await.unwrap_or_default();
            let truncated = truncate_body(&body_text);
            return Err(IncidentSinkError::BadGateway {
                status: status.as_u16(),
                body: truncated,
            });
        }

        let parsed: EnqueueResponse = resp.json().await?;
        let dedup = parsed
            .dedup_key
            .clone()
            .unwrap_or_else(|| derive_dedup_key(event));

        // PagerDuty does not return a browser URL on the enqueue
        // response; the canonical "view this incident" URL is built
        // server-side from `dedup_key`. We emit a stable URL placeholder
        // that contains the dedup key so operators can search it inside
        // the PagerDuty UI, matching the contract our dashboard expects.
        let external_url = format!("https://app.pagerduty.com/incidents?incident_key={dedup}");

        debug!(
            target: "sx_integrations::pagerduty",
            dedup_key = %dedup,
            message = parsed.message.as_deref().unwrap_or("Event processed"),
            "pagerduty trigger accepted"
        );

        Ok(EmissionReceipt {
            external_id: dedup,
            external_url,
        })
    }

    fn name(&self) -> &'static str {
        "pagerduty"
    }
}

/// Derive a deterministic dedup key from an [`IncidentEvent`].
///
/// PagerDuty collapses duplicate `trigger` events with the same
/// `dedup_key` into one open incident. Stable per `(tenant_id,
/// finding.id)` so re-emissions of the same finding never spawn
/// multiple incidents; for non-finding events the key includes the kind
/// + title so distinct events stay distinct.
fn derive_dedup_key(event: &IncidentEvent) -> String {
    event.finding.as_ref().map_or_else(
        || {
            let kind = match event.kind {
                IncidentKind::FindingEmitted => "finding",
                IncidentKind::PlaybookTriggered => "playbook",
                IncidentKind::AuditChainBreak => "audit-break",
            };
            format!("sx::{}::{}::{}", event.tenant_id, kind, event.title)
        },
        |digest| format!("sx::{}::finding::{}", event.tenant_id, digest.id),
    )
}

/// Map an [`IncidentKind`] to the PagerDuty `payload.class` field. The
/// class is purely metadata for the operator's incident list.
const fn kind_class(kind: IncidentKind) -> &'static str {
    match kind {
        IncidentKind::FindingEmitted => "sentinelx.finding",
        IncidentKind::PlaybookTriggered => "sentinelx.playbook",
        IncidentKind::AuditChainBreak => "sentinelx.audit_chain_break",
    }
}

/// PagerDuty caps `payload.summary` at 1024 characters. We trim
/// preemptively rather than risk a 400.
fn truncate_summary(s: &str) -> String {
    const PD_SUMMARY_CAP: usize = 1024;
    if s.len() <= PD_SUMMARY_CAP {
        s.to_owned()
    } else {
        let mut end = PD_SUMMARY_CAP;
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
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn sink_for(server: &MockServer) -> PagerDutyIncidentSink {
        let url = Url::parse(&format!("{}/v2/enqueue", server.uri())).unwrap();
        PagerDutyIncidentSink::new(
            reqwest::Client::new(),
            url,
            SecretString::from("pd-routing-key".to_owned()),
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
    async fn happy_path_returns_receipt_with_dedup_key() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v2/enqueue"))
            .and(header("content-type", "application/json"))
            .and(body_partial_json(json!({
                "routing_key": "pd-routing-key",
                "event_action": "trigger",
                "dedup_key": "sx::t-1::finding::f-1",
                "payload": {
                    "severity": "critical",
                    "source": "t-1",
                    "class": "sentinelx.finding"
                }
            })))
            .respond_with(ResponseTemplate::new(202).set_body_json(json!({
                "status": "success",
                "message": "Event processed",
                "dedup_key": "sx::t-1::finding::f-1"
            })))
            .expect(1)
            .mount(&server)
            .await;

        let sink = sink_for(&server);
        let receipt = sink
            .emit(&event(IncidentKind::FindingEmitted, Severity::Critical))
            .await
            .unwrap();
        assert_eq!(receipt.external_id, "sx::t-1::finding::f-1");
        assert!(receipt
            .external_url
            .contains("incident_key=sx::t-1::finding::f-1"));
    }

    #[tokio::test]
    async fn unauthorised_401_maps_to_unauthenticated() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v2/enqueue"))
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
    async fn rate_limited_429_returns_retry_after() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v2/enqueue"))
            .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "5"))
            .mount(&server)
            .await;

        let sink = sink_for(&server);
        let err = sink
            .emit(&event(IncidentKind::FindingEmitted, Severity::Critical))
            .await
            .unwrap_err();
        match err {
            IncidentSinkError::RateLimited { retry_after } => {
                assert_eq!(retry_after, Some(Duration::from_secs(5)));
            }
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn server_error_5xx_maps_to_bad_gateway() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v2/enqueue"))
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
    async fn payload_severity_maps_high_to_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v2/enqueue"))
            .and(body_partial_json(json!({
                "event_action": "trigger",
                "payload": { "severity": "error" }
            })))
            .respond_with(ResponseTemplate::new(202).set_body_json(json!({
                "status": "success",
                "message": "ok",
                "dedup_key": "x"
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
    async fn source_override_appears_in_payload() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v2/enqueue"))
            .and(body_partial_json(json!({
                "payload": { "source": "custom-source" }
            })))
            .respond_with(ResponseTemplate::new(202).set_body_json(json!({
                "status": "success",
                "message": "ok",
                "dedup_key": "x"
            })))
            .expect(1)
            .mount(&server)
            .await;

        let url = Url::parse(&format!("{}/v2/enqueue", server.uri())).unwrap();
        let sink = PagerDutyIncidentSink::new(
            reqwest::Client::new(),
            url,
            SecretString::from("pd-routing-key".to_owned()),
            Some("custom-source".to_owned()),
        );
        sink.emit(&event(IncidentKind::FindingEmitted, Severity::Critical))
            .await
            .unwrap();
    }

    #[test]
    fn severity_mapping_collapses_low_and_info() {
        assert_eq!(
            PagerDutySeverity::from_sx_severity(Severity::Critical),
            PagerDutySeverity::Critical
        );
        assert_eq!(
            PagerDutySeverity::from_sx_severity(Severity::High),
            PagerDutySeverity::Error
        );
        assert_eq!(
            PagerDutySeverity::from_sx_severity(Severity::Medium),
            PagerDutySeverity::Warning
        );
        assert_eq!(
            PagerDutySeverity::from_sx_severity(Severity::Low),
            PagerDutySeverity::Info
        );
        assert_eq!(
            PagerDutySeverity::from_sx_severity(Severity::Info),
            PagerDutySeverity::Info
        );
    }

    #[test]
    fn dedup_key_uses_finding_id_when_present() {
        let key = derive_dedup_key(&event(IncidentKind::FindingEmitted, Severity::Critical));
        assert_eq!(key, "sx::t-1::finding::f-1");
    }

    #[test]
    fn dedup_key_for_playbook_uses_kind_and_title() {
        let mut e = event(IncidentKind::PlaybookTriggered, Severity::High);
        e.finding = None;
        let key = derive_dedup_key(&e);
        assert!(key.starts_with("sx::t-1::playbook::"));
        assert!(key.contains("Critical SQLi at /login"));
    }

    #[test]
    fn debug_impl_redacts_routing_key() {
        let url = Url::parse("https://events.pagerduty.com/v2/enqueue").unwrap();
        let sink = PagerDutyIncidentSink::new(
            reqwest::Client::new(),
            url,
            SecretString::from("super-secret-pd-key".to_owned()),
            None,
        );
        let dbg = format!("{sink:?}");
        assert!(
            !dbg.contains("super-secret-pd-key"),
            "routing key leaked in Debug: {dbg}"
        );
        assert!(dbg.contains("<redacted>"));
    }

    #[test]
    fn truncate_summary_caps_at_1024_chars() {
        let s = "a".repeat(2000);
        let out = truncate_summary(&s);
        assert_eq!(out.len(), 1024);
    }

    #[test]
    fn truncate_summary_keeps_short_strings_intact() {
        assert_eq!(truncate_summary("short"), "short");
    }
}
