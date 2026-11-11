//! Splunk HTTP Event Collector (HEC) forwarder.
//!
//! Posts JSON envelopes to `{base_url}/services/collector/event` with the
//! Splunk-flavoured `Authorization: Splunk {token}` header. Supports
//! single-event and batched submissions.
//!
//! Splunk HEC accepts batched events by *concatenating* JSON envelopes
//! without a separator (or with whitespace). We use newline-delimited
//! JSON which Splunk parses identically and which is much easier to
//! inspect on the wire.

use std::fmt;

use reqwest::{Client, StatusCode, Url};
use secrecy::{ExposeSecret, SecretString};
use serde::Serialize;
use serde_json::Value;
use tracing::{debug, warn};

use crate::error::IntegrationError;
use crate::siem::AuditEvent;

/// HEC events endpoint, appended to the configured base URL.
const HEC_EVENT_PATH: &str = "services/collector/event";

/// Forwarder that ships [`AuditEvent`]s to a Splunk HEC endpoint.
///
/// The HEC token is held as a [`SecretString`] so the `Debug` impl below
/// can redact it. Cloning is cheap: the inner `reqwest::Client` uses an
/// `Arc` internally and the rest of the fields are small.
#[derive(Clone)]
pub struct SplunkHecForwarder {
    http: Client,
    base_url: Url,
    token: SecretString,
    index: Option<String>,
}

impl fmt::Debug for SplunkHecForwarder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SplunkHecForwarder")
            .field("base_url", &self.base_url.as_str())
            .field("token", &"<redacted>")
            .field("index", &self.index)
            .finish_non_exhaustive()
    }
}

/// Wire envelope sent to Splunk HEC.
///
/// Splunk treats the `event` field as opaque JSON — we send the full
/// audit event there so all metadata is searchable.
#[derive(Debug, Serialize)]
struct HecEnvelope<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    index: Option<&'a str>,
    sourcetype: &'static str,
    source: &'static str,
    event: Value,
}

impl SplunkHecForwarder {
    /// Construct a new forwarder.
    ///
    /// `base_url` is the Splunk HEC root (e.g.
    /// `https://splunk.example.com:8088/`). The events endpoint path is
    /// appended internally.
    #[must_use]
    pub const fn new(
        http: Client,
        base_url: Url,
        token: SecretString,
        index: Option<String>,
    ) -> Self {
        Self {
            http,
            base_url,
            token,
            index,
        }
    }

    /// Send a single event.
    ///
    /// Thin wrapper over [`Self::send_batch`] with a one-element slice.
    pub async fn send(&self, event: &AuditEvent) -> Result<(), IntegrationError> {
        self.send_batch(std::slice::from_ref(event)).await
    }

    /// Send a batch of events as newline-delimited JSON envelopes.
    ///
    /// An empty batch is a no-op that returns `Ok(())` without making an
    /// HTTP call.
    #[allow(clippy::cognitive_complexity)] // linear: serialise → POST → status switch → emit
    pub async fn send_batch(&self, events: &[AuditEvent]) -> Result<(), IntegrationError> {
        if events.is_empty() {
            return Ok(());
        }

        let endpoint = self
            .base_url
            .join(HEC_EVENT_PATH)
            .map_err(IntegrationError::format)?;
        let body = self.serialize_batch(events)?;
        let auth = format!("Splunk {}", self.token.expose_secret());

        debug!(
            target: "sx_integrations::siem::splunk_hec",
            event_count = events.len(),
            endpoint = %endpoint,
            "submitting batch to splunk hec"
        );

        let resp = self
            .http
            .post(endpoint)
            .header(reqwest::header::AUTHORIZATION, auth)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .await?;

        let status = resp.status();
        if status.is_success() {
            return Ok(());
        }

        if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
            warn!(
                target: "sx_integrations::siem::splunk_hec",
                %status,
                "splunk hec rejected request"
            );
            return Err(IntegrationError::Unauthorized);
        }

        if status == StatusCode::TOO_MANY_REQUESTS {
            let retry_after_secs = resp
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.trim().parse::<u64>().ok());
            warn!(
                target: "sx_integrations::siem::splunk_hec",
                retry_after = ?retry_after_secs,
                "splunk hec rate limited"
            );
            return Err(IntegrationError::RateLimited { retry_after_secs });
        }

        Err(IntegrationError::Transport(format!(
            "splunk hec returned non-2xx status {status}"
        )))
    }

    /// Serialize a batch into NDJSON. Exposed for tests.
    fn serialize_batch(&self, events: &[AuditEvent]) -> Result<String, IntegrationError> {
        let mut out = String::with_capacity(events.len() * 256);
        for ev in events {
            let envelope = HecEnvelope {
                index: self.index.as_deref(),
                sourcetype: "sentinelx:audit",
                source: "sentinelx",
                event: build_event_value(ev),
            };
            let line = serde_json::to_string(&envelope)?;
            out.push_str(&line);
            out.push('\n');
        }
        Ok(out)
    }
}

/// Build the JSON value embedded in the `event` field of a HEC envelope.
fn build_event_value(ev: &AuditEvent) -> Value {
    let mut obj = serde_json::Map::new();
    obj.insert("action".to_owned(), Value::String(ev.action.clone()));
    obj.insert("title".to_owned(), Value::String(ev.title.clone()));
    obj.insert(
        "severity".to_owned(),
        Value::String(ev.severity.label().to_owned()),
    );
    if let Some(actor) = &ev.actor {
        obj.insert("actor".to_owned(), Value::String(actor.clone()));
    }
    if let Some(src) = &ev.source {
        obj.insert("source".to_owned(), Value::String(src.clone()));
    }
    for (k, v) in &ev.fields {
        obj.insert(k.clone(), v.clone());
    }
    Value::Object(obj)
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

    fn token() -> SecretString {
        SecretString::new("hec-token-shhh".to_owned().into_boxed_str())
    }

    fn forwarder_for(server: &MockServer) -> SplunkHecForwarder {
        let url = Url::parse(&format!("{}/", server.uri())).unwrap();
        SplunkHecForwarder::new(
            reqwest::Client::new(),
            url,
            token(),
            Some("sx_audit".to_owned()),
        )
    }

    fn sample_event() -> AuditEvent {
        AuditEvent {
            action: "login.success".to_owned(),
            title: "user signed in".to_owned(),
            severity: Severity::Info,
            actor: Some("u-42".to_owned()),
            source: Some("10.0.0.1".to_owned()),
            fields: serde_json::Map::new(),
        }
    }

    #[tokio::test]
    async fn send_success_200_returns_ok() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/services/collector/event"))
            .and(header("authorization", "Splunk hec-token-shhh"))
            .and(header("content-type", "application/json"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({"text": "Success", "code": 0})),
            )
            .expect(1)
            .mount(&server)
            .await;

        let fwd = forwarder_for(&server);
        fwd.send(&sample_event()).await.unwrap();
    }

    #[tokio::test]
    async fn send_401_maps_to_unauthorized() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/services/collector/event"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&server)
            .await;

        let fwd = forwarder_for(&server);
        let err = fwd.send(&sample_event()).await.unwrap_err();
        assert!(matches!(err, IntegrationError::Unauthorized));
    }

    #[tokio::test]
    async fn send_429_parses_retry_after_header() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/services/collector/event"))
            .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "42"))
            .mount(&server)
            .await;

        let fwd = forwarder_for(&server);
        let err = fwd.send(&sample_event()).await.unwrap_err();
        match err {
            IntegrationError::RateLimited { retry_after_secs } => {
                assert_eq!(retry_after_secs, Some(42));
            }
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn batch_of_ten_is_serialised_as_ndjson() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/services/collector/event"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        let fwd = forwarder_for(&server);
        let events: Vec<_> = (0..10)
            .map(|i| AuditEvent {
                action: format!("evt.{i}"),
                title: format!("event {i}"),
                severity: Severity::Low,
                actor: None,
                source: None,
                fields: serde_json::Map::new(),
            })
            .collect();

        // First verify the serialisation directly: 10 lines, each parseable as JSON,
        // each carrying the configured index.
        let body = fwd.serialize_batch(&events).unwrap();
        let lines: Vec<&str> = body.lines().collect();
        assert_eq!(lines.len(), 10);
        for (i, line) in lines.iter().enumerate() {
            let v: Value = serde_json::from_str(line).unwrap();
            assert_eq!(v["index"], "sx_audit");
            assert_eq!(v["sourcetype"], "sentinelx:audit");
            assert_eq!(v["event"]["action"], format!("evt.{i}"));
            assert_eq!(v["event"]["severity"], "low");
        }

        // Then send and confirm the mock saw exactly one POST.
        fwd.send_batch(&events).await.unwrap();
    }

    #[test]
    fn debug_impl_redacts_token() {
        let fwd = SplunkHecForwarder::new(
            reqwest::Client::new(),
            Url::parse("https://splunk.example/").unwrap(),
            SecretString::new("super-secret-token".to_owned().into_boxed_str()),
            None,
        );
        let dbg = format!("{fwd:?}");
        assert!(dbg.contains("<redacted>"), "debug output: {dbg}");
        assert!(
            !dbg.contains("super-secret-token"),
            "token leaked in debug output: {dbg}"
        );
    }

    #[tokio::test]
    async fn empty_batch_is_noop() {
        let server = MockServer::start().await;
        // No expectations registered — any request would 404.
        let fwd = forwarder_for(&server);
        fwd.send_batch(&[]).await.unwrap();
    }
}
