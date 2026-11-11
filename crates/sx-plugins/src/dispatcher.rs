//! HMAC-signed outbound webhook dispatcher.
//!
//! The dispatcher:
//!
//! 1. Builds a [`crate::envelope::PluginEnvelope`].
//! 2. Computes HMAC-SHA256 over the serialised body using the
//!    plugin-supplied secret.
//! 3. POSTs the body with the signature carried in the
//!    [`SIGNATURE_HEADER`] header.
//! 4. Records the outcome ([`DispatchOutcome`]) so the read-side history
//!    endpoint can surface it.
//!
//! The MVP is intentionally non-retrying — failures are logged and
//! persisted but no back-off / re-queue path is wired. The follow-up
//! task can layer a retry policy on top of [`PluginDispatcher::dispatch`].

use std::time::{Duration, Instant};

use hmac::{Hmac, Mac};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::envelope::{EventKind, PluginEnvelope};
use crate::manifest::PluginId;

/// HTTP header carrying the hex-encoded HMAC-SHA256 digest.
pub const SIGNATURE_HEADER: &str = "X-Sentinelx-Signature";

/// HTTP header carrying the RFC 3339 dispatch timestamp.
pub const TIMESTAMP_HEADER: &str = "X-Sentinelx-Timestamp";

/// Default per-dispatch timeout (5 seconds — task requirement).
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

/// How much of the plugin response body is captured into the history
/// record (so the dashboard can render it without unbounded payloads).
const RESPONSE_EXCERPT_BYTES: usize = 1024;

type HmacSha256 = Hmac<Sha256>;

/// URL scheme policy applied to plugin webhook URLs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllowedScheme {
    /// Only `https://` URLs are permitted (production default).
    HttpsOnly,
    /// Both `http://` and `https://` URLs are permitted (dev override).
    HttpOrHttps,
}

/// Dispatcher configuration.
#[derive(Debug, Clone)]
pub struct DispatcherConfig {
    /// Per-dispatch timeout — applies to the full request/response
    /// round trip.
    pub timeout: Duration,
    /// Whether HTTP webhook URLs are allowed. Defaults to `false`;
    /// production should never flip this.
    pub allow_http: bool,
}

impl Default for DispatcherConfig {
    fn default() -> Self {
        Self {
            timeout: DEFAULT_TIMEOUT,
            allow_http: false,
        }
    }
}

impl DispatcherConfig {
    /// Resolve the URL-scheme policy implied by `allow_http`.
    #[must_use]
    pub const fn scheme_policy(&self) -> AllowedScheme {
        if self.allow_http {
            AllowedScheme::HttpOrHttps
        } else {
            AllowedScheme::HttpsOnly
        }
    }
}

/// Outcome categorisation persisted alongside every dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DispatchStatus {
    /// Plugin returned a 2xx response.
    Success,
    /// Plugin returned a non-2xx response.
    Failed,
    /// Request timed out before a response was received.
    Timeout,
    /// Request never left the dispatcher (e.g. URL scheme rejected,
    /// transport error).
    Rejected,
}

impl DispatchStatus {
    /// Stable wire string used by the DB column.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failed => "failed",
            Self::Timeout => "timeout",
            Self::Rejected => "rejected",
        }
    }
}

/// Per-dispatch outcome surfaced to the caller (controller, adapter).
#[derive(Debug, Clone)]
pub struct DispatchOutcome {
    /// Outcome category.
    pub status: DispatchStatus,
    /// Round-trip latency in milliseconds.
    pub latency_ms: u32,
    /// Plugin HTTP status code (if a response was received).
    pub http_status: Option<u16>,
    /// First N bytes of the plugin response body, UTF-8 lossy.
    pub response_excerpt: Option<String>,
    /// Structured error reason — only populated when the dispatch
    /// could not be completed (transport error / URL rejected).
    pub error: Option<String>,
}

/// Per-dispatch history record persisted by the adapter so the
/// dashboard's `GET /v1/plugins/{id}/dispatches` can surface it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DispatchRecord {
    /// Unique dispatch id (UUID v4).
    pub id: uuid::Uuid,
    /// Tenant the dispatch was scoped to.
    pub tenant_id: String,
    /// Plugin the envelope was sent to.
    pub plugin_id: PluginId,
    /// Event kind triggering the dispatch.
    pub event_kind: EventKind,
    /// SHA-256 of the canonicalised body (32 bytes) — surfaced so
    /// auditors can verify a known payload was dispatched without
    /// retaining the cleartext body.
    pub payload_hash: [u8; 32],
    /// Outcome category.
    pub status: DispatchStatus,
    /// Round-trip latency in milliseconds.
    pub latency_ms: u32,
    /// First N bytes of the plugin response body.
    pub response_excerpt: Option<String>,
    /// RFC 3339 dispatch timestamp.
    pub ts: String,
}

/// Errors the dispatcher surfaces to callers (controller, adapter).
#[derive(Debug, Clone, thiserror::Error)]
pub enum DispatchError {
    /// The webhook URL violated the configured scheme policy.
    #[error("webhook URL rejected: {0}")]
    UrlRejected(String),
    /// Envelope could not be serialised.
    #[error("envelope serialise: {0}")]
    Serialise(String),
    /// HMAC could not be constructed from the secret bytes.
    #[error("hmac key: {0}")]
    HmacKey(String),
    /// Underlying HTTP client failed to build a request.
    #[error("request build: {0}")]
    RequestBuild(String),
}

/// Outbound webhook dispatcher.
///
/// Constructed once with a shared [`reqwest::Client`] so the dispatcher
/// reuses TLS sessions across plugins.
#[derive(Debug, Clone)]
pub struct PluginDispatcher {
    client: reqwest::Client,
    cfg: DispatcherConfig,
}

impl PluginDispatcher {
    /// Build a new dispatcher with the supplied configuration.
    ///
    /// # Errors
    ///
    /// Surfaces the underlying [`reqwest::Error`] if the HTTP client
    /// could not be constructed (TLS init, etc.).
    pub fn new(cfg: DispatcherConfig) -> Result<Self, reqwest::Error> {
        let client = reqwest::Client::builder()
            .user_agent("SentinelX-Plugin-Dispatcher/0.1")
            .timeout(cfg.timeout)
            .build()?;
        Ok(Self { client, cfg })
    }

    /// Build a dispatcher with a caller-supplied [`reqwest::Client`].
    ///
    /// Useful for tests that swap in a wiremock-backed client without
    /// re-doing the TLS handshake setup.
    #[must_use]
    pub const fn with_client(client: reqwest::Client, cfg: DispatcherConfig) -> Self {
        Self { client, cfg }
    }

    /// Inspect the active configuration.
    #[must_use]
    pub const fn config(&self) -> &DispatcherConfig {
        &self.cfg
    }

    /// Dispatch a single envelope to `webhook_url`, signed with
    /// `secret`.
    ///
    /// Never panics; every failure path lands in a [`DispatchOutcome`]
    /// or a [`DispatchError`].
    ///
    /// # Errors
    ///
    /// Returns [`DispatchError`] when the dispatch *could not be
    /// attempted* (URL rejected, envelope unserialisable, HMAC key
    /// rejected). Transport failures, timeouts, and non-2xx responses
    /// are reported via [`DispatchOutcome::status`].
    pub async fn dispatch(
        &self,
        webhook_url: &str,
        secret: &SecretString,
        envelope: PluginEnvelope,
    ) -> Result<(DispatchOutcome, [u8; 32]), DispatchError> {
        validate_url(webhook_url, self.cfg.scheme_policy())?;

        // Serialise the envelope once; the bytes are then both signed
        // and POSTed verbatim so the plugin sees a body whose digest
        // matches the header.
        let mut envelope = envelope;
        let body_for_hint = envelope
            .to_bytes()
            .map_err(|e| DispatchError::Serialise(e.to_string()))?;
        let sig_full =
            sign_body(secret, &body_for_hint).map_err(|e| DispatchError::HmacKey(e.to_string()))?;
        envelope.signature_hint = sig_full.chars().take(8).collect();
        let body = envelope
            .to_bytes()
            .map_err(|e| DispatchError::Serialise(e.to_string()))?;
        let signature =
            sign_body(secret, &body).map_err(|e| DispatchError::HmacKey(e.to_string()))?;

        let payload_hash = sha256_digest(&body);

        let ts = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .unwrap_or_else(|_| envelope.ts.clone());

        let request = self
            .client
            .post(webhook_url)
            .header("Content-Type", "application/json")
            .header(SIGNATURE_HEADER, &signature)
            .header(TIMESTAMP_HEADER, &ts)
            .body(body);

        let started = Instant::now();
        let outcome = match request.send().await {
            Ok(resp) => self.consume_response(resp, started).await,
            Err(err) => {
                let elapsed = started.elapsed();
                if err.is_timeout() {
                    DispatchOutcome {
                        status: DispatchStatus::Timeout,
                        latency_ms: clamp_millis(elapsed),
                        http_status: None,
                        response_excerpt: None,
                        error: Some("request timed out".to_owned()),
                    }
                } else {
                    DispatchOutcome {
                        status: DispatchStatus::Rejected,
                        latency_ms: clamp_millis(elapsed),
                        http_status: None,
                        response_excerpt: None,
                        error: Some(err.to_string()),
                    }
                }
            }
        };

        tracing::info!(
            target: "sx_plugins.dispatcher",
            event = %envelope.event_kind.as_str(),
            tenant_id = %envelope.tenant_id,
            status = outcome.status.as_str(),
            latency_ms = outcome.latency_ms,
            "plugin dispatch complete"
        );

        Ok((outcome, payload_hash))
    }

    /// Drain the response body up to [`RESPONSE_EXCERPT_BYTES`] and
    /// project the outcome.
    async fn consume_response(&self, resp: reqwest::Response, started: Instant) -> DispatchOutcome {
        let http_status = resp.status();
        let success = http_status.is_success();
        let text = match resp.text().await {
            Ok(t) => t,
            Err(err) => {
                return DispatchOutcome {
                    status: DispatchStatus::Failed,
                    latency_ms: clamp_millis(started.elapsed()),
                    http_status: Some(http_status.as_u16()),
                    response_excerpt: None,
                    error: Some(format!("response read: {err}")),
                };
            }
        };
        let excerpt = if text.is_empty() {
            None
        } else {
            let bytes = text.as_bytes();
            let take = bytes.len().min(RESPONSE_EXCERPT_BYTES);
            Some(String::from_utf8_lossy(bytes.get(..take).unwrap_or(&[])).into_owned())
        };
        let status = if success {
            DispatchStatus::Success
        } else {
            DispatchStatus::Failed
        };
        DispatchOutcome {
            status,
            latency_ms: clamp_millis(started.elapsed()),
            http_status: Some(http_status.as_u16()),
            response_excerpt: excerpt,
            error: None,
        }
    }
}

/// Compute the hex-encoded HMAC-SHA256 of `body` keyed by `secret`.
///
/// # Errors
///
/// Returns a hard-coded message when the secret bytes cannot key an
/// HMAC instance (this never happens for SHA-256 — any key length is
/// valid — but the type signature keeps callers honest).
pub fn sign_body(secret: &SecretString, body: &[u8]) -> Result<String, &'static str> {
    let mut mac = HmacSha256::new_from_slice(secret.expose_secret().as_bytes())
        .map_err(|_| "invalid hmac key length")?;
    mac.update(body);
    Ok(hex::encode(mac.finalize().into_bytes()))
}

/// Constant-time verification of an HMAC-SHA256 signature in hex form.
///
/// Used by plugin SDKs (and by tests) to confirm a dispatched body
/// matches the signature header.
#[must_use]
pub fn verify_signature(secret: &SecretString, body: &[u8], signature_hex: &str) -> bool {
    let Ok(provided) = hex::decode(signature_hex) else {
        return false;
    };
    let Ok(expected) = sign_body(secret, body) else {
        return false;
    };
    let Ok(expected_bytes) = hex::decode(&expected) else {
        return false;
    };
    expected_bytes.ct_eq(&provided).into()
}

fn validate_url(raw: &str, policy: AllowedScheme) -> Result<(), DispatchError> {
    let parsed =
        url::Url::parse(raw).map_err(|e| DispatchError::UrlRejected(format!("parse: {e}")))?;
    match parsed.scheme() {
        "https" => Ok(()),
        "http" => match policy {
            AllowedScheme::HttpOrHttps => Ok(()),
            AllowedScheme::HttpsOnly => Err(DispatchError::UrlRejected(
                "http scheme requires allow_http=true".to_owned(),
            )),
        },
        other => Err(DispatchError::UrlRejected(format!(
            "unsupported scheme: {other}"
        ))),
    }
}

fn sha256_digest(body: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(body);
    let digest = hasher.finalize();
    let mut out = [0_u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn clamp_millis(d: Duration) -> u32 {
    let ms = d.as_millis();
    if ms > u128::from(u32::MAX) {
        u32::MAX
    } else {
        u32::try_from(ms).unwrap_or(u32::MAX)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use secrecy::SecretString;

    #[test]
    fn sign_body_round_trips_through_verify() {
        let secret = SecretString::new("super-shared-secret".to_owned().into());
        let body = b"{\"event\":\"finding.created\"}";
        let sig = sign_body(&secret, body).unwrap();
        assert!(verify_signature(&secret, body, &sig));
    }

    #[test]
    fn verify_rejects_tampered_body() {
        let secret = SecretString::new("k".to_owned().into());
        let sig = sign_body(&secret, b"abc").unwrap();
        assert!(!verify_signature(&secret, b"abd", &sig));
    }

    #[test]
    fn verify_rejects_wrong_secret() {
        let s1 = SecretString::new("k1".to_owned().into());
        let s2 = SecretString::new("k2".to_owned().into());
        let sig = sign_body(&s1, b"abc").unwrap();
        assert!(!verify_signature(&s2, b"abc", &sig));
    }

    #[test]
    fn verify_rejects_non_hex_signature() {
        let secret = SecretString::new("k".to_owned().into());
        assert!(!verify_signature(&secret, b"abc", "not-hex"));
    }

    #[test]
    fn validate_url_accepts_https() {
        validate_url("https://plugin.example/hook", AllowedScheme::HttpsOnly).unwrap();
    }

    #[test]
    fn validate_url_rejects_http_under_strict_policy() {
        let err = validate_url("http://plugin.example/hook", AllowedScheme::HttpsOnly)
            .expect_err("http must be rejected");
        assert!(matches!(err, DispatchError::UrlRejected(_)));
    }

    #[test]
    fn validate_url_accepts_http_under_dev_policy() {
        validate_url("http://plugin.example/hook", AllowedScheme::HttpOrHttps).unwrap();
    }

    #[test]
    fn validate_url_rejects_other_schemes() {
        let err = validate_url("ftp://plugin.example/", AllowedScheme::HttpOrHttps)
            .expect_err("ftp must be rejected");
        assert!(matches!(err, DispatchError::UrlRejected(_)));
    }

    #[test]
    fn dispatch_status_as_str_is_stable() {
        assert_eq!(DispatchStatus::Success.as_str(), "success");
        assert_eq!(DispatchStatus::Failed.as_str(), "failed");
        assert_eq!(DispatchStatus::Timeout.as_str(), "timeout");
        assert_eq!(DispatchStatus::Rejected.as_str(), "rejected");
    }

    #[test]
    fn clamp_millis_saturates_on_overflow() {
        let huge = Duration::from_secs(u64::from(u32::MAX) + 10);
        assert_eq!(clamp_millis(huge), u32::MAX);
    }

    #[test]
    fn config_default_is_strict_https() {
        let cfg = DispatcherConfig::default();
        assert!(!cfg.allow_http);
        assert_eq!(cfg.scheme_policy(), AllowedScheme::HttpsOnly);
        assert_eq!(cfg.timeout, DEFAULT_TIMEOUT);
    }
}
