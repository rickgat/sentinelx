//! Slack webhook ingestion.
//!
//! Slack signs Events API and slash-command requests with HMAC-SHA256
//! over the concatenation `v0:{timestamp}:{body}`. The hex digest is
//! transmitted in the `X-Slack-Signature` header as `v0=<hex>`, and the
//! timestamp travels alongside in `X-Slack-Request-Timestamp`.
//!
//! Slack documents a strict 5-minute replay window between
//! `X-Slack-Request-Timestamp` and the receiver's clock. Older or
//! future-dated requests MUST be rejected to mitigate replay attacks.
//!
//! See: <https://api.slack.com/authentication/verifying-requests-from-slack>

use hmac::{Hmac, Mac};
use secrecy::{ExposeSecret, SecretString};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::common::WebhookEvent;
use crate::error::WebhookError;

/// Canonical name for the Slack signature header.
pub const SIGNATURE_HEADER: &str = "X-Slack-Signature";

/// Canonical name for the Slack timestamp header used in the v0 signing
/// scheme.
pub const TIMESTAMP_HEADER: &str = "X-Slack-Request-Timestamp";

/// Replay window enforced by [`verify_signature`], in seconds. Matches
/// Slack's documented 5-minute window.
pub const REPLAY_WINDOW_SECS: i64 = 300;

type HmacSha256 = Hmac<Sha256>;

/// Constant-time verification of a Slack v0 signature, including
/// replay-window enforcement.
///
/// `timestamp` and `now` are seconds since the Unix epoch. A request
/// is rejected with [`WebhookError::ReplayWindowExceeded`] when
/// `|now - timestamp| > REPLAY_WINDOW_SECS`.
///
/// # Errors
///
/// * [`WebhookError::ReplayWindowExceeded`] — outside the 5-minute
///   replay window relative to `now`.
/// * [`WebhookError::InvalidSignature`] — header missing, malformed,
///   or did not match the recomputed HMAC.
pub fn verify_signature(
    secret: &SecretString,
    timestamp: i64,
    body: &[u8],
    signature_header: Option<&str>,
    now: i64,
) -> Result<(), WebhookError> {
    check_replay_window(timestamp, now)?;
    let provided = decode_v0_header(signature_header)?;
    let expected = compute_v0_hmac(secret, timestamp, body)?;
    if expected.ct_eq(&provided).into() {
        Ok(())
    } else {
        tracing::debug!(provider = "slack", "signature mismatch");
        Err(WebhookError::InvalidSignature)
    }
}

fn check_replay_window(timestamp: i64, now: i64) -> Result<(), WebhookError> {
    let delta = now.saturating_sub(timestamp).abs();
    if delta > REPLAY_WINDOW_SECS {
        tracing::debug!(
            provider = "slack",
            delta_secs = delta,
            "timestamp outside replay window"
        );
        Err(WebhookError::ReplayWindowExceeded)
    } else {
        Ok(())
    }
}

fn decode_v0_header(header: Option<&str>) -> Result<Vec<u8>, WebhookError> {
    let Some(raw) = header else {
        tracing::debug!(provider = "slack", "signature header missing");
        return Err(WebhookError::InvalidSignature);
    };
    let Some(hex_part) = raw.strip_prefix("v0=") else {
        tracing::debug!(provider = "slack", "signature header missing v0= prefix");
        return Err(WebhookError::InvalidSignature);
    };
    hex::decode(hex_part).map_err(|_| WebhookError::InvalidSignature)
}

fn compute_v0_hmac(
    secret: &SecretString,
    timestamp: i64,
    body: &[u8],
) -> Result<Vec<u8>, WebhookError> {
    let mut mac = HmacSha256::new_from_slice(secret.expose_secret().as_bytes())
        .map_err(|_| WebhookError::InvalidSignature)?;
    mac.update(b"v0:");
    mac.update(timestamp.to_string().as_bytes());
    mac.update(b":");
    mac.update(body);
    Ok(mac.finalize().into_bytes().to_vec())
}

/// Verify a Slack delivery and project it into a [`WebhookEvent`].
///
/// Slack Events API requests carry `type` at the top level (e.g.
/// `event_callback`) and a nested `event.type` inside. This function
/// projects the kind as `event_callback.<event.type>` when both are
/// present, falling back to the top-level `type` otherwise.
///
/// # Errors
///
/// * [`WebhookError::ReplayWindowExceeded`] — outside the replay window.
/// * [`WebhookError::InvalidSignature`] — signature mismatch.
/// * [`WebhookError::BadPayload`] — body is not valid JSON.
/// * [`WebhookError::Unsupported`] — no `type` field present.
pub fn verify_and_parse(
    secret: &SecretString,
    timestamp: i64,
    body: &[u8],
    signature_header: Option<&str>,
    now: i64,
) -> Result<WebhookEvent, WebhookError> {
    verify_signature(secret, timestamp, body, signature_header, now)?;

    let payload: serde_json::Value =
        serde_json::from_slice(body).map_err(|_| WebhookError::BadPayload)?;

    let kind = derive_kind(&payload)
        .ok_or_else(|| WebhookError::Unsupported("missing slack event type".to_owned()))?;
    tracing::info!(provider = "slack", event = %kind, "accepted webhook");
    Ok(WebhookEvent::new("slack", &kind, payload))
}

fn derive_kind(payload: &serde_json::Value) -> Option<String> {
    let top = payload.get("type").and_then(serde_json::Value::as_str)?;
    let inner = payload
        .get("event")
        .and_then(|e| e.get("type"))
        .and_then(serde_json::Value::as_str);
    Some(inner.map_or_else(|| top.to_owned(), |i| format!("{top}.{i}")))
}
