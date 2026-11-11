//! GitHub webhook ingestion.
//!
//! GitHub signs payloads with HMAC-SHA256 over the raw request body,
//! transmitting the digest in the `X-Hub-Signature-256` header as
//! `sha256=<hex>`. Implementations MUST use a constant-time comparison
//! against the recomputed digest — this module routes through
//! [`subtle::ConstantTimeEq`].
//!
//! See: <https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries>

use hmac::{Hmac, Mac};
use secrecy::{ExposeSecret, SecretString};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::common::WebhookEvent;
use crate::error::WebhookError;

/// Canonical name for the signature header GitHub sets on every
/// outbound delivery.
pub const SIGNATURE_HEADER: &str = "X-Hub-Signature-256";

/// Canonical name for the event-type header GitHub sets on every
/// outbound delivery (e.g. `pull_request`, `push`, `security_advisory`).
pub const EVENT_HEADER: &str = "X-GitHub-Event";

type HmacSha256 = Hmac<Sha256>;

/// Constant-time verification of a GitHub webhook signature.
///
/// `signature_header` is the raw header value
/// (`sha256=<hex>`). `body` is the *exact* raw request body bytes as
/// received — any re-encoding will cause a legitimate mismatch.
///
/// # Errors
///
/// Returns [`WebhookError::InvalidSignature`] if the header is missing
/// the `sha256=` prefix, contains non-hex bytes, has the wrong length,
/// or does not match the recomputed HMAC.
pub fn verify_signature(
    secret: &SecretString,
    signature_header: Option<&str>,
    body: &[u8],
) -> Result<(), WebhookError> {
    let provided = decode_sha256_header(signature_header)?;
    let expected = compute_hmac(secret, body)?;
    if expected.ct_eq(&provided).into() {
        Ok(())
    } else {
        tracing::debug!(provider = "github", "signature mismatch");
        Err(WebhookError::InvalidSignature)
    }
}

fn decode_sha256_header(header: Option<&str>) -> Result<Vec<u8>, WebhookError> {
    let Some(raw) = header else {
        tracing::debug!(provider = "github", "signature header missing");
        return Err(WebhookError::InvalidSignature);
    };
    let Some(hex_part) = raw.strip_prefix("sha256=") else {
        tracing::debug!(
            provider = "github",
            "signature header missing sha256= prefix"
        );
        return Err(WebhookError::InvalidSignature);
    };
    hex::decode(hex_part).map_err(|_| WebhookError::InvalidSignature)
}

fn compute_hmac(secret: &SecretString, body: &[u8]) -> Result<Vec<u8>, WebhookError> {
    let mut mac = HmacSha256::new_from_slice(secret.expose_secret().as_bytes())
        .map_err(|_| WebhookError::InvalidSignature)?;
    mac.update(body);
    Ok(mac.finalize().into_bytes().to_vec())
}

/// Verify a GitHub delivery and project it into a [`WebhookEvent`].
///
/// # Errors
///
/// * [`WebhookError::InvalidSignature`] — signature missing or invalid.
/// * [`WebhookError::BadPayload`] — body is not valid JSON.
/// * [`WebhookError::Unsupported`] — `X-GitHub-Event` header missing.
pub fn verify_and_parse(
    secret: &SecretString,
    signature_header: Option<&str>,
    event_header: Option<&str>,
    body: &[u8],
) -> Result<WebhookEvent, WebhookError> {
    verify_signature(secret, signature_header, body)?;

    let event_type = event_header
        .ok_or_else(|| WebhookError::Unsupported("missing X-GitHub-Event".to_owned()))?;

    let payload: serde_json::Value =
        serde_json::from_slice(body).map_err(|_| WebhookError::BadPayload)?;

    let kind = derive_kind(event_type, &payload);
    tracing::info!(provider = "github", event = %kind, "accepted webhook");
    Ok(WebhookEvent::new("github", &kind, payload))
}

/// Combine the `X-GitHub-Event` header with the payload's `action`
/// field when present (e.g. `pull_request.opened`).
fn derive_kind(event_type: &str, payload: &serde_json::Value) -> String {
    match event_type {
        "pull_request" | "issues" | "security_advisory" | "release" | "check_run"
        | "check_suite" => payload
            .get("action")
            .and_then(serde_json::Value::as_str)
            .map_or_else(
                || event_type.to_owned(),
                |action| format!("{event_type}.{action}"),
            ),
        other => other.to_owned(),
    }
}
