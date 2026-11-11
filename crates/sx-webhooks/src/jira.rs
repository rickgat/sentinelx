//! Jira webhook ingestion.
//!
//! Jira Cloud and self-managed Jira Data Center deliver webhook
//! payloads with a top-level `webhookEvent` field
//! (e.g. `jira:issue_created`). When the integration is configured
//! with a signing secret, Jira transmits an HMAC-SHA256 digest of the
//! raw body in the `X-Hub-Signature` header as `sha256=<hex>`.
//!
//! See: <https://developer.atlassian.com/server/jira/platform/webhooks/>

use hmac::{Hmac, Mac};
use secrecy::{ExposeSecret, SecretString};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::common::WebhookEvent;
use crate::error::WebhookError;

/// Canonical name for the Jira signature header.
pub const SIGNATURE_HEADER: &str = "X-Hub-Signature";

type HmacSha256 = Hmac<Sha256>;

/// Constant-time verification of a Jira webhook signature.
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
        tracing::debug!(provider = "jira", "signature mismatch");
        Err(WebhookError::InvalidSignature)
    }
}

fn decode_sha256_header(header: Option<&str>) -> Result<Vec<u8>, WebhookError> {
    let Some(raw) = header else {
        tracing::debug!(provider = "jira", "signature header missing");
        return Err(WebhookError::InvalidSignature);
    };
    let Some(hex_part) = raw.strip_prefix("sha256=") else {
        tracing::debug!(provider = "jira", "signature header missing sha256= prefix");
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

/// Verify a Jira delivery and project it into a [`WebhookEvent`].
///
/// # Errors
///
/// * [`WebhookError::InvalidSignature`] — signature missing or invalid.
/// * [`WebhookError::BadPayload`] — body is not valid JSON.
/// * [`WebhookError::Unsupported`] — missing top-level `webhookEvent`.
pub fn verify_and_parse(
    secret: &SecretString,
    signature_header: Option<&str>,
    body: &[u8],
) -> Result<WebhookEvent, WebhookError> {
    verify_signature(secret, signature_header, body)?;

    let payload: serde_json::Value =
        serde_json::from_slice(body).map_err(|_| WebhookError::BadPayload)?;

    let kind = payload
        .get("webhookEvent")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| WebhookError::Unsupported("missing webhookEvent".to_owned()))?
        .to_owned();
    tracing::info!(provider = "jira", event = %kind, "accepted webhook");
    Ok(WebhookEvent::new("jira", &kind, payload))
}
