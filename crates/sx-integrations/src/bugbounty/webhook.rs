//! Inbound webhook verification + canonical [`CanonicalFinding`] mapping.
//!
//! The HTTP surface lives in `sx-api`:
//!
//! * `POST /v1/integrations/bugbounty/inbound/{platform}`
//!
//! The controller deserialises the headers + raw body, looks up the
//! tenant's webhook HMAC secret via [`super::config::load_webhook_secret`],
//! and calls [`verify_signature`] **before** any deserialisation of the
//! body. On success the controller calls [`map_to_finding`] to project
//! the payload into a [`CanonicalFinding`].
//!
//! ## Signature scheme
//!
//! Both HackerOne and Bugcrowd deliver an HMAC-SHA256 over the raw
//! request body. The header carrying the digest differs by platform:
//!
//! | Platform   | Header              | Encoding |
//! |------------|---------------------|----------|
//! | HackerOne  | `X-H1-Signature`    | hex      |
//! | Bugcrowd   | `X-Bugcrowd-Signature` | hex   |
//!
//! Verification uses a *constant-time* compare ([`subtle::ConstantTimeEq`])
//! so a timing oracle cannot leak the secret.
//!
//! ## Source tag
//!
//! Inbound findings are tagged
//! `bugbounty.<platform>.researcher_<researcher_id>` per the P3-010
//! contract.

use hmac::{Hmac, Mac};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use thiserror::Error;

use crate::siem::Severity;

use super::connector::BugBountyKind;

/// HMAC-SHA256 instance over the raw request body.
type HmacSha256 = Hmac<Sha256>;

/// Header carrying the HMAC signature on HackerOne webhook deliveries.
pub const HACKERONE_SIGNATURE_HEADER: &str = "x-h1-signature";

/// Header carrying the HMAC signature on Bugcrowd webhook deliveries.
pub const BUGCROWD_SIGNATURE_HEADER: &str = "x-bugcrowd-signature";

/// Errors surfaced by webhook verification + mapping.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum WebhookError {
    /// The signature header was absent.
    #[error("missing signature header")]
    MissingSignature,

    /// The signature header was present but the value was not valid hex
    /// or the wrong length for HMAC-SHA256 (32 bytes / 64 hex chars).
    #[error("malformed signature header")]
    MalformedSignature,

    /// The HMAC-SHA256 over the body did not match the header value.
    #[error("signature mismatch")]
    SignatureMismatch,

    /// The payload could not be parsed as JSON, or the expected fields
    /// were missing / wrong type.
    #[error("malformed webhook payload: {0}")]
    MalformedPayload(String),

    /// The webhook secret material was empty or otherwise unusable.
    #[error("invalid webhook secret")]
    InvalidSecret,
}

/// Header name carrying the HMAC signature for `platform`.
#[must_use]
pub const fn signature_header_for(platform: BugBountyKind) -> &'static str {
    match platform {
        BugBountyKind::HackerOne => HACKERONE_SIGNATURE_HEADER,
        BugBountyKind::Bugcrowd => BUGCROWD_SIGNATURE_HEADER,
    }
}

/// Verify the HMAC-SHA256 of `body_bytes` against the hex-encoded
/// `signature_hex` value using `secret`. Performs a **constant-time**
/// comparison via [`subtle::ConstantTimeEq`].
///
/// # Errors
///
/// * [`WebhookError::InvalidSecret`] when `secret` is empty (defence in
///   depth — an empty secret would accept arbitrary signatures and is
///   never a legitimate configuration).
/// * [`WebhookError::MalformedSignature`] when `signature_hex` is not a
///   valid hex string or is the wrong length.
/// * [`WebhookError::SignatureMismatch`] when the digests differ.
pub fn verify_signature(
    secret: &SecretString,
    body_bytes: &[u8],
    signature_hex: &str,
) -> Result<(), WebhookError> {
    let secret_bytes = secret.expose_secret().as_bytes();
    if secret_bytes.is_empty() {
        return Err(WebhookError::InvalidSecret);
    }

    // Trim and strip optional `sha256=` prefix that some platforms send.
    let raw = signature_hex.trim();
    let raw = raw.strip_prefix("sha256=").unwrap_or(raw);
    let expected_bytes = hex::decode(raw).map_err(|_| WebhookError::MalformedSignature)?;
    if expected_bytes.len() != 32 {
        return Err(WebhookError::MalformedSignature);
    }

    // `Hmac::new_from_slice` accepts any key length for SHA-256; the only
    // failure mode is OOM, which we surface as an invalid-secret error.
    let mut mac =
        HmacSha256::new_from_slice(secret_bytes).map_err(|_| WebhookError::InvalidSecret)?;
    mac.update(body_bytes);
    let computed = mac.finalize().into_bytes();

    // Constant-time compare. `ct_eq` returns a `Choice` which we collapse
    // into a boolean only for control flow — the underlying byte
    // comparison itself does not short-circuit.
    if computed.as_slice().ct_eq(&expected_bytes).unwrap_u8() == 1 {
        Ok(())
    } else {
        Err(WebhookError::SignatureMismatch)
    }
}

/// Canonical inbound finding produced by [`map_to_finding`].
///
/// The shape is connector-agnostic — the controller hands this to the
/// downstream finding ingest pipeline. The `source` field carries the
/// stable
/// `bugbounty.<platform>.researcher_<researcher_id>` tag.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CanonicalFinding {
    /// Stable source tag — `bugbounty.hackerone.researcher_42` etc.
    pub source: String,
    /// Platform-side researcher identifier.
    pub researcher_id: String,
    /// Platform-side report identifier.
    pub report_id: String,
    /// Program handle the report was filed against.
    pub program_handle: String,
    /// Short title of the report.
    pub title: String,
    /// Long-form description of the report.
    pub description: String,
    /// Severity, mapped onto the SentinelX five-level scale.
    pub severity: Severity,
}

/// Map a verified inbound webhook payload to a [`CanonicalFinding`].
///
/// The body may carry either the HackerOne JSON:API envelope or the
/// Bugcrowd JSON:API envelope; both expose the relevant fields under
/// `data.attributes`. We accept either, plus a flat fallback shape for
/// testability.
///
/// # Errors
///
/// Returns [`WebhookError::MalformedPayload`] when a required field is
/// missing or the JSON is malformed.
pub fn map_to_finding(
    platform: BugBountyKind,
    body_bytes: &[u8],
) -> Result<CanonicalFinding, WebhookError> {
    let value: serde_json::Value = serde_json::from_slice(body_bytes)
        .map_err(|e| WebhookError::MalformedPayload(e.to_string()))?;

    // Both platforms use JSON:API for their v1/v2 surfaces. Fall through
    // a JSON:API path first; if no `data.attributes` envelope is present,
    // treat the whole document as the attributes payload (this also
    // accepts flat fixtures from tests).
    let attrs = value.pointer("/data/attributes").unwrap_or(&value).clone();

    let researcher_id = attrs
        .pointer("/researcher/id")
        .or_else(|| attrs.get("researcher_id"))
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| WebhookError::MalformedPayload("missing researcher id".into()))?;

    let report_id = value
        .pointer("/data/id")
        .or_else(|| attrs.get("report_id"))
        .or_else(|| attrs.get("id"))
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| WebhookError::MalformedPayload("missing report id".into()))?;

    let program_handle = attrs
        .pointer("/program/handle")
        .or_else(|| attrs.get("program_handle"))
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| WebhookError::MalformedPayload("missing program handle".into()))?;

    let title = attrs
        .get("title")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| WebhookError::MalformedPayload("missing title".into()))?;

    let description = attrs
        .get("vulnerability_information")
        .or_else(|| attrs.get("description"))
        .or_else(|| attrs.get("body"))
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .unwrap_or_default();

    let severity_label = attrs
        .pointer("/severity/rating")
        .or_else(|| attrs.get("severity"))
        .and_then(serde_json::Value::as_str)
        .map_or_else(|| "medium".to_owned(), str::to_ascii_lowercase);
    let severity = parse_severity(&severity_label);

    Ok(CanonicalFinding {
        source: format!(
            "bugbounty.{}.researcher_{}",
            platform.as_wire(),
            researcher_id
        ),
        researcher_id,
        report_id,
        program_handle,
        title,
        description,
        severity,
    })
}

/// Map a vendor severity string to the SentinelX [`Severity`] scale.
///
/// Unknown values map to [`Severity::Medium`] — a conservative default
/// that ensures inbound reports always land somewhere triagable. The
/// `"medium"` / `"p3"` aliases are deliberately folded into the wildcard
/// arm so the table stays clippy-clean while still documenting the
/// platform labels that land there explicitly.
fn parse_severity(label: &str) -> Severity {
    match label {
        "info" | "informational" | "none" => Severity::Info,
        "low" | "p4" => Severity::Low,
        "high" | "p2" => Severity::High,
        "critical" | "p1" => Severity::Critical,
        // `"medium"` and `"p3"` land here intentionally — the wildcard
        // and the medium arm shared a body, so we let the wildcard catch
        // both rather than tripping `match_same_arms`.
        _ => Severity::Medium,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use hmac::Mac;

    fn sign(secret: &str, body: &[u8]) -> String {
        let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(body);
        hex::encode(mac.finalize().into_bytes())
    }

    #[test]
    fn verify_signature_accepts_matching_hex() {
        let secret = SecretString::from("hmac-secret".to_owned());
        let body = b"{\"hello\":\"world\"}";
        let sig = sign("hmac-secret", body);
        assert!(verify_signature(&secret, body, &sig).is_ok());
    }

    #[test]
    fn verify_signature_accepts_sha256_prefix() {
        let secret = SecretString::from("hmac-secret".to_owned());
        let body = b"{}";
        let sig = format!("sha256={}", sign("hmac-secret", body));
        assert!(verify_signature(&secret, body, &sig).is_ok());
    }

    #[test]
    fn verify_signature_rejects_tampered_body() {
        let secret = SecretString::from("hmac-secret".to_owned());
        let body = b"{\"hello\":\"world\"}";
        let sig = sign("hmac-secret", body);
        let tampered = b"{\"hello\":\"WORLD\"}";
        let err = verify_signature(&secret, tampered, &sig).unwrap_err();
        assert_eq!(err, WebhookError::SignatureMismatch);
    }

    #[test]
    fn verify_signature_rejects_wrong_secret() {
        let secret = SecretString::from("hmac-secret".to_owned());
        let body = b"{}";
        let sig = sign("WRONG-SECRET", body);
        let err = verify_signature(&secret, body, &sig).unwrap_err();
        assert_eq!(err, WebhookError::SignatureMismatch);
    }

    #[test]
    fn verify_signature_rejects_malformed_hex() {
        let secret = SecretString::from("hmac-secret".to_owned());
        let body = b"{}";
        let err = verify_signature(&secret, body, "not-hex!!").unwrap_err();
        assert_eq!(err, WebhookError::MalformedSignature);
    }

    #[test]
    fn verify_signature_rejects_short_digest() {
        let secret = SecretString::from("hmac-secret".to_owned());
        let body = b"{}";
        let err = verify_signature(&secret, body, "deadbeef").unwrap_err();
        assert_eq!(err, WebhookError::MalformedSignature);
    }

    #[test]
    fn verify_signature_rejects_empty_secret() {
        let secret = SecretString::from(String::new());
        let body = b"{}";
        let sig = sign("anything", body);
        let err = verify_signature(&secret, body, &sig).unwrap_err();
        assert_eq!(err, WebhookError::InvalidSecret);
    }

    #[test]
    fn signature_header_for_returns_per_platform_name() {
        assert_eq!(
            signature_header_for(BugBountyKind::HackerOne),
            HACKERONE_SIGNATURE_HEADER
        );
        assert_eq!(
            signature_header_for(BugBountyKind::Bugcrowd),
            BUGCROWD_SIGNATURE_HEADER
        );
    }

    #[test]
    fn map_to_finding_handles_hackerone_envelope() {
        let body = br#"{
            "data": {
                "id": "98765",
                "type": "report",
                "attributes": {
                    "title": "XSS in /search",
                    "vulnerability_information": "Reflected XSS via q",
                    "researcher": { "id": "42" },
                    "program": { "handle": "acme" },
                    "severity": { "rating": "high" }
                }
            }
        }"#;
        let f = map_to_finding(BugBountyKind::HackerOne, body).unwrap();
        assert_eq!(f.source, "bugbounty.hackerone.researcher_42");
        assert_eq!(f.researcher_id, "42");
        assert_eq!(f.report_id, "98765");
        assert_eq!(f.program_handle, "acme");
        assert_eq!(f.title, "XSS in /search");
        assert_eq!(f.description, "Reflected XSS via q");
        assert_eq!(f.severity, Severity::High);
    }

    #[test]
    fn map_to_finding_handles_bugcrowd_envelope_with_p1() {
        let body = br#"{
            "data": {
                "id": "11111111-2222-3333-4444-555555555555",
                "type": "submission",
                "attributes": {
                    "title": "RCE",
                    "description": "Remote code exec on /upload",
                    "researcher": { "id": "rs-7" },
                    "program": { "handle": "acme-public" },
                    "severity": "p1"
                }
            }
        }"#;
        let f = map_to_finding(BugBountyKind::Bugcrowd, body).unwrap();
        assert_eq!(f.source, "bugbounty.bugcrowd.researcher_rs-7");
        assert_eq!(f.researcher_id, "rs-7");
        assert_eq!(f.report_id, "11111111-2222-3333-4444-555555555555");
        assert_eq!(f.program_handle, "acme-public");
        assert_eq!(f.severity, Severity::Critical);
    }

    #[test]
    fn map_to_finding_handles_flat_fixture() {
        let body = br#"{
            "id": "r-1",
            "researcher_id": "rs-1",
            "program_handle": "acme",
            "title": "SQLi",
            "description": "SQLi in /login",
            "severity": "medium"
        }"#;
        let f = map_to_finding(BugBountyKind::HackerOne, body).unwrap();
        assert_eq!(f.report_id, "r-1");
        assert_eq!(f.researcher_id, "rs-1");
        assert_eq!(f.severity, Severity::Medium);
    }

    #[test]
    fn map_to_finding_rejects_malformed_json() {
        let err = map_to_finding(BugBountyKind::HackerOne, b"{not json").unwrap_err();
        assert!(matches!(err, WebhookError::MalformedPayload(_)));
    }

    #[test]
    fn map_to_finding_rejects_missing_fields() {
        let body = br#"{"data": {"id": "1", "attributes": {"title": "x"}}}"#;
        let err = map_to_finding(BugBountyKind::HackerOne, body).unwrap_err();
        assert!(matches!(err, WebhookError::MalformedPayload(_)));
    }

    #[test]
    fn parse_severity_unknown_defaults_to_medium() {
        assert_eq!(parse_severity("space-alien"), Severity::Medium);
        assert_eq!(parse_severity(""), Severity::Medium);
        assert_eq!(parse_severity("info"), Severity::Info);
        assert_eq!(parse_severity("p4"), Severity::Low);
        assert_eq!(parse_severity("p1"), Severity::Critical);
    }
}
