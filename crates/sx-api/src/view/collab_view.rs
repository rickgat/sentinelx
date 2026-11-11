//! Collaborator (OOB token / callback) DTOs.
//!
//! These views are the wire shape exchanged on
//! `POST /v1/collab/tokens` and `GET /v1/collab/tokens/{token}/callbacks`.
//!
//! Strings are kept opaque so this crate does not depend on the concrete
//! [`sx_collab::model::Token`] type: callers may evolve the internal token
//! format independently of the HTTP contract.

use serde::{Deserialize, Serialize};
use validator::Validate;

/// `POST /v1/collab/tokens` request body.
///
/// `tenant_id` is the tenant uuid that owns the originating finding;
/// `finding_id` is treated as opaque text — any non-empty string is
/// accepted at this layer and resolved further down by the collaborator
/// allocator.
#[derive(Debug, Clone, Deserialize, Serialize, Validate)]
pub struct CollabAllocateTokenRequestView {
    /// Tenant uuid the new token is bound to.
    #[validate(custom(function = "validate_uuid"))]
    pub tenant_id: String,
    /// Caller-provided finding identifier.
    #[validate(length(min = 1))]
    pub finding_id: String,
}

/// `POST /v1/collab/tokens` response body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollabAllocateTokenResponseView {
    /// Newly minted 16-hex-char OOB token.
    pub token: String,
    /// Base domain the token is scoped under — receivers answer for
    /// `<token>.oob.<base_domain>`.
    pub base_domain: String,
    /// RFC 3339 timestamp at which the token's callback retention expires.
    pub expires_at: String,
}

/// `GET /v1/collab/tokens/{token}/callbacks` response body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollabCallbacksResponseView {
    /// Echo of the lookup token.
    pub token: String,
    /// Every recorded callback that resolved to `token`.
    pub callbacks: Vec<CallbackView>,
}

/// A single recorded callback projected onto a stable wire shape.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallbackView {
    /// Variant tag — `"dns"`, `"http"`, or `"smtp"`.
    pub kind: String,
    /// RFC 3339 reception timestamp.
    pub received_at: String,
    /// Peer source IP if the transport exposed one.
    pub source_ip: Option<String>,
    /// Variant-specific payload (method/path/headers for HTTP,
    /// query-type for DNS, envelope/excerpt for SMTP). Opaque JSON so the
    /// wire surface stays decoupled from the receiver implementations.
    pub details: serde_json::Value,
}

/// Validate that `value` parses as a uuid (any version).
///
/// We accept any uuid representation `Uuid::parse_str` accepts so callers
/// may pass tenant ids minted by v4 or v7 generators interchangeably.
fn validate_uuid(value: &str) -> Result<(), validator::ValidationError> {
    if uuid::Uuid::parse_str(value).is_ok() {
        Ok(())
    } else {
        Err(validator::ValidationError::new("invalid_uuid"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocate_request_validates_token_uuid() {
        // Reject: tenant_id is not a uuid.
        let bad = CollabAllocateTokenRequestView {
            tenant_id: "not-a-uuid".into(),
            finding_id: "F-001".into(),
        };
        assert!(bad.validate().is_err());

        // Accept: tenant_id is a valid uuid + finding_id is non-empty.
        let good = CollabAllocateTokenRequestView {
            tenant_id: "00000000-0000-4000-8000-000000000000".into(),
            finding_id: "F-001".into(),
        };
        assert!(good.validate().is_ok());

        // Reject: empty finding_id.
        let empty_finding = CollabAllocateTokenRequestView {
            tenant_id: "00000000-0000-4000-8000-000000000000".into(),
            finding_id: String::new(),
        };
        assert!(empty_finding.validate().is_err());
    }

    #[test]
    fn callback_view_kind_round_trip_serde() {
        let cb = CallbackView {
            kind: "http".into(),
            received_at: "2026-05-29T12:00:00Z".into(),
            source_ip: Some("127.0.0.1".into()),
            details: serde_json::json!({
                "method": "GET",
                "path": "/probe",
            }),
        };
        let json = serde_json::to_string(&cb).unwrap();
        let back: CallbackView = serde_json::from_str(&json).unwrap();
        assert_eq!(back.kind, "http");
        assert_eq!(back.received_at, "2026-05-29T12:00:00Z");
        assert_eq!(back.source_ip.as_deref(), Some("127.0.0.1"));
        assert_eq!(
            back.details.get("method").and_then(|v| v.as_str()),
            Some("GET")
        );
    }
}
