//! MFA DTOs — TOTP enrollment, verification, disable, status.
//!
//! Backs the four authenticated endpoints under `/v1/mfa/*` that
//! customers use to self-manage their TOTP second factor:
//!
//! - `POST /v1/mfa/enroll`  → [`EnrollResponse`]
//! - `POST /v1/mfa/verify`  → [`VerifyRequest`]
//! - `POST /v1/mfa/disable` → [`DisableRequest`]
//! - `GET  /v1/mfa/status`  → [`MfaStatusView`]
//!
//! ## Secret hygiene
//!
//! - The shared secret is emitted **once** at enrollment time in
//!   base32 form. Recovery codes are likewise returned **plaintext**
//!   only at enrollment; the adapter persists their SHA-256 hash so a
//!   database breach does not surrender every user's backup factor.
//! - DTOs deliberately do not implement `Debug` for fields holding
//!   secrets; callers MUST NOT log them. The structural `Debug` is
//!   omitted from [`EnrollResponse`] to make accidental tracing harder.

use serde::{Deserialize, Serialize};
use validator::Validate;

/// `POST /v1/mfa/enroll` response.
///
/// The base32-encoded secret + otpauth URI are emitted **once**; the
/// caller is expected to render the URI as a QR code and discard it.
/// Recovery codes are likewise plaintext exactly once — after the call
/// returns the adapter only retains their SHA-256 hash.
#[derive(Clone, Serialize, Deserialize)]
pub struct EnrollResponse {
    /// Base32 (RFC 4648, no padding) encoded shared secret. 32 chars
    /// for the SentinelX default (20-byte secret).
    pub secret_base32: String,
    /// `otpauth://totp/...` URI for QR-code rendering. Includes the
    /// issuer + account label and the base32 secret.
    pub otpauth_uri: String,
    /// Plaintext recovery codes (6 × 8 alphanumeric chars). Only
    /// returned here; afterwards the adapter only holds their hash.
    pub recovery_codes: Vec<String>,
}

impl std::fmt::Debug for EnrollResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnrollResponse")
            .field("secret_base32", &"<redacted>")
            .field("otpauth_uri", &"<redacted>")
            .field("recovery_codes_count", &self.recovery_codes.len())
            .finish()
    }
}

/// `POST /v1/mfa/verify` request.
///
/// `code` may carry either a 6-digit TOTP value OR a single-use
/// recovery code (8 alphanumeric chars). The adapter tries TOTP first
/// then falls back to recovery codes.
#[derive(Clone, Deserialize, Validate)]
pub struct VerifyRequest {
    /// TOTP code or recovery code.
    #[validate(length(min = 6, max = 32))]
    pub code: String,
}

impl std::fmt::Debug for VerifyRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifyRequest")
            .field("code", &"<redacted>")
            .finish()
    }
}

/// `POST /v1/mfa/disable` request.
///
/// Requires the caller to prove possession of their current second
/// factor before MFA can be removed. Like [`VerifyRequest`], a valid
/// TOTP or recovery code is accepted.
#[derive(Clone, Deserialize, Validate)]
pub struct DisableRequest {
    /// TOTP code or recovery code.
    #[validate(length(min = 6, max = 32))]
    pub code: String,
}

impl std::fmt::Debug for DisableRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DisableRequest")
            .field("code", &"<redacted>")
            .finish()
    }
}

/// `GET /v1/mfa/status` response.
///
/// `enrolled = false` means the user has not yet completed the
/// enroll → verify flow. `last_verified_at` is `None` until the first
/// successful verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MfaStatusView {
    /// Whether the user holds an active TOTP secret.
    pub enrolled: bool,
    /// RFC 3339 timestamp of the last successful verification, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_verified_at: Option<String>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn verify_request_redacts_code_in_debug() {
        let r = VerifyRequest {
            code: "123456".to_owned(),
        };
        let s = format!("{r:?}");
        assert!(!s.contains("123456"));
        assert!(s.contains("<redacted>"));
    }

    #[test]
    fn disable_request_redacts_code_in_debug() {
        let r = DisableRequest {
            code: "secret-code".to_owned(),
        };
        let s = format!("{r:?}");
        assert!(!s.contains("secret-code"));
    }

    #[test]
    fn enroll_response_redacts_secret_in_debug() {
        let r = EnrollResponse {
            secret_base32: "JBSWY3DPEHPK3PXP".to_owned(),
            otpauth_uri: "otpauth://totp/SentinelX:alice".to_owned(),
            recovery_codes: vec!["aaaa1111".to_owned(), "bbbb2222".to_owned()],
        };
        let s = format!("{r:?}");
        assert!(!s.contains("JBSWY3DPEHPK3PXP"));
        assert!(!s.contains("aaaa1111"));
    }

    #[test]
    fn status_serialises_without_last_verified_when_absent() {
        let s = MfaStatusView {
            enrolled: false,
            last_verified_at: None,
        };
        let v = serde_json::to_value(s).unwrap();
        assert_eq!(v["enrolled"], false);
        assert!(v.get("last_verified_at").is_none());
    }

    #[test]
    fn verify_request_validates_length() {
        let bad = VerifyRequest {
            code: "12".to_owned(),
        };
        assert!(bad.validate().is_err());
        let ok = VerifyRequest {
            code: "123456".to_owned(),
        };
        assert!(ok.validate().is_ok());
    }
}
