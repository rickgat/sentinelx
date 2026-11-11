//! Posture claim model + JWT decode helpers.
//!
//! ## Wire shape
//!
//! ```json
//! {
//!   "iss": "sentinelx-agent",
//!   "aud": "sentinelx",
//!   "iat": 1717180800,
//!   "exp": 1717184400,
//!   "device_id": "01010101-…",
//!   "os_name": "macOS",
//!   "os_version": "14.5.0",
//!   "disk_encrypted": true,
//!   "screen_lock_minutes": 5,
//!   "edr_present": true,
//!   "edr_vendor": "CrowdStrike",
//!   "agent_version": "0.4.2"
//! }
//! ```
//!
//! The `iss`, `aud`, `iat`, and `exp` claims are standard JWT registered
//! fields; only the posture-specific fields are described above. The decoder
//! treats every posture field as optional and falls back to least-trust
//! defaults (`false` / `None`) when absent — see [`PostureClaims::default`].

use std::collections::HashMap;

use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Maximum acceptable age (in seconds) of a posture JWT before evaluation
/// treats the signal as stale.
///
/// Set to one hour to balance signal-freshness against the overhead of
/// re-issuing a JWT on every request. Concrete services may override the
/// value when constructing [`crate::service::InMemoryDeviceTrustService`].
pub const DEFAULT_MAX_AGE_SECONDS: u64 = 3_600;

/// Posture claims surfaced by the client agent.
///
/// Every field is optional from the wire's perspective; absent fields decode
/// to their `Default` value so the evaluator never trusts a missing signal.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(default)]
pub struct PostureClaims {
    /// JWT `iss` claim. Usually `"sentinelx-agent"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    /// JWT `aud` claim. Usually `"sentinelx"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,
    /// Issued-at, seconds since Unix epoch.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<i64>,
    /// Expiration, seconds since Unix epoch.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,
    /// Device identifier minted by the agent on first enrolment.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    /// Operating-system family — `"macOS"`, `"Windows"`, `"Linux"`, ...
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os_name: Option<String>,
    /// Dotted OS version string (e.g. `"14.5.0"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os_version: Option<String>,
    /// Whether the agent reports a fully-encrypted system disk.
    pub disk_encrypted: bool,
    /// Inactivity threshold (minutes) at which the OS engages the screen lock.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub screen_lock_minutes: Option<u32>,
    /// Whether an endpoint detection-and-response agent is running.
    pub edr_present: bool,
    /// Optional EDR vendor identifier (`"CrowdStrike"`, `"SentinelOne"`, ...).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub edr_vendor: Option<String>,
    /// Reporting agent version (semver string).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_version: Option<String>,
    /// Catch-all for vendor-specific signals the policy can opt-into. The map
    /// is preserved across decode/encode so future policy rules can read it
    /// without a schema change.
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub extra: HashMap<String, serde_json::Value>,
}

impl PostureClaims {
    /// Construct a sparse posture claim with only `os_name` populated. Mostly
    /// useful for tests.
    #[must_use]
    pub fn with_os(os_name: impl Into<String>) -> Self {
        Self {
            os_name: Some(os_name.into()),
            ..Self::default()
        }
    }
}

/// Error variants returned by [`decode_posture_jwt`].
#[derive(Debug, Clone, Error)]
pub enum PostureJwtError {
    /// Header could not be parsed.
    #[error("posture jwt header malformed")]
    MalformedHeader,
    /// Signature verification failed — tampered or wrong key.
    #[error("posture jwt signature invalid")]
    InvalidSignature,
    /// Token expired (`exp < now`).
    #[error("posture jwt expired")]
    Expired,
    /// Token issued more than `max_age_seconds` ago.
    #[error("posture jwt stale")]
    Stale,
    /// Claims JSON did not match [`PostureClaims`].
    #[error("posture jwt claims invalid: {0}")]
    InvalidClaims(String),
    /// The configured algorithm does not match the token header.
    #[error("posture jwt algorithm mismatch")]
    AlgorithmMismatch,
}

/// Decode and validate a posture JWT signed with HMAC-SHA256.
///
/// `secret` is the same shared secret used by the session JWT for the MVP;
/// asymmetric keys can be plumbed through later by swapping the
/// [`DecodingKey`] builder.
///
/// On success returns the parsed [`PostureClaims`]. Failures surface as
/// [`PostureJwtError`] variants without leaking the raw `jsonwebtoken` error
/// strings (which can contain key fragments in some failure modes).
pub fn decode_posture_jwt(
    token: &str,
    secret: &[u8],
    now_unix: i64,
    max_age_seconds: u64,
) -> Result<PostureClaims, PostureJwtError> {
    let header = decode_header(token).map_err(|_| PostureJwtError::MalformedHeader)?;
    if header.alg != Algorithm::HS256 {
        return Err(PostureJwtError::AlgorithmMismatch);
    }

    // `jsonwebtoken::Validation` defaults check `exp`. We also enforce `iat`
    // freshness against `max_age_seconds` below so a token signed an hour ago
    // does not slip in even if it carries a far-future `exp`.
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;
    validation.validate_nbf = false;
    validation.required_spec_claims = std::collections::HashSet::new();
    // We do not pin `iss`/`aud` here: tenants may run their own agents with
    // bespoke identifiers; the policy layer enforces vendor / origin rules.
    validation.set_audience::<&str>(&[]);
    validation.set_issuer::<&str>(&[]);

    let data = decode::<PostureClaims>(token, &DecodingKey::from_secret(secret), &validation)
        .map_err(|err| match err.kind() {
            jsonwebtoken::errors::ErrorKind::ExpiredSignature => PostureJwtError::Expired,
            jsonwebtoken::errors::ErrorKind::Json(e) => {
                PostureJwtError::InvalidClaims(e.to_string())
            }
            // Every other failure mode — InvalidSignature, InvalidToken,
            // Crypto(_), Base64, Utf8, etc. — collapses to "signature
            // invalid" so we never leak internal error strings.
            _ => PostureJwtError::InvalidSignature,
        })?;

    if let Some(iat) = data.claims.iat {
        let age = now_unix.saturating_sub(iat);
        // Negative ages (token issued in the future) are tolerated within
        // `max_age_seconds` but a wildly future `iat` is treated as stale to
        // catch obvious clock drift / replay.
        let max = i64::try_from(max_age_seconds).unwrap_or(i64::MAX);
        if age > max || age < -max {
            return Err(PostureJwtError::Stale);
        }
    }

    Ok(data.claims)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};

    fn sign(claims: &PostureClaims, secret: &[u8]) -> String {
        encode(
            &Header::new(Algorithm::HS256),
            claims,
            &EncodingKey::from_secret(secret),
        )
        .unwrap()
    }

    fn now_secs() -> i64 {
        time::OffsetDateTime::now_utc().unix_timestamp()
    }

    #[test]
    fn decodes_well_formed_token() {
        let now = now_secs();
        let claims = PostureClaims {
            iat: Some(now),
            exp: Some(now + 60),
            os_name: Some("macOS".into()),
            os_version: Some("14.5.0".into()),
            disk_encrypted: true,
            screen_lock_minutes: Some(5),
            edr_present: true,
            ..PostureClaims::default()
        };
        let secret = b"a-very-secret-shared-key-1234567";
        let token = sign(&claims, secret);
        let decoded = decode_posture_jwt(&token, secret, now, 3_600).unwrap();
        assert_eq!(decoded.os_name.as_deref(), Some("macOS"));
        assert!(decoded.disk_encrypted);
    }

    #[test]
    fn rejects_tampered_signature() {
        let now = now_secs();
        let claims = PostureClaims {
            iat: Some(now),
            exp: Some(now + 60),
            ..PostureClaims::default()
        };
        let secret = b"a-very-secret-shared-key-1234567";
        let mut token = sign(&claims, secret);
        // Flip a character of the signature.
        let last = token.pop().unwrap_or('a');
        let swap = if last == 'a' { 'b' } else { 'a' };
        token.push(swap);
        let err = decode_posture_jwt(&token, secret, now, 3_600).unwrap_err();
        matches!(err, PostureJwtError::InvalidSignature);
    }

    #[test]
    fn rejects_wrong_secret() {
        let now = now_secs();
        let claims = PostureClaims {
            iat: Some(now),
            exp: Some(now + 60),
            ..PostureClaims::default()
        };
        let token = sign(&claims, b"correct-secret--correct-secret--");
        let err = decode_posture_jwt(&token, b"different--------------different", now, 3_600)
            .unwrap_err();
        matches!(err, PostureJwtError::InvalidSignature);
    }

    #[test]
    fn rejects_expired_token() {
        let now = now_secs();
        let claims = PostureClaims {
            iat: Some(now - 7_200),
            exp: Some(now - 60),
            ..PostureClaims::default()
        };
        let secret = b"a-very-secret-shared-key-1234567";
        let token = sign(&claims, secret);
        let err = decode_posture_jwt(&token, secret, now, 3_600).unwrap_err();
        matches!(err, PostureJwtError::Expired);
    }

    #[test]
    fn rejects_stale_iat() {
        let now = now_secs();
        let claims = PostureClaims {
            iat: Some(now - 7_200),
            // `exp` far in the future so the freshness check (not exp) trips.
            exp: Some(now + 86_400),
            ..PostureClaims::default()
        };
        let secret = b"a-very-secret-shared-key-1234567";
        let token = sign(&claims, secret);
        let err = decode_posture_jwt(&token, secret, now, 3_600).unwrap_err();
        matches!(err, PostureJwtError::Stale);
    }

    #[test]
    fn malformed_token_is_rejected() {
        let err = decode_posture_jwt("not-a-jwt", b"any-secret------any-secret------", 0, 3_600)
            .unwrap_err();
        matches!(err, PostureJwtError::MalformedHeader);
    }
}
