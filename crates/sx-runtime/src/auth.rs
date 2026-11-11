//! Per-tenant HMAC-SHA256 webhook authentication.
//!
//! Falco (or a `falcosidekick` shim) signs the JSON body with a shared
//! secret using HMAC-SHA256 over the canonical string
//! `v1:{timestamp}:{body}`. The hex digest is carried in the
//! `X-Sentinelx-Runtime-Signature` header as `v1=<hex>` and the timestamp
//! travels in `X-Sentinelx-Runtime-Timestamp`. The tenant id is carried in
//! `X-Sentinelx-Tenant`.
//!
//! Constant-time comparison via [`subtle::ConstantTimeEq`] prevents the
//! verifier from leaking timing information about the signing key. Stale
//! requests outside the [`RUNTIME_REPLAY_WINDOW_SECS`] window are rejected
//! before HMAC computation.

use hmac::{Hmac, Mac};
use secrecy::{ExposeSecret, SecretString};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::error::RuntimeError;

/// Header carrying the per-tenant identifier.
pub const TENANT_HEADER: &str = "X-Sentinelx-Tenant";

/// Header carrying the HMAC signature in `v1=<hex>` form.
pub const SIGNATURE_HEADER: &str = "X-Sentinelx-Runtime-Signature";

/// Header carrying the Unix timestamp (seconds) used in the signing
/// string.
pub const TIMESTAMP_HEADER: &str = "X-Sentinelx-Runtime-Timestamp";

/// Replay window enforced by [`verify_hmac`], in seconds. Five minutes,
/// matching the Slack / GitHub norm.
pub const RUNTIME_REPLAY_WINDOW_SECS: i64 = 300;

type HmacSha256 = Hmac<Sha256>;

/// Verify the HMAC signature carried in `signature_header` over the
/// canonical string `v1:{timestamp}:{body}` using `secret`.
///
/// `now` is the verifier's clock, in Unix seconds — taking it as a
/// parameter keeps the function deterministic and pure (useful in tests).
///
/// # Errors
///
/// * [`RuntimeError::ReplayWindowExceeded`] — `|now - timestamp|` exceeds
///   [`RUNTIME_REPLAY_WINDOW_SECS`].
/// * [`RuntimeError::InvalidSignature`] — header missing, malformed, or
///   did not match the recomputed HMAC.
pub fn verify_hmac(
    secret: &SecretString,
    timestamp: i64,
    body: &[u8],
    signature_header: Option<&str>,
    now: i64,
) -> Result<(), RuntimeError> {
    check_replay_window(timestamp, now)?;
    let provided = decode_v1_header(signature_header)?;
    let expected = compute_v1_hmac(secret, timestamp, body)?;
    if expected.ct_eq(&provided).into() {
        Ok(())
    } else {
        tracing::debug!(target: "sx_runtime", "runtime webhook signature mismatch");
        Err(RuntimeError::InvalidSignature)
    }
}

fn check_replay_window(timestamp: i64, now: i64) -> Result<(), RuntimeError> {
    let delta = now.saturating_sub(timestamp).abs();
    if delta > RUNTIME_REPLAY_WINDOW_SECS {
        tracing::debug!(
            target: "sx_runtime",
            delta_secs = delta,
            "runtime webhook timestamp outside replay window"
        );
        Err(RuntimeError::ReplayWindowExceeded)
    } else {
        Ok(())
    }
}

fn decode_v1_header(header: Option<&str>) -> Result<Vec<u8>, RuntimeError> {
    let Some(raw) = header else {
        tracing::debug!(target: "sx_runtime", "runtime webhook signature header missing");
        return Err(RuntimeError::InvalidSignature);
    };
    let Some(hex_part) = raw.strip_prefix("v1=") else {
        tracing::debug!(target: "sx_runtime", "runtime webhook signature header missing v1= prefix");
        return Err(RuntimeError::InvalidSignature);
    };
    hex::decode(hex_part).map_err(|_| RuntimeError::InvalidSignature)
}

fn compute_v1_hmac(
    secret: &SecretString,
    timestamp: i64,
    body: &[u8],
) -> Result<Vec<u8>, RuntimeError> {
    let mut mac = HmacSha256::new_from_slice(secret.expose_secret().as_bytes())
        .map_err(|_| RuntimeError::InvalidSignature)?;
    mac.update(b"v1:");
    mac.update(timestamp.to_string().as_bytes());
    mac.update(b":");
    mac.update(body);
    Ok(mac.finalize().into_bytes().to_vec())
}

/// Test-only helper: produce a `v1=<hex>` signature header for a body.
///
/// Available outside `#[cfg(test)]` so integration tests in sibling
/// crates can produce signed fixtures without re-implementing the HMAC.
#[doc(hidden)]
#[must_use]
pub fn sign_body_for_tests(secret: &SecretString, timestamp: i64, body: &[u8]) -> String {
    // Errors here would mean we cannot construct an HMAC with the given
    // key length — the static key length used by tests never trips it,
    // but we still propagate a deterministic fallback rather than panic.
    let mac = compute_v1_hmac(secret, timestamp, body).unwrap_or_else(|_| Vec::new());
    format!("v1={}", hex::encode(mac))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn secret() -> SecretString {
        SecretString::from("super-secret-key".to_owned())
    }

    #[test]
    fn matching_signature_verifies() {
        let body = br#"{"rule":"r","priority":"Notice"}"#;
        let ts = 1_700_000_000;
        let sig = sign_body_for_tests(&secret(), ts, body);
        assert!(verify_hmac(&secret(), ts, body, Some(&sig), ts).is_ok());
    }

    #[test]
    fn mismatched_signature_fails() {
        let body = b"abc";
        let ts = 1_700_000_000;
        let bogus = "v1=deadbeef";
        let err = verify_hmac(&secret(), ts, body, Some(bogus), ts).unwrap_err();
        assert!(matches!(err, RuntimeError::InvalidSignature));
    }

    #[test]
    fn missing_signature_fails() {
        let body = b"abc";
        let ts = 1_700_000_000;
        let err = verify_hmac(&secret(), ts, body, None, ts).unwrap_err();
        assert!(matches!(err, RuntimeError::InvalidSignature));
    }

    #[test]
    fn missing_v1_prefix_fails() {
        let body = b"abc";
        let ts = 1_700_000_000;
        let sig = sign_body_for_tests(&secret(), ts, body);
        let no_prefix = sig.strip_prefix("v1=").unwrap();
        let err = verify_hmac(&secret(), ts, body, Some(no_prefix), ts).unwrap_err();
        assert!(matches!(err, RuntimeError::InvalidSignature));
    }

    #[test]
    fn replay_window_rejects_old_request() {
        let body = b"abc";
        let ts = 1_700_000_000;
        let sig = sign_body_for_tests(&secret(), ts, body);
        let now = ts + RUNTIME_REPLAY_WINDOW_SECS + 1;
        let err = verify_hmac(&secret(), ts, body, Some(&sig), now).unwrap_err();
        assert!(matches!(err, RuntimeError::ReplayWindowExceeded));
    }

    #[test]
    fn replay_window_rejects_future_dated_request() {
        let body = b"abc";
        let ts = 1_700_000_000;
        let sig = sign_body_for_tests(&secret(), ts, body);
        let now = ts - RUNTIME_REPLAY_WINDOW_SECS - 1;
        let err = verify_hmac(&secret(), ts, body, Some(&sig), now).unwrap_err();
        assert!(matches!(err, RuntimeError::ReplayWindowExceeded));
    }

    #[test]
    fn wrong_key_fails_verification() {
        let body = b"abc";
        let ts = 1_700_000_000;
        let sig = sign_body_for_tests(&secret(), ts, body);
        let other = SecretString::from("different".to_owned());
        let err = verify_hmac(&other, ts, body, Some(&sig), ts).unwrap_err();
        assert!(matches!(err, RuntimeError::InvalidSignature));
    }
}
