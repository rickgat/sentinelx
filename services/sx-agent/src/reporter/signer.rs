//! HMAC-SHA256 request signer.
//!
//! `HmacSigner` wraps a `SecretString` and exposes a single `sign(&[u8])`
//! method that returns lowercase hex of `HMAC-SHA256(secret, body)`. The
//! secret is held in a `secrecy::SecretString` so accidental `Debug`
//! prints render as `[REDACTED]`, and we never log the produced signature
//! at any level — both because it's a credential equivalent (anyone with
//! the signature plus body can replay) and because the spec mandates it.

use hmac::{Hmac, Mac};
use secrecy::{ExposeSecret, SecretString};
use sha2::Sha256;

use crate::error::AgentError;

/// Minimum acceptable shared-secret length, in bytes.
pub const MIN_SECRET_BYTES: usize = 32;

type HmacSha256 = Hmac<Sha256>;

/// Signs request bodies with HMAC-SHA256 using a shared secret.
pub struct HmacSigner {
    secret: SecretString,
}

impl std::fmt::Debug for HmacSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never expose the secret length or contents in Debug output.
        f.debug_struct("HmacSigner").finish_non_exhaustive()
    }
}

impl HmacSigner {
    /// Build a signer, validating the secret is at least
    /// [`MIN_SECRET_BYTES`] long.
    pub fn new(secret: SecretString) -> Result<Self, AgentError> {
        if secret.expose_secret().len() < MIN_SECRET_BYTES {
            return Err(AgentError::Secret(format!(
                "shared secret must be at least {MIN_SECRET_BYTES} bytes"
            )));
        }
        Ok(Self { secret })
    }

    /// Returns lowercase hex of `HMAC-SHA256(secret, body)`.
    #[must_use]
    pub fn sign(&self, body: &[u8]) -> String {
        // `Hmac::new_from_slice` only fails if the underlying hash rejects
        // the key length. SHA-256 accepts any key length, so this is
        // infallible — but we route through `let...else` to avoid `unwrap`.
        let Ok(mut mac) = HmacSha256::new_from_slice(self.secret.expose_secret().as_bytes()) else {
            // Unreachable in practice; fall back to an empty signature so
            // we never panic. The constructor already enforced length so an
            // empty-string fallback here would also have failed.
            tracing::error!("hmac key rejected by sha256 backend (unreachable)");
            return String::new();
        };
        mac.update(body);
        hex::encode(mac.finalize().into_bytes())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use secrecy::SecretString;

    #[test]
    fn hmac_signer_rejects_short_secret() {
        let s = SecretString::from("too-short".to_owned());
        let err = HmacSigner::new(s).unwrap_err();
        match err {
            AgentError::Secret(msg) => assert!(msg.contains("32"), "msg was {msg}"),
            other => panic!("expected AgentError::Secret, got {other:?}"),
        }
    }

    #[test]
    fn hmac_signer_accepts_exactly_32_bytes() {
        let s = SecretString::from("a".repeat(32));
        let signer = HmacSigner::new(s).unwrap();
        let sig = signer.sign(b"hello");
        assert_eq!(sig.len(), 64);
    }

    /// RFC 4231 — HMAC-SHA-256 Test Case 1.
    ///
    /// Key  = 0x0b * 20 (20 bytes)
    /// Data = "Hi There" (8 bytes)
    /// Expected HMAC-SHA-256 =
    ///   b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7
    ///
    /// The 20-byte RFC key is below our 32-byte production minimum, so we
    /// exercise the underlying `HmacSha256` directly and additionally
    /// verify `HmacSigner` agrees with the same backend when given a
    /// production-length secret.
    #[test]
    fn hmac_signer_known_vector() {
        let key = [0x0b_u8; 20];
        let data = b"Hi There";
        let mut mac = HmacSha256::new_from_slice(&key).unwrap();
        mac.update(data);
        let hex_out = hex::encode(mac.finalize().into_bytes());
        assert_eq!(
            hex_out,
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );

        // HmacSigner agrees with the same backend on a 32-byte secret.
        let secret_string = "a".repeat(32);
        let signer = HmacSigner::new(SecretString::from(secret_string.clone())).unwrap();
        let mut mac2 = HmacSha256::new_from_slice(secret_string.as_bytes()).unwrap();
        mac2.update(b"payload");
        let expected = hex::encode(mac2.finalize().into_bytes());
        assert_eq!(signer.sign(b"payload"), expected);
    }
}
