//! Pluggable envelope-encryption surface for signing-key secrets.
//!
//! The signing-key persistence path needs to write `secret_enc` and read
//! it back as `SecretString`. Rather than tightly coupling this crate to
//! `sx_secrets::EnvelopeKeyManager` (which is generic over the KMS
//! provider + DEK store, making it awkward to express in a trait
//! object), we declare a narrow trait here and let the composition root
//! adapt.
//!
//! Two implementations live in this crate:
//!
//! - [`PlaintextCipher`] — no-op identity. Useful in tests and the
//!   default in-memory build. Marked clearly so production deployments
//!   notice if the wiring is wrong (we log a warning when the rotator
//!   sees one).
//! - The real production cipher (envelope-encrypt via
//!   `sx_secrets::EnvelopeKeyManager`) lives in `sx-monolith` so it can
//!   take the full generic chain without leaking it into this crate.
//!
//! ## Format
//!
//! `seal` returns an opaque `String`. `open` accepts that same string.
//! Implementations MUST NOT lose information across a `seal` / `open`
//! round-trip: the verifier and signer both rely on the round-trip
//! equality of the secret bytes.

use async_trait::async_trait;
use secrecy::{ExposeSecret, SecretString};
use thiserror::Error;

/// Errors surfaced by [`SecretCipher`] implementations.
#[derive(Debug, Error)]
pub enum CipherError {
    /// The provider rejected the request (KMS down, IAM, …).
    #[error("cipher provider error: {0}")]
    Provider(String),
    /// The caller passed a ciphertext the implementation could not
    /// decode (wrong KMS, corrupt data, …).
    #[error("cipher format error: {0}")]
    Format(String),
}

impl CipherError {
    /// Build a provider error from any [`std::fmt::Display`].
    pub fn provider<E: std::fmt::Display>(err: E) -> Self {
        Self::Provider(err.to_string())
    }
    /// Build a format error from any [`std::fmt::Display`].
    pub fn format<E: std::fmt::Display>(err: E) -> Self {
        Self::Format(err.to_string())
    }
}

/// Async, provider-agnostic envelope-encryption port for HMAC secrets.
///
/// Implementations MUST be `Send + Sync` and SHOULD be cheap to clone
/// (HTTP clients behind `Arc`, no per-call state).
#[async_trait]
pub trait SecretCipher: Send + Sync {
    /// Encrypt `plaintext` and return the on-disk ciphertext.
    async fn seal(&self, tenant_id: &str, plaintext: &SecretString) -> Result<String, CipherError>;

    /// Decrypt the on-disk ciphertext back into a [`SecretString`].
    async fn open(&self, tenant_id: &str, ciphertext: &str) -> Result<SecretString, CipherError>;
}

#[async_trait]
impl<T: SecretCipher + ?Sized> SecretCipher for std::sync::Arc<T> {
    async fn seal(&self, tenant_id: &str, plaintext: &SecretString) -> Result<String, CipherError> {
        (**self).seal(tenant_id, plaintext).await
    }
    async fn open(&self, tenant_id: &str, ciphertext: &str) -> Result<SecretString, CipherError> {
        (**self).open(tenant_id, ciphertext).await
    }
}

/// Identity cipher — round-trips plaintext untouched.
///
/// `seal` returns the plaintext untouched, `open` wraps it back into a
/// [`SecretString`]. Used for unit tests and the in-memory build where
/// there is no envelope-encryption stack wired in. Production
/// deployments install a `sx-secrets`-backed cipher.
#[derive(Debug, Default, Clone, Copy)]
pub struct PlaintextCipher;

#[async_trait]
impl SecretCipher for PlaintextCipher {
    async fn seal(
        &self,
        _tenant_id: &str,
        plaintext: &SecretString,
    ) -> Result<String, CipherError> {
        Ok(plaintext.expose_secret().to_owned())
    }

    async fn open(&self, _tenant_id: &str, ciphertext: &str) -> Result<SecretString, CipherError> {
        Ok(SecretString::new(ciphertext.to_owned().into_boxed_str()))
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::similar_names
)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn plaintext_cipher_round_trips() {
        let c = PlaintextCipher;
        let s = SecretString::new("hello-secret".to_owned().into_boxed_str());
        let sealed = c.seal("tenant", &s).await.unwrap();
        let opened = c.open("tenant", &sealed).await.unwrap();
        assert_eq!(opened.expose_secret(), "hello-secret");
    }
}
