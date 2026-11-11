//! Outbound webhook signer (MED-003).
//!
//! Given the raw bytes of the request body, the signer:
//!
//! 1. Picks the latest active key for the tenant (`store.latest_kid`).
//! 2. Computes HMAC-SHA256 over the body.
//! 3. Returns the `(kid, signature_hex)` pair so the HTTP-layer can
//!    stamp `X-SentinelX-Kid` + `X-SentinelX-Signature` headers.
//!
//! ## Security
//!
//! - The HMAC secret never leaves the [`secrecy::SecretString`] beyond
//!   the call to `Hmac::new_from_slice`.
//! - `tracing` emits the kid (non-secret) and signature length only.
//! - If the tenant has no active key (`store.active` returned empty),
//!   the signer surfaces [`SignerError::NoActiveKey`] so the caller can
//!   raise an operator alert instead of silently shipping unsigned
//!   payloads.

use std::sync::Arc;

use hmac::{Hmac, Mac};
use secrecy::ExposeSecret;
use sha2::Sha256;
use thiserror::Error;
use tracing::debug;

use super::key::Kid;
use super::store::{SigningKeyStore, StoreError};

type HmacSha256 = Hmac<Sha256>;

/// Errors surfaced by [`WebhookSigner::sign`].
#[derive(Debug, Error)]
pub enum SignerError {
    /// The tenant has no active signing key. The composition root or
    /// admin operator must mint one (via the rotator) before any
    /// outbound webhook can be dispatched.
    #[error("no active signing key for tenant")]
    NoActiveKey,
    /// The signing-key store returned an error.
    #[error("signing-key store error: {0}")]
    Store(#[from] StoreError),
    /// HMAC computation failed.
    #[error("hmac error: {0}")]
    Hmac(String),
}

/// The two headers the signer wants on the outbound HTTP request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedPayload {
    /// Key id that produced the signature. Goes on `X-SentinelX-Kid`.
    pub kid: Kid,
    /// Hex-encoded HMAC-SHA256 over the raw body. Goes on
    /// `X-SentinelX-Signature` (`sha256=<hex>` format).
    pub signature_hex: String,
}

impl SignedPayload {
    /// Render the signature header value with the canonical
    /// `sha256=<hex>` prefix.
    #[must_use]
    pub fn signature_header_value(&self) -> String {
        format!("sha256={}", self.signature_hex)
    }
}

/// Outbound webhook signer.
///
/// Holds a shared reference to the [`SigningKeyStore`]; clone is cheap
/// (a single `Arc` clone).
#[derive(Debug, Clone)]
pub struct WebhookSigner {
    store: Arc<dyn SigningKeyStore>,
}

impl WebhookSigner {
    /// Construct from a shared store.
    #[must_use]
    pub fn new(store: Arc<dyn SigningKeyStore>) -> Self {
        Self { store }
    }

    /// Sign `body` for `tenant_id`. Picks the latest active key and
    /// computes HMAC-SHA256.
    ///
    /// # Errors
    ///
    /// - [`SignerError::NoActiveKey`] when the tenant has no rows in
    ///   the store. The caller MUST treat this as an operator-visible
    ///   misconfiguration rather than silently dropping the payload.
    /// - [`SignerError::Store`] on a backend failure.
    pub async fn sign(&self, tenant_id: &str, body: &[u8]) -> Result<SignedPayload, SignerError> {
        let now = chrono::Utc::now();
        let active = self.store.active(tenant_id, now).await?;
        let key = active.into_iter().next().ok_or(SignerError::NoActiveKey)?;
        let mut mac = HmacSha256::new_from_slice(key.secret.expose_secret().as_bytes())
            .map_err(|e| SignerError::Hmac(e.to_string()))?;
        mac.update(body);
        let tag = mac.finalize().into_bytes();
        let signature_hex = hex::encode(tag);
        debug!(
            target: "sx_webhooks::signing::signer",
            tenant_id = %tenant_id,
            kid = %key.kid,
            sig_len = signature_hex.len(),
            body_len = body.len(),
            "outbound webhook signed"
        );
        Ok(SignedPayload {
            kid: key.kid,
            signature_hex,
        })
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
    use crate::signing::key::SigningKey;
    use crate::signing::store::InMemorySigningKeyStore;

    #[tokio::test]
    async fn sign_emits_kid_and_hex_signature() {
        let store = Arc::new(InMemorySigningKeyStore::new());
        let key = SigningKey::mint("tenant-a");
        store.insert(&key).await.unwrap();
        let signer = WebhookSigner::new(store.clone());
        let signed = signer.sign("tenant-a", b"hello").await.unwrap();
        assert_eq!(signed.kid, key.kid);
        // hex-encoded SHA-256 is 64 chars.
        assert_eq!(signed.signature_hex.len(), 64);
        assert!(signed.signature_hex.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(
            signed.signature_header_value(),
            format!("sha256={}", signed.signature_hex)
        );
    }

    #[tokio::test]
    async fn sign_rejects_tenant_without_active_key() {
        let store = Arc::new(InMemorySigningKeyStore::new());
        let signer = WebhookSigner::new(store);
        let err = signer.sign("ghost", b"x").await.unwrap_err();
        assert!(matches!(err, SignerError::NoActiveKey));
    }

    #[tokio::test]
    async fn sign_uses_most_recent_active_key() {
        let store = Arc::new(InMemorySigningKeyStore::new());
        let now = chrono::Utc::now();
        let old = SigningKey {
            tenant_id: "t".into(),
            kid: Kid::new("kid_old"),
            secret: secrecy::SecretString::new("old".to_owned().into_boxed_str()),
            created_at: now - chrono::Duration::days(80),
            activated_at: now - chrono::Duration::days(80),
            retired_at: None,
        };
        let new = SigningKey {
            tenant_id: "t".into(),
            kid: Kid::new("kid_new"),
            secret: secrecy::SecretString::new("new".to_owned().into_boxed_str()),
            created_at: now,
            activated_at: now,
            retired_at: None,
        };
        store.insert(&old).await.unwrap();
        store.insert(&new).await.unwrap();
        let signer = WebhookSigner::new(store);
        let signed = signer.sign("t", b"x").await.unwrap();
        assert_eq!(signed.kid.as_str(), "kid_new");
    }

    #[tokio::test]
    async fn sign_is_deterministic_for_same_key_and_body() {
        let store = Arc::new(InMemorySigningKeyStore::new());
        let k = SigningKey {
            tenant_id: "t".into(),
            kid: Kid::new("kid_fixed"),
            secret: secrecy::SecretString::new("fixed-secret".to_owned().into_boxed_str()),
            created_at: chrono::Utc::now(),
            activated_at: chrono::Utc::now() - chrono::Duration::minutes(1),
            retired_at: None,
        };
        store.insert(&k).await.unwrap();
        let signer = WebhookSigner::new(store);
        let a = signer.sign("t", b"hello").await.unwrap();
        let b = signer.sign("t", b"hello").await.unwrap();
        assert_eq!(a, b);
    }
}
