//! Outbound webhook verifier (MED-003).
//!
//! Used by the *receiver* side of the verifier endpoint (the loopback
//! receiver in `sx-webhooks` integration tests, plus any tenant tooling
//! that wants to verify `SentinelX` outbound deliveries). Given the raw
//! request body, the kid header value, and the signature header value,
//! the verifier:
//!
//! 1. Looks up the row for `(tenant_id, kid)` (must still be active at
//!    `now`).
//! 2. Recomputes HMAC-SHA256 over the body with the row's secret.
//! 3. Compares the recomputed digest to the supplied signature in
//!    **constant time** via `subtle::ConstantTimeEq`.
//!
//! Returns `Ok(())` on a match, [`VerifierError::InvalidSignature`]
//! otherwise. Coarse error surface on purpose — neither the caller nor
//! a possible attacker should be able to distinguish "wrong kid" from
//! "wrong signature".

use std::sync::Arc;

use hmac::{Hmac, Mac};
use secrecy::ExposeSecret;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use thiserror::Error;

use super::key::Kid;
use super::store::{SigningKeyStore, StoreError};

type HmacSha256 = Hmac<Sha256>;

/// Errors surfaced by [`WebhookVerifier::verify`].
#[derive(Debug, Error)]
pub enum VerifierError {
    /// The signature header was malformed, the kid was unknown, the
    /// row was retired, or the HMAC did not match. Coarse-grained on
    /// purpose.
    #[error("invalid webhook signature")]
    InvalidSignature,
    /// The signing-key store returned an error.
    #[error("signing-key store error: {0}")]
    Store(#[from] StoreError),
}

/// Outbound webhook verifier.
#[derive(Debug, Clone)]
pub struct WebhookVerifier {
    store: Arc<dyn SigningKeyStore>,
}

impl WebhookVerifier {
    /// Construct from a shared store.
    #[must_use]
    pub fn new(store: Arc<dyn SigningKeyStore>) -> Self {
        Self { store }
    }

    /// Verify `signature_hex` over `body` for the `(tenant_id, kid)`
    /// pair. Any failure path collapses to
    /// [`VerifierError::InvalidSignature`].
    ///
    /// `signature_hex` MAY carry a leading `sha256=` prefix — the
    /// verifier strips it before parsing.
    ///
    /// # Errors
    ///
    /// - [`VerifierError::InvalidSignature`] on any mismatch.
    /// - [`VerifierError::Store`] on a backend failure.
    pub async fn verify(
        &self,
        tenant_id: &str,
        kid: &Kid,
        signature_hex: &str,
        body: &[u8],
    ) -> Result<(), VerifierError> {
        let stripped = signature_hex
            .strip_prefix("sha256=")
            .unwrap_or(signature_hex);
        // Hex-decode early — malformed signatures never even touch the
        // store, and we always return the same error variant so timing
        // does not leak which step failed.
        let Ok(supplied) = hex::decode(stripped) else {
            return Err(VerifierError::InvalidSignature);
        };

        let now = chrono::Utc::now();
        let active = self.store.active(tenant_id, now).await?;
        let Some(key) = active.into_iter().find(|k| k.kid == *kid) else {
            return Err(VerifierError::InvalidSignature);
        };
        let mut mac = HmacSha256::new_from_slice(key.secret.expose_secret().as_bytes())
            .map_err(|_| VerifierError::InvalidSignature)?;
        mac.update(body);
        let expected = mac.finalize().into_bytes();
        if expected.ct_eq(&supplied).into() {
            Ok(())
        } else {
            Err(VerifierError::InvalidSignature)
        }
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
    use crate::signing::signer::WebhookSigner;
    use crate::signing::store::InMemorySigningKeyStore;
    use chrono::{Duration, Utc};

    #[tokio::test]
    async fn signed_payload_verifies() {
        let store = Arc::new(InMemorySigningKeyStore::new());
        store.insert(&SigningKey::mint("t")).await.unwrap();
        let signer = WebhookSigner::new(store.clone());
        let signed = signer.sign("t", b"hello").await.unwrap();
        let verifier = WebhookVerifier::new(store);
        verifier
            .verify("t", &signed.kid, &signed.signature_hex, b"hello")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn signed_payload_with_sha256_prefix_verifies() {
        let store = Arc::new(InMemorySigningKeyStore::new());
        store.insert(&SigningKey::mint("t")).await.unwrap();
        let signer = WebhookSigner::new(store.clone());
        let signed = signer.sign("t", b"hello").await.unwrap();
        let verifier = WebhookVerifier::new(store);
        verifier
            .verify("t", &signed.kid, &signed.signature_header_value(), b"hello")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn wrong_body_rejected() {
        let store = Arc::new(InMemorySigningKeyStore::new());
        store.insert(&SigningKey::mint("t")).await.unwrap();
        let signer = WebhookSigner::new(store.clone());
        let signed = signer.sign("t", b"hello").await.unwrap();
        let verifier = WebhookVerifier::new(store);
        let err = verifier
            .verify("t", &signed.kid, &signed.signature_hex, b"tampered")
            .await
            .unwrap_err();
        assert!(matches!(err, VerifierError::InvalidSignature));
    }

    #[tokio::test]
    async fn unknown_kid_rejected() {
        let store = Arc::new(InMemorySigningKeyStore::new());
        store.insert(&SigningKey::mint("t")).await.unwrap();
        let signer = WebhookSigner::new(store.clone());
        let signed = signer.sign("t", b"hello").await.unwrap();
        let verifier = WebhookVerifier::new(store);
        let err = verifier
            .verify("t", &Kid::new("kid_zz"), &signed.signature_hex, b"hello")
            .await
            .unwrap_err();
        assert!(matches!(err, VerifierError::InvalidSignature));
    }

    #[tokio::test]
    async fn malformed_signature_rejected() {
        let store = Arc::new(InMemorySigningKeyStore::new());
        let k = SigningKey::mint("t");
        let kid = k.kid.clone();
        store.insert(&k).await.unwrap();
        let verifier = WebhookVerifier::new(store);
        let err = verifier
            .verify("t", &kid, "not-hex", b"hello")
            .await
            .unwrap_err();
        assert!(matches!(err, VerifierError::InvalidSignature));
    }

    #[tokio::test]
    async fn retired_key_rejected() {
        let store = Arc::new(InMemorySigningKeyStore::new());
        let k = SigningKey::mint("t");
        let kid = k.kid.clone();
        store.insert(&k).await.unwrap();
        // Retire immediately.
        let retire_at = Utc::now() - Duration::seconds(1);
        store.retire("t", &kid, retire_at).await.unwrap();
        let verifier = WebhookVerifier::new(store);
        // Even with a valid-looking hex, the row is no longer active.
        let err = verifier
            .verify("t", &kid, &"00".repeat(32), b"hello")
            .await
            .unwrap_err();
        assert!(matches!(err, VerifierError::InvalidSignature));
    }

    #[tokio::test]
    async fn grace_window_accepts_old_and_new_kids() {
        let store = Arc::new(InMemorySigningKeyStore::new());
        let now = Utc::now();
        let old = SigningKey {
            tenant_id: "t".into(),
            kid: Kid::new("kid_old"),
            secret: secrecy::SecretString::new("old-secret".to_owned().into_boxed_str()),
            created_at: now - Duration::days(90),
            activated_at: now - Duration::days(90),
            // Will retire in 7 days (grace window still open).
            retired_at: Some(now + Duration::days(7)),
        };
        let new = SigningKey {
            tenant_id: "t".into(),
            kid: Kid::new("kid_new"),
            secret: secrecy::SecretString::new("new-secret".to_owned().into_boxed_str()),
            created_at: now,
            activated_at: now,
            retired_at: None,
        };
        store.insert(&old).await.unwrap();
        store.insert(&new).await.unwrap();
        let signer = WebhookSigner::new(store.clone());
        let signed_new = signer.sign("t", b"hello").await.unwrap();
        // The signer picked the newer kid (highest activated_at).
        assert_eq!(signed_new.kid.as_str(), "kid_new");

        // Sign with the old key by hand and verify it still passes.
        let mut mac = HmacSha256::new_from_slice(b"old-secret").unwrap();
        mac.update(b"hello");
        let old_sig = hex::encode(mac.finalize().into_bytes());
        let verifier = WebhookVerifier::new(store);
        verifier
            .verify("t", &Kid::new("kid_old"), &old_sig, b"hello")
            .await
            .unwrap();
        // And the new one passes too.
        verifier
            .verify("t", &signed_new.kid, &signed_new.signature_hex, b"hello")
            .await
            .unwrap();
    }
}
