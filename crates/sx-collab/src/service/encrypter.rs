//! `CallbackEncrypter` port and the Phase-1 no-op implementation.
//!
//! The collaborator captures attacker-controlled HTTP bodies and SMTP DATA
//! payloads.  Those are interesting for verification and useless for
//! anything else — but they are still attacker-controlled bytes.  The
//! production storage path encrypts each body with a per-tenant AEAD key
//! before persistence.
//!
//! ## AEAD wiring path
//!
//! 1. `sx-iam` exposes a `TenantKeyService` that resolves
//!    `TenantId -> aead::Key` from KMS (or HSM in production).
//! 2. A `KmsCallbackEncrypter` implementation in `sx-storage` wraps that
//!    service, derives a per-record nonce (XChaCha20-Poly1305), and stores
//!    `nonce || ciphertext` in the `callbacks.body` column.
//! 3. `LookupCallbacksByTokenUseCase` decrypts on read using the same key
//!    handle.
//!
//! Phase 1 uses [`NoOpEncrypter`].  Calls to `encrypt`/`decrypt` return the
//! input unchanged — no compatibility break is required when the real
//! implementation lands, because both call paths go through the same
//! trait.

use async_trait::async_trait;

use crate::error::CollabError;

/// Symmetric AEAD wrapper over the captured callback body.
///
/// Implementations MUST be deterministic only insofar as decrypt-after-
/// encrypt round-trips the plaintext.  Re-encrypting the same plaintext is
/// allowed (and recommended) to produce different ciphertexts.
#[async_trait]
pub trait CallbackEncrypter: Send + Sync + std::fmt::Debug {
    /// Wrap `plaintext` for the given tenant.
    async fn encrypt(&self, tenant_id_hex: &str, plaintext: &[u8]) -> Result<Vec<u8>, CollabError>;

    /// Unwrap a previously encrypted byte string.
    async fn decrypt(&self, tenant_id_hex: &str, ciphertext: &[u8])
        -> Result<Vec<u8>, CollabError>;
}

/// Identity encrypter used in tests and Phase-1 deployments.
///
/// This implementation deliberately performs no transformation; callers
/// MUST swap in a real AEAD before storing real customer bodies on disk.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoOpEncrypter;

#[async_trait]
impl CallbackEncrypter for NoOpEncrypter {
    async fn encrypt(
        &self,
        _tenant_id_hex: &str,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CollabError> {
        Ok(plaintext.to_vec())
    }

    async fn decrypt(
        &self,
        _tenant_id_hex: &str,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CollabError> {
        Ok(ciphertext.to_vec())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::{CallbackEncrypter, NoOpEncrypter};

    #[tokio::test]
    async fn no_op_round_trips() {
        let enc = NoOpEncrypter;
        let cipher = enc.encrypt("t", b"hello").await.unwrap();
        assert_eq!(cipher, b"hello");
        let plain = enc.decrypt("t", &cipher).await.unwrap();
        assert_eq!(plain, b"hello");
    }
}
