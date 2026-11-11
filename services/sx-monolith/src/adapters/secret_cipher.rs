//! Local authenticated secret cipher — the real `SecretCipher` the
//! `sx_webhooks` trait doc says "lives in sx-monolith".
//!
//! Provides **at-rest encryption** for stored secrets (plugin webhook
//! signing secrets today) in deployments that have no external KMS
//! envelope provider configured — strictly better than the
//! `PlaintextCipher` fallback it replaces, without touching the platform's
//! KMS-backed path (`sx_secrets::EnvelopeKeyManager`), which remains the
//! intended production cipher once a KMS provider is wired.
//!
//! ## Construction
//!
//! - **AEAD:** XChaCha20-Poly1305 (24-byte random nonce per `seal`, so a
//!   repeated plaintext never yields a repeated ciphertext; authenticated,
//!   so tampering is detected on `open`).
//! - **Key:** derived once from the deployment's JWT signing key as
//!   `SHA-256("sentinelx:local-secret-cipher:v1" || signing_key)` — a
//!   domain-separated KDF, so the data key is **not** the signing key
//!   itself. Held zeroized-on-drop.
//! - **Associated data:** the `tenant_id` is bound as AEAD associated
//!   data, so a ciphertext authenticated for one tenant cannot be replayed
//!   under another.
//!
//! ## On-disk format
//!
//! `x1:` + base64(`nonce (24 bytes) || ciphertext||tag`). The `x1:` scheme
//! tag lets a future cipher revision coexist; `open` rejects anything else.

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use chacha20poly1305::aead::{Aead, KeyInit, OsRng, Payload};
use chacha20poly1305::{AeadCore, XChaCha20Poly1305, XNonce};
use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest, Sha256};
use sx_webhooks::signing::secret_cipher::{CipherError, SecretCipher};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Scheme tag prefixing every ciphertext this cipher emits.
const SCHEME: &str = "x1:";

/// Domain-separation label for the key-derivation step.
const KDF_INFO: &[u8] = b"sentinelx:local-secret-cipher:v1";

/// Nonce length for XChaCha20-Poly1305 (extended nonce).
const NONCE_LEN: usize = 24;

/// Local AEAD `SecretCipher`. Cheap to clone the key; the AEAD state is
/// rebuilt per call (microseconds) so no lock is held across awaits.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub(crate) struct LocalSecretCipher {
    key: [u8; 32],
}

impl std::fmt::Debug for LocalSecretCipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render the key.
        f.debug_struct("LocalSecretCipher").finish_non_exhaustive()
    }
}

impl LocalSecretCipher {
    /// Derive the data key from the deployment signing key and build the
    /// cipher. The key is `SHA-256(KDF_INFO || signing_key)` — domain-
    /// separated, so the encryption key is distinct from the signing key.
    pub(crate) fn from_signing_key(signing_key: &[u8]) -> Self {
        let mut input = KDF_INFO.to_vec();
        input.extend_from_slice(signing_key);
        let digest = Sha256::digest(&input);
        input.zeroize();
        let mut key = [0u8; 32];
        key.copy_from_slice(&digest);
        Self { key }
    }

    fn aead(&self) -> XChaCha20Poly1305 {
        XChaCha20Poly1305::new((&self.key).into())
    }
}

#[async_trait]
impl SecretCipher for LocalSecretCipher {
    async fn seal(&self, tenant_id: &str, plaintext: &SecretString) -> Result<String, CipherError> {
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ct = self
            .aead()
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext.expose_secret().as_bytes(),
                    aad: tenant_id.as_bytes(),
                },
            )
            .map_err(CipherError::provider)?;
        let mut blob = Vec::with_capacity(NONCE_LEN + ct.len());
        blob.extend_from_slice(nonce.as_slice());
        blob.extend_from_slice(&ct);
        let encoded = format!("{SCHEME}{}", B64.encode(&blob));
        blob.zeroize();
        Ok(encoded)
    }

    async fn open(&self, tenant_id: &str, ciphertext: &str) -> Result<SecretString, CipherError> {
        let body = ciphertext
            .strip_prefix(SCHEME)
            .ok_or_else(|| CipherError::format("unknown secret-cipher scheme"))?;
        let blob = B64.decode(body).map_err(CipherError::format)?;
        if blob.len() <= NONCE_LEN {
            return Err(CipherError::format("ciphertext too short"));
        }
        let (nonce, ct) = blob.split_at(NONCE_LEN);
        let mut pt = self
            .aead()
            .decrypt(
                XNonce::from_slice(nonce),
                Payload {
                    msg: ct,
                    aad: tenant_id.as_bytes(),
                },
            )
            .map_err(CipherError::provider)?;
        let s = String::from_utf8(pt.clone()).map_err(|e| {
            pt.zeroize();
            CipherError::format(e)
        })?;
        pt.zeroize();
        Ok(SecretString::new(s.into_boxed_str()))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    const TENANT: &str = "01010101-0101-0101-0101-010101010101";

    fn cipher() -> LocalSecretCipher {
        LocalSecretCipher::from_signing_key(b"deployment-signing-key-material")
    }

    #[tokio::test]
    async fn round_trips_a_secret() {
        let c = cipher();
        let secret = SecretString::new("hunter2-webhook-signing".to_owned().into_boxed_str());
        let sealed = c.seal(TENANT, &secret).await.unwrap();
        // Not plaintext at rest.
        assert!(sealed.starts_with("x1:"));
        assert!(!sealed.contains("hunter2"));
        let opened = c.open(TENANT, &sealed).await.unwrap();
        assert_eq!(opened.expose_secret(), "hunter2-webhook-signing");
    }

    #[tokio::test]
    async fn nonce_is_fresh_each_seal() {
        let c = cipher();
        let secret = SecretString::new("same-plaintext".to_owned().into_boxed_str());
        let a = c.seal(TENANT, &secret).await.unwrap();
        let b = c.seal(TENANT, &secret).await.unwrap();
        assert_ne!(
            a, b,
            "a repeated plaintext must not yield a repeated ciphertext"
        );
    }

    #[tokio::test]
    async fn wrong_tenant_aad_fails_to_open() {
        let c = cipher();
        let secret = SecretString::new("tenant-bound".to_owned().into_boxed_str());
        let sealed = c.seal(TENANT, &secret).await.unwrap();
        let err = c
            .open("02020202-0202-0202-0202-020202020202", &sealed)
            .await
            .unwrap_err();
        assert!(matches!(err, CipherError::Provider(_)));
    }

    #[tokio::test]
    async fn tampered_ciphertext_fails() {
        let c = cipher();
        let secret = SecretString::new("integrity".to_owned().into_boxed_str());
        let sealed = c.seal(TENANT, &secret).await.unwrap();
        // Flip a base64 char in the body.
        let mut chars: Vec<char> = sealed.chars().collect();
        let last = chars.len() - 1;
        chars[last] = if chars[last] == 'A' { 'B' } else { 'A' };
        let tampered: String = chars.into_iter().collect();
        assert!(c.open(TENANT, &tampered).await.is_err());
    }

    #[tokio::test]
    async fn rejects_foreign_scheme() {
        let c = cipher();
        let err = c.open(TENANT, "plaintext-no-scheme").await.unwrap_err();
        assert!(matches!(err, CipherError::Format(_)));
    }

    #[test]
    fn derived_key_is_not_the_signing_key() {
        let c = LocalSecretCipher::from_signing_key(b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        assert_ne!(&c.key, b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    }
}
