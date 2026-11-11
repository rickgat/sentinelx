//! The [`KmsKeyProvider`] trait and shared value types.
//!
//! The trait is intentionally minimal: every KMS we plan to integrate
//! (Vault Transit, AWS KMS, GCP KMS) supports the same four primitives.
//! Provider-specific concerns (key spec, IAM scoping, audit hooks) are
//! handled inside each implementation, not surfaced at the trait level.

use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};

use crate::error::SecretsError;

/// Opaque ciphertext envelope returned by a KMS encrypt operation.
///
/// The contents are deliberately opaque — different providers use
/// different prefixes (Vault uses `vault:v1:…`, AWS KMS uses a
/// proprietary blob). Callers should treat this as a token: store it,
/// pass it back to [`KmsKeyProvider::decrypt`], and never try to parse
/// the inner bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ciphertext(pub String);

impl Ciphertext {
    /// Construct a ciphertext envelope from a provider-emitted string.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// The opaque, provider-specific ciphertext token.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A freshly minted data encryption key returned by
/// [`KmsKeyProvider::generate_dek`].
///
/// * `plaintext` — the raw key bytes; the caller uses them to encrypt
///   the payload locally and **must** drop them immediately after.
///   Wrapped in [`SecretString`] so they are zeroised on drop and
///   never logged.
/// * `wrapped` — the ciphertext form, safe to persist. Pass back to
///   [`KmsKeyProvider::decrypt`] to recover the plaintext on demand.
/// * `key_id` — the KEK identifier under which the DEK was wrapped.
/// * `version` — the KEK version active at generation time. Used to
///   support staged rotation: an old wrapped DEK can be detected and
///   re-wrapped under the new KEK version.
#[derive(Debug)]
pub struct WrappedDek {
    /// Identifier of the KEK that wrapped this DEK.
    pub key_id: String,
    /// KEK version active when the DEK was minted.
    pub version: u32,
    /// Raw plaintext key bytes (base64-encoded). Drop after first use.
    pub plaintext: SecretString,
    /// Wrapped (encrypted) DEK; safe to persist next to the payload.
    pub wrapped: Ciphertext,
    /// Wall-clock timestamp of generation.
    pub created_at: DateTime<Utc>,
}

impl WrappedDek {
    /// Construct a `WrappedDek` from already-decoded parts.
    #[must_use]
    pub fn new(
        key_id: impl Into<String>,
        version: u32,
        plaintext: SecretString,
        wrapped: Ciphertext,
    ) -> Self {
        Self {
            key_id: key_id.into(),
            version,
            plaintext,
            wrapped,
            created_at: Utc::now(),
        }
    }
}

/// Result of a key rotation: which version is now active and when it
/// became so.
///
/// Rotation never invalidates old wrapped material — providers keep
/// previous versions around so old DEKs can still be unwrapped. Crypto-
/// erase, however, deletes the KEK outright; see [`crate::shred`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyVersion {
    /// The new active version number (monotonic, starts at 1).
    pub version: u32,
    /// Wall-clock timestamp the rotation took effect.
    pub created_at: DateTime<Utc>,
}

impl KeyVersion {
    /// Construct a `KeyVersion` stamped with the current time.
    #[must_use]
    pub fn now(version: u32) -> Self {
        Self {
            version,
            created_at: Utc::now(),
        }
    }
}

/// Async abstraction over a KMS providing envelope-encryption primitives.
///
/// Implementations must be `Send + Sync` so they can be shared across
/// tasks behind an [`Arc`].
///
/// ## Required semantics
///
/// * [`encrypt`](Self::encrypt) — wraps small plaintexts (typically a
///   DEK or a token) under `key_id` and returns an opaque ciphertext.
/// * [`decrypt`](Self::decrypt) — the inverse. Returns
///   [`SecretsError::Unauthorized`] when the underlying key has been
///   destroyed or access is denied.
/// * [`generate_dek`](Self::generate_dek) — produces a fresh DEK along
///   with its wrapped form in a single round-trip.
/// * [`rotate`](Self::rotate) — bumps the KEK to a new version. Old
///   versions remain available for decrypt until explicitly destroyed.
#[async_trait]
pub trait KmsKeyProvider: Send + Sync {
    /// Encrypt `plaintext` under the KEK named `key_id`.
    async fn encrypt(
        &self,
        key_id: &str,
        plaintext: &SecretString,
    ) -> Result<Ciphertext, SecretsError>;

    /// Decrypt a previously-produced [`Ciphertext`] under `key_id`.
    async fn decrypt(
        &self,
        key_id: &str,
        ciphertext: &Ciphertext,
    ) -> Result<SecretString, SecretsError>;

    /// Generate a fresh data encryption key wrapped under `key_id`.
    async fn generate_dek(&self, key_id: &str) -> Result<WrappedDek, SecretsError>;

    /// Rotate the KEK named `key_id` to a new version.
    async fn rotate(&self, key_id: &str) -> Result<KeyVersion, SecretsError>;
}

#[async_trait]
impl<T> KmsKeyProvider for Arc<T>
where
    T: KmsKeyProvider + ?Sized,
{
    async fn encrypt(
        &self,
        key_id: &str,
        plaintext: &SecretString,
    ) -> Result<Ciphertext, SecretsError> {
        (**self).encrypt(key_id, plaintext).await
    }

    async fn decrypt(
        &self,
        key_id: &str,
        ciphertext: &Ciphertext,
    ) -> Result<SecretString, SecretsError> {
        (**self).decrypt(key_id, ciphertext).await
    }

    async fn generate_dek(&self, key_id: &str) -> Result<WrappedDek, SecretsError> {
        (**self).generate_dek(key_id).await
    }

    async fn rotate(&self, key_id: &str) -> Result<KeyVersion, SecretsError> {
        (**self).rotate(key_id).await
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn ciphertext_round_trips_through_as_str() {
        let ct = Ciphertext::new("vault:v1:abcdef");
        assert_eq!(ct.as_str(), "vault:v1:abcdef");
    }

    #[test]
    fn key_version_now_stamps_current_time() {
        let kv = KeyVersion::now(2);
        assert_eq!(kv.version, 2);
        // Should be within a small window of now.
        let delta = Utc::now().signed_duration_since(kv.created_at);
        assert!(delta.num_seconds().abs() < 5);
    }
}
