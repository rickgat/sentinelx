//! Canonical Key Encryption Key (KEK) provider abstraction (TRD §27).
//!
//! Where [`crate::kms`] models the *legacy* `SentinelX` envelope-encryption
//! plumbing (Vault Transit `encrypt`/`decrypt`/`generate_dek`/`rotate`),
//! this module hosts the **canonical** KEK trait specified by TRD §27.1.
//! The two coexist on purpose:
//!
//! * [`crate::kms::KmsKeyProvider`] is the existing surface every
//!   downstream (DEK manager, shredder, audit) is already wired to.
//!   Removing it would be a workspace-wide refactor.
//! * [`KekProvider`] is the forward-looking surface that lets new
//!   providers (AWS KMS, GCP KMS, Azure Key Vault, on-prem HSM) plug in
//!   without each having to re-implement the legacy four-verb API.
//!
//! A follow-up task will migrate [`crate::dek`] and [`crate::shred`] from
//! `KmsKeyProvider` to `KekProvider`. Until then, the new trait lives
//! side-by-side. A Vault wrapper for the new trait is deferred until the
//! existing Vault Transit client surface is finalised (see TRD §27.2).
//!
//! ## Trait shape (TRD §27.1, verbatim)
//!
//! ```ignore
//! #[async_trait]
//! pub trait KekProvider: Send + Sync {
//!     fn provider_id(&self) -> &'static str;
//!     async fn wrap(&self, plaintext: &[u8], key_id: &str, context: &EncryptionContext)
//!         -> Result<Vec<u8>, KekError>;
//!     async fn unwrap(&self, ciphertext: &[u8], key_id: &str, context: &EncryptionContext)
//!         -> Result<SecretVec, KekError>;
//!     async fn rotate(&self, key_id: &str) -> Result<NewKeyVersion, KekError>;
//! }
//! ```
//!
//! `EncryptionContext` is propagated to the KMS as an
//! "additional authenticated data" map (AWS KMS `EncryptionContext`,
//! GCP KMS `additional_authenticated_data`, Vault Transit
//! `context`). Mismatched contexts on unwrap surface as
//! [`KekError::ContextMismatch`].

#![allow(clippy::module_name_repetitions)]

pub mod aws;
pub mod azure;
pub mod gcp;

pub use azure::{AzureKeyVaultConfig, AzureKeyVaultKekProvider};
pub use gcp::GcpKmsKekProvider;

use std::collections::HashMap;
use std::fmt;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::dek::TenantId;

/// Identifier propagated to the KMS as additional authenticated data.
///
/// Both [`KekProvider::wrap`] and [`KekProvider::unwrap`] receive this
/// value. Implementations are required to forward it to the underlying
/// KMS verbatim (AWS KMS calls this `EncryptionContext`; GCP KMS calls
/// it `additional_authenticated_data`; Vault Transit calls it
/// `context`). A mismatch on unwrap MUST yield
/// [`KekError::ContextMismatch`].
///
/// The on-the-wire shape is a string→string map. We pick the *smallest*
/// schema that lets the caller pin both the tenant and the DEK version:
///
/// * `tenant_id` — the [`TenantId`] of the data being protected.
/// * `dek_version` — monotonic version of the wrapped DEK, lets staged
///   rotation distinguish payloads encrypted under different DEK
///   versions even when they share a KEK.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptionContext {
    /// Tenant the wrapped material belongs to.
    pub tenant_id: TenantId,
    /// DEK version active at wrap time.
    pub dek_version: u32,
}

impl EncryptionContext {
    /// Construct a context from its two components.
    #[must_use]
    pub const fn new(tenant_id: TenantId, dek_version: u32) -> Self {
        Self {
            tenant_id,
            dek_version,
        }
    }

    /// Render the context as a `HashMap<String,String>` suitable for the
    /// AWS KMS `EncryptionContext` parameter (and the equivalent
    /// AAD-style fields on other providers).
    ///
    /// Keys are stable identifiers (`tenant_id`, `dek_version`) — these
    /// are part of the on-the-wire contract and must not be renamed
    /// without a coordinated rotation across every deployed wrapper.
    #[must_use]
    pub fn to_map(&self) -> HashMap<String, String> {
        let mut map = HashMap::with_capacity(2);
        map.insert("tenant_id".to_owned(), self.tenant_id.to_string());
        map.insert("dek_version".to_owned(), self.dek_version.to_string());
        map
    }

    /// Parse a context map back into an [`EncryptionContext`].
    ///
    /// # Errors
    ///
    /// Returns [`KekError::Format`] when either key is missing or
    /// malformed (non-UUID `tenant_id`, non-numeric `dek_version`).
    pub fn from_map(map: &HashMap<String, String>) -> Result<Self, KekError> {
        let tenant_raw = map
            .get("tenant_id")
            .ok_or_else(|| KekError::format("encryption context missing `tenant_id`"))?;
        let dek_raw = map
            .get("dek_version")
            .ok_or_else(|| KekError::format("encryption context missing `dek_version`"))?;
        let tenant_uuid = uuid::Uuid::parse_str(tenant_raw).map_err(|e| {
            KekError::format(format!("encryption context `tenant_id` not a uuid: {e}"))
        })?;
        let dek_version = dek_raw.parse::<u32>().map_err(|e| {
            KekError::format(format!("encryption context `dek_version` not a u32: {e}"))
        })?;
        Ok(Self {
            tenant_id: TenantId::new(tenant_uuid),
            dek_version,
        })
    }
}

/// Outcome of a successful [`KekProvider::rotate`] call.
///
/// `version` is the *new* active version number. Older versions remain
/// available for unwrap until the provider explicitly destroys them
/// (see [`crate::shred`]).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NewKeyVersion {
    /// The KEK identifier (provider-specific opaque name, e.g. an AWS
    /// KMS alias or key ARN, or a Vault Transit key name).
    pub key_id: String,
    /// The new active version (monotonic, starts at 1).
    pub version: u32,
    /// Wall-clock timestamp the rotation took effect.
    pub created_at: DateTime<Utc>,
}

impl NewKeyVersion {
    /// Construct a `NewKeyVersion` stamped with the current time.
    #[must_use]
    pub fn now(key_id: impl Into<String>, version: u32) -> Self {
        Self {
            key_id: key_id.into(),
            version,
            created_at: Utc::now(),
        }
    }
}

/// Zeroising wrapper around plaintext bytes returned by [`KekProvider::unwrap`].
///
/// `SecretVec` owns a `Vec<u8>` and guarantees the buffer is zeroed on
/// drop via [`zeroize::Zeroize`]. The only way to access the inner bytes
/// is [`SecretVec::expose_secret`]; callers are expected to take a
/// reference, use it, and let the wrapper drop as soon as possible.
///
/// We deliberately do not implement `Clone`, `Debug` (beyond a redacted
/// stub), `Serialize`, or `Display` — every one of those would risk
/// leaking the plaintext through a debug print or a structured log.
#[derive(ZeroizeOnDrop)]
pub struct SecretVec {
    inner: Vec<u8>,
}

impl SecretVec {
    /// Construct a `SecretVec` from raw bytes. Ownership of the buffer
    /// moves into the wrapper; the original `Vec` is consumed.
    #[must_use]
    pub const fn new(inner: Vec<u8>) -> Self {
        Self { inner }
    }

    /// Borrow the underlying plaintext bytes.
    ///
    /// The returned slice borrows from `self`; once `self` is dropped
    /// the bytes are zeroed. Callers MUST NOT clone the slice into a
    /// long-lived `Vec` outside the wrapper.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8] {
        &self.inner
    }

    /// Number of bytes held.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.inner.len()
    }

    /// `true` when the wrapper holds zero bytes.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl fmt::Debug for SecretVec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretVec")
            .field("len", &self.inner.len())
            .field("bytes", &"<redacted>")
            .finish()
    }
}

impl From<Vec<u8>> for SecretVec {
    fn from(v: Vec<u8>) -> Self {
        Self::new(v)
    }
}

// `Zeroize` is implemented manually so that callers may call
// `.zeroize()` explicitly without dropping the wrapper. `ZeroizeOnDrop`
// above handles the drop-time guarantee.
impl Zeroize for SecretVec {
    fn zeroize(&mut self) {
        self.inner.zeroize();
    }
}

/// Errors surfaced by [`KekProvider`] implementations.
#[derive(Debug, Error)]
pub enum KekError {
    /// The provider has not been configured (e.g. the Vault stub was
    /// constructed without a backing Transit client).
    #[error("kek provider `{0}` is not configured")]
    ProviderNotConfigured(&'static str),

    /// The underlying KMS rejected the request. The first field is the
    /// provider identifier (e.g. `"aws-kms"`, `"vault-transit"`); the
    /// second is a redacted, log-safe description of what went wrong.
    #[error("kek provider `{0}` error: {1}")]
    Provider(&'static str, String),

    /// Unwrap was called with an [`EncryptionContext`] that does not
    /// match the one used at wrap time. The plaintext was NOT recovered.
    #[error("encryption context mismatch on unwrap")]
    ContextMismatch,

    /// The requested KEK does not exist (or has been destroyed).
    #[error("kek not found: {0}")]
    NotFound(String),

    /// Caller is not authorised to perform the operation.
    #[error("kek operation unauthorized")]
    Unauthorized,

    /// The provider response could not be parsed (malformed ciphertext,
    /// missing field, invalid base64, …).
    #[error("kek format error: {0}")]
    Format(String),

    /// Network / TLS / timeout failure talking to the provider.
    #[error("kek transport error: {0}")]
    Transport(String),
}

impl KekError {
    /// Convenience constructor for provider-side errors.
    pub fn provider<E: fmt::Display>(provider_id: &'static str, err: E) -> Self {
        Self::Provider(provider_id, err.to_string())
    }

    /// Convenience constructor for format errors.
    pub fn format<E: fmt::Display>(err: E) -> Self {
        Self::Format(err.to_string())
    }

    /// Convenience constructor for transport errors.
    pub fn transport<E: fmt::Display>(err: E) -> Self {
        Self::Transport(err.to_string())
    }
}

/// Async abstraction over a KMS providing envelope-encryption primitives
/// (TRD §27.1).
///
/// Implementations MUST be `Send + Sync` so they can be shared across
/// tasks behind an [`std::sync::Arc`].
///
/// ## Required semantics
///
/// * [`wrap`](Self::wrap) — encrypts `plaintext` under the KEK named
///   `key_id`, propagating `context` to the KMS as additional
///   authenticated data. Returns an opaque provider-specific
///   ciphertext.
/// * [`unwrap`](Self::unwrap) — the inverse. The supplied `context`
///   MUST match the one used at wrap time; otherwise the implementation
///   MUST return [`KekError::ContextMismatch`].
/// * [`rotate`](Self::rotate) — bumps the KEK to a new version. Older
///   versions remain available for unwrap.
#[async_trait]
pub trait KekProvider: Send + Sync {
    /// Stable string identifier for the provider (e.g. `"aws-kms"`,
    /// `"vault-transit"`, `"gcp-kms"`). Used in observability and in
    /// [`KekError::Provider`] payloads so operators can disambiguate
    /// across multi-provider deployments.
    fn provider_id(&self) -> &'static str;

    /// Encrypt `plaintext` under the KEK named `key_id`.
    async fn wrap(
        &self,
        plaintext: &[u8],
        key_id: &str,
        context: &EncryptionContext,
    ) -> Result<Vec<u8>, KekError>;

    /// Decrypt a previously-produced ciphertext under `key_id`.
    async fn unwrap(
        &self,
        ciphertext: &[u8],
        key_id: &str,
        context: &EncryptionContext,
    ) -> Result<SecretVec, KekError>;

    /// Rotate the KEK named `key_id` to a new version.
    async fn rotate(&self, key_id: &str) -> Result<NewKeyVersion, KekError>;
}

#[async_trait]
impl<T> KekProvider for std::sync::Arc<T>
where
    T: KekProvider + ?Sized,
{
    fn provider_id(&self) -> &'static str {
        (**self).provider_id()
    }

    async fn wrap(
        &self,
        plaintext: &[u8],
        key_id: &str,
        context: &EncryptionContext,
    ) -> Result<Vec<u8>, KekError> {
        (**self).wrap(plaintext, key_id, context).await
    }

    async fn unwrap(
        &self,
        ciphertext: &[u8],
        key_id: &str,
        context: &EncryptionContext,
    ) -> Result<SecretVec, KekError> {
        (**self).unwrap(ciphertext, key_id, context).await
    }

    async fn rotate(&self, key_id: &str) -> Result<NewKeyVersion, KekError> {
        (**self).rotate(key_id).await
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use uuid::Uuid;

    /// Minimal mock provider used by the trait-object construction test.
    /// Echoes plaintext back as the "ciphertext" so we can verify a
    /// round-trip through the trait without a live KMS.
    struct MockKek;

    #[async_trait]
    impl KekProvider for MockKek {
        fn provider_id(&self) -> &'static str {
            "mock"
        }

        async fn wrap(
            &self,
            plaintext: &[u8],
            _key_id: &str,
            _context: &EncryptionContext,
        ) -> Result<Vec<u8>, KekError> {
            Ok(plaintext.to_vec())
        }

        async fn unwrap(
            &self,
            ciphertext: &[u8],
            _key_id: &str,
            _context: &EncryptionContext,
        ) -> Result<SecretVec, KekError> {
            Ok(SecretVec::new(ciphertext.to_vec()))
        }

        async fn rotate(&self, key_id: &str) -> Result<NewKeyVersion, KekError> {
            Ok(NewKeyVersion::now(key_id, 2))
        }
    }

    fn ctx() -> EncryptionContext {
        EncryptionContext::new(TenantId::new(Uuid::nil()), 1)
    }

    #[tokio::test]
    async fn trait_object_construction_round_trips_through_box_dyn() {
        let provider: Box<dyn KekProvider> = Box::new(MockKek);
        assert_eq!(provider.provider_id(), "mock");

        let ct = provider.wrap(b"hello", "k", &ctx()).await.unwrap();
        let pt = provider.unwrap(&ct, "k", &ctx()).await.unwrap();
        assert_eq!(pt.expose_secret(), b"hello");

        let v = provider.rotate("k").await.unwrap();
        assert_eq!(v.key_id, "k");
        assert_eq!(v.version, 2);
    }

    #[tokio::test]
    async fn trait_object_works_behind_arc_dyn() {
        // The blanket `impl<T> KekProvider for Arc<T>` should let us
        // store the provider as a cheaply-cloneable handle in a
        // service container.
        let provider: Arc<dyn KekProvider> = Arc::new(MockKek);
        let cloned = Arc::clone(&provider);
        assert_eq!(cloned.provider_id(), "mock");
        let ct = cloned.wrap(b"x", "k", &ctx()).await.unwrap();
        assert_eq!(ct, b"x");
    }

    #[test]
    fn encryption_context_to_map_round_trips() {
        let original = EncryptionContext::new(TenantId::random(), 7);
        let map = original.to_map();
        assert_eq!(map.len(), 2);
        assert_eq!(
            map.get("tenant_id").map(String::as_str),
            Some(original.tenant_id.to_string().as_str())
        );
        assert_eq!(map.get("dek_version").map(String::as_str), Some("7"));

        let parsed = EncryptionContext::from_map(&map).unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn encryption_context_from_map_rejects_malformed_inputs() {
        let mut bad = HashMap::new();
        bad.insert("dek_version".to_owned(), "1".to_owned());
        let err = EncryptionContext::from_map(&bad).unwrap_err();
        assert!(matches!(err, KekError::Format(_)));

        let mut bad = HashMap::new();
        bad.insert("tenant_id".to_owned(), Uuid::nil().to_string());
        bad.insert("dek_version".to_owned(), "not-a-number".to_owned());
        let err = EncryptionContext::from_map(&bad).unwrap_err();
        assert!(matches!(err, KekError::Format(_)));

        let mut bad = HashMap::new();
        bad.insert("tenant_id".to_owned(), "not-a-uuid".to_owned());
        bad.insert("dek_version".to_owned(), "1".to_owned());
        let err = EncryptionContext::from_map(&bad).unwrap_err();
        assert!(matches!(err, KekError::Format(_)));
    }

    #[test]
    fn encryption_context_serde_json_round_trips() {
        let original = EncryptionContext::new(TenantId::random(), 42);
        let json = serde_json::to_string(&original).unwrap();
        let back: EncryptionContext = serde_json::from_str(&json).unwrap();
        assert_eq!(back, original);
    }

    #[test]
    fn secret_vec_zeroizes_inner_bytes_on_explicit_zeroize() {
        // We can't observe the buffer *after* drop (the address is gone),
        // but we can observe an explicit `.zeroize()` overwriting the
        // bytes in place. `ZeroizeOnDrop` is exercised at compile time
        // by the derive and at runtime by drop; this test pins the
        // explicit behaviour so future refactors don't silently lose
        // it.
        let mut sv = SecretVec::new(vec![0x42, 0x42, 0x42, 0x42]);
        assert_eq!(sv.expose_secret(), &[0x42, 0x42, 0x42, 0x42]);
        sv.zeroize();
        // After zeroize the vec's length is zeroed (zeroize crate
        // contract for `Vec<u8>`); we just confirm we no longer see the
        // original pattern.
        assert!(sv.expose_secret().iter().all(|b| *b == 0));
    }

    #[test]
    fn secret_vec_debug_redacts_inner_bytes() {
        let sv = SecretVec::new(b"super-secret-bytes".to_vec());
        let rendered = format!("{sv:?}");
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains("super-secret-bytes"));
        assert!(rendered.contains("len"));
    }

    #[test]
    fn new_key_version_stamps_current_time() {
        let v = NewKeyVersion::now("alias/foo", 3);
        assert_eq!(v.key_id, "alias/foo");
        assert_eq!(v.version, 3);
        let delta = Utc::now().signed_duration_since(v.created_at);
        assert!(delta.num_seconds().abs() < 5);
    }

    #[test]
    fn kek_error_provider_helper_renders_provider_id_in_display() {
        let err = KekError::provider("aws-kms", "AccessDenied");
        let rendered = format!("{err}");
        assert!(rendered.contains("aws-kms"));
        assert!(rendered.contains("AccessDenied"));
    }
}
