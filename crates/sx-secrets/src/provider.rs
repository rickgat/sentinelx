//! The [`SecretsProvider`] trait and an in-memory fixture implementation.
//!
//! Every backend in this crate implements [`SecretsProvider`]. The
//! [`InMemoryProvider`] is provided primarily for tests and for ephemeral
//! dev runs where standing up a real Vault is overkill.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use secrecy::{ExposeSecret, SecretString};
use tokio::sync::Mutex;

use crate::error::SecretsError;

/// Async abstraction over a secret store.
///
/// All implementations must be `Send + Sync` so they can be shared across
/// tasks behind an [`Arc`].
///
/// ## Path semantics
///
/// Paths are opaque, slash-delimited strings (e.g.
/// `"prod/db/postgres"`). Backends are free to mount them into their own
/// namespace; the [`crate::vault::VaultProvider`] for example prepends
/// `/v1/{mount}/data/` and resolves the value at `.data.data.value`.
#[async_trait]
pub trait SecretsProvider: Send + Sync {
    /// Fetch the secret at `path`.
    ///
    /// Returns [`SecretsError::NotFound`] if the backend reports the path
    /// does not exist, [`SecretsError::Unauthorized`] for authn/authz
    /// failures, [`SecretsError::Format`] for parse failures, and
    /// [`SecretsError::Transport`] for I/O.
    async fn get(&self, path: &str) -> Result<SecretString, SecretsError>;

    /// Store `value` at `path`, overwriting any previous version.
    ///
    /// Backends that support versioning (e.g. Vault KV v2) typically
    /// append a new version rather than mutating the existing one;
    /// reads still observe the latest version.
    async fn put(&self, path: &str, value: SecretString) -> Result<(), SecretsError>;
}

#[async_trait]
impl<T> SecretsProvider for Arc<T>
where
    T: SecretsProvider + ?Sized,
{
    async fn get(&self, path: &str) -> Result<SecretString, SecretsError> {
        (**self).get(path).await
    }

    async fn put(&self, path: &str, value: SecretString) -> Result<(), SecretsError> {
        (**self).put(path, value).await
    }
}

/// Process-local, in-memory implementation of [`SecretsProvider`].
///
/// Useful in tests (to stub out a real backend) and in dev runs where
/// secrets are seeded programmatically. Backed by a `tokio::sync::Mutex`
/// over a `HashMap`; cheap to clone since the storage is held behind an
/// [`Arc`].
#[derive(Debug, Default, Clone)]
pub struct InMemoryProvider {
    store: Arc<Mutex<HashMap<String, String>>>,
}

impl InMemoryProvider {
    /// Construct an empty in-memory provider.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Count the entries currently stored.
    ///
    /// Primarily intended for tests / observability — production code
    /// should not rely on this number for correctness.
    pub async fn len(&self) -> usize {
        self.store.lock().await.len()
    }

    /// Returns `true` if the store currently has no entries.
    pub async fn is_empty(&self) -> bool {
        self.store.lock().await.is_empty()
    }
}

#[async_trait]
impl SecretsProvider for InMemoryProvider {
    async fn get(&self, path: &str) -> Result<SecretString, SecretsError> {
        let guard = self.store.lock().await;
        guard.get(path).map_or_else(
            || Err(SecretsError::NotFound(path.to_owned())),
            |value| Ok(SecretString::new(value.clone().into_boxed_str())),
        )
    }

    async fn put(&self, path: &str, value: SecretString) -> Result<(), SecretsError> {
        self.store
            .lock()
            .await
            .insert(path.to_owned(), value.expose_secret().to_owned());
        Ok(())
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::expect_used,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;

    fn secret(s: &str) -> SecretString {
        SecretString::new(s.to_owned().into_boxed_str())
    }

    #[tokio::test]
    async fn in_memory_round_trip() {
        let provider = InMemoryProvider::new();
        assert!(provider.is_empty().await);
        provider.put("prod/db", secret("hunter2")).await.unwrap();
        assert_eq!(provider.len().await, 1);
        let got = provider.get("prod/db").await.unwrap();
        assert_eq!(got.expose_secret(), "hunter2");
    }

    #[tokio::test]
    async fn in_memory_missing_path_is_not_found() {
        let provider = InMemoryProvider::new();
        let err = provider.get("nope").await.unwrap_err();
        assert!(matches!(err, SecretsError::NotFound(p) if p == "nope"));
    }

    #[tokio::test]
    async fn in_memory_overwrites_previous_value() {
        let provider = InMemoryProvider::new();
        provider.put("k", secret("v1")).await.unwrap();
        provider.put("k", secret("v2")).await.unwrap();
        let got = provider.get("k").await.unwrap();
        assert_eq!(got.expose_secret(), "v2");
        assert_eq!(provider.len().await, 1);
    }
}
