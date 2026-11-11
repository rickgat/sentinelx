//! Per-tenant ingestion-key lookup, backed by an
//! [`sx_secrets::SecretsProvider`].
//!
//! Falco-ingestion HMAC keys live in the secrets backend under the
//! per-tenant path:
//!
//! ```text
//! runtime/falco/{tenant_id}/webhook-key
//! ```
//!
//! [`TenantKeyStore`] resolves a tenant id to a [`secrecy::SecretString`]
//! key, returning [`crate::error::RuntimeError::UnknownTenant`] when the
//! backend reports the path does not exist. Network / authn / authz
//! failures are mapped onto [`crate::error::RuntimeError::Internal`].

use std::sync::Arc;

use secrecy::SecretString;
use sx_secrets::{SecretsError, SecretsProvider};

use crate::error::RuntimeError;

/// Vault / KV path prefix under which the per-tenant signing keys are
/// stored. The full path is `{PREFIX}/{tenant_id}/webhook-key`.
pub const FALCO_KEY_VAULT_PREFIX: &str = "runtime/falco";

/// Lookup port: `tenant_id` -> shared HMAC key.
#[derive(Clone)]
pub struct TenantKeyStore {
    inner: Arc<dyn SecretsProvider>,
}

impl std::fmt::Debug for TenantKeyStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TenantKeyStore").finish_non_exhaustive()
    }
}

impl TenantKeyStore {
    /// Build a store on top of any [`SecretsProvider`].
    #[must_use]
    pub fn new(inner: Arc<dyn SecretsProvider>) -> Self {
        Self { inner }
    }

    /// Look up the HMAC signing key for `tenant_id`.
    ///
    /// # Errors
    ///
    /// * [`RuntimeError::UnknownTenant`] when no key is provisioned for
    ///   the tenant.
    /// * [`RuntimeError::Internal`] for any other secrets backend failure
    ///   (transport, format, authz, ...).
    pub async fn key_for_tenant(&self, tenant_id: &str) -> Result<SecretString, RuntimeError> {
        let path = format!("{FALCO_KEY_VAULT_PREFIX}/{tenant_id}/webhook-key");
        match self.inner.get(&path).await {
            Ok(secret) => Ok(secret),
            Err(SecretsError::NotFound(_)) => Err(RuntimeError::UnknownTenant),
            Err(e) => {
                tracing::warn!(
                    target: "sx_runtime",
                    tenant_id,
                    error = %e,
                    "tenant key lookup failed",
                );
                Err(RuntimeError::Internal("tenant key lookup".into()))
            }
        }
    }

    /// Provision (or rotate) the HMAC signing key for `tenant_id`.
    /// Useful for tests and admin tooling; the production code path is
    /// expected to write through the secrets backend directly.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError::Internal`] when the backend rejects the
    /// write.
    pub async fn put_key(&self, tenant_id: &str, key: SecretString) -> Result<(), RuntimeError> {
        let path = format!("{FALCO_KEY_VAULT_PREFIX}/{tenant_id}/webhook-key");
        self.inner
            .put(&path, key)
            .await
            .map_err(|e| RuntimeError::Internal(format!("tenant key store: {e}")))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;
    use sx_secrets::InMemoryProvider;

    #[tokio::test]
    async fn put_then_get_round_trip() {
        let provider: Arc<dyn SecretsProvider> = Arc::new(InMemoryProvider::new());
        let store = TenantKeyStore::new(provider);
        store
            .put_key("t1", SecretString::from("key-1".to_owned()))
            .await
            .unwrap();
        let k = store.key_for_tenant("t1").await.unwrap();
        assert_eq!(k.expose_secret(), "key-1");
    }

    #[tokio::test]
    async fn unknown_tenant_surfaces_unknown_error() {
        let provider: Arc<dyn SecretsProvider> = Arc::new(InMemoryProvider::new());
        let store = TenantKeyStore::new(provider);
        let err = store.key_for_tenant("does-not-exist").await.unwrap_err();
        assert!(matches!(err, RuntimeError::UnknownTenant));
    }

    #[tokio::test]
    async fn rotates_in_place() {
        let provider: Arc<dyn SecretsProvider> = Arc::new(InMemoryProvider::new());
        let store = TenantKeyStore::new(provider);
        store
            .put_key("t1", SecretString::from("v1".to_owned()))
            .await
            .unwrap();
        store
            .put_key("t1", SecretString::from("v2".to_owned()))
            .await
            .unwrap();
        let k = store.key_for_tenant("t1").await.unwrap();
        assert_eq!(k.expose_secret(), "v2");
    }
}
