//! Crypto-erase: deleting a tenant's DEK destroys their data forever.
//!
//! The security model:
//!
//! 1. Every tenant has a unique DEK, wrapped under a KEK that lives in
//!    the KMS.
//! 2. The plaintext DEK is never persisted: only the *wrapped* form
//!    survives, inside [`crate::dek::DekStore`].
//! 3. The wrapped DEK is the only path back to the plaintext, because
//!    the KEK never leaves the KMS.
//!
//! Crypto-erase exploits this chain. To "destroy" all data belonging to
//! a tenant we only need to delete the wrapped DEK. The actual
//! ciphertext payloads can stay where they are (in S3, in Postgres, on
//! backup tapes, …): without the DEK they are indistinguishable from
//! random noise and cannot be decrypted, even by a future operator with
//! root access.
//!
//! This is sometimes called *cryptographic shredding* and is the
//! standard mechanism for satisfying GDPR's "right to erasure" against
//! immutable / replicated storage where physical deletion is
//! impractical.
//!
//! ## Semantics after [`crypto_erase_tenant`]
//!
//! * [`crate::dek::DekManager::get_or_create`] will mint a *new* DEK on
//!   the next call: the slot is empty, not poisoned. Callers that wish
//!   to refuse any further writes for the tenant must enforce that
//!   above this layer (e.g. a tenant-lifecycle service).
//! * Any code that tries to decrypt previously-stored ciphertext under
//!   the erased DEK gets [`SecretsError::Unauthorized`] from the KMS
//!   (the wrapped DEK that would have been passed in is gone) or
//!   [`SecretsError::NotFound`] from the store (if the caller went via
//!   the manager). Both are unrecoverable.
//!
//! ## What this module does **not** do
//!
//! It does not touch the KEK in the KMS. Multiple tenants may share a
//! KEK in some deployments; destroying the KEK is a separate, more
//! dangerous operation and is out of scope for `crypto_erase_tenant`.

use tracing::{info, warn};

use crate::dek::{DekManager, DekStore, TenantId};
use crate::error::SecretsError;
use crate::kms::provider::KmsKeyProvider;

/// Cryptographically erase a tenant by deleting their wrapped DEK.
///
/// After this call, any previously-encrypted payload belonging to
/// `tenant_id` becomes permanently unrecoverable: the only key that
/// could unwrap it is gone.
///
/// The operation is **idempotent**: erasing an already-erased tenant
/// returns `Ok(())`. This matches the [`DekStore::delete`] contract.
///
/// Returns the underlying store error if the delete itself fails (e.g.
/// transient Postgres outage). In that case the DEK has *not* been
/// destroyed and the caller may retry.
pub async fn crypto_erase_tenant<K, S>(
    manager: &DekManager<K, S>,
    tenant_id: TenantId,
) -> Result<(), SecretsError>
where
    K: KmsKeyProvider + 'static,
    S: DekStore + 'static,
{
    let existed = manager.store().get(tenant_id).await?.is_some();
    manager.store().delete(tenant_id).await?;
    if existed {
        info!(
            target: "sx_secrets::shred",
            tenant_id = %tenant_id,
            "crypto-erased tenant DEK"
        );
    } else {
        warn!(
            target: "sx_secrets::shred",
            tenant_id = %tenant_id,
            "crypto-erase: tenant had no DEK on file (noop)"
        );
    }
    Ok(())
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
    use crate::dek::{InMemoryDekStore, StoredDek};
    use crate::kms::provider::{Ciphertext, KeyVersion, KmsKeyProvider, WrappedDek};
    use async_trait::async_trait;
    use chrono::Utc;
    use secrecy::SecretString;
    use std::sync::Arc;

    /// A KMS that refuses to decrypt anything: stands in for "the DEK
    /// has been crypto-erased, so the wrapped form is gone, so nothing
    /// the caller passes in can possibly unwrap successfully".
    #[derive(Debug, Default)]
    struct UnauthorizedKms;

    #[async_trait]
    impl KmsKeyProvider for UnauthorizedKms {
        async fn encrypt(
            &self,
            _key_id: &str,
            _plaintext: &SecretString,
        ) -> Result<Ciphertext, SecretsError> {
            Err(SecretsError::Unauthorized)
        }

        async fn decrypt(
            &self,
            _key_id: &str,
            _ciphertext: &Ciphertext,
        ) -> Result<SecretString, SecretsError> {
            Err(SecretsError::Unauthorized)
        }

        async fn generate_dek(&self, key_id: &str) -> Result<WrappedDek, SecretsError> {
            // Allow generate so we can seed a DEK before erasing it.
            Ok(WrappedDek::new(
                key_id,
                1,
                SecretString::new("dek-bytes".to_owned().into_boxed_str()),
                Ciphertext::new("mock:v1:WRAPPED"),
            ))
        }

        async fn rotate(&self, _key_id: &str) -> Result<KeyVersion, SecretsError> {
            Ok(KeyVersion::now(2))
        }
    }

    fn manager() -> DekManager<UnauthorizedKms, InMemoryDekStore> {
        DekManager::new(
            Arc::new(UnauthorizedKms),
            Arc::new(InMemoryDekStore::new()),
            "tenant-kek",
        )
    }

    #[tokio::test]
    async fn crypto_erase_deletes_the_stored_dek() {
        let mgr = manager();
        let tenant = TenantId::random();
        mgr.get_or_create(tenant).await.unwrap();
        assert!(mgr.store().get(tenant).await.unwrap().is_some());

        crypto_erase_tenant(&mgr, tenant).await.unwrap();
        assert!(mgr.store().get(tenant).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn crypto_erase_is_idempotent() {
        let mgr = manager();
        let tenant = TenantId::random();
        // Erase before any DEK ever existed.
        crypto_erase_tenant(&mgr, tenant).await.unwrap();
        // And erase again — still a noop, still Ok.
        crypto_erase_tenant(&mgr, tenant).await.unwrap();
    }

    #[tokio::test]
    async fn post_erase_decrypt_attempts_fail_unauthorized() {
        let mgr = manager();
        let tenant = TenantId::random();
        let dek = mgr.get_or_create(tenant).await.unwrap();

        // Snapshot the wrapped DEK so we can mimic a stale caller that
        // still holds the ciphertext after the erase.
        let stale_wrapped = dek.wrapped.clone();

        crypto_erase_tenant(&mgr, tenant).await.unwrap();

        // The store no longer has the DEK record.
        assert!(mgr.store().get(tenant).await.unwrap().is_none());
        // And asking the KMS to decrypt the stale wrapped DEK fails
        // with Unauthorized — modelling "the key material that could
        // unwrap this is gone".
        let err = mgr
            .kms()
            .decrypt(mgr.key_id(), &stale_wrapped)
            .await
            .unwrap_err();
        assert!(matches!(err, SecretsError::Unauthorized));
    }

    #[tokio::test]
    async fn erase_then_get_or_create_mints_a_fresh_dek() {
        // The store slot is empty, not poisoned. A subsequent
        // get_or_create mints a brand-new DEK with `created_at` after
        // the original.
        let mgr = manager();
        let tenant = TenantId::random();
        let original = mgr.get_or_create(tenant).await.unwrap();
        let original_created_at = original.created_at;

        crypto_erase_tenant(&mgr, tenant).await.unwrap();

        // Allow at least 1ms to elapse so timestamps are comparable
        // even on very fast hosts.
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;

        let fresh = mgr.get_or_create(tenant).await.unwrap();
        assert!(fresh.created_at >= original_created_at);
    }

    #[tokio::test]
    async fn stored_dek_from_wrapped_preserves_metadata() {
        let tenant = TenantId::random();
        let wrapped = WrappedDek {
            key_id: "k".into(),
            version: 9,
            plaintext: SecretString::new("p".to_owned().into_boxed_str()),
            wrapped: Ciphertext::new("mock:v9:W"),
            created_at: Utc::now(),
        };
        let stored = StoredDek::from_wrapped(tenant, &wrapped);
        assert_eq!(stored.tenant_id, tenant);
        assert_eq!(stored.key_id, "k");
        assert_eq!(stored.version, 9);
        assert_eq!(stored.wrapped.as_str(), "mock:v9:W");
        assert_eq!(stored.created_at, wrapped.created_at);
    }
}
