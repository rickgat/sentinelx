//! [`EnvelopeKeyManager`] — the operator-facing facade for tenant-scoped
//! DEK lifecycle operations (CRIT-003).
//!
//! `EnvelopeKeyManager` is a thin, opinionated wrapper around
//! [`crate::dek::DekManager`] and the rotation orchestrator in
//! [`crate::dek_rotation`]. It exists so the public surface the CLI and
//! REST handlers consume is a single, named entry point (`rotate_dek`,
//! `rotation_status`, `cancel_rotation`) rather than a hand-rolled chain
//! of `DekManager` + `DekRotationJob` + `RotationProgressStore` calls.
//!
//! ## Why a wrapper, not a method on `DekManager`?
//!
//! [`crate::dek::DekManager`] is generic over `K: KmsKeyProvider` and
//! `S: DekStore` and knows nothing about visitors, audit, or progress
//! storage. Rotation is *also* generic over those plus the visitor set
//! and the audit sink. A facade keeps the constructor flat without
//! piling another five generic parameters onto `DekManager`.
//!
//! ## Operations
//!
//! | Method                      | Maps to                                                |
//! |-----------------------------|--------------------------------------------------------|
//! | [`Self::rotate_dek`]        | [`DekRotationJob::run_for_tenant`] (auto-bumps target) |
//! | [`Self::rotate_dek_to`]     | [`DekRotationJob::run_for_tenant`] (explicit target)   |
//! | [`Self::rotation_status`]   | [`DekRotationJob::status_for_tenant`]                  |
//! | [`Self::cancel_rotation`]   | [`DekRotationJob::cancel_for_tenant`]                  |
//! | [`Self::policy`]            | [`crate::dek_rotation::RotationPolicyStore::get`]      |
//!
//! Every method scopes by [`crate::dek::TenantId`] — a misconfigured
//! caller cannot read or write another tenant's rotation state because
//! both the orchestrator and the progress / policy stores plumb the
//! tenant id straight through to the RLS-aware SQL adapters.
//!
//! ## Forward-secrecy
//!
//! On successful rotation the orchestrator overwrites the stored
//! wrapped DEK with the new version, and the resolved old-DEK
//! plaintext goes out of scope (wrapped in [`secrecy::SecretString`]
//! whose `Drop` zeroizes the buffer). After a `rotate_dek` returns
//! `Completed`, the only remaining record of the previous DEK is the
//! KMS-side wrapped form, which the operator can purge via the
//! KMS-native key-version expiry policy.

#![allow(clippy::module_name_repetitions)]

use std::sync::Arc;

use crate::dek::{DekManager, DekStore, TenantId};
use crate::dek_rotation::{
    DekRotationError, DekRotationJob, RotationCheckpoint, RotationPolicyRow,
};
use crate::kms::provider::KmsKeyProvider;

/// Facade exposing tenant-scoped DEK rotation operations.
///
/// Holds a shared reference to the rotation orchestrator built at the
/// composition root. Clone is cheap (all internal state is `Arc`).
pub struct EnvelopeKeyManager<K, S> {
    job: Arc<DekRotationJob<K, S>>,
}

impl<K, S> std::fmt::Debug for EnvelopeKeyManager<K, S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnvelopeKeyManager").finish_non_exhaustive()
    }
}

impl<K, S> Clone for EnvelopeKeyManager<K, S> {
    fn clone(&self) -> Self {
        Self {
            job: Arc::clone(&self.job),
        }
    }
}

impl<K, S> EnvelopeKeyManager<K, S>
where
    K: KmsKeyProvider + 'static,
    S: DekStore + 'static,
{
    /// Construct from an already-built rotation orchestrator.
    #[must_use]
    pub const fn new(job: Arc<DekRotationJob<K, S>>) -> Self {
        Self { job }
    }

    /// Borrow the underlying rotation orchestrator.
    ///
    /// Exposed so the CLI / REST adapters can dispatch lower-level
    /// operations (audit sink replay, in-memory store inspection in
    /// tests) without holding a second `Arc` themselves.
    #[must_use]
    pub const fn job(&self) -> &Arc<DekRotationJob<K, S>> {
        &self.job
    }

    /// Borrow the underlying [`DekManager`].
    ///
    /// Exposed so callers can perform DEK operations that are not
    /// covered by the rotation surface — for example, minting the
    /// initial DEK on first tenant use.
    #[must_use]
    pub fn dek_manager(&self) -> &Arc<DekManager<K, S>> {
        self.job.manager_handle()
    }

    /// Rotate the tenant's DEK to the next available version.
    ///
    /// The target version is auto-computed as
    /// `max(current_stored_dek_version, latest_rotation_target) + 1`,
    /// so repeated invocations always advance.
    ///
    /// # Errors
    ///
    /// Returns [`DekRotationError`] when the orchestrator, KMS, or any
    /// visitor fails. The progress row is stamped `Failed` on hard
    /// failure so an operator can resume after triage.
    pub async fn rotate_dek(
        &self,
        tenant_id: TenantId,
    ) -> Result<RotationCheckpoint, DekRotationError> {
        let next = self.next_target_version(tenant_id).await?;
        self.job.run_for_tenant(tenant_id, next).await
    }

    /// Rotate the tenant's DEK to an explicit target version.
    ///
    /// Useful for replays / dry-runs: pass the *current* version and the
    /// orchestrator no-ops (because every row is already `>= target`).
    /// Pass a strictly higher version and rotation proceeds.
    ///
    /// # Errors
    ///
    /// As for [`Self::rotate_dek`].
    pub async fn rotate_dek_to(
        &self,
        tenant_id: TenantId,
        target_version: u32,
    ) -> Result<RotationCheckpoint, DekRotationError> {
        self.job.run_for_tenant(tenant_id, target_version).await
    }

    /// Report the latest rotation checkpoint for `tenant_id`.
    ///
    /// Returns `Ok(None)` when the tenant has never rotated.
    ///
    /// # Errors
    ///
    /// Returns [`DekRotationError::Store`] if the progress store
    /// rejects the read.
    pub async fn rotation_status(
        &self,
        tenant_id: TenantId,
    ) -> Result<Option<RotationCheckpoint>, DekRotationError> {
        self.job.status_for_tenant(tenant_id).await
    }

    /// Mark the active rotation for `tenant_id` as cancelled. Returns
    /// `Ok(None)` when there is no rotation row for the tenant.
    ///
    /// # Errors
    ///
    /// Returns [`DekRotationError::Store`] on a progress-store failure.
    pub async fn cancel_rotation(
        &self,
        tenant_id: TenantId,
    ) -> Result<Option<RotationCheckpoint>, DekRotationError> {
        self.job.cancel_for_tenant(tenant_id).await
    }

    /// Read the per-tenant rotation policy.
    ///
    /// Returns `Ok(None)` when the tenant has never had a policy row
    /// inserted; callers should treat the absent case as
    /// `default_for(tenant_id)`.
    ///
    /// # Errors
    ///
    /// Returns [`DekRotationError::Store`] on a policy-store failure.
    pub async fn policy(
        &self,
        tenant_id: TenantId,
    ) -> Result<Option<RotationPolicyRow>, DekRotationError> {
        self.job.policy_handle().get(tenant_id).await
    }

    async fn next_target_version(&self, tenant_id: TenantId) -> Result<u32, DekRotationError> {
        let latest_rotation = self.job.status_for_tenant(tenant_id).await?;
        let stored_version = self
            .job
            .manager_handle()
            .store()
            .get(tenant_id)
            .await
            .map_err(DekRotationError::from)?
            .map(|d| d.version)
            .unwrap_or_default();
        let next = latest_rotation
            .map(|cp| cp.target_dek_version)
            .unwrap_or_default()
            .max(stored_version)
            .saturating_add(1);
        Ok(next.max(1))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::dek::{DekManager, InMemoryDekStore};
    use crate::dek_rotation::{
        DekRotationAuditSink, DekRotationJob, InMemoryDekRotationAuditSink,
        InMemoryRotationPolicyStore, InMemoryRotationProgressStore, ReencryptionVisitor,
        RotationConfig, RotationJobStatus, RotationPolicyStore, RotationProgressStore,
        VisitorBatchOutcome,
    };
    use crate::kms::provider::{Ciphertext, KeyVersion, KmsKeyProvider, WrappedDek};
    use async_trait::async_trait;
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    use secrecy::{ExposeSecret, SecretString};
    use std::sync::atomic::{AtomicU32, Ordering};
    use uuid::Uuid;

    use crate::error::SecretsError;

    #[derive(Debug, Default)]
    struct MockKms {
        version: AtomicU32,
    }
    impl MockKms {
        fn new() -> Self {
            Self {
                version: AtomicU32::new(1),
            }
        }
    }

    #[async_trait]
    impl KmsKeyProvider for MockKms {
        async fn encrypt(
            &self,
            _key_id: &str,
            plaintext: &SecretString,
        ) -> Result<Ciphertext, SecretsError> {
            Ok(Ciphertext::new(format!(
                "mock:v{}:{}",
                self.version.load(Ordering::SeqCst),
                B64.encode(plaintext.expose_secret().as_bytes())
            )))
        }

        async fn decrypt(
            &self,
            _key_id: &str,
            ciphertext: &Ciphertext,
        ) -> Result<SecretString, SecretsError> {
            let parts: Vec<&str> = ciphertext.as_str().splitn(3, ':').collect();
            if parts.len() != 3 {
                return Err(SecretsError::format("bad mock ct"));
            }
            // INVARIANT: parts.len() == 3 verified above.
            #[allow(clippy::indexing_slicing)]
            let bytes = B64
                .decode(parts[2])
                .map_err(|e| SecretsError::format(e.to_string()))?;
            let s = String::from_utf8(bytes).map_err(|e| SecretsError::format(e.to_string()))?;
            Ok(SecretString::new(s.into_boxed_str()))
        }

        async fn generate_dek(&self, key_id: &str) -> Result<WrappedDek, SecretsError> {
            let v = self.version.load(Ordering::SeqCst);
            let pt_str = format!("dek-bytes-v{v}");
            let wrapped = Ciphertext::new(format!("mock:v{}:{}", v, B64.encode(pt_str.as_bytes())));
            Ok(WrappedDek::new(
                key_id,
                v,
                SecretString::new(pt_str.into_boxed_str()),
                wrapped,
            ))
        }

        async fn rotate(&self, _key_id: &str) -> Result<KeyVersion, SecretsError> {
            let v = self.version.fetch_add(1, Ordering::SeqCst) + 1;
            Ok(KeyVersion::now(v))
        }
    }

    struct NoopVisitor;

    #[async_trait]
    impl ReencryptionVisitor for NoopVisitor {
        fn visitor_id(&self) -> &'static str {
            "noop"
        }

        async fn count_remaining(
            &self,
            _tenant_id: TenantId,
            _target_version: u32,
        ) -> Result<u64, DekRotationError> {
            Ok(0)
        }

        async fn reencrypt_batch(
            &self,
            _tenant_id: TenantId,
            _cursor: Option<&str>,
            _batch_size: u32,
            _target_version: u32,
            _old_dek_plaintext: &SecretString,
            _new_dek_plaintext: &SecretString,
        ) -> Result<VisitorBatchOutcome, DekRotationError> {
            Ok(VisitorBatchOutcome {
                rows_reencrypted: 0,
                next_cursor: None,
                exhausted: true,
            })
        }
    }

    fn build() -> EnvelopeKeyManager<MockKms, InMemoryDekStore> {
        let kms = Arc::new(MockKms::new());
        let store = Arc::new(InMemoryDekStore::new());
        let manager = Arc::new(DekManager::new(kms, store, "tenant-kek"));
        let progress: Arc<dyn RotationProgressStore> =
            Arc::new(InMemoryRotationProgressStore::new());
        let policy: Arc<dyn RotationPolicyStore> = Arc::new(InMemoryRotationPolicyStore::new());
        let audit: Arc<dyn DekRotationAuditSink> = Arc::new(InMemoryDekRotationAuditSink::new());
        let visitors: Vec<Arc<dyn ReencryptionVisitor>> = vec![Arc::new(NoopVisitor)];
        let job = Arc::new(DekRotationJob::new(
            manager,
            progress,
            policy,
            audit,
            visitors,
            RotationConfig::defaults(),
        ));
        EnvelopeKeyManager::new(job)
    }

    #[tokio::test]
    async fn rotate_dek_advances_version_monotonically() {
        let envelope = build();
        let tenant = TenantId::new(Uuid::now_v7());
        // Seed an initial DEK so the manager has a baseline.
        envelope.dek_manager().get_or_create(tenant).await.unwrap();

        let cp1 = envelope.rotate_dek(tenant).await.unwrap();
        assert_eq!(cp1.status, RotationJobStatus::Completed);
        let v1 = cp1.target_dek_version;
        assert!(v1 >= 1);

        let cp2 = envelope.rotate_dek(tenant).await.unwrap();
        assert!(cp2.target_dek_version > v1, "must advance monotonically");
    }

    #[tokio::test]
    async fn rotation_status_returns_none_for_pristine_tenant() {
        let envelope = build();
        let tenant = TenantId::new(Uuid::now_v7());
        assert!(envelope.rotation_status(tenant).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn rotation_status_returns_latest_completed_checkpoint() {
        let envelope = build();
        let tenant = TenantId::new(Uuid::now_v7());
        envelope.dek_manager().get_or_create(tenant).await.unwrap();
        let _ = envelope.rotate_dek(tenant).await.unwrap();
        let cp = envelope.rotation_status(tenant).await.unwrap().unwrap();
        assert_eq!(cp.status, RotationJobStatus::Completed);
    }

    #[tokio::test]
    async fn cancel_rotation_noops_for_unknown_tenant() {
        let envelope = build();
        let tenant = TenantId::new(Uuid::now_v7());
        assert!(envelope.cancel_rotation(tenant).await.unwrap().is_none());
    }
}
