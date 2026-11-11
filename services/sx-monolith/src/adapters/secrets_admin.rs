//! Per-tenant DEK rotation admin adapter (CRIT-003).
//!
//! Two flavours:
//!
//! - [`DisabledDekRotationAdmin`] — the default. Returns
//!   `Phase3PortError::Invalid("dek rotation disabled")` so the HTTP
//!   routes are reachable for RBAC + smoke-test purposes while the
//!   production rotation stack is being wired in. This mirrors the
//!   pattern other "stack-gated" admin surfaces use in the monolith
//!   (`SamlSpPort`, `BugBountyPort`, etc.).
//! - [`InProcessDekRotationAdmin`] — wraps a fully-wired
//!   [`sx_secrets::EnvelopeKeyManager`]. Built only when the operator
//!   has provisioned a KMS provider, visitor registry, and progress /
//!   policy stores. Surfaces orchestrator results back through
//!   [`Phase3PortError`].
//!
//! Both adapters scope strictly by `tenant_id`: there is no cross-tenant
//! API on this surface. Operator-initiated rotations originate from the
//! `admin:secrets` permission gate in the controller layer.

use async_trait::async_trait;
use std::sync::Arc;
use uuid::Uuid;

use sx_api::port::{DekRotationAdminPort, Phase3PortError};
use sx_api::view::secrets_admin_view::RotationProgressView;
use sx_secrets::dek::{DekStore, TenantId};
use sx_secrets::dek_rotation::{DekRotationError, RotationCheckpoint, RotationJobStatus};
use sx_secrets::kms::provider::KmsKeyProvider;
use sx_secrets::EnvelopeKeyManager;

/// Default adapter used when the deployment has not wired in a real
/// rotation stack. Returns deterministic "disabled" errors via the
/// default trait impls.
#[derive(Debug, Default, Clone, Copy)]
pub struct DisabledDekRotationAdmin;

#[async_trait]
impl DekRotationAdminPort for DisabledDekRotationAdmin {
    // Default trait impls return Invalid / NotFound — sufficient.
}

/// In-process adapter backed by an [`EnvelopeKeyManager`].
///
/// Generic over the KMS provider and DEK store so the composition root
/// can pick any concrete pair (Vault Transit + Postgres in production,
/// in-memory stubs in tests).
pub struct InProcessDekRotationAdmin<K, S> {
    envelope: EnvelopeKeyManager<K, S>,
}

impl<K, S> std::fmt::Debug for InProcessDekRotationAdmin<K, S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InProcessDekRotationAdmin")
            .finish_non_exhaustive()
    }
}

impl<K, S> Clone for InProcessDekRotationAdmin<K, S> {
    fn clone(&self) -> Self {
        Self {
            envelope: self.envelope.clone(),
        }
    }
}

impl<K, S> InProcessDekRotationAdmin<K, S>
where
    K: KmsKeyProvider + 'static,
    S: DekStore + 'static,
{
    /// Construct from a built envelope manager.
    #[must_use]
    #[allow(dead_code)]
    pub const fn new(envelope: EnvelopeKeyManager<K, S>) -> Self {
        Self { envelope }
    }

    /// Borrow the underlying envelope manager.
    #[must_use]
    #[allow(dead_code)]
    pub const fn envelope(&self) -> &EnvelopeKeyManager<K, S> {
        &self.envelope
    }

    /// Wrap in an `Arc<dyn DekRotationAdminPort>` for the AppState.
    #[must_use]
    #[allow(dead_code)]
    pub fn into_arc(self) -> Arc<dyn DekRotationAdminPort> {
        Arc::new(self)
    }
}

#[async_trait]
impl<K, S> DekRotationAdminPort for InProcessDekRotationAdmin<K, S>
where
    K: KmsKeyProvider + 'static,
    S: DekStore + 'static,
{
    async fn rotate_dek(
        &self,
        tenant_id: &str,
        target_version: Option<u32>,
    ) -> Result<RotationProgressView, Phase3PortError> {
        let tenant = parse_tenant(tenant_id)?;
        // Ensure the manager has minted a DEK so the unwrap-old plumbing
        // has a baseline to read.
        self.envelope
            .dek_manager()
            .get_or_create(tenant)
            .await
            .map_err(|e| Phase3PortError::Dependency(redact(e)))?;

        let cp = match target_version {
            Some(v) => self.envelope.rotate_dek_to(tenant, v).await,
            None => self.envelope.rotate_dek(tenant).await,
        }
        .map_err(map_rotation_err)?;
        Ok(checkpoint_to_view(tenant_id, &cp))
    }

    async fn rotation_progress(
        &self,
        tenant_id: &str,
    ) -> Result<RotationProgressView, Phase3PortError> {
        let tenant = parse_tenant(tenant_id)?;
        let status = self
            .envelope
            .rotation_status(tenant)
            .await
            .map_err(map_rotation_err)?;
        match status {
            Some(cp) => Ok(checkpoint_to_view(tenant_id, &cp)),
            None => Err(Phase3PortError::NotFound),
        }
    }
}

/// Parse a `tenant_id` UUID. The error surface is `Phase3PortError::Invalid`
/// so the controller maps it to a 422.
fn parse_tenant(s: &str) -> Result<TenantId, Phase3PortError> {
    Uuid::parse_str(s.trim())
        .map(TenantId::new)
        .map_err(|e| Phase3PortError::Invalid(format!("tenant_id: {e}")))
}

/// Surface-redacted projection of a [`RotationCheckpoint`]. Never
/// includes ciphertext or plaintext bytes.
fn checkpoint_to_view(tenant_id: &str, cp: &RotationCheckpoint) -> RotationProgressView {
    RotationProgressView {
        tenant_id: tenant_id.to_owned(),
        target_dek_version: cp.target_dek_version,
        status: match cp.status {
            RotationJobStatus::Pending => "pending".to_owned(),
            RotationJobStatus::InProgress => "in_progress".to_owned(),
            RotationJobStatus::Completed => "completed".to_owned(),
            RotationJobStatus::Failed => "failed".to_owned(),
            RotationJobStatus::Cancelled => "cancelled".to_owned(),
        },
        processed_rows: cp.processed_rows,
        total_rows: cp.total_rows,
        started_at: cp.started_at.to_rfc3339(),
        last_checkpoint_at: cp.last_checkpoint_at.to_rfc3339(),
        last_error: cp.last_error.clone(),
    }
}

fn redact<E: std::fmt::Display>(err: E) -> String {
    // Mirror the rotation orchestrator's audit-emit convention: only
    // the redacted display surfaces. Errors here come from KMS / store
    // adapters that have already pre-redacted; we forward as-is.
    err.to_string()
}

fn map_rotation_err(err: DekRotationError) -> Phase3PortError {
    match err {
        DekRotationError::Kms(_) | DekRotationError::Store(_) => {
            Phase3PortError::Dependency(redact(err))
        }
        DekRotationError::Visitor(_) => Phase3PortError::Dependency(redact(err)),
        DekRotationError::VerificationMismatch { .. }
        | DekRotationError::IllegalTransition { .. } => Phase3PortError::Internal(redact(err)),
        DekRotationError::Cancelled => Phase3PortError::Invalid("rotation cancelled".into()),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    use secrecy::{ExposeSecret, SecretString};
    use std::sync::atomic::{AtomicU32, Ordering};
    use sx_secrets::dek_rotation::{
        DekRotationAuditSink, DekRotationJob, InMemoryDekRotationAuditSink,
        InMemoryRotationPolicyStore, InMemoryRotationProgressStore, ReencryptionVisitor,
        RotationConfig, RotationPolicyStore, RotationProgressStore, VisitorBatchOutcome,
    };
    use sx_secrets::kms::provider::{Ciphertext, KeyVersion, WrappedDek};
    use sx_secrets::{DekManager, InMemoryDekStore, SecretsError};

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
                return Err(SecretsError::Format("bad mock ct".into()));
            }
            let bytes = B64
                .decode(parts[2])
                .map_err(|e| SecretsError::Format(e.to_string()))?;
            let s = String::from_utf8(bytes).map_err(|e| SecretsError::Format(e.to_string()))?;
            Ok(SecretString::new(s.into_boxed_str()))
        }

        async fn generate_dek(&self, key_id: &str) -> Result<WrappedDek, SecretsError> {
            let v = self.version.load(Ordering::SeqCst);
            let pt = format!("dek-v{v}");
            let wrapped = Ciphertext::new(format!("mock:v{}:{}", v, B64.encode(pt.as_bytes())));
            Ok(WrappedDek::new(
                key_id,
                v,
                SecretString::new(pt.into_boxed_str()),
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
        async fn count_remaining(&self, _t: TenantId, _v: u32) -> Result<u64, DekRotationError> {
            Ok(0)
        }
        async fn reencrypt_batch(
            &self,
            _t: TenantId,
            _c: Option<&str>,
            _b: u32,
            _v: u32,
            _o: &SecretString,
            _n: &SecretString,
        ) -> Result<VisitorBatchOutcome, DekRotationError> {
            Ok(VisitorBatchOutcome {
                rows_reencrypted: 0,
                next_cursor: None,
                exhausted: true,
            })
        }
    }

    fn build_in_process() -> InProcessDekRotationAdmin<MockKms, InMemoryDekStore> {
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
        InProcessDekRotationAdmin::new(EnvelopeKeyManager::new(job))
    }

    #[tokio::test]
    async fn disabled_adapter_rejects_with_invalid() {
        let adapter = DisabledDekRotationAdmin;
        let err = adapter
            .rotate_dek("00000000-0000-7000-8000-000000000001", None)
            .await
            .unwrap_err();
        assert!(matches!(err, Phase3PortError::Invalid(_)));
        let err = adapter
            .rotation_progress("00000000-0000-7000-8000-000000000001")
            .await
            .unwrap_err();
        assert!(matches!(err, Phase3PortError::NotFound));
    }

    #[tokio::test]
    async fn in_process_rotate_returns_completed_progress() {
        let adapter = build_in_process();
        let tenant_uuid = Uuid::now_v7();
        let view = adapter
            .rotate_dek(&tenant_uuid.to_string(), None)
            .await
            .unwrap();
        assert_eq!(view.status, "completed");
        assert_eq!(view.processed_rows, 0); // noop visitor
    }

    #[tokio::test]
    async fn in_process_progress_round_trips_after_rotate() {
        let adapter = build_in_process();
        let tenant_uuid = Uuid::now_v7();
        // Pre-rotation: NotFound.
        let err = adapter
            .rotation_progress(&tenant_uuid.to_string())
            .await
            .unwrap_err();
        assert!(matches!(err, Phase3PortError::NotFound));
        // Rotate.
        let _ = adapter
            .rotate_dek(&tenant_uuid.to_string(), None)
            .await
            .unwrap();
        // Now progress reflects the run.
        let view = adapter
            .rotation_progress(&tenant_uuid.to_string())
            .await
            .unwrap();
        assert_eq!(view.status, "completed");
    }

    #[tokio::test]
    async fn invalid_tenant_id_surfaces_invalid() {
        let adapter = build_in_process();
        let err = adapter.rotate_dek("not-a-uuid", None).await.unwrap_err();
        assert!(matches!(err, Phase3PortError::Invalid(_)));
    }

    #[tokio::test]
    async fn explicit_target_version_drives_to_completion() {
        let adapter = build_in_process();
        let tenant_uuid = Uuid::now_v7();
        // First call auto-bumps to version 2 (initial DEK = v1).
        let v1 = adapter
            .rotate_dek(&tenant_uuid.to_string(), None)
            .await
            .unwrap();
        // Explicit next version (+1) advances further. The
        // orchestrator's `resolve_new_dek_plaintext` rotates the
        // manager once per call, so we cannot leap-frog versions in
        // one operation — that's a separate operator workflow.
        let v2 = adapter
            .rotate_dek(&tenant_uuid.to_string(), Some(v1.target_dek_version + 1))
            .await
            .unwrap();
        assert!(v2.target_dek_version > v1.target_dek_version);
    }
}
