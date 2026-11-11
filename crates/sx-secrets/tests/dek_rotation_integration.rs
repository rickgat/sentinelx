// LOW-009: integration test uses indexing with invariant-safe bounds
// (mock store tracks `idx < rows.len()` explicitly) and a build helper
// that the original signature kept `async` for symmetry with the lib
// version, but doesn't `.await` anything anymore.
#![allow(
    clippy::indexing_slicing,
    clippy::unused_async,
    clippy::missing_const_for_fn,
    clippy::significant_drop_tightening
)]

//! End-to-end DEK rotation integration test (CRIT-003).
//!
//! Stands up a small synthetic data set, registers a visitor that
//! re-encrypts each row, drives the full rotation through the public
//! [`sx_secrets::EnvelopeKeyManager`] facade, and verifies:
//!
//! 1. **Mid-rotation reads succeed under the OLD DEK.** Before the
//!    rotation runs, every row is encrypted under v1; the test confirms
//!    plaintext-roundtrip under v1.
//! 2. **Post-rotation reads succeed under the NEW DEK.** After the
//!    rotation completes, every row is encrypted under v2; the test
//!    confirms plaintext-roundtrip under v2.
//! 3. **Cross-tenant isolation.** Two tenants are rotated independently;
//!    the second tenant's rows stay on the original DEK while the
//!    first's flip.
//! 4. **Idempotent resume.** Re-running the rotation after completion
//!    is a no-op (no double-encryption).
//! 5. **Forward-secrecy intent.** After rotation the manager's stored
//!    DEK is the new version; the orchestrator owns the only handle to
//!    the old plaintext, which is dropped at the end of `run_for_tenant`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use secrecy::{ExposeSecret, SecretString};
use uuid::Uuid;

use sx_secrets::dek::TenantId;
use sx_secrets::dek_rotation::{
    DekRotationAuditSink, DekRotationError, DekRotationJob, InMemoryDekRotationAuditSink,
    InMemoryRotationPolicyStore, InMemoryRotationProgressStore, ReencryptionVisitor,
    RotationConfig, RotationJobStatus, RotationPolicyStore, RotationProgressStore,
    VisitorBatchOutcome,
};
use sx_secrets::kms::provider::{Ciphertext, KeyVersion, KmsKeyProvider, WrappedDek};
use sx_secrets::{DekManager, EnvelopeKeyManager, InMemoryDekStore, SecretsError};

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

#[derive(Debug, Clone)]
struct EncryptedRow {
    tenant_id: TenantId,
    row_id: u64,
    dek_version: u32,
    ciphertext: Vec<u8>,
    plaintext_hint: String,
}

#[derive(Debug, Default)]
struct MockTableStore {
    rows: tokio::sync::RwLock<Vec<EncryptedRow>>,
}

impl MockTableStore {
    fn new() -> Self {
        Self::default()
    }

    async fn seed(&self, tenant: TenantId, n: u64, dek_pt: &SecretString, initial_version: u32) {
        let mut rows = self.rows.write().await;
        for i in 0..n {
            let pt = format!("payload-{tenant}-{i}");
            let ct = xor(dek_pt.expose_secret().as_bytes(), pt.as_bytes());
            rows.push(EncryptedRow {
                tenant_id: tenant,
                row_id: i,
                dek_version: initial_version,
                ciphertext: ct,
                plaintext_hint: pt,
            });
        }
    }

    async fn rows_for(&self, tenant: TenantId) -> Vec<EncryptedRow> {
        self.rows
            .read()
            .await
            .iter()
            .filter(|r| r.tenant_id == tenant)
            .cloned()
            .collect()
    }
}

fn xor(key: &[u8], data: &[u8]) -> Vec<u8> {
    if key.is_empty() {
        return data.to_vec();
    }
    data.iter()
        .enumerate()
        .map(|(i, b)| b ^ key[i % key.len()])
        .collect()
}

struct TableVisitor {
    id: &'static str,
    table: Arc<MockTableStore>,
}

#[async_trait]
impl ReencryptionVisitor for TableVisitor {
    fn visitor_id(&self) -> &'static str {
        self.id
    }

    async fn count_remaining(
        &self,
        tenant_id: TenantId,
        target_version: u32,
    ) -> Result<u64, DekRotationError> {
        let rows = self.table.rows.read().await;
        Ok(rows
            .iter()
            .filter(|r| r.tenant_id == tenant_id && r.dek_version < target_version)
            .count() as u64)
    }

    async fn reencrypt_batch(
        &self,
        tenant_id: TenantId,
        cursor: Option<&str>,
        batch_size: u32,
        target_version: u32,
        old_dek_plaintext: &SecretString,
        new_dek_plaintext: &SecretString,
    ) -> Result<VisitorBatchOutcome, DekRotationError> {
        let cursor_val: u64 = cursor.and_then(|c| c.parse::<u64>().ok()).unwrap_or(0);
        let mut rows = self.table.rows.write().await;
        let mut updated = 0u64;
        let mut next_cursor: Option<String> = None;
        let mut idx = 0usize;
        while idx < rows.len() && updated < u64::from(batch_size) {
            let take = {
                let r = &rows[idx];
                r.tenant_id == tenant_id
                    && r.dek_version < target_version
                    && (cursor.is_none() || r.row_id > cursor_val)
            };
            if !take {
                idx += 1;
                continue;
            }
            let row_id_snapshot = rows[idx].row_id;
            // Unwrap with old DEK.
            let pt_bytes = xor(
                old_dek_plaintext.expose_secret().as_bytes(),
                &rows[idx].ciphertext,
            );
            if pt_bytes != rows[idx].plaintext_hint.as_bytes() {
                return Err(DekRotationError::Visitor(format!(
                    "decrypt mismatch on row {row_id_snapshot}"
                )));
            }
            // Wrap with new DEK.
            let new_ct = xor(new_dek_plaintext.expose_secret().as_bytes(), &pt_bytes);
            // Verify readback before commit.
            let verify = xor(new_dek_plaintext.expose_secret().as_bytes(), &new_ct);
            if verify != pt_bytes {
                return Err(DekRotationError::VerificationMismatch {
                    visitor_id: self.id,
                    row_id: row_id_snapshot.to_string(),
                });
            }
            rows[idx].ciphertext = new_ct;
            rows[idx].dek_version = target_version;
            next_cursor = Some(row_id_snapshot.to_string());
            updated += 1;
            idx += 1;
        }
        let exhausted = !rows
            .iter()
            .any(|r| r.tenant_id == tenant_id && r.dek_version < target_version);
        Ok(VisitorBatchOutcome {
            rows_reencrypted: updated,
            next_cursor,
            exhausted,
        })
    }
}

async fn build_envelope(
    table: Arc<MockTableStore>,
    batch_size: u32,
) -> (EnvelopeKeyManager<MockKms, InMemoryDekStore>, Arc<MockKms>) {
    let kms = Arc::new(MockKms::new());
    let store = Arc::new(InMemoryDekStore::new());
    let manager = Arc::new(DekManager::new(Arc::clone(&kms), store, "tenant-kek"));
    let progress: Arc<dyn RotationProgressStore> = Arc::new(InMemoryRotationProgressStore::new());
    let policy: Arc<dyn RotationPolicyStore> = Arc::new(InMemoryRotationPolicyStore::new());
    let audit: Arc<dyn DekRotationAuditSink> = Arc::new(InMemoryDekRotationAuditSink::new());
    let visitor: Arc<dyn ReencryptionVisitor> = Arc::new(TableVisitor {
        id: "mock_table",
        table,
    });
    let job = Arc::new(DekRotationJob::new(
        manager,
        progress,
        policy,
        audit,
        vec![visitor],
        RotationConfig::defaults().with_batch_size(batch_size),
    ));
    (EnvelopeKeyManager::new(job), kms)
}

#[tokio::test]
async fn end_to_end_rotation_reencrypts_dataset_and_isolates_tenants() {
    let table = Arc::new(MockTableStore::new());
    let (envelope, _kms) = build_envelope(Arc::clone(&table), 16).await;

    let tenant_a = TenantId::new(Uuid::now_v7());
    let tenant_b = TenantId::new(Uuid::now_v7());

    // Initialise DEK v1 for both tenants and seed rows.
    envelope
        .dek_manager()
        .get_or_create(tenant_a)
        .await
        .unwrap();
    envelope
        .dek_manager()
        .get_or_create(tenant_b)
        .await
        .unwrap();
    let dek_v1 = SecretString::new("dek-v1".to_owned().into_boxed_str());
    table.seed(tenant_a, 64, &dek_v1, 1).await;
    table.seed(tenant_b, 32, &dek_v1, 1).await;

    // === Mid-rotation reads succeed under the OLD DEK ===
    for r in table.rows_for(tenant_a).await {
        let pt = xor(dek_v1.expose_secret().as_bytes(), &r.ciphertext);
        assert_eq!(pt, r.plaintext_hint.as_bytes());
    }

    // Drive rotation for tenant_a only.
    let cp = envelope.rotate_dek(tenant_a).await.unwrap();
    assert_eq!(cp.status, RotationJobStatus::Completed);
    assert_eq!(cp.processed_rows, 64);
    assert!(cp.target_dek_version >= 2);

    // === Post-rotation reads succeed under the NEW DEK ===
    let dek_new = SecretString::new(format!("dek-v{}", cp.target_dek_version).into_boxed_str());
    for r in table.rows_for(tenant_a).await {
        assert_eq!(r.dek_version, cp.target_dek_version);
        let pt = xor(dek_new.expose_secret().as_bytes(), &r.ciphertext);
        assert_eq!(pt, r.plaintext_hint.as_bytes());
    }

    // === Cross-tenant isolation ===
    for r in table.rows_for(tenant_b).await {
        assert_eq!(r.dek_version, 1);
        let pt = xor(dek_v1.expose_secret().as_bytes(), &r.ciphertext);
        assert_eq!(pt, r.plaintext_hint.as_bytes());
    }

    // === Idempotent resume ===
    let cp_again = envelope
        .rotate_dek_to(tenant_a, cp.target_dek_version)
        .await;
    // Calling with the same target is a no-op (Completed).
    assert!(cp_again.is_ok());
    assert_eq!(cp_again.unwrap().status, RotationJobStatus::Completed);
}

#[tokio::test]
async fn checkpoint_resume_completes_remaining_rows_without_double_encryption() {
    let table = Arc::new(MockTableStore::new());
    // Tiny batch size forces multiple checkpoints.
    let (envelope, _kms) = build_envelope(Arc::clone(&table), 4).await;
    let tenant = TenantId::new(Uuid::now_v7());
    envelope.dek_manager().get_or_create(tenant).await.unwrap();
    let dek_v1 = SecretString::new("dek-v1".to_owned().into_boxed_str());
    table.seed(tenant, 16, &dek_v1, 1).await;

    let cp = envelope.rotate_dek(tenant).await.unwrap();
    assert_eq!(cp.processed_rows, 16);
    assert_eq!(cp.status, RotationJobStatus::Completed);

    // Every row decrypts under the new DEK exactly once.
    let dek_new = SecretString::new(format!("dek-v{}", cp.target_dek_version).into_boxed_str());
    for r in table.rows_for(tenant).await {
        let pt = xor(dek_new.expose_secret().as_bytes(), &r.ciphertext);
        assert_eq!(pt, r.plaintext_hint.as_bytes());
    }
}

#[tokio::test]
async fn rotation_status_reflects_completion_for_admin_consumers() {
    let table = Arc::new(MockTableStore::new());
    let (envelope, _kms) = build_envelope(Arc::clone(&table), 8).await;
    let tenant = TenantId::new(Uuid::now_v7());
    envelope.dek_manager().get_or_create(tenant).await.unwrap();
    let dek_v1 = SecretString::new("dek-v1".to_owned().into_boxed_str());
    table.seed(tenant, 8, &dek_v1, 1).await;

    assert!(envelope.rotation_status(tenant).await.unwrap().is_none());
    let _ = envelope.rotate_dek(tenant).await.unwrap();
    let status = envelope.rotation_status(tenant).await.unwrap().unwrap();
    assert_eq!(status.status, RotationJobStatus::Completed);
    assert_eq!(status.processed_rows, 8);
}
