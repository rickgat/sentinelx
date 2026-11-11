//! P1-004 — Cross-tenant isolation regression suite.
//!
//! Two tenants drive a full collect-and-export round-trip against the
//! same `EvidenceCollectionService`, then the test asserts that neither
//! tenant can observe the other's run row, evidence file row, WORM
//! object body, or bundle bytes. The store, the WORM object store, and
//! the audit sink all forbid cross-tenant access at the trait level —
//! this test pins that contract end-to-end.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::sync::Arc;
use std::sync::Mutex;

use async_trait::async_trait;
use time::macros::datetime;
use time::OffsetDateTime;

use sx_compliance::collector::types::{Evidence, EvidenceContentType};
use sx_compliance::model::framework::Framework;
use sx_compliance::p1_004::collector::{EvidenceCollector, P1004CollectError};
use sx_compliance::p1_004::control::{ids, ControlId};
use sx_compliance::p1_004::service::{
    AuditEntry, AuditSink, EvidenceCollectionService, ServiceError, TenantHmacKeyProvider,
};
use sx_compliance::p1_004::store::{EvidenceStore, InMemoryEvidenceStore, StoreError, TenantId};
use sx_compliance::p1_004::worm::{InMemoryWormStore, ObjectStoreError, WormStore};

/// Audit sink that records every entry so tenant separation can be
/// asserted at the audit-trail level too.
#[derive(Debug, Default)]
struct RecordingAudit {
    entries: Mutex<Vec<AuditEntry>>,
}

#[async_trait]
impl AuditSink for RecordingAudit {
    async fn record(&self, entry: &AuditEntry) -> Result<(), ServiceError> {
        self.entries.lock().unwrap().push(entry.clone());
        Ok(())
    }
}

/// Deterministic per-tenant HMAC key — production wires this through
/// `sx-secrets`; the test does the same thing without the secret crate.
#[derive(Debug, Default)]
struct PerTenantKey;

#[async_trait]
impl TenantHmacKeyProvider for PerTenantKey {
    async fn signing_key(&self, tenant_id: &TenantId) -> Result<Vec<u8>, ServiceError> {
        Ok(format!("hmac-key-for-{}", tenant_id.as_str()).into_bytes())
    }
}

/// Lightweight collector that just emits a constant payload — exercises
/// the WORM path without needing the AWS / Vault / Postgres clients.
#[derive(Debug)]
struct ConstCollector {
    cid: &'static str,
    body: Vec<u8>,
}

#[async_trait]
impl EvidenceCollector for ConstCollector {
    fn id(&self) -> ControlId {
        ControlId::new(self.cid)
    }

    async fn collect(
        &self,
        _tenant_id: &TenantId,
        now: OffsetDateTime,
    ) -> Result<Evidence, P1004CollectError> {
        Ok(Evidence::new(
            self.cid,
            Framework::Soc2,
            now,
            EvidenceContentType::Json,
            self.body.clone(),
            "1.0.0",
        ))
    }
}

fn wire() -> (
    EvidenceCollectionService,
    Arc<InMemoryEvidenceStore>,
    Arc<InMemoryWormStore>,
    Arc<RecordingAudit>,
) {
    let store = Arc::new(InMemoryEvidenceStore::new());
    let worm = Arc::new(InMemoryWormStore::new());
    let audit = Arc::new(RecordingAudit::default());
    let svc = EvidenceCollectionService::new(
        store.clone(),
        worm.clone(),
        Arc::new(PerTenantKey),
        audit.clone(),
    );
    (svc, store, worm, audit)
}

#[tokio::test(flavor = "current_thread")]
async fn tenant_a_and_b_cannot_read_each_other_runs() {
    let (svc, store, worm, _audit) = wire();

    let tenant_a = TenantId::new("tenant-a");
    let tenant_b = TenantId::new("tenant-b");
    let collectors_a: Vec<Arc<dyn EvidenceCollector>> = vec![Arc::new(ConstCollector {
        cid: ids::MFA_ENROLLMENT_RATE,
        body: b"{\"tenant\":\"a\"}".to_vec(),
    })];
    let collectors_b: Vec<Arc<dyn EvidenceCollector>> = vec![Arc::new(ConstCollector {
        cid: ids::MFA_ENROLLMENT_RATE,
        body: b"{\"tenant\":\"b\"}".to_vec(),
    })];
    let now = datetime!(2026-06-12 00:00:00 UTC);

    let out_a = svc
        .collect_and_export(&tenant_a, &collectors_a, now, now, now)
        .await
        .unwrap();
    let out_b = svc
        .collect_and_export(&tenant_b, &collectors_b, now, now, now)
        .await
        .unwrap();

    // Distinct runs, distinct bundle keys.
    assert_ne!(out_a.run_id, out_b.run_id);
    assert_ne!(out_a.bundle_key, out_b.bundle_key);

    // `get_run` cross-tenant must be forbidden.
    let err = store
        .get_run(&tenant_b, out_a.run_id)
        .await
        .expect_err("cross-tenant get_run must fail");
    assert!(matches!(err, StoreError::Forbidden));

    // `list_files` cross-tenant must be forbidden too.
    let err = store
        .list_files(&tenant_a, out_b.run_id)
        .await
        .expect_err("cross-tenant list_files must fail");
    assert!(matches!(err, StoreError::Forbidden));

    // `list_bundle_runs` returns *only* the calling tenant's runs.
    let bundles_a = store.list_bundle_runs(&tenant_a).await.unwrap();
    assert_eq!(bundles_a.len(), 1);
    assert_eq!(bundles_a[0].id, out_a.run_id);
    let bundles_b = store.list_bundle_runs(&tenant_b).await.unwrap();
    assert_eq!(bundles_b.len(), 1);
    assert_eq!(bundles_b[0].id, out_b.run_id);

    // WORM cross-tenant access must be forbidden.
    let err = worm
        .get(&tenant_b, &out_a.bundle_key)
        .await
        .expect_err("cross-tenant worm get must fail");
    assert!(matches!(err, ObjectStoreError::Forbidden));
    let err = worm
        .get(&tenant_a, &out_b.bundle_key)
        .await
        .expect_err("cross-tenant worm get must fail");
    assert!(matches!(err, ObjectStoreError::Forbidden));

    // But the legitimate same-tenant read succeeds.
    let bytes_a = worm.get(&tenant_a, &out_a.bundle_key).await.unwrap();
    let bytes_b = worm.get(&tenant_b, &out_b.bundle_key).await.unwrap();
    assert!(!bytes_a.is_empty());
    assert!(!bytes_b.is_empty());
    // Different signing keys + different payloads -> different bytes.
    assert_ne!(bytes_a, bytes_b);
}

#[tokio::test(flavor = "current_thread")]
async fn worm_refuses_to_overwrite_existing_bundle_key() {
    // The service constructs a unique key per-run from the UUID, so a
    // legitimate re-collection produces a different key. We exercise the
    // WORM refusal directly to make the property unambiguous.
    let worm = InMemoryWormStore::new();
    let t = TenantId::new("tenant-a");
    worm.put_immutable(&t, "tenant/tenant-a/bundles/r1.zip", b"v1", 365)
        .await
        .unwrap();
    let err = worm
        .put_immutable(&t, "tenant/tenant-a/bundles/r1.zip", b"v2", 365)
        .await
        .expect_err("WORM must reject overwrites");
    assert!(matches!(err, ObjectStoreError::AlreadyExists(_)));

    // The original bytes survived the failed overwrite attempt.
    let got = worm
        .get(&t, "tenant/tenant-a/bundles/r1.zip")
        .await
        .unwrap();
    assert_eq!(got, b"v1");
}
