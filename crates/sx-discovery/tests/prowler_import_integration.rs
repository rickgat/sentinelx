//! Golden-fixture integration tests for the Prowler v4 import pipeline
//! (P1-009).
//!
//! Covers:
//!
//! - `golden_gcp_fixture_produces_expected_findings`
//! - `golden_azure_fixture_produces_expected_findings`
//! - `cross_tenant_rejection_blocks_import`
//! - `tenant_isolation_in_sink`
//! - `kev_uplift_applied_for_azure_storage_finding`

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation
)]

use std::sync::Arc;

use sx_discovery::prelude::*;

const GCP_FIXTURE: &[u8] = include_bytes!("fixtures/prowler_gcp.json");
const AZURE_FIXTURE: &[u8] = include_bytes!("fixtures/prowler_azure.json");

fn make_uc(
    tenant: TenantId,
    accounts: &[(CloudProvider, &str)],
    kev: Arc<dyn KevCatalog>,
) -> (
    ImportProwlerUseCase,
    Arc<InMemoryMulticloudSink>,
    Arc<RecordingAuditSink>,
) {
    let sink: Arc<InMemoryMulticloudSink> = Arc::new(InMemoryMulticloudSink::new());
    let audit: Arc<RecordingAuditSink> = Arc::new(RecordingAuditSink::new());
    let mut tenants = TenantCloudRegistry::new();
    for (provider, account) in accounts {
        tenants.register(*provider, *account, tenant);
    }
    let uc = ImportProwlerUseCase::new(
        CheckIdRegistry::with_defaults(),
        Arc::new(tenants),
        sink.clone(),
        audit.clone(),
        kev,
    );
    (uc, sink, audit)
}

#[tokio::test]
async fn golden_gcp_fixture_produces_expected_findings() {
    let tenant = TenantId::new();
    let (uc, sink, audit) = make_uc(
        tenant,
        &[(CloudProvider::Gcp, "sx-golden-gcp")],
        Arc::new(NullKevCatalog),
    );

    let out = uc
        .execute(ImportProwlerInput {
            tenant_id: tenant,
            actor: "user:gcp-import".into(),
            bytes: GCP_FIXTURE,
        })
        .await
        .unwrap();

    // The fixture has 3 FAIL+gcp rows (one is `unknown_check`), 1 PASS,
    // and 1 AWS row (skipped). All three FAIL+gcp rows should be parsed.
    assert_eq!(out.parsed, 3, "expected 3 FAIL gcp findings parsed");
    assert_eq!(out.rejected_cross_tenant, 0);
    assert_eq!(out.deduplicated, 0);
    assert_eq!(out.written, 3);
    assert_eq!(
        out.unmapped_check_ids, 1,
        "totally_unknown_check should fall through to the unmapped bucket",
    );

    let rows = sink.snapshot();
    assert_eq!(rows.len(), 3);

    // Check the canonical id mapping for the IAM finding.
    let iam = rows
        .iter()
        .find(|f| f.prowler_check_id == "iam_sa_user_managed_keys")
        .expect("iam finding present");
    assert_eq!(iam.check_id, "cspm.gcp.iam.sa_user_managed_keys");
    assert_eq!(iam.cloud_provider, CloudProvider::Gcp);
    assert_eq!(iam.account_id, "sx-golden-gcp");
    assert_eq!(iam.region.as_deref(), Some("us-central1"));
    assert!(iam
        .asset_id
        .starts_with("//iam.googleapis.com/projects/sx-golden-gcp/serviceAccounts/"));
    assert_eq!(iam.severity, Severity::High);
    assert_eq!(iam.original_severity, Severity::High);
    assert!(!iam.kev_uplifted);
    assert!(iam.compliance_refs.iter().any(|c| c.contains("CIS-2.0")));

    // Check that the unknown id falls through to the unmapped bucket.
    let unmapped = rows
        .iter()
        .find(|f| f.prowler_check_id == "totally_unknown_check")
        .expect("unknown check present");
    assert_eq!(unmapped.check_id, "cspm.gcp.unmapped.totally_unknown_check");

    // The firewall row should be critical.
    let fw = rows
        .iter()
        .find(|f| f.prowler_check_id == "compute_firewall_rule_open_to_internet")
        .expect("fw finding present");
    assert_eq!(fw.severity, Severity::Critical);

    // Audit event.
    assert_eq!(audit.events().len(), 1);
    let ev = &audit.events()[0];
    assert_eq!(ev.parsed_findings, 3);
    assert_eq!(ev.written_findings, 3);
    assert_eq!(ev.upload_bytes as usize, GCP_FIXTURE.len());
    assert_eq!(ev.upload_digest.len(), 64, "sha-256 hex is 64 chars");
}

#[tokio::test]
async fn golden_azure_fixture_produces_expected_findings() {
    let tenant = TenantId::new();
    let (uc, sink, _audit) = make_uc(
        tenant,
        &[(CloudProvider::Azure, "00000000-0000-0000-0000-000000000001")],
        Arc::new(NullKevCatalog),
    );

    let out = uc
        .execute(ImportProwlerInput {
            tenant_id: tenant,
            actor: "user:azure-import".into(),
            bytes: AZURE_FIXTURE,
        })
        .await
        .unwrap();

    // The fixture has 3 FAIL azure rows and 1 MUTED — only 3 are parsed.
    assert_eq!(out.parsed, 3);
    assert_eq!(out.written, 3);
    assert_eq!(out.rejected_cross_tenant, 0);

    let rows = sink.snapshot();
    let storage = rows
        .iter()
        .find(|f| f.prowler_check_id == "storage_blob_public_access_level_is_disabled")
        .expect("storage finding present");
    assert_eq!(
        storage.check_id,
        "cspm.azure.storage.blob_public_access_enabled"
    );
    assert_eq!(storage.severity, Severity::Critical);
    // ARN-equivalent canonical id should start with /subscriptions/.
    assert!(storage.asset_id.starts_with("/subscriptions/"));
    assert!(storage.asset_id.contains("storageAccounts/goldenstorage"));

    // Mixed-case keywords in the NSG row should be canonicalised.
    let nsg = rows
        .iter()
        .find(|f| f.prowler_check_id == "network_nsg_allow_internet_inbound_ssh")
        .expect("nsg finding present");
    assert!(
        nsg.asset_id.starts_with("/subscriptions/"),
        "leading lowercase keyword"
    );
    assert!(nsg.asset_id.contains("/resourceGroups/golden-rg/"));
    assert!(nsg.asset_id.contains("/providers/Microsoft.Network/"));
}

#[tokio::test]
async fn cross_tenant_rejection_blocks_import() {
    let importer = TenantId::new();
    let other = TenantId::new();

    // Owned by *other* — importer cannot upload findings against it.
    let sink: Arc<InMemoryMulticloudSink> = Arc::new(InMemoryMulticloudSink::new());
    let audit: Arc<RecordingAuditSink> = Arc::new(RecordingAuditSink::new());
    let mut tenants = TenantCloudRegistry::new();
    tenants.register(
        CloudProvider::Azure,
        "00000000-0000-0000-0000-000000000001",
        other,
    );
    let uc = ImportProwlerUseCase::new(
        CheckIdRegistry::with_defaults(),
        Arc::new(tenants),
        sink.clone(),
        audit.clone(),
        Arc::new(NullKevCatalog),
    );

    let err = uc
        .execute(ImportProwlerInput {
            tenant_id: importer,
            actor: "user:bad".into(),
            bytes: AZURE_FIXTURE,
        })
        .await
        .expect_err("cross-tenant must reject");
    assert!(
        matches!(err, ProwlerImportError::CrossTenant { .. }),
        "expected CrossTenant error, got {err:?}",
    );
    assert!(sink.is_empty(), "no findings should be persisted");
}

#[tokio::test]
async fn tenant_isolation_in_sink() {
    // Two tenants each import the GCP fixture but against *different*
    // project ids. The sink must keep them isolated.
    let t1 = TenantId::new();
    let t2 = TenantId::new();

    // Each tenant owns its own project id; we reuse the same fixture body
    // but rewrite the project id for t2 in-memory.
    let body_t1 = GCP_FIXTURE.to_vec();
    let body_t2 = String::from_utf8(GCP_FIXTURE.to_vec())
        .unwrap()
        .replace("sx-golden-gcp", "sx-golden-other")
        .into_bytes();

    let sink: Arc<InMemoryMulticloudSink> = Arc::new(InMemoryMulticloudSink::new());
    let audit: Arc<RecordingAuditSink> = Arc::new(RecordingAuditSink::new());
    let mut tenants = TenantCloudRegistry::new();
    tenants.register(CloudProvider::Gcp, "sx-golden-gcp", t1);
    tenants.register(CloudProvider::Gcp, "sx-golden-other", t2);
    let uc = ImportProwlerUseCase::new(
        CheckIdRegistry::with_defaults(),
        Arc::new(tenants),
        sink.clone(),
        audit.clone(),
        Arc::new(NullKevCatalog),
    );

    uc.execute(ImportProwlerInput {
        tenant_id: t1,
        actor: "alice".into(),
        bytes: &body_t1,
    })
    .await
    .unwrap();
    uc.execute(ImportProwlerInput {
        tenant_id: t2,
        actor: "bob".into(),
        bytes: &body_t2,
    })
    .await
    .unwrap();

    assert_eq!(sink.len(), 6, "3 + 3 distinct dedupe keys");
    assert_eq!(sink.snapshot_for_tenant(t1).len(), 3);
    assert_eq!(sink.snapshot_for_tenant(t2).len(), 3);
    assert!(sink
        .snapshot_for_tenant(t1)
        .iter()
        .all(|f| f.tenant_id == t1));
    assert!(sink
        .snapshot_for_tenant(t2)
        .iter()
        .all(|f| f.tenant_id == t2));
    assert_eq!(audit.len(), 2, "one audit row per import");
}

#[tokio::test]
async fn kev_uplift_applied_for_azure_storage_finding() {
    use sx_discovery::prowler_import::kev::InMemoryKevCatalog;

    let tenant = TenantId::new();
    let mut kev = InMemoryKevCatalog::new();
    kev.insert(
        CloudProvider::Azure,
        "cspm.azure.storage.blob_public_access_enabled",
    );

    let (uc, sink, _) = make_uc(
        tenant,
        &[(CloudProvider::Azure, "00000000-0000-0000-0000-000000000001")],
        Arc::new(kev),
    );

    let out = uc
        .execute(ImportProwlerInput {
            tenant_id: tenant,
            actor: "x".into(),
            bytes: AZURE_FIXTURE,
        })
        .await
        .unwrap();

    // The storage finding is already critical, so the *severity* doesn't
    // change but `kev_uplifted` must be set so the dashboard can highlight
    // it.
    let storage = sink
        .snapshot()
        .into_iter()
        .find(|f| f.check_id == "cspm.azure.storage.blob_public_access_enabled")
        .expect("storage row present");
    assert_eq!(storage.severity, Severity::Critical);
    assert!(storage.kev_uplifted, "kev flag must be set");
    // Already-critical doesn't increment the counter — it stays at zero.
    assert_eq!(out.kev_uplifts_applied, 0);
}
