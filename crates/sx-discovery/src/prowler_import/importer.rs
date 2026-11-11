//! End-to-end Prowler-import use case.
//!
//! Combines the parser, check-id registry, resource normaliser, KEV uplift,
//! deduplicator, audit sink and a [`MulticloudFindingSink`] into a single
//! async use case that:
//!
//! 1. Verifies the payload is within the configured size budget.
//! 2. Hashes the payload (SHA-256) for the audit log.
//! 3. Parses every finding from the Prowler v4 JSON body.
//! 4. Rejects findings whose embedded account is not registered for the
//!    importing tenant (cross-tenant rejection).
//! 5. Maps Prowler check ids → `SentinelX` check ids.
//! 6. Builds ARN-equivalent resource ids.
//! 7. Applies KEV severity uplifts.
//! 8. Dedupes in-batch by `(tenant_id, asset_id, check_id)`.
//! 9. Writes findings to the sink in chunks (bounded by `write_chunk_size`)
//!    so a single oversized batch never blocks the runtime.
//! 10. Records exactly one audit event.
//!
//! The HTTP layer (`POST /v1/discovery/prowler/import`) is expected to call
//! `spawn` a background task wrapping [`ImportProwlerUseCase::execute`]
//! and return `202 Accepted` with a tracking id within the 5 s budget.
//! This crate intentionally does **not** depend on `axum` — the HTTP wiring
//! lives in `sx-api` / `sx-monolith`.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::contracts::TenantId;

use super::audit::{AuditSink, ProwlerImportAuditEvent};
use super::dedupe::{DedupeKey, Deduplicator};
use super::error::ProwlerImportError;
use super::kev::KevCatalog;
use super::model::{CloudProvider, MulticloudCspmFinding, ProwlerFinding};
use super::parser::parse_prowler_v4_json;
use super::registry::CheckIdRegistry;
use super::resource::build_resource_id;

/// Default upload size limit (100 MB, matching the spec).
pub const DEFAULT_MAX_UPLOAD_BYTES: u64 = 100 * 1024 * 1024;

/// Default chunk size when writing findings to the sink.
pub const DEFAULT_WRITE_CHUNK_SIZE: usize = 500;

// ---------------------------------------------------------------------------
// Tenant ↔ cloud-account registry
// ---------------------------------------------------------------------------

/// Maps cloud accounts (GCP project id / Azure subscription id) to the
/// tenants that own them.
///
/// Required by the cross-tenant rejection rule: a finding referencing
/// `ProjectId = foo-prod` from tenant `T1`'s upload is rejected if
/// `foo-prod` is registered to tenant `T2`.
#[derive(Debug, Default, Clone)]
pub struct TenantCloudRegistry {
    map: HashMap<(CloudProvider, String), TenantId>,
}

impl TenantCloudRegistry {
    /// New empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register `(provider, account)` to `tenant_id`.
    pub fn register(
        &mut self,
        provider: CloudProvider,
        account: impl Into<String>,
        tenant: TenantId,
    ) {
        self.map.insert((provider, account.into()), tenant);
    }

    /// Look up the tenant who owns `(provider, account)`.
    #[must_use]
    pub fn lookup(&self, provider: CloudProvider, account: &str) -> Option<TenantId> {
        self.map.get(&(provider, account.to_owned())).copied()
    }

    /// `true` iff `tenant` owns `(provider, account)`, or if the account is
    /// unregistered (in which case it's treated as belonging to the importing
    /// tenant — first writer wins).
    #[must_use]
    pub fn authorised(&self, tenant: TenantId, provider: CloudProvider, account: &str) -> bool {
        self.lookup(provider, account)
            .is_none_or(|owner| owner == tenant)
    }

    /// Total number of registered (provider, account) entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// `true` iff empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Sink trait
// ---------------------------------------------------------------------------

/// Async sink for multicloud CSPM findings.
///
/// Implementations are expected to upsert by
/// `(tenant_id, asset_id, check_id)` so cross-batch dedupe works
/// transparently. Production wiring will back this with the
/// `cspm_findings_multicloud` Postgres table.
#[async_trait::async_trait]
pub trait MulticloudFindingSink: Send + Sync + std::fmt::Debug {
    /// Write a batch of findings. The batch is bounded by the importer's
    /// configured `write_chunk_size`.
    async fn write_batch(
        &self,
        findings: &[MulticloudCspmFinding],
    ) -> Result<usize, ProwlerImportError>;
}

/// In-memory sink — convenient for unit tests and the default monolith
/// build. Writes are idempotent on `(tenant_id, asset_id, check_id)` so
/// re-uploads dedupe naturally.
#[derive(Debug, Default)]
pub struct InMemoryMulticloudSink {
    rows: Mutex<HashMap<DedupeKey, MulticloudCspmFinding>>,
}

impl InMemoryMulticloudSink {
    /// New empty sink.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot every persisted finding for inspection.
    #[must_use]
    pub fn snapshot(&self) -> Vec<MulticloudCspmFinding> {
        match self.rows.lock() {
            Ok(g) => g.values().cloned().collect(),
            Err(poisoned) => poisoned.into_inner().values().cloned().collect(),
        }
    }

    /// Number of distinct findings currently persisted.
    #[must_use]
    pub fn len(&self) -> usize {
        match self.rows.lock() {
            Ok(g) => g.len(),
            Err(poisoned) => poisoned.into_inner().len(),
        }
    }

    /// `true` iff empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Filter findings by tenant. Tenant isolation check helper.
    #[must_use]
    pub fn snapshot_for_tenant(&self, tenant: TenantId) -> Vec<MulticloudCspmFinding> {
        self.snapshot()
            .into_iter()
            .filter(|f| f.tenant_id == tenant)
            .collect()
    }
}

#[async_trait::async_trait]
impl MulticloudFindingSink for InMemoryMulticloudSink {
    async fn write_batch(
        &self,
        findings: &[MulticloudCspmFinding],
    ) -> Result<usize, ProwlerImportError> {
        let mut written = 0usize;
        let mut g = match self.rows.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        for f in findings {
            let key = DedupeKey::new(f.tenant_id, &f.asset_id, &f.check_id);
            // Upsert — replace on duplicate so the most recent severity wins.
            if g.insert(key, f.clone()).is_none() {
                written += 1;
            }
        }
        Ok(written)
    }
}

// ---------------------------------------------------------------------------
// Use case input / output
// ---------------------------------------------------------------------------

/// Input to [`ImportProwlerUseCase::execute`].
#[derive(Debug)]
pub struct ImportProwlerInput<'a> {
    /// Tenant performing the import.
    pub tenant_id: TenantId,
    /// Free-form actor identifier for the audit log.
    pub actor: String,
    /// Raw Prowler v4 JSON bytes.
    pub bytes: &'a [u8],
}

/// Output from [`ImportProwlerUseCase::execute`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportProwlerOutput {
    /// Findings parsed (post-filter, pre-dedupe).
    pub parsed: u32,
    /// Findings actually written to the sink.
    pub written: u32,
    /// Cross-tenant rejections.
    pub rejected_cross_tenant: u32,
    /// In-batch duplicates suppressed.
    pub deduplicated: u32,
    /// Number of KEV uplifts applied.
    pub kev_uplifts_applied: u32,
    /// Unmapped Prowler check ids encountered. Useful for content-team
    /// follow-up.
    pub unmapped_check_ids: u32,
}

// ---------------------------------------------------------------------------
// Use case
// ---------------------------------------------------------------------------

/// End-to-end Prowler import use case.
#[derive(Debug)]
pub struct ImportProwlerUseCase {
    registry: CheckIdRegistry,
    tenant_registry: Arc<TenantCloudRegistry>,
    sink: Arc<dyn MulticloudFindingSink>,
    audit: Arc<dyn AuditSink>,
    kev: Arc<dyn KevCatalog>,
    max_upload_bytes: u64,
    write_chunk_size: usize,
}

impl ImportProwlerUseCase {
    /// Build a new use case with sensible defaults
    /// (100 MB upload limit, 500-row write chunks).
    pub fn new(
        registry: CheckIdRegistry,
        tenant_registry: Arc<TenantCloudRegistry>,
        sink: Arc<dyn MulticloudFindingSink>,
        audit: Arc<dyn AuditSink>,
        kev: Arc<dyn KevCatalog>,
    ) -> Self {
        Self {
            registry,
            tenant_registry,
            sink,
            audit,
            kev,
            max_upload_bytes: DEFAULT_MAX_UPLOAD_BYTES,
            write_chunk_size: DEFAULT_WRITE_CHUNK_SIZE,
        }
    }

    /// Override the upload size limit (must be > 0).
    #[must_use]
    pub const fn with_max_upload_bytes(mut self, limit: u64) -> Self {
        if limit > 0 {
            self.max_upload_bytes = limit;
        }
        self
    }

    /// Override the write chunk size (clamped to >= 1).
    #[must_use]
    pub fn with_chunk_size(mut self, chunk: usize) -> Self {
        self.write_chunk_size = chunk.max(1);
        self
    }

    /// Execute the import.
    ///
    /// # Errors
    ///
    /// - [`ProwlerImportError::TooLarge`] when `bytes` exceeds the
    ///   configured upload limit.
    /// - [`ProwlerImportError::Malformed`] when the JSON cannot be parsed.
    /// - [`ProwlerImportError::CrossTenant`] when **every** parsed finding
    ///   targets accounts the importing tenant does not own. (Partial
    ///   cross-tenant violations are recorded in the output instead of
    ///   failing the whole import — see [`ImportProwlerOutput::rejected_cross_tenant`].)
    /// - [`ProwlerImportError::Sink`] when the sink rejects a batch write.
    pub async fn execute(
        &self,
        input: ImportProwlerInput<'_>,
    ) -> Result<ImportProwlerOutput, ProwlerImportError> {
        // 1. Size check.
        let len = input.bytes.len() as u64;
        if len > self.max_upload_bytes {
            return Err(ProwlerImportError::TooLarge {
                actual: len,
                limit: self.max_upload_bytes,
            });
        }

        // 2. Digest (SHA-256) for audit log.
        let upload_digest = sha256_hex(input.bytes);

        // 3. Parse.
        let parsed = parse_prowler_v4_json(input.bytes)?;
        let parsed_count = parsed.len();

        // 4-8. Transform.
        let now = OffsetDateTime::now_utc();
        let mut dedupe = Deduplicator::new();
        let mut to_write: Vec<MulticloudCspmFinding> = Vec::with_capacity(parsed_count);
        let mut rejected_cross_tenant: u32 = 0;
        let mut deduplicated: u32 = 0;
        let mut kev_uplifts_applied: u32 = 0;
        let mut unmapped_check_ids: u32 = 0;
        let mut rejected_accounts: HashSet<(CloudProvider, String)> = HashSet::new();

        for f in &parsed {
            // 4. Cross-tenant check.
            if !self
                .tenant_registry
                .authorised(input.tenant_id, f.provider, &f.account_id)
            {
                rejected_cross_tenant += 1;
                rejected_accounts.insert((f.provider, f.account_id.clone()));
                continue;
            }

            // 5. Build resource id.
            let Some(parts) = build_resource_id(f) else {
                continue;
            };

            // 6. Map check id.
            let mapped = self.registry.map(f.provider, &f.prowler_check_id);
            if mapped.is_unmapped {
                unmapped_check_ids += 1;
            }

            // 7. KEV uplift (applied unconditionally, but counter is only
            // bumped for rows that survive in-batch dedupe so the metric
            // matches the number of *persisted* uplifts).
            let mut severity = f.severity;
            let mut kev_uplifted = false;
            let mut kev_severity_changed = false;
            if self.kev.matches(f.provider, &mapped.check_id) {
                let uplifted = severity.uplift_one();
                kev_uplifted = true;
                if uplifted != severity {
                    severity = uplifted;
                    kev_severity_changed = true;
                }
            }

            // 8. Dedupe in-batch.
            let key = DedupeKey::new(input.tenant_id, &parts.canonical, &mapped.check_id);
            if !dedupe.admit(key) {
                deduplicated += 1;
                continue;
            }
            if kev_severity_changed {
                kev_uplifts_applied += 1;
            }

            to_write.push(build_finding(
                input.tenant_id,
                f,
                &mapped.check_id,
                &parts.canonical,
                severity,
                kev_uplifted,
                now,
            ));
        }

        // If every finding was a cross-tenant violation and there were any
        // findings at all, surface as a hard error so the caller can refuse
        // the upload.
        if parsed_count > 0 && rejected_cross_tenant as usize == parsed_count {
            if let Some((provider, account)) = rejected_accounts.into_iter().next() {
                return Err(ProwlerImportError::CrossTenant {
                    tenant: input.tenant_id.to_string(),
                    account: format!("{provider}:{account}"),
                });
            }
        }

        // 9. Chunked write.
        let mut written_total: u32 = 0;
        for chunk in to_write.chunks(self.write_chunk_size) {
            let n = self.sink.write_batch(chunk).await?;
            // Saturating-cast to u32 (chunk size is bounded).
            written_total = written_total.saturating_add(u32::try_from(n).unwrap_or(u32::MAX));
        }

        // 10. Audit.
        let event = ProwlerImportAuditEvent {
            id: Uuid::now_v7(),
            tenant_id: input.tenant_id,
            actor: input.actor,
            upload_digest,
            upload_bytes: len,
            parsed_findings: u32::try_from(parsed_count).unwrap_or(u32::MAX),
            written_findings: written_total,
            rejected_cross_tenant,
            deduplicated,
            kev_uplifts_applied,
            recorded_at: now,
        };
        self.audit.record(event);

        Ok(ImportProwlerOutput {
            parsed: u32::try_from(parsed_count).unwrap_or(u32::MAX),
            written: written_total,
            rejected_cross_tenant,
            deduplicated,
            kev_uplifts_applied,
            unmapped_check_ids,
        })
    }
}

#[allow(clippy::too_many_arguments)]
fn build_finding(
    tenant_id: TenantId,
    f: &ProwlerFinding,
    check_id: &str,
    canonical: &str,
    severity: super::model::Severity,
    kev_uplifted: bool,
    now: OffsetDateTime,
) -> MulticloudCspmFinding {
    MulticloudCspmFinding {
        id: Uuid::now_v7(),
        tenant_id,
        check_id: check_id.to_owned(),
        prowler_check_id: f.prowler_check_id.clone(),
        cloud_provider: f.provider,
        account_id: f.account_id.clone(),
        region: f.region.clone(),
        asset_id: canonical.to_owned(),
        resource_name: f.resource_name.clone(),
        resource_type: f.resource_type.clone(),
        severity,
        original_severity: f.severity,
        kev_uplifted,
        status_extended: f.status_extended.clone(),
        description: f.description.clone(),
        remediation: f.remediation.clone(),
        compliance_refs: f.compliance_refs.clone(),
        created_at: now,
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation
)]
mod tests {
    use super::*;
    use crate::prowler_import::audit::{NullAuditSink, RecordingAuditSink};
    use crate::prowler_import::kev::{InMemoryKevCatalog, NullKevCatalog};

    fn small_gcp_payload() -> &'static [u8] {
        br#"[
            {
                "Status": "FAIL",
                "Provider": "gcp",
                "CheckID": "iam_sa_user_managed_keys",
                "Severity": "high",
                "ProjectId": "demo",
                "Region": "us-central1",
                "ResourceUID": "//iam.googleapis.com/projects/demo/serviceAccounts/sa@demo.iam.gserviceaccount.com",
                "ResourceName": "sa",
                "ResourceType": "ServiceAccount"
            },
            {
                "Status": "FAIL",
                "Provider": "gcp",
                "CheckID": "iam_sa_user_managed_keys",
                "Severity": "high",
                "ProjectId": "demo",
                "ResourceUID": "//iam.googleapis.com/projects/demo/serviceAccounts/sa@demo.iam.gserviceaccount.com"
            }
        ]"#
    }

    fn build_uc(
        tenant: TenantId,
        register_demo: bool,
    ) -> (
        ImportProwlerUseCase,
        Arc<InMemoryMulticloudSink>,
        Arc<RecordingAuditSink>,
    ) {
        let sink = Arc::new(InMemoryMulticloudSink::new());
        let audit = Arc::new(RecordingAuditSink::new());
        let mut tenants = TenantCloudRegistry::new();
        if register_demo {
            tenants.register(CloudProvider::Gcp, "demo", tenant);
        }
        let uc = ImportProwlerUseCase::new(
            CheckIdRegistry::with_defaults(),
            Arc::new(tenants),
            sink.clone(),
            audit.clone(),
            Arc::new(NullKevCatalog),
        );
        (uc, sink, audit)
    }

    #[tokio::test]
    async fn happy_path_dedupes_within_batch() {
        let tenant = TenantId::new();
        let (uc, sink, audit) = build_uc(tenant, true);
        let out = uc
            .execute(ImportProwlerInput {
                tenant_id: tenant,
                actor: "user:test".into(),
                bytes: small_gcp_payload(),
            })
            .await
            .unwrap();
        assert_eq!(out.parsed, 2);
        assert_eq!(out.written, 1, "in-batch dedupe collapses identical key");
        assert_eq!(out.deduplicated, 1);
        assert_eq!(out.rejected_cross_tenant, 0);
        assert_eq!(sink.len(), 1);
        assert_eq!(audit.len(), 1);
    }

    #[tokio::test]
    async fn upload_size_limit_enforced() {
        let tenant = TenantId::new();
        let (uc, _, _) = build_uc(tenant, true);
        let uc = uc.with_max_upload_bytes(8);
        let err = uc
            .execute(ImportProwlerInput {
                tenant_id: tenant,
                actor: "x".into(),
                bytes: small_gcp_payload(),
            })
            .await
            .unwrap_err();
        assert!(matches!(err, ProwlerImportError::TooLarge { .. }));
    }

    #[tokio::test]
    async fn cross_tenant_rejection_when_account_owned_by_other() {
        let importer = TenantId::new();
        let other = TenantId::new();
        let sink = Arc::new(InMemoryMulticloudSink::new());
        let audit: Arc<dyn AuditSink> = Arc::new(NullAuditSink);
        let mut tenants = TenantCloudRegistry::new();
        tenants.register(CloudProvider::Gcp, "demo", other); // owned by *other*
        let uc = ImportProwlerUseCase::new(
            CheckIdRegistry::with_defaults(),
            Arc::new(tenants),
            sink.clone(),
            audit,
            Arc::new(NullKevCatalog),
        );
        let err = uc
            .execute(ImportProwlerInput {
                tenant_id: importer,
                actor: "attacker".into(),
                bytes: small_gcp_payload(),
            })
            .await
            .unwrap_err();
        assert!(
            matches!(err, ProwlerImportError::CrossTenant { .. }),
            "expected hard cross-tenant error, got {err:?}"
        );
        assert!(sink.is_empty(), "no findings should be written");
    }

    #[tokio::test]
    async fn malformed_json_rejected() {
        let tenant = TenantId::new();
        let (uc, _, _) = build_uc(tenant, true);
        let err = uc
            .execute(ImportProwlerInput {
                tenant_id: tenant,
                actor: "x".into(),
                bytes: b"not valid",
            })
            .await
            .unwrap_err();
        assert!(matches!(err, ProwlerImportError::Malformed(_)));
    }

    #[tokio::test]
    async fn kev_uplift_bumps_severity() {
        let tenant = TenantId::new();
        let sink = Arc::new(InMemoryMulticloudSink::new());
        let audit = Arc::new(RecordingAuditSink::new());
        let mut tenants = TenantCloudRegistry::new();
        tenants.register(CloudProvider::Gcp, "demo", tenant);
        let mut kev = InMemoryKevCatalog::new();
        kev.insert(CloudProvider::Gcp, "cspm.gcp.iam.sa_user_managed_keys");
        let uc = ImportProwlerUseCase::new(
            CheckIdRegistry::with_defaults(),
            Arc::new(tenants),
            sink.clone(),
            audit.clone(),
            Arc::new(kev),
        );
        let out = uc
            .execute(ImportProwlerInput {
                tenant_id: tenant,
                actor: "x".into(),
                bytes: small_gcp_payload(),
            })
            .await
            .unwrap();
        assert_eq!(out.kev_uplifts_applied, 1, "one unique row, one uplift");
        let row = &sink.snapshot()[0];
        // high -> critical
        assert_eq!(row.severity, super::super::model::Severity::Critical);
        assert_eq!(row.original_severity, super::super::model::Severity::High);
        assert!(row.kev_uplifted);
    }

    #[tokio::test]
    async fn audit_event_emitted_with_metrics() {
        let tenant = TenantId::new();
        let (uc, _sink, audit) = build_uc(tenant, true);
        uc.execute(ImportProwlerInput {
            tenant_id: tenant,
            actor: "alice".into(),
            bytes: small_gcp_payload(),
        })
        .await
        .unwrap();
        let events = audit.events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].tenant_id, tenant);
        assert_eq!(events[0].actor, "alice");
        assert_eq!(events[0].parsed_findings, 2);
        assert_eq!(events[0].written_findings, 1);
        assert_eq!(events[0].deduplicated, 1);
        assert_eq!(events[0].upload_bytes as usize, small_gcp_payload().len());
        assert!(!events[0].upload_digest.is_empty());
    }

    #[tokio::test]
    async fn empty_array_succeeds_without_audit_skip() {
        let tenant = TenantId::new();
        let (uc, sink, audit) = build_uc(tenant, true);
        let out = uc
            .execute(ImportProwlerInput {
                tenant_id: tenant,
                actor: "x".into(),
                bytes: b"[]",
            })
            .await
            .unwrap();
        assert_eq!(out.parsed, 0);
        assert_eq!(out.written, 0);
        assert!(sink.is_empty());
        // We still emit one audit row so operators can see "you uploaded
        // a file with no findings".
        assert_eq!(audit.len(), 1);
    }
}
