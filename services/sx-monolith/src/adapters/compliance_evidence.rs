//! P1-004 — `ComplianceEvidencePort` adapter.
//!
//! Wires the `sx-compliance::p1_004::EvidenceCollectionService` (which
//! ties collectors, the WORM object store, the metadata repository,
//! and the audit sink together) into the `sx-api` HTTP-port shape.
//!
//! ## In-memory by default
//!
//! The MVP composition root binds the trait dependencies to the
//! reference in-memory implementations exposed by the compliance crate:
//!
//! * `InMemoryWormStore`        — mirrors S3 Object Lock no-overwrite
//!   semantics; the production wiring replaces this with an
//!   `aws-sdk-s3` adapter that sets the retention to Compliance mode
//!   for 7 years.
//! * `InMemoryEvidenceStore`    — Postgres-shaped repository; the
//!   migration `20270601000000__create_compliance_evidence.sql`
//!   defines the schema a future `PgEvidenceStore` will plug behind
//!   the same trait.
//! ## Collectors (PRG-01 — no fabricated passes)
//!
//! Every collector carries an explicit `determinable` + `source` in its
//! evidence payload and **never asserts a compliance pass it did not
//! actually verify**:
//!
//! * `AuditChainIntegrityCollector` — **real**. Runs the platform's own
//!   `sx_audit::VerifyChainUseCase` over the tenant's append-only chain
//!   (keyless SHA-256 hash + linkage + sequence verification) and reports
//!   the true `records_examined` / `verified` / `first_failing_seq`. Works
//!   in both the in-memory and Postgres audit deployments.
//! * Four `NotConfiguredCollector`s (MFA enrolment, AWS IAM password
//!   policy, Vault sealed-state, kill-switch recency) — emit
//!   `determinable = false`, `status = "not_configured"` with the concrete
//!   source each still needs. They are honest placeholders, not fake
//!   passes; see `docs/PRODUCTION_READINESS_GAPS.md` (PRG-01) for the
//!   per-collector real-sourcing follow-ups.
//! * `RecordingAudit`           — logs every event via `tracing`; the
//!   production binding forwards to `sx_audit::AppendOnlyChain`.
//!
//! The adapter's job is to translate the HTTP-side strings into
//! application-side types, parse the optional period bounds, and
//! collapse application errors into [`ComplianceEvidencePortError`].

use std::str::FromStr;
use std::sync::Arc;

use async_trait::async_trait;
use sx_api::port::{ComplianceEvidencePort, ComplianceEvidencePortError};
use sx_api::view::compliance_evidence_view::{
    BundleSummaryView, CollectEvidenceResponseView, DownloadBundleResponseView,
    ListBundlesResponseView,
};
use sx_audit::prelude::{AuditError as SxAuditError, AuditSink as SxAuditSink, VerifyChainUseCase};
use sx_compliance::collector::types::{Evidence, EvidenceContentType};
use sx_compliance::model::framework::Framework;
use sx_compliance::p1_004::collector::{EvidenceCollector as P1004Collector, P1004CollectError};
use sx_compliance::p1_004::control::{ids, ControlId};
use sx_compliance::p1_004::service::{
    AuditEntry, AuditSink, EvidenceCollectionService, ServiceError, TenantHmacKeyProvider,
};
use sx_compliance::p1_004::store::{EvidenceStore, InMemoryEvidenceStore, StoreError, TenantId};
use sx_compliance::p1_004::worm::{InMemoryWormStore, WormStore};
use sx_core::value_object::ids::TenantId as CoreTenantId;
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};
use tracing::info;
use uuid::Uuid;

/// Bundle returned by [`build`] — the trait object handed to
/// `AppState.compliance_evidence` plus the bare service for downstream
/// tests / observability hooks.
#[allow(dead_code)] // service handle retained for future wiring.
pub(crate) struct ComplianceEvidenceBundle {
    /// Trait object plugged into [`sx_api::AppState::compliance_evidence`].
    pub port: Arc<dyn ComplianceEvidencePort>,
    /// Direct handle to the application-layer service. Useful for the
    /// continuous-collection cron once it lands.
    pub service: Arc<EvidenceCollectionService>,
    /// Direct handle to the in-memory WORM store so the future
    /// pre-signed-URL adapter can be wired in without re-parsing the
    /// composition root.
    pub worm: Arc<InMemoryWormStore>,
}

/// Build the MVP composition: in-memory dependencies + five stub
/// collectors. The signing key is per-tenant via a deterministic
/// derivation that matches the in-memory test fixtures.
/// Build the P1-004 composition. `audit_sink` is the platform's shared
/// append-only audit chain (the same handle the rest of the monolith
/// appends to), used by the real audit-chain integrity collector.
#[allow(dead_code)] // wired in by `build_app_state`.
pub(crate) fn build(audit_sink: Arc<dyn SxAuditSink>) -> ComplianceEvidenceBundle {
    let store: Arc<dyn EvidenceStore> = Arc::new(InMemoryEvidenceStore::new());
    let worm = Arc::new(InMemoryWormStore::new());
    let audit: Arc<dyn AuditSink> = Arc::new(TracingAuditSink);
    let keys: Arc<dyn TenantHmacKeyProvider> = Arc::new(DerivedTenantKey);
    let service = Arc::new(EvidenceCollectionService::new(
        Arc::clone(&store),
        Arc::clone(&worm) as Arc<dyn WormStore>,
        keys,
        audit,
    ));
    info!(
        target = "adapters.compliance_evidence.built",
        "P1-004 bundle constructed"
    );
    let port: Arc<dyn ComplianceEvidencePort> = Arc::new(EvidenceAdapter {
        service: Arc::clone(&service),
        store,
        worm: Arc::clone(&worm) as Arc<dyn WormStore>,
        collectors: builtin_collectors(audit_sink),
    });
    ComplianceEvidenceBundle {
        port,
        service,
        worm,
    }
}

/// `EvidenceAdapter` is the trait-object façade plugged into
/// `AppState.compliance_evidence`.
struct EvidenceAdapter {
    service: Arc<EvidenceCollectionService>,
    store: Arc<dyn EvidenceStore>,
    worm: Arc<dyn WormStore>,
    collectors: Vec<Arc<dyn P1004Collector>>,
}

#[async_trait]
impl ComplianceEvidencePort for EvidenceAdapter {
    async fn collect(
        &self,
        tenant_id: &str,
        period_start: Option<&str>,
        period_end: Option<&str>,
    ) -> Result<CollectEvidenceResponseView, ComplianceEvidencePortError> {
        let tid = TenantId::new(tenant_id);
        let now = OffsetDateTime::now_utc();
        let end = match period_end {
            None => now,
            Some(s) => OffsetDateTime::parse(s, &Rfc3339)
                .map_err(|e| ComplianceEvidencePortError::Invalid(format!("period_end: {e}")))?,
        };
        let start = match period_start {
            None => end - Duration::days(7),
            Some(s) => OffsetDateTime::parse(s, &Rfc3339)
                .map_err(|e| ComplianceEvidencePortError::Invalid(format!("period_start: {e}")))?,
        };
        if end < start {
            return Err(ComplianceEvidencePortError::Invalid(
                "period_end must be >= period_start".to_owned(),
            ));
        }

        let outcome = self
            .service
            .collect_and_export(&tid, &self.collectors, now, start, end)
            .await
            .map_err(map_service_error)?;

        let files: u32 = u32::try_from(outcome.files).unwrap_or(u32::MAX);
        Ok(CollectEvidenceResponseView {
            run_id: outcome.run_id.to_string(),
            bundle_key: outcome.bundle_key,
            bundle_sha256: outcome.bundle_sha256,
            files,
        })
    }

    async fn list_bundles(
        &self,
        tenant_id: &str,
    ) -> Result<ListBundlesResponseView, ComplianceEvidencePortError> {
        let tid = TenantId::new(tenant_id);
        let rows = self
            .store
            .list_bundle_runs(&tid)
            .await
            .map_err(map_store_error)?;
        let mut bundles = Vec::with_capacity(rows.len());
        for row in rows {
            let bundle_key = row.bundle_key.unwrap_or_default();
            let bundle_sha256 = row.bundle_sha256.unwrap_or_default();
            let started_at = row
                .started_at
                .format(&Rfc3339)
                .map_err(|e| ComplianceEvidencePortError::Internal(e.to_string()))?;
            let finished_at = match row.finished_at {
                None => None,
                Some(ts) => Some(
                    ts.format(&Rfc3339)
                        .map_err(|e| ComplianceEvidencePortError::Internal(e.to_string()))?,
                ),
            };
            bundles.push(BundleSummaryView {
                run_id: row.id.to_string(),
                bundle_key,
                bundle_sha256,
                started_at,
                finished_at,
            });
        }
        Ok(ListBundlesResponseView { bundles })
    }

    async fn download_bundle(
        &self,
        tenant_id: &str,
        run_id: &str,
    ) -> Result<DownloadBundleResponseView, ComplianceEvidencePortError> {
        let tid = TenantId::new(tenant_id);
        let parsed = Uuid::from_str(run_id)
            .map_err(|e| ComplianceEvidencePortError::Invalid(format!("run_id: {e}")))?;
        let row = self
            .store
            .get_run(&tid, parsed)
            .await
            .map_err(map_store_error)?;
        let Some(bundle_key) = row.bundle_key else {
            return Err(ComplianceEvidencePortError::NotFound);
        };
        let bundle_sha256 = row.bundle_sha256.unwrap_or_default();
        // Defence in depth: verify the bundle is reachable in the WORM
        // store for the calling tenant — surfaces a `Forbidden` if a
        // different tenant somehow held the same `run_id`.
        let _present = self
            .worm
            .exists(&tid, &bundle_key)
            .await
            .map_err(|e| match e {
                sx_compliance::p1_004::worm::ObjectStoreError::Forbidden => {
                    ComplianceEvidencePortError::Forbidden
                }
                other => ComplianceEvidencePortError::Dependency(other.to_string()),
            })?;
        Ok(DownloadBundleResponseView {
            run_id: parsed.to_string(),
            bundle_key: bundle_key.clone(),
            bundle_sha256,
            // The MVP returns an internal-scheme key so callers can
            // distinguish it from a real S3 pre-signed URL. The
            // production adapter substitutes
            // `aws-sdk-s3::presigning::PresigningConfig`.
            presigned_url: format!("sentinelx://worm/{bundle_key}"),
            expires_in_seconds: 300,
        })
    }
}

// ---------------------------------------------------------------------------
// Error translation
// ---------------------------------------------------------------------------

fn map_service_error(err: ServiceError) -> ComplianceEvidencePortError {
    match err {
        ServiceError::Collector(P1004CollectError::Fetch(m)) => {
            ComplianceEvidencePortError::Dependency(m)
        }
        ServiceError::Collector(P1004CollectError::Encoding(m) | P1004CollectError::Invalid(m)) => {
            ComplianceEvidencePortError::Invalid(m)
        }
        ServiceError::ObjectStore(e) => ComplianceEvidencePortError::Dependency(e.to_string()),
        ServiceError::Store(e) => map_store_error(e),
        ServiceError::Bundle(e) => ComplianceEvidencePortError::Internal(e.to_string()),
        ServiceError::Audit(m) | ServiceError::Secrets(m) | ServiceError::Internal(m) => {
            ComplianceEvidencePortError::Internal(m)
        }
    }
}

fn map_store_error(err: StoreError) -> ComplianceEvidencePortError {
    match err {
        StoreError::NotFound => ComplianceEvidencePortError::NotFound,
        StoreError::Forbidden => ComplianceEvidencePortError::Forbidden,
        StoreError::Conflict(m) => ComplianceEvidencePortError::Invalid(m),
        StoreError::Backend(m) => ComplianceEvidencePortError::Dependency(m),
    }
}

// ---------------------------------------------------------------------------
// In-memory dependencies
// ---------------------------------------------------------------------------

/// Forwards every audit entry to `tracing` so the structured fields
/// land in the same place every other audit event in the monolith
/// does. The production wiring substitutes an `sx-audit::AppendOnlyChain`
/// sink.
#[derive(Debug, Default)]
struct TracingAuditSink;

#[async_trait]
impl AuditSink for TracingAuditSink {
    async fn record(&self, entry: &AuditEntry) -> Result<(), ServiceError> {
        info!(
            target = "compliance.evidence.audit",
            event = entry.event,
            tenant = entry.tenant_id.as_str(),
            run_id = %entry.run_id,
            bundle_key = entry.bundle_key.as_deref().unwrap_or(""),
            "compliance evidence audit event",
        );
        Ok(())
    }
}

/// Deterministic per-tenant signing key. Production replaces this with
/// the `sx-secrets` provider; the MVP uses a stable derivation so the
/// tenant scoping is exercised end-to-end.
#[derive(Debug, Default)]
struct DerivedTenantKey;

#[async_trait]
impl TenantHmacKeyProvider for DerivedTenantKey {
    async fn signing_key(&self, tenant_id: &TenantId) -> Result<Vec<u8>, ServiceError> {
        // 64-byte secret per tenant — sufficient for HMAC-SHA256.
        Ok(format!(
            "sx-compliance-evidence-mvp-hmac::{}::{}",
            tenant_id.as_str(),
            "v1"
        )
        .into_bytes())
    }
}

// ---------------------------------------------------------------------------
// Collectors (PRG-01) — real where a source exists in-process, otherwise
// an honest `not_configured` record. None ever fabricates a pass.
// ---------------------------------------------------------------------------

/// Evidence-payload schema version emitted by the collectors below.
const COLLECTOR_VERSION: &str = "1.0.0";

fn builtin_collectors(audit_sink: Arc<dyn SxAuditSink>) -> Vec<Arc<dyn P1004Collector>> {
    vec![
        // Real: verifies the tenant's append-only audit chain end-to-end.
        Arc::new(AuditChainIntegrityCollector {
            verifier: Arc::new(VerifyChainUseCase::new(audit_sink)),
        }),
        // Honest placeholders — determinable:false, never a fake pass.
        Arc::new(NotConfiguredCollector::mfa_enrollment()),
        Arc::new(NotConfiguredCollector::iam_password_policy()),
        Arc::new(NotConfiguredCollector::vault_sealed_state()),
        Arc::new(NotConfiguredCollector::kill_switch_recency()),
    ]
}

/// Builds an honest "evidence could not be collected" payload. It records
/// the control, the concrete source still required, and the reason — and
/// crucially sets `determinable: false` so a reviewer never mistakes it for
/// a verified compliance pass.
#[derive(Debug)]
struct NotConfiguredCollector {
    control: &'static str,
    framework: Framework,
    required_source: &'static str,
    reason: &'static str,
}

impl NotConfiguredCollector {
    fn mfa_enrollment() -> Self {
        Self {
            control: ids::MFA_ENROLLMENT_RATE,
            framework: Framework::Soc2,
            required_source: "durable MFA + IAM user store (per-tenant enrolment query)",
            reason: "MFA enrolment is tracked in a per-process in-memory store in this \
                     deployment; a durable MFA/IAM store is required for a tenant-wide \
                     enrolment-rate attestation",
        }
    }

    fn iam_password_policy() -> Self {
        Self {
            control: ids::AWS_IAM_PASSWORD_POLICY,
            framework: Framework::PciDss,
            required_source: "aws-sdk-iam GetAccountPasswordPolicy",
            reason: "no AWS IAM integration is configured in this deployment",
        }
    }

    fn vault_sealed_state() -> Self {
        Self {
            control: ids::VAULT_SEALED_STATE,
            framework: Framework::Soc2,
            required_source: "Vault sys/seal-status probe",
            reason: "no Vault integration is configured in this deployment",
        }
    }

    fn kill_switch_recency() -> Self {
        Self {
            control: ids::KILL_SWITCH_TESTED_RECENTLY,
            framework: Framework::Soc2,
            required_source: "persistent kill-switch test-history store",
            reason: "kill-switch test events are not persisted in this deployment; a \
                     durable kill_switch_events store is required to attest recency",
        }
    }
}

#[async_trait]
impl P1004Collector for NotConfiguredCollector {
    fn id(&self) -> ControlId {
        ControlId::new(self.control)
    }
    async fn collect(
        &self,
        tenant_id: &TenantId,
        now: OffsetDateTime,
    ) -> Result<Evidence, P1004CollectError> {
        let payload = serde_json::json!({
            "control_id": self.control,
            "tenant_id": tenant_id.as_str(),
            "determinable": false,
            "status": "not_configured",
            "required_source": self.required_source,
            "reason": self.reason,
            "collected_at": now.format(&Rfc3339).unwrap_or_default(),
        });
        let bytes =
            serde_json::to_vec(&payload).map_err(|e| P1004CollectError::Encoding(e.to_string()))?;
        Ok(Evidence::new(
            self.control,
            self.framework,
            now,
            EvidenceContentType::Json,
            bytes,
            COLLECTOR_VERSION,
        ))
    }
}

/// Real audit-chain integrity collector. Replays the tenant's append-only
/// chain through [`VerifyChainUseCase`] — the same keyless (SHA-256 hash +
/// linkage + sequence) verification the platform uses elsewhere — and
/// records the genuine outcome. An empty chain verifies vacuously
/// (`records_examined: 0`); a divergence reports the first failing seq.
struct AuditChainIntegrityCollector {
    verifier: Arc<VerifyChainUseCase>,
}

impl std::fmt::Debug for AuditChainIntegrityCollector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditChainIntegrityCollector")
            .finish_non_exhaustive()
    }
}

impl AuditChainIntegrityCollector {
    const SOURCE: &'static str =
        "sx_audit append-only chain (keyless SHA-256 hash + linkage + sequence verify)";
}

#[async_trait]
impl P1004Collector for AuditChainIntegrityCollector {
    fn id(&self) -> ControlId {
        ControlId::new(ids::AUDIT_CHAIN_INTEGRITY_VERIFY)
    }
    async fn collect(
        &self,
        tenant_id: &TenantId,
        now: OffsetDateTime,
    ) -> Result<Evidence, P1004CollectError> {
        let collected_at = now.format(&Rfc3339).unwrap_or_default();
        // The compliance tenant id is textual; the audit chain is keyed by
        // the core UUID tenant id. A non-UUID tenant cannot be mapped onto a
        // chain, so we emit an honest `determinable: false` rather than a
        // fabricated result.
        let payload = match Uuid::parse_str(tenant_id.as_str().trim()) {
            Err(e) => serde_json::json!({
                "control_id": ids::AUDIT_CHAIN_INTEGRITY_VERIFY,
                "tenant_id": tenant_id.as_str(),
                "determinable": false,
                "status": "not_determinable",
                "reason": format!("tenant id is not a UUID: {e}"),
                "collected_at": collected_at,
            }),
            Ok(uuid) => {
                let core_tid = CoreTenantId::from_uuid(uuid);
                match self.verifier.verify(core_tid, 1, u64::MAX).await {
                    Ok(report) => serde_json::json!({
                        "control_id": ids::AUDIT_CHAIN_INTEGRITY_VERIFY,
                        "tenant_id": tenant_id.as_str(),
                        "determinable": true,
                        "source": Self::SOURCE,
                        "outcome": {
                            "records_examined": report.entries_checked,
                            "verified": report.first_divergence_at.is_none(),
                            "first_failing_seq": report.first_divergence_at,
                        },
                        "collected_at": collected_at,
                    }),
                    Err(SxAuditError::SequenceGap { at_seq }) => serde_json::json!({
                        "control_id": ids::AUDIT_CHAIN_INTEGRITY_VERIFY,
                        "tenant_id": tenant_id.as_str(),
                        "determinable": true,
                        "source": Self::SOURCE,
                        "outcome": {
                            "verified": false,
                            "first_failing_seq": at_seq,
                            "divergence": "sequence_gap",
                        },
                        "collected_at": collected_at,
                    }),
                    Err(SxAuditError::ChainDivergence {
                        at_seq,
                        expected,
                        actual,
                    }) => serde_json::json!({
                        "control_id": ids::AUDIT_CHAIN_INTEGRITY_VERIFY,
                        "tenant_id": tenant_id.as_str(),
                        "determinable": true,
                        "source": Self::SOURCE,
                        "outcome": {
                            "verified": false,
                            "first_failing_seq": at_seq,
                            "divergence": "hash_mismatch",
                            "expected_hash": expected,
                            "actual_hash": actual,
                        },
                        "collected_at": collected_at,
                    }),
                    // A read/serialisation/internal error means we could not
                    // determine integrity — report that honestly, never a pass.
                    Err(e) => serde_json::json!({
                        "control_id": ids::AUDIT_CHAIN_INTEGRITY_VERIFY,
                        "tenant_id": tenant_id.as_str(),
                        "determinable": false,
                        "status": "not_determinable",
                        "source": Self::SOURCE,
                        "reason": format!("audit chain read failed: {e}"),
                        "collected_at": collected_at,
                    }),
                }
            }
        };
        let bytes =
            serde_json::to_vec(&payload).map_err(|e| P1004CollectError::Encoding(e.to_string()))?;
        Ok(Evidence::new(
            ids::AUDIT_CHAIN_INTEGRITY_VERIFY,
            Framework::Iso27001,
            now,
            EvidenceContentType::Json,
            bytes,
            COLLECTOR_VERSION,
        ))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::adapters::audit_query::InMemoryAuditBufferSink;
    use tracing::warn;

    /// A fresh, empty in-memory audit chain for the collector to verify.
    fn test_audit_sink() -> Arc<dyn SxAuditSink> {
        Arc::new(InMemoryAuditBufferSink::new())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn end_to_end_collect_round_trip() {
        let bundle = build(test_audit_sink());
        let out = bundle
            .port
            .collect("tenant-alpha", None, None)
            .await
            .unwrap();
        assert_eq!(out.files, 5);
        assert!(out.bundle_key.starts_with("tenant/tenant-alpha/bundles/"));

        let list = bundle.port.list_bundles("tenant-alpha").await.unwrap();
        assert_eq!(list.bundles.len(), 1);

        let dl = bundle
            .port
            .download_bundle("tenant-alpha", &out.run_id)
            .await
            .unwrap();
        assert_eq!(dl.bundle_sha256, out.bundle_sha256);
        assert!(dl.presigned_url.starts_with("sentinelx://worm/"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn invalid_run_id_in_download_is_unprocessable() {
        let bundle = build(test_audit_sink());
        let err = bundle
            .port
            .download_bundle("t", "not-a-uuid")
            .await
            .unwrap_err();
        assert!(matches!(err, ComplianceEvidencePortError::Invalid(_)));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cross_tenant_download_is_forbidden() {
        let bundle = build(test_audit_sink());
        let out = bundle.port.collect("tenant-a", None, None).await.unwrap();
        let err = bundle
            .port
            .download_bundle("tenant-b", &out.run_id)
            .await
            .unwrap_err();
        // Either Forbidden (cross-tenant) — the in-memory store returns
        // this explicitly for cross-tenant `get_run`.
        assert!(
            matches!(err, ComplianceEvidencePortError::Forbidden),
            "expected Forbidden, got {err:?}"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn period_end_before_period_start_is_invalid() {
        let bundle = build(test_audit_sink());
        let err = bundle
            .port
            .collect(
                "tenant-c",
                Some("2026-06-20T00:00:00Z"),
                Some("2026-06-10T00:00:00Z"),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, ComplianceEvidencePortError::Invalid(_)));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn audit_chain_collector_really_verifies_an_empty_chain() {
        // A UUID tenant with no audit entries verifies vacuously: the
        // collector must report a *real* determinable result (0 records,
        // verified), not a fabricated payload.
        let collector = AuditChainIntegrityCollector {
            verifier: Arc::new(VerifyChainUseCase::new(test_audit_sink())),
        };
        let tid = TenantId::new("11111111-1111-1111-1111-111111111111");
        let ev = collector
            .collect(&tid, OffsetDateTime::now_utc())
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&ev.payload).unwrap();
        assert_eq!(v["determinable"], serde_json::json!(true));
        assert_eq!(v["outcome"]["verified"], serde_json::json!(true));
        assert_eq!(v["outcome"]["records_examined"], serde_json::json!(0));
        assert_eq!(v["outcome"]["first_failing_seq"], serde_json::Value::Null);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn audit_chain_collector_is_honest_for_non_uuid_tenant() {
        let collector = AuditChainIntegrityCollector {
            verifier: Arc::new(VerifyChainUseCase::new(test_audit_sink())),
        };
        let tid = TenantId::new("tenant-alpha");
        let ev = collector
            .collect(&tid, OffsetDateTime::now_utc())
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&ev.payload).unwrap();
        // Never a fabricated pass: a non-UUID tenant is not determinable.
        assert_eq!(v["determinable"], serde_json::json!(false));
        assert!(v.get("outcome").is_none(), "must not assert an outcome");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn not_configured_collector_never_asserts_a_pass() {
        let collector = NotConfiguredCollector::vault_sealed_state();
        let tid = TenantId::new("11111111-1111-1111-1111-111111111111");
        let ev = collector
            .collect(&tid, OffsetDateTime::now_utc())
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&ev.payload).unwrap();
        assert_eq!(v["determinable"], serde_json::json!(false));
        assert_eq!(v["status"], serde_json::json!("not_configured"));
        // No "verified":true anywhere — this is the S1 guard.
        assert!(v.get("outcome").is_none());
    }

    #[test]
    fn warn_path_is_quiet() {
        // Make sure the unused `warn!` import does not regress to a
        // dead-code warning; the tests above don't exercise it.
        warn!("compliance evidence warn path smoke");
    }
}
