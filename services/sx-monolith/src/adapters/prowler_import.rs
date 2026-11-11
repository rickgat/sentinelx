//! Prowler v4 native-JSON CSPM import adapter (P1-009).
//!
//! Bridges the HTTP layer to
//! [`sx_discovery::prowler_import::ImportProwlerUseCase`]. The adapter
//! owns:
//!
//! - the per-tenant [`TenantCloudRegistry`] (mutable so future admin
//!   endpoints can register / unregister cloud accounts at runtime);
//! - a single [`InMemoryMulticloudSink`] (Postgres swap-in lands in the
//!   migration follow-up);
//! - a [`RecordingAuditSink`] so the audit log is queryable in-process
//!   while the Postgres audit pipeline is being wired;
//! - a [`NullKevCatalog`] by default — the real catalogue is fed from
//!   `sx-intel-feeds` and plugs in via the same trait without any code
//!   changes here.
//!
//! The adapter is intentionally **stateful per process**: it implements
//! [`sx_api::port::ProwlerImportPort`] which the HTTP layer holds via
//! `Arc<dyn>`. Use-case construction is cheap (clones of `Arc`) so we
//! build a fresh `ImportProwlerUseCase` per call to avoid lock contention
//! on the shared registry.

use std::sync::Arc;

use async_trait::async_trait;
use sx_api::port::{ProwlerImportPort, ProwlerImportPortError};
use sx_api::view::prowler_import_view::ProwlerImportResponse;
use sx_discovery::prelude::{
    AuditSink, CheckIdRegistry, ImportProwlerInput, ImportProwlerUseCase, InMemoryMulticloudSink,
    KevCatalog, NullKevCatalog, ProwlerImportError, RecordingAuditSink, TenantCloudRegistry,
    TenantId,
};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use uuid::Uuid;

/// In-memory adapter wiring the Prowler-import use case into the HTTP
/// layer.
pub(crate) struct ProwlerImportAdapter {
    registry: CheckIdRegistry,
    tenant_registry: Arc<TenantCloudRegistry>,
    sink: Arc<InMemoryMulticloudSink>,
    audit: Arc<RecordingAuditSink>,
    kev: Arc<dyn KevCatalog>,
}

impl std::fmt::Debug for ProwlerImportAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProwlerImportAdapter")
            .field("registered_accounts", &self.tenant_registry.len())
            .field("findings_persisted", &self.sink.len())
            .field("audit_events", &self.audit.len())
            .finish_non_exhaustive()
    }
}

impl ProwlerImportAdapter {
    /// Build a fresh adapter with the default check-id registry and the
    /// null KEV catalogue. The tenant registry is empty — production
    /// wiring will seed it from the tenant configuration store.
    pub(crate) fn new() -> Self {
        Self {
            registry: CheckIdRegistry::with_defaults(),
            tenant_registry: Arc::new(TenantCloudRegistry::new()),
            sink: Arc::new(InMemoryMulticloudSink::new()),
            audit: Arc::new(RecordingAuditSink::new()),
            kev: Arc::new(NullKevCatalog),
        }
    }

    fn audit_sink(&self) -> Arc<dyn AuditSink> {
        // `RecordingAuditSink` is `Send + Sync + Debug` — fits the
        // trait-object contract directly.
        self.audit.clone()
    }

    fn now_rfc3339() -> String {
        OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .unwrap_or_else(|_| "1970-01-01T00:00:00Z".into())
    }

    fn parse_tenant(raw: &str) -> Result<TenantId, ProwlerImportPortError> {
        let uuid = uuid::Uuid::parse_str(raw)
            .map_err(|e| ProwlerImportPortError::Internal(format!("invalid tenant id: {e}")))?;
        Ok(TenantId::from_uuid(uuid))
    }

    fn map_err(err: ProwlerImportError) -> ProwlerImportPortError {
        match err {
            ProwlerImportError::TooLarge { actual, limit } => {
                ProwlerImportPortError::TooLarge { actual, limit }
            }
            ProwlerImportError::Malformed(m) => ProwlerImportPortError::Malformed(m),
            ProwlerImportError::CrossTenant { tenant, account } => {
                ProwlerImportPortError::CrossTenant(format!(
                    "tenant '{tenant}' is not registered for account '{account}'"
                ))
            }
            ProwlerImportError::Io(m) | ProwlerImportError::Sink(m) => {
                ProwlerImportPortError::Internal(m)
            }
        }
    }
}

#[async_trait]
impl ProwlerImportPort for ProwlerImportAdapter {
    async fn import(
        &self,
        tenant_id: &str,
        actor: &str,
        bytes: &[u8],
    ) -> Result<ProwlerImportResponse, ProwlerImportPortError> {
        let tenant = Self::parse_tenant(tenant_id)?;

        let uc = ImportProwlerUseCase::new(
            self.registry.clone(),
            self.tenant_registry.clone(),
            self.sink.clone(),
            self.audit_sink(),
            self.kev.clone(),
        );

        let upload_bytes = bytes.len() as u64;
        let before = self.audit.len();

        let out = uc
            .execute(ImportProwlerInput {
                tenant_id: tenant,
                actor: actor.to_owned(),
                bytes,
            })
            .await
            .map_err(Self::map_err)?;

        // Pull the audit row we just emitted to surface its sha-256 digest
        // on the wire. The recorder appends in order, so the last event
        // is ours.
        let events = self.audit.events();
        let upload_digest = events
            .get(before)
            .map(|e| e.upload_digest.clone())
            .unwrap_or_default();

        Ok(ProwlerImportResponse {
            id: Uuid::now_v7().to_string(),
            tenant_id: tenant_id.to_owned(),
            upload_digest,
            upload_bytes,
            parsed: out.parsed,
            written: out.written,
            rejected_cross_tenant: out.rejected_cross_tenant,
            deduplicated: out.deduplicated,
            kev_uplifts_applied: out.kev_uplifts_applied,
            unmapped_check_ids: out.unmapped_check_ids,
            accepted_at: Self::now_rfc3339(),
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const GCP_PAYLOAD: &[u8] = br#"[
        {
            "Status": "FAIL",
            "Provider": "gcp",
            "CheckID": "iam_sa_user_managed_keys",
            "Severity": "high",
            "ProjectId": "demo",
            "Region": "us-central1",
            "ResourceUID": "//iam.googleapis.com/projects/demo/serviceAccounts/sa@demo.iam.gserviceaccount.com"
        }
    ]"#;

    #[tokio::test]
    async fn import_emits_audit_and_returns_metrics() {
        let a = ProwlerImportAdapter::new();
        // Register the project under the importing tenant. We cheat by
        // grabbing a fresh TenantId, then registering it on a new
        // registry — easiest way to keep this an integration test.
        let tenant = TenantId::new();
        let mut tenants = TenantCloudRegistry::new();
        tenants.register(sx_discovery::prelude::CloudProvider::Gcp, "demo", tenant);
        let a2 = ProwlerImportAdapter {
            registry: CheckIdRegistry::with_defaults(),
            tenant_registry: Arc::new(tenants),
            sink: Arc::new(InMemoryMulticloudSink::new()),
            audit: Arc::new(RecordingAuditSink::new()),
            kev: Arc::new(NullKevCatalog),
        };

        let resp = a2
            .import(&tenant.to_string(), "user:alice", GCP_PAYLOAD)
            .await
            .unwrap();

        assert_eq!(resp.tenant_id, tenant.to_string());
        assert_eq!(resp.parsed, 1);
        assert_eq!(resp.written, 1);
        assert_eq!(resp.upload_bytes as usize, GCP_PAYLOAD.len());
        assert_eq!(resp.upload_digest.len(), 64);
        assert!(!resp.accepted_at.is_empty());

        // ensures the `_` arg used above silences the warning.
        let _ = a; // keep the constructor warm-tested
    }

    #[tokio::test]
    async fn cross_tenant_returns_forbidden_kind() {
        let importer = TenantId::new();
        let other = TenantId::new();
        let mut tenants = TenantCloudRegistry::new();
        tenants.register(sx_discovery::prelude::CloudProvider::Gcp, "demo", other);
        let a = ProwlerImportAdapter {
            registry: CheckIdRegistry::with_defaults(),
            tenant_registry: Arc::new(tenants),
            sink: Arc::new(InMemoryMulticloudSink::new()),
            audit: Arc::new(RecordingAuditSink::new()),
            kev: Arc::new(NullKevCatalog),
        };
        let err = a
            .import(&importer.to_string(), "user:bad", GCP_PAYLOAD)
            .await
            .unwrap_err();
        assert!(matches!(err, ProwlerImportPortError::CrossTenant(_)));
    }

    #[tokio::test]
    async fn malformed_payload_is_rejected() {
        let a = ProwlerImportAdapter::new();
        let t = TenantId::new();
        let err = a
            .import(&t.to_string(), "u", b"not json")
            .await
            .unwrap_err();
        assert!(matches!(err, ProwlerImportPortError::Malformed(_)));
    }

    #[tokio::test]
    async fn invalid_tenant_string_is_internal_error() {
        let a = ProwlerImportAdapter::new();
        let err = a.import("not-a-uuid", "u", b"[]").await.unwrap_err();
        assert!(matches!(err, ProwlerImportPortError::Internal(_)));
    }
}
