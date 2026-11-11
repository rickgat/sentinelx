//! Composition-root wiring for the P2-016 Falco runtime ingest service.
//!
//! The adapter constructs an in-memory tenant-key store on top of
//! [`sx_secrets::InMemoryProvider`] and, per PRG-04, a **durable** audit
//! sink ([`IngestionAuditChainSink`]) that forwards each
//! [`sx_runtime::IngestionAuditEvent`] into the hash-chained `sx-audit`
//! trail via [`RecordAuditEventUseCase`], so runtime-ingest batches join
//! the tenant-wide, tamper-evident audit log.
//!
//! The remaining follow-up is tenant-key storage: it still uses the
//! in-memory provider because no external [`sx_secrets::SecretsProvider`]
//! (Vault Transit, AWS/GCP/Azure KMS) is configured for runtime keys in
//! this deployment. When one is, it swaps in behind the same
//! [`TenantKeyStore`].
//!
//! The bootstrap path seeds a single tenant key for the
//! development-mode admin tenant so the webhook is testable out of the
//! box. The seed is gated on `settings.bootstrap.enabled` so production
//! deployments never auto-mint a key.

use std::str::FromStr;
use std::sync::Arc;

use async_trait::async_trait;
use secrecy::SecretString;
use serde_json::json;
use sx_api::port::{RuntimeFalcoOverridesPort, RuntimeOverridesPortError};
use sx_api::view::runtime_view::{
    DeleteFalcoOverrideRequest, DeleteFalcoOverrideResponse, FalcoOverrideListResponse,
    FalcoOverrideView, PutFalcoOverrideRequest,
};
use sx_audit::prelude::{Actor, ActorKind, AuditAction, NewAuditEvent, RecordAuditEventUseCase};
use sx_config::schema::bootstrap::BootstrapConfig;
use sx_core::value_object::ids::TenantId as CoreTenantId;
use sx_runtime::{
    FalcoIngestService, IngestionAuditEvent, IngestionAuditSink, MemOverrideStore, OverrideAction,
    OverrideAuditEvent, OverrideAuditSink, OverrideStore, RecordingOverrideAuditSink, RuntimeError,
    TenantKeyStore,
};
use sx_secrets::{InMemoryProvider, SecretsProvider};
use time::format_description::well_known::Rfc3339;

/// Bundle returned by [`build`].
#[derive(Clone)]
pub(crate) struct RuntimeBundle {
    /// The wired-up Falco ingestion service, ready to be inserted into
    /// [`sx_api::AppState`].
    pub service: Arc<FalcoIngestService>,
    /// Handle to the underlying key store, kept so the bootstrap path
    /// can seed a dev-mode key without re-wrapping the provider.
    pub key_store: TenantKeyStore,
    /// HIGH-006 — admin port wired against the same in-memory
    /// override store the ingestion service consults. Inserted into
    /// `AppState::runtime_falco_overrides` so the admin HTTP surface
    /// and the ingest path observe the same row set.
    pub overrides_port: Arc<dyn RuntimeFalcoOverridesPort>,
}

impl std::fmt::Debug for RuntimeBundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RuntimeBundle").finish_non_exhaustive()
    }
}

/// Build the runtime bundle. Wires the in-memory tenant-key secrets
/// provider (no external `SecretsProvider` is configured for runtime keys
/// in this deployment) and, per PRG-04, a durable ingestion audit sink that
/// forwards each batch into the hash-chained `sx-audit` trail.
/// HIGH-006 — the override store is an [`sx_runtime::MemOverrideStore`]
/// shared between the ingest service and the new admin port; the
/// override audit sink is a [`RecordingOverrideAuditSink`] which also
/// emits a `tracing::info!` line per row so operators have observability
/// before the Postgres-backed implementation lands.
pub(crate) fn build(audit_recorder: Arc<RecordAuditEventUseCase>) -> RuntimeBundle {
    let provider: Arc<dyn SecretsProvider> = Arc::new(InMemoryProvider::new());
    let key_store = TenantKeyStore::new(provider);
    // PRG-04: forward each ingest-batch audit event into the durable
    // hash-chained sx-audit trail instead of dropping it on a null sink.
    let audit: Arc<dyn IngestionAuditSink> = Arc::new(IngestionAuditChainSink {
        recorder: audit_recorder,
    });
    let override_store_arc: Arc<dyn OverrideStore> = Arc::new(MemOverrideStore::new());
    let override_audit_arc: Arc<dyn OverrideAuditSink> =
        Arc::new(RecordingOverrideAuditSink::new());
    let service = Arc::new(FalcoIngestService::with_overrides(
        key_store.clone(),
        audit,
        Arc::clone(&override_store_arc),
        Arc::clone(&override_audit_arc),
    ));
    let overrides_port: Arc<dyn RuntimeFalcoOverridesPort> =
        Arc::new(InMemoryFalcoOverridesAdapter {
            store: override_store_arc,
            audit: override_audit_arc,
        });
    RuntimeBundle {
        service,
        key_store,
        overrides_port,
    }
}

/// PRG-04 — durable ingestion audit sink.
///
/// Forwards every [`IngestionAuditEvent`] (one per Falco ingest batch) into
/// the hash-chained `sx-audit` trail via [`RecordAuditEventUseCase`], so
/// runtime-ingest batches join the tenant-wide, tamper-evident audit log
/// instead of being dropped by the previous no-op sink. A non-UUID tenant
/// id is logged and skipped (never panics); an append failure is logged and
/// swallowed so a transient audit-store hiccup never fails live ingestion.
struct IngestionAuditChainSink {
    recorder: Arc<RecordAuditEventUseCase>,
}

impl std::fmt::Debug for IngestionAuditChainSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IngestionAuditChainSink")
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl IngestionAuditSink for IngestionAuditChainSink {
    async fn record(&self, event: IngestionAuditEvent) -> Result<(), RuntimeError> {
        let Ok(tenant) = CoreTenantId::from_str(&event.tenant_id) else {
            tracing::warn!(
                target: "adapters.runtime.audit",
                tenant_id = %event.tenant_id,
                "skipping sx-audit append for runtime-ingest batch: tenant id is not a UUID",
            );
            return Ok(());
        };
        let outcome = serde_json::to_value(event.outcome).unwrap_or(serde_json::Value::Null);
        let evt = NewAuditEvent {
            tenant_id: tenant,
            actor: Actor {
                kind: ActorKind::System,
                id: "falco-ingest".to_owned(),
                ip: None,
                user_agent: None,
            },
            action: AuditAction::Custom {
                code: "runtime.falco.ingest".to_owned(),
            },
            resource_kind: "runtime_ingest".to_owned(),
            resource_id: "falco_batch".to_owned(),
            before: None,
            after: Some(json!({
                "alert_count": event.alert_count,
                "accepted": event.accepted,
                "rejected": event.rejected,
                "outcome": outcome,
                "reason": event.reason,
            })),
            request_id: String::new(),
            ts: Some(event.at),
        };
        if let Err(err) = self.recorder.record(evt).await {
            tracing::warn!(
                target: "adapters.runtime.audit",
                error = %err,
                "sx-audit append failed for runtime-ingest batch; batch still processed",
            );
        }
        Ok(())
    }
}

/// HIGH-006 admin-port adapter.
///
/// Forwards every list / upsert / delete call into the shared
/// [`OverrideStore`], records an [`OverrideAuditEvent`] for every
/// mutation, and emits a structured `tracing::info!` line on the
/// `adapters.runtime.overrides` target so operators have observability
/// even before the Postgres-backed `sx-audit` adapter is wired in.
#[derive(Clone)]
struct InMemoryFalcoOverridesAdapter {
    store: Arc<dyn OverrideStore>,
    audit: Arc<dyn OverrideAuditSink>,
}

impl std::fmt::Debug for InMemoryFalcoOverridesAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InMemoryFalcoOverridesAdapter")
            .finish_non_exhaustive()
    }
}

fn parse_action(s: &str) -> Result<OverrideAction, RuntimeOverridesPortError> {
    OverrideAction::parse(s)
        .ok_or_else(|| RuntimeOverridesPortError::Invalid(format!("unknown action: {s}")))
}

fn format_set_at(at: time::OffsetDateTime) -> String {
    at.format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned())
}

#[async_trait]
impl RuntimeFalcoOverridesPort for InMemoryFalcoOverridesAdapter {
    async fn list(
        &self,
        tenant_id: &str,
    ) -> Result<FalcoOverrideListResponse, RuntimeOverridesPortError> {
        let rows = self
            .store
            .list_for_tenant(tenant_id)
            .await
            .map_err(|e| RuntimeOverridesPortError::Dependency(e.to_string()))?;
        let rows = rows
            .into_iter()
            .map(|r| FalcoOverrideView {
                rule_name: r.rule_name,
                subkey: r.subkey,
                action: r.action.as_str().to_owned(),
                reason: r.reason,
                set_by: r.set_by,
                set_at: format_set_at(r.set_at),
            })
            .collect();
        Ok(FalcoOverrideListResponse { rows })
    }

    async fn upsert(
        &self,
        tenant_id: &str,
        actor: &str,
        req: PutFalcoOverrideRequest,
    ) -> Result<FalcoOverrideView, RuntimeOverridesPortError> {
        let action = parse_action(&req.action)?;
        let row = self
            .store
            .upsert(
                tenant_id,
                &req.rule_name,
                &req.subkey,
                action,
                &req.reason,
                actor,
            )
            .await
            .map_err(|e| RuntimeOverridesPortError::Dependency(e.to_string()))?;
        let audit_event = OverrideAuditEvent::mutation(
            tenant_id,
            &row.rule_name,
            &row.subkey,
            action,
            &row.reason,
            actor,
        );
        self.audit
            .record(audit_event)
            .await
            .map_err(|e| RuntimeOverridesPortError::Dependency(e.to_string()))?;
        tracing::info!(
            target: "adapters.runtime.overrides",
            tenant_id = %tenant_id,
            actor = %actor,
            rule_name = %row.rule_name,
            subkey = %row.subkey,
            action = %action.as_str(),
            "falco override upserted",
        );
        Ok(FalcoOverrideView {
            rule_name: row.rule_name,
            subkey: row.subkey,
            action: action.as_str().to_owned(),
            reason: row.reason,
            set_by: row.set_by,
            set_at: format_set_at(row.set_at),
        })
    }

    async fn delete(
        &self,
        tenant_id: &str,
        actor: &str,
        req: DeleteFalcoOverrideRequest,
    ) -> Result<DeleteFalcoOverrideResponse, RuntimeOverridesPortError> {
        let removed = self
            .store
            .delete(tenant_id, &req.rule_name, &req.subkey)
            .await
            .map_err(|e| RuntimeOverridesPortError::Dependency(e.to_string()))?;
        // Always record an audit event — including a no-op delete —
        // so an attacker cannot probe row existence by watching the
        // audit chain.
        let audit_event =
            OverrideAuditEvent::deletion(tenant_id, &req.rule_name, &req.subkey, actor);
        self.audit
            .record(audit_event)
            .await
            .map_err(|e| RuntimeOverridesPortError::Dependency(e.to_string()))?;
        tracing::info!(
            target: "adapters.runtime.overrides",
            tenant_id = %tenant_id,
            actor = %actor,
            rule_name = %req.rule_name,
            subkey = %req.subkey,
            removed,
            "falco override deletion processed",
        );
        Ok(DeleteFalcoOverrideResponse { removed })
    }
}

/// Seed a development-mode HMAC ingestion key for the bootstrap tenant
/// so the webhook is reachable out of the box. The seed is gated on
/// `bootstrap.enabled` upstream — this helper only writes when invoked.
///
/// Production deployments provision keys via the secrets backend
/// directly (`runtime/falco/{tenant_id}/webhook-key`); this seed is
/// strictly a developer-experience affordance.
pub(crate) async fn seed_dev_tenant_key(bundle: &RuntimeBundle, bootstrap: &BootstrapConfig) {
    let tenant_id = bootstrap.admin_tenant_id.map_or_else(
        || "01010101-0101-0101-0101-010101010101".to_owned(),
        |u| u.to_string(),
    );
    let key = SecretString::from("dev-runtime-webhook-key".to_owned());
    if let Err(err) = bundle.key_store.put_key(&tenant_id, key).await {
        tracing::warn!(
            target: "adapters.runtime",
            error = %err,
            tenant_id = %tenant_id,
            "runtime dev tenant key seed failed",
        );
        return;
    }
    tracing::info!(
        target: "adapters.runtime",
        tenant_id = %tenant_id,
        "seeded dev-mode runtime webhook key",
    );
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use sx_runtime::auth::sign_body_for_tests;

    /// An audit recorder over a fresh in-memory audit chain, for `build`.
    fn test_recorder() -> Arc<RecordAuditEventUseCase> {
        let sink = crate::adapters::audit_query::build(None).sink;
        Arc::new(RecordAuditEventUseCase::new(
            sink as Arc<dyn sx_audit::prelude::AuditSink>,
        ))
    }

    #[tokio::test]
    async fn bundle_round_trips_an_ingest_call() {
        let bundle = build(test_recorder());
        let tenant = "01010101-0101-0101-0101-010101010101";
        let key = "k";
        bundle
            .key_store
            .put_key(tenant, SecretString::from(key.to_owned()))
            .await
            .unwrap();
        let body = br#"{"rule":"r","priority":"Notice"}"#;
        let ts = 1_700_000_000;
        let sig = sign_body_for_tests(&SecretString::from(key.to_owned()), ts, body);
        let report = bundle
            .service
            .ingest(tenant, ts, Some(&sig), body, ts)
            .await
            .unwrap();
        assert_eq!(report.accepted, 1);
    }

    // ---------------------------------------------------------------
    // HIGH-006 admin port integration tests
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn admin_upsert_then_list_returns_the_row() {
        let bundle = build(test_recorder());
        let tenant = "t1";
        let actor = "00000000-0000-0000-0000-000000000001";
        let put = PutFalcoOverrideRequest {
            rule_name: "Terminal shell in container".into(),
            subkey: "execve".into(),
            action: "deny".into(),
            reason: "noisy".into(),
        };
        let row = bundle
            .overrides_port
            .upsert(tenant, actor, put)
            .await
            .unwrap();
        assert_eq!(row.action, "deny");
        assert_eq!(row.set_by, actor);

        let listed = bundle.overrides_port.list(tenant).await.unwrap();
        assert_eq!(listed.rows.len(), 1);
        assert_eq!(listed.rows[0].rule_name, "Terminal shell in container");
    }

    #[tokio::test]
    async fn admin_unknown_action_returns_invalid() {
        let bundle = build(test_recorder());
        let err = bundle
            .overrides_port
            .upsert(
                "t1",
                "u",
                PutFalcoOverrideRequest {
                    rule_name: "r".into(),
                    subkey: "s".into(),
                    action: "shrug".into(),
                    reason: "x".into(),
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(err, RuntimeOverridesPortError::Invalid(_)));
    }

    #[tokio::test]
    async fn admin_delete_is_idempotent_and_records_audit() {
        let bundle = build(test_recorder());
        let tenant = "t1";
        let actor = "u";
        bundle
            .overrides_port
            .upsert(
                tenant,
                actor,
                PutFalcoOverrideRequest {
                    rule_name: "r".into(),
                    subkey: "execve".into(),
                    action: "deny".into(),
                    reason: "x".into(),
                },
            )
            .await
            .unwrap();
        let first = bundle
            .overrides_port
            .delete(
                tenant,
                actor,
                DeleteFalcoOverrideRequest {
                    rule_name: "r".into(),
                    subkey: "execve".into(),
                },
            )
            .await
            .unwrap();
        assert!(first.removed);
        let second = bundle
            .overrides_port
            .delete(
                tenant,
                actor,
                DeleteFalcoOverrideRequest {
                    rule_name: "r".into(),
                    subkey: "execve".into(),
                },
            )
            .await
            .unwrap();
        assert!(!second.removed);
    }

    #[tokio::test]
    async fn ingest_consults_overrides_set_via_admin_port() {
        let bundle = build(test_recorder());
        let tenant = "01010101-0101-0101-0101-010101010101";
        let key = "k";
        bundle
            .key_store
            .put_key(tenant, SecretString::from(key.to_owned()))
            .await
            .unwrap();
        // Wire a Deny override for the rule.
        bundle
            .overrides_port
            .upsert(
                tenant,
                "u",
                PutFalcoOverrideRequest {
                    rule_name: "Terminal shell in container".into(),
                    subkey: "*".into(),
                    action: "deny".into(),
                    reason: "noisy".into(),
                },
            )
            .await
            .unwrap();

        let body = br#"{"rule":"Terminal shell in container","priority":"Warning","output":"x"}"#;
        let ts = 1_700_000_000;
        let sig = sign_body_for_tests(&SecretString::from(key.to_owned()), ts, body);
        let report = bundle
            .service
            .ingest(tenant, ts, Some(&sig), body, ts)
            .await
            .unwrap();

        assert_eq!(report.alert_count, 1);
        assert_eq!(report.accepted, 0);
        assert_eq!(report.suppressed, 1);
        assert!(report.findings.is_empty());
    }
}
