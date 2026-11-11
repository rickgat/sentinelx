//! SOAR adapter (P3-005) — wires `sx_soar::InMemorySoarService` behind
//! the [`sx_api::port::SoarPort`] HTTP trait.
//!
//! The composition root supplies:
//!
//! * an [`sx_soar::ActionRegistry`] populated with the three MVP
//!   downstream adapters (HTTP requester, remediation play runner,
//!   webhook emitter) + a no-op stub used in tests;
//! * an optional `sx_audit::RecordAuditEventUseCase` so workflow CRUD +
//!   run events flow into the platform-wide audit log.
//!
//! The adapter validates uuid path parameters before forwarding to the
//! service so the in-crate store never sees malformed input.

use std::str::FromStr;
use std::sync::Arc;

use async_trait::async_trait;
use sqlx::types::Json;
use sqlx::{PgPool, Row as _};
use sx_api::port::{SoarPort, SoarPortError};
use sx_api::view::soar_view::{
    CreateWorkflowRequest, WorkflowRunView, WorkflowSummaryView, WorkflowView,
};
use sx_audit::prelude::{
    Actor, ActorKind, AuditAction, AuditSink, NewAuditEvent, RecordAuditEventUseCase,
};
use sx_core::value_object::ids::TenantId;
use sx_soar::{
    Action, ActionExecutor, ActionRegistry, AuditHook, DagExecutor, InMemorySoarService, SoarError,
    SoarService, TriggerEvent, Workflow, WorkflowDraft, WorkflowRun,
};
use tracing::warn;
use uuid::Uuid;

/// SOAR audit `resource_kind` label persisted on every CRUD/run event.
const RESOURCE_KIND: &str = "soar_workflow";

/// Bundle of SOAR handles handed to the composition root.
#[derive(Clone)]
pub(crate) struct SoarBundle {
    /// HTTP-facing trait object installed onto [`sx_api::AppState`].
    pub soar: Arc<dyn SoarPort>,
}

/// Build the SOAR bundle.
///
/// `audit_recorder` is forwarded into the in-crate audit hook adapter so
/// every workflow CRUD + run event flows into the platform audit log.
pub(crate) fn build(
    audit_recorder: Option<Arc<RecordAuditEventUseCase>>,
    postgres: Option<(PgPool, u64)>,
) -> SoarBundle {
    let registry = Arc::new(default_registry());
    let audit: Option<Arc<dyn AuditHook>> =
        audit_recorder.map(|r| Arc::new(SoarAuditBridge { inner: r }) as Arc<dyn AuditHook>);
    // Workflows + runs are durable (Postgres) when the DB is enabled — so a
    // saved automation workflow and its run history survive a restart — else
    // in-memory (dev quick-start). The action registry / DAG executor is the
    // same either way.
    let svc: Arc<dyn SoarService> = match postgres {
        Some((pool, stmt_timeout_ms)) => Arc::new(PgSoarService::new(
            pool,
            stmt_timeout_ms,
            Arc::clone(&registry),
            audit,
        )),
        None => Arc::new(InMemorySoarService::new(registry, audit)),
    };
    let port: Arc<dyn SoarPort> = Arc::new(SoarAdapter { svc });
    SoarBundle { soar: port }
}

/// Build the default `ActionRegistry` wired to the three MVP downstream
/// adapters (HTTP, remediation play, webhook) plus the noop for tests +
/// dry-runs.
fn default_registry() -> ActionRegistry {
    ActionRegistry::new()
        .register("http_request", Arc::new(HttpRequestStub))
        .register("run_remediation_play", Arc::new(RemediationPlayStub))
        .register("emit_webhook", Arc::new(WebhookEmitStub))
        .register("noop", Arc::new(NoopStub))
}

// ---------------------------------------------------------------------------
// Durable Postgres-backed SOAR service (workflows + runs survive restart)
// ---------------------------------------------------------------------------

/// Postgres-backed [`SoarService`].
///
/// The composition root bound SOAR to the in-memory service, so every saved
/// automation workflow and its run history was lost on a monolith restart and
/// invisible across instances. This persists them.
///
/// The action registry / [`DagExecutor`] is static orchestration (not
/// data-loss), so it is reused verbatim — `run_workflow` loads the workflow
/// from Postgres, runs the DAG through the same executor, and persists the
/// resulting [`WorkflowRun`]. Each [`Workflow`]/[`WorkflowRun`] aggregate is
/// stored losslessly as JSONB keyed by `(tenant_id, id)`, with scalar
/// projections (`name`/`enabled`, `workflow_id`/`started_at`) for listing.
///
/// Both ids are bound explicitly and every query carries a `tenant_id`
/// predicate, so — like the other id-keyed stores in this program — the
/// tables are not under tenant RLS.
struct PgSoarService {
    pool: PgPool,
    stmt_timeout_ms: u64,
    executor: Arc<DagExecutor>,
    audit: Option<Arc<dyn AuditHook>>,
}

impl std::fmt::Debug for PgSoarService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PgSoarService").finish_non_exhaustive()
    }
}

impl PgSoarService {
    fn new(
        pool: PgPool,
        stmt_timeout_ms: u64,
        registry: Arc<ActionRegistry>,
        audit: Option<Arc<dyn AuditHook>>,
    ) -> Self {
        Self {
            pool,
            stmt_timeout_ms,
            executor: Arc::new(DagExecutor::new(registry)),
            audit,
        }
    }

    fn internal(e: impl std::fmt::Display) -> SoarError {
        SoarError::internal(format!("soar store: {e}"))
    }

    async fn begin(&self) -> Result<sqlx::Transaction<'_, sqlx::Postgres>, SoarError> {
        let mut tx = self.pool.begin().await.map_err(Self::internal)?;
        let bounded = self.stmt_timeout_ms.clamp(1, 60_000);
        sqlx::query(&format!("SET LOCAL statement_timeout = {bounded}"))
            .execute(&mut *tx)
            .await
            .map_err(Self::internal)?;
        Ok(tx)
    }

    async fn emit_audit(&self, tenant_id: Uuid, event: &str, detail: serde_json::Value) {
        if let Some(hook) = self.audit.as_ref() {
            hook.emit(tenant_id, event, detail).await;
        }
    }
}

#[async_trait]
impl SoarService for PgSoarService {
    async fn create_workflow(
        &self,
        tenant_id: Uuid,
        draft: WorkflowDraft,
    ) -> Result<Workflow, SoarError> {
        let id = Uuid::now_v7();
        let wf = draft.into_workflow(id, tenant_id)?;
        let mut tx = self.begin().await?;
        sqlx::query(
            "INSERT INTO soar_workflows \
                 (tenant_id, workflow_id, name, enabled, aggregate, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, now(), now())",
        )
        .bind(tenant_id)
        .bind(id)
        .bind(&wf.name)
        .bind(wf.enabled)
        .bind(Json(&wf))
        .execute(&mut *tx)
        .await
        .map_err(Self::internal)?;
        tx.commit().await.map_err(Self::internal)?;
        self.emit_audit(
            tenant_id,
            "workflow_created",
            serde_json::json!({ "workflow_id": id, "name": wf.name }),
        )
        .await;
        Ok(wf)
    }

    async fn get_workflow(
        &self,
        tenant_id: Uuid,
        workflow_id: Uuid,
    ) -> Result<Workflow, SoarError> {
        let mut tx = self.begin().await?;
        let row = sqlx::query(
            "SELECT aggregate FROM soar_workflows WHERE tenant_id = $1 AND workflow_id = $2",
        )
        .bind(tenant_id)
        .bind(workflow_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(Self::internal)?;
        tx.commit().await.map_err(Self::internal)?;
        let row = row.ok_or(SoarError::NotFound)?;
        row.try_get::<Json<Workflow>, _>("aggregate")
            .map(|j| j.0)
            .map_err(Self::internal)
    }

    async fn list_workflows(&self, tenant_id: Uuid) -> Result<Vec<Workflow>, SoarError> {
        let mut tx = self.begin().await?;
        let rows = sqlx::query("SELECT aggregate FROM soar_workflows WHERE tenant_id = $1")
            .bind(tenant_id)
            .fetch_all(&mut *tx)
            .await
            .map_err(Self::internal)?;
        tx.commit().await.map_err(Self::internal)?;
        rows.iter()
            .map(|r| {
                r.try_get::<Json<Workflow>, _>("aggregate")
                    .map(|j| j.0)
                    .map_err(Self::internal)
            })
            .collect()
    }

    async fn update_workflow(
        &self,
        tenant_id: Uuid,
        workflow_id: Uuid,
        draft: WorkflowDraft,
    ) -> Result<Workflow, SoarError> {
        let wf = draft.into_workflow(workflow_id, tenant_id)?;
        let mut tx = self.begin().await?;
        let res = sqlx::query(
            "UPDATE soar_workflows \
             SET name = $3, enabled = $4, aggregate = $5, updated_at = now() \
             WHERE tenant_id = $1 AND workflow_id = $2",
        )
        .bind(tenant_id)
        .bind(workflow_id)
        .bind(&wf.name)
        .bind(wf.enabled)
        .bind(Json(&wf))
        .execute(&mut *tx)
        .await
        .map_err(Self::internal)?;
        tx.commit().await.map_err(Self::internal)?;
        if res.rows_affected() == 0 {
            return Err(SoarError::NotFound);
        }
        self.emit_audit(
            tenant_id,
            "workflow_updated",
            serde_json::json!({ "workflow_id": workflow_id }),
        )
        .await;
        Ok(wf)
    }

    async fn delete_workflow(&self, tenant_id: Uuid, workflow_id: Uuid) -> Result<(), SoarError> {
        let mut tx = self.begin().await?;
        let res =
            sqlx::query("DELETE FROM soar_workflows WHERE tenant_id = $1 AND workflow_id = $2")
                .bind(tenant_id)
                .bind(workflow_id)
                .execute(&mut *tx)
                .await
                .map_err(Self::internal)?;
        tx.commit().await.map_err(Self::internal)?;
        if res.rows_affected() == 0 {
            return Err(SoarError::NotFound);
        }
        self.emit_audit(
            tenant_id,
            "workflow_deleted",
            serde_json::json!({ "workflow_id": workflow_id }),
        )
        .await;
        Ok(())
    }

    async fn run_workflow(
        &self,
        tenant_id: Uuid,
        workflow_id: Uuid,
        event: TriggerEvent,
    ) -> Result<WorkflowRun, SoarError> {
        // Load the durable workflow, then run the DAG through the shared
        // executor — execution is stateless orchestration, only the result
        // is persisted.
        let wf = self.get_workflow(tenant_id, workflow_id).await?;
        self.emit_audit(
            tenant_id,
            "run_started",
            serde_json::json!({ "workflow_id": workflow_id }),
        )
        .await;
        let run = self.executor.execute(&wf, &event).await?;
        let mut tx = self.begin().await?;
        sqlx::query(
            "INSERT INTO soar_runs \
                 (tenant_id, run_id, workflow_id, started_at, aggregate) \
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(tenant_id)
        .bind(run.id)
        .bind(workflow_id)
        .bind(&run.started_at)
        .bind(Json(&run))
        .execute(&mut *tx)
        .await
        .map_err(Self::internal)?;
        tx.commit().await.map_err(Self::internal)?;
        self.emit_audit(
            tenant_id,
            "run_completed",
            serde_json::json!({
                "workflow_id": workflow_id,
                "run_id": run.id,
                "status": run.status,
            }),
        )
        .await;
        Ok(run)
    }

    async fn get_run(&self, tenant_id: Uuid, run_id: Uuid) -> Result<WorkflowRun, SoarError> {
        let mut tx = self.begin().await?;
        let row =
            sqlx::query("SELECT aggregate FROM soar_runs WHERE tenant_id = $1 AND run_id = $2")
                .bind(tenant_id)
                .bind(run_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(Self::internal)?;
        tx.commit().await.map_err(Self::internal)?;
        let row = row.ok_or(SoarError::NotFound)?;
        row.try_get::<Json<WorkflowRun>, _>("aggregate")
            .map(|j| j.0)
            .map_err(Self::internal)
    }

    async fn list_runs(
        &self,
        tenant_id: Uuid,
        limit: usize,
    ) -> Result<Vec<WorkflowRun>, SoarError> {
        let capped = i64::try_from(limit).unwrap_or(i64::MAX).clamp(0, 1000);
        let mut tx = self.begin().await?;
        // `started_at` is an RFC-3339 string, which sorts lexicographically
        // in chronological order, so a text ORDER BY gives newest-first.
        let rows = sqlx::query(
            "SELECT aggregate FROM soar_runs WHERE tenant_id = $1 \
             ORDER BY started_at DESC LIMIT $2",
        )
        .bind(tenant_id)
        .bind(capped)
        .fetch_all(&mut *tx)
        .await
        .map_err(Self::internal)?;
        tx.commit().await.map_err(Self::internal)?;
        rows.iter()
            .map(|r| {
                r.try_get::<Json<WorkflowRun>, _>("aggregate")
                    .map(|j| j.0)
                    .map_err(Self::internal)
            })
            .collect()
    }
}

/// HTTP-facing adapter — projects in-process types onto wire DTOs.
pub(crate) struct SoarAdapter {
    svc: Arc<dyn SoarService>,
}

impl std::fmt::Debug for SoarAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SoarAdapter").finish_non_exhaustive()
    }
}

fn parse_uuid(label: &str, raw: &str) -> Result<Uuid, SoarPortError> {
    Uuid::parse_str(raw).map_err(|_| SoarPortError::Invalid(format!("invalid {label} uuid")))
}

fn parse_tenant(tenant_id: &str) -> Result<Uuid, SoarPortError> {
    Uuid::parse_str(tenant_id).map_err(|_| SoarPortError::Invalid("invalid tenant uuid".into()))
}

fn map_soar(err: SoarError) -> SoarPortError {
    match err {
        SoarError::NotFound => SoarPortError::NotFound,
        SoarError::InvalidDefinition(m) => SoarPortError::Invalid(m),
        SoarError::ActionFailed { node_id, reason } => {
            SoarPortError::Invalid(format!("action `{node_id}` failed: {reason}"))
        }
        SoarError::Storage(m) | SoarError::Internal(m) => SoarPortError::Internal(m),
    }
}

#[async_trait]
impl SoarPort for SoarAdapter {
    async fn create_workflow(
        &self,
        tenant_id: &str,
        req: CreateWorkflowRequest,
    ) -> Result<WorkflowView, SoarPortError> {
        let tenant = parse_tenant(tenant_id)?;
        let draft = WorkflowDraft {
            name: req.name,
            definition: req.definition,
            enabled: req.enabled,
        };
        let wf = self
            .svc
            .create_workflow(tenant, draft)
            .await
            .map_err(map_soar)?;
        Ok(wf.into())
    }

    async fn get_workflow(
        &self,
        tenant_id: &str,
        workflow_id: &str,
    ) -> Result<WorkflowView, SoarPortError> {
        let tenant = parse_tenant(tenant_id)?;
        let id = parse_uuid("workflow", workflow_id)?;
        let wf = self.svc.get_workflow(tenant, id).await.map_err(map_soar)?;
        Ok(wf.into())
    }

    async fn list_workflows(
        &self,
        tenant_id: &str,
        limit: u32,
    ) -> Result<Vec<WorkflowSummaryView>, SoarPortError> {
        let tenant = parse_tenant(tenant_id)?;
        let workflows = self.svc.list_workflows(tenant).await.map_err(map_soar)?;
        // The in-crate `Workflow` does not retain a per-row creation
        // timestamp today — stamp the wall clock at fetch time so the
        // wire shape stays stable until the persisted column lands.
        let now = time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned());
        Ok(workflows
            .iter()
            .take(limit as usize)
            .map(|w| WorkflowSummaryView::from_workflow(w, now.clone()))
            .collect())
    }

    async fn run_workflow(
        &self,
        tenant_id: &str,
        workflow_id: &str,
        event: TriggerEvent,
    ) -> Result<WorkflowRunView, SoarPortError> {
        let tenant = parse_tenant(tenant_id)?;
        let id = parse_uuid("workflow", workflow_id)?;
        let run = self
            .svc
            .run_workflow(tenant, id, event)
            .await
            .map_err(map_soar)?;
        Ok(run.into())
    }

    async fn get_run(
        &self,
        tenant_id: &str,
        run_id: &str,
    ) -> Result<WorkflowRunView, SoarPortError> {
        let tenant = parse_tenant(tenant_id)?;
        let id = parse_uuid("run", run_id)?;
        let run = self.svc.get_run(tenant, id).await.map_err(map_soar)?;
        Ok(run.into())
    }
}

/// `AuditHook` adapter bridging the SOAR engine's audit emissions into
/// the platform-wide `RecordAuditEventUseCase`.
struct SoarAuditBridge {
    inner: Arc<RecordAuditEventUseCase>,
}

#[async_trait]
impl AuditHook for SoarAuditBridge {
    async fn emit(&self, tenant_id: Uuid, event: &str, detail: serde_json::Value) {
        let tenant_str = tenant_id.to_string();
        let Ok(parsed_tenant) = TenantId::from_str(&tenant_str) else {
            warn!(
                target: "adapters.soar.audit",
                tenant_id = %tenant_id,
                "skipping audit append: malformed tenant id (not a UUID)",
            );
            return;
        };
        let resource_id = if let Some(s) = detail.get("workflow_id").and_then(|v| v.as_str()) {
            s.to_owned()
        } else if let Some(s) = detail.get("run_id").and_then(|v| v.as_str()) {
            s.to_owned()
        } else {
            "soar_workflow".to_owned()
        };
        let evt = NewAuditEvent {
            tenant_id: parsed_tenant,
            actor: Actor {
                kind: ActorKind::Service,
                id: "sx_soar".to_owned(),
                ip: None,
                user_agent: None,
            },
            action: AuditAction::Custom {
                code: event.to_owned(),
            },
            resource_kind: RESOURCE_KIND.to_owned(),
            resource_id,
            before: None,
            after: Some(detail),
            request_id: String::new(),
            ts: None,
        };
        if let Err(err) = self.inner.record(evt).await {
            warn!(
                target: "adapters.soar.audit",
                event = %event,
                error = %err,
                "soar audit append failed; in-crate state retains the run",
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Default action executor stubs.
//
// The MVP ships safe-by-default stubs so the SOAR engine fans out
// observable events to logs + the run-log; concrete production adapters
// (real HTTP requester, real sx-webhooks bridge, real remediation play
// runner) land behind these traits in follow-up commits.
// ---------------------------------------------------------------------------

struct HttpRequestStub;
#[async_trait]
impl ActionExecutor for HttpRequestStub {
    async fn execute(
        &self,
        action: &Action,
        _trigger_payload: &serde_json::Value,
    ) -> Result<serde_json::Value, SoarError> {
        match action {
            Action::HttpRequest { method, url, .. } => {
                tracing::info!(
                    target: "adapters.soar.http",
                    method = %method,
                    url = %url,
                    "soar http_request fired (stubbed)",
                );
                Ok(serde_json::json!({
                    "stubbed": true,
                    "method": method,
                    "url": url,
                }))
            }
            other => Err(SoarError::internal(format!(
                "http_request executor invoked with non-http action: {}",
                other.kind()
            ))),
        }
    }
}

struct RemediationPlayStub;
#[async_trait]
impl ActionExecutor for RemediationPlayStub {
    async fn execute(
        &self,
        action: &Action,
        _trigger_payload: &serde_json::Value,
    ) -> Result<serde_json::Value, SoarError> {
        match action {
            Action::RunRemediationPlay { play_id, params } => {
                tracing::info!(
                    target: "adapters.soar.remediation",
                    play_id = %play_id,
                    "soar run_remediation_play fired (stubbed)",
                );
                Ok(serde_json::json!({
                    "stubbed": true,
                    "play_id": play_id,
                    "params": params,
                }))
            }
            other => Err(SoarError::internal(format!(
                "run_remediation_play executor invoked with non-play action: {}",
                other.kind()
            ))),
        }
    }
}

struct WebhookEmitStub;
#[async_trait]
impl ActionExecutor for WebhookEmitStub {
    async fn execute(
        &self,
        action: &Action,
        trigger_payload: &serde_json::Value,
    ) -> Result<serde_json::Value, SoarError> {
        match action {
            Action::EmitWebhook { topic, payload } => {
                tracing::info!(
                    target: "adapters.soar.webhook",
                    topic = %topic,
                    "soar emit_webhook fired (stubbed)",
                );
                let body = payload.clone().unwrap_or_else(|| trigger_payload.clone());
                Ok(serde_json::json!({
                    "stubbed": true,
                    "topic": topic,
                    "payload_bytes": serde_json::to_string(&body).map(|s| s.len()).unwrap_or(0),
                }))
            }
            other => Err(SoarError::internal(format!(
                "emit_webhook executor invoked with non-webhook action: {}",
                other.kind()
            ))),
        }
    }
}

struct NoopStub;
#[async_trait]
impl ActionExecutor for NoopStub {
    async fn execute(
        &self,
        action: &Action,
        _trigger_payload: &serde_json::Value,
    ) -> Result<serde_json::Value, SoarError> {
        Ok(serde_json::json!({ "kind": action.kind() }))
    }
}

/// Test-only constructor used by the in-monolith integration tests so
/// they can inject a deterministic audit sink without re-implementing
/// the build helper.
#[allow(dead_code)] // referenced from integration tests
pub(crate) fn build_with_sink<S: AuditSink + 'static>(
    sink: Arc<S>,
) -> (Arc<dyn SoarPort>, Arc<RecordAuditEventUseCase>, Arc<S>) {
    let recorder_sink: Arc<dyn AuditSink> = Arc::clone(&sink) as Arc<dyn AuditSink>;
    let recorder = Arc::new(RecordAuditEventUseCase::new(recorder_sink));
    let bundle = build(Some(Arc::clone(&recorder)), None);
    (bundle.soar, recorder, sink)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use sx_soar::{Edge, Node, Severity, Trigger, TriggerEvent, WorkflowGraph};

    fn graph() -> WorkflowGraph {
        WorkflowGraph {
            nodes: vec![
                Node::Trigger {
                    id: "t".into(),
                    trigger: Trigger::FindingCreated {
                        min_severity: Severity::High,
                    },
                },
                Node::Action {
                    id: "http".into(),
                    action: Action::HttpRequest {
                        method: "POST".into(),
                        url: "https://example.com/incident".into(),
                        headers: HashMap::new(),
                        body: None,
                    },
                },
                Node::Action {
                    id: "hook".into(),
                    action: Action::EmitWebhook {
                        topic: "soar.demo".into(),
                        payload: None,
                    },
                },
            ],
            edges: vec![
                Edge {
                    from: "t".into(),
                    to: "http".into(),
                },
                Edge {
                    from: "http".into(),
                    to: "hook".into(),
                },
            ],
        }
    }

    #[tokio::test]
    async fn create_round_trips_through_adapter() {
        let bundle = build(None, None);
        let tenant = Uuid::new_v4().to_string();
        let req = CreateWorkflowRequest {
            name: "demo".into(),
            definition: graph(),
            enabled: true,
        };
        let view = bundle.soar.create_workflow(&tenant, req).await.unwrap();
        assert_eq!(view.tenant_id, tenant);
        let back = bundle.soar.get_workflow(&tenant, &view.id).await.unwrap();
        assert_eq!(back.id, view.id);
        assert_eq!(back.name, "demo");
    }

    #[tokio::test]
    async fn run_completes_for_matching_event() {
        let bundle = build(None, None);
        let tenant = Uuid::new_v4().to_string();
        let view = bundle
            .soar
            .create_workflow(
                &tenant,
                CreateWorkflowRequest {
                    name: "demo".into(),
                    definition: graph(),
                    enabled: true,
                },
            )
            .await
            .unwrap();
        let run = bundle
            .soar
            .run_workflow(
                &tenant,
                &view.id,
                TriggerEvent::FindingCreated {
                    finding_id: "F-1".into(),
                    severity: Severity::Critical,
                    payload: serde_json::Value::Null,
                },
            )
            .await
            .unwrap();
        assert_eq!(run.status, "ok");
        // Trigger frame + two action frames.
        assert_eq!(run.node_results.len(), 3);
    }

    #[tokio::test]
    async fn malformed_tenant_uuid_rejected() {
        let bundle = build(None, None);
        let err = bundle
            .soar
            .get_workflow("not-a-uuid", &Uuid::new_v4().to_string())
            .await
            .unwrap_err();
        assert!(matches!(err, SoarPortError::Invalid(_)));
    }

    #[tokio::test]
    async fn cycle_in_definition_rejected() {
        let bundle = build(None, None);
        let tenant = Uuid::new_v4().to_string();
        let mut g = graph();
        // Introduce a back-edge.
        g.edges.push(Edge {
            from: "hook".into(),
            to: "http".into(),
        });
        let err = bundle
            .soar
            .create_workflow(
                &tenant,
                CreateWorkflowRequest {
                    name: "demo".into(),
                    definition: g,
                    enabled: true,
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(err, SoarPortError::Invalid(_)));
    }

    /// Durability proof against a real Postgres: create a workflow → run it
    /// (DAG executed through the shared executor, run persisted) → *fresh
    /// service (restart-equivalent)* → the workflow and its run history
    /// survive → delete removes the workflow.
    ///
    /// Gated on `TEST_DATABASE_URL` (silent no-op in CI; workspace live-DB
    /// fixture convention). The SOAR tables have no tenant FK.
    #[tokio::test]
    async fn pg_soar_workflow_and_runs_survive_restart() {
        #[allow(clippy::disallowed_methods)]
        let Ok(url) = std::env::var("TEST_DATABASE_URL") else {
            return;
        };
        let tenant = Uuid::new_v4();
        let workflow_id;
        let run_id;
        {
            let pool = sqlx::PgPool::connect(&url).await.expect("connect");
            let svc = PgSoarService::new(pool, 15_000, Arc::new(default_registry()), None);
            let wf = svc
                .create_workflow(
                    tenant,
                    WorkflowDraft {
                        name: "live".into(),
                        definition: graph(),
                        enabled: true,
                    },
                )
                .await
                .expect("create");
            workflow_id = wf.id;
            assert_eq!(svc.list_workflows(tenant).await.unwrap().len(), 1);
            let run = svc
                .run_workflow(
                    tenant,
                    workflow_id,
                    TriggerEvent::FindingCreated {
                        finding_id: "F-1".into(),
                        severity: Severity::Critical,
                        payload: serde_json::json!({}),
                    },
                )
                .await
                .expect("run");
            run_id = run.id;
        }

        // Fresh service == a fresh process. In-memory state would be gone.
        {
            let pool = sqlx::PgPool::connect(&url).await.expect("reconnect");
            let svc = PgSoarService::new(pool, 15_000, Arc::new(default_registry()), None);
            let wf = svc
                .get_workflow(tenant, workflow_id)
                .await
                .expect("workflow survived restart");
            assert_eq!(wf.name, "live");
            let got_run = svc
                .get_run(tenant, run_id)
                .await
                .expect("run survived restart");
            assert_eq!(got_run.id, run_id);
            assert!(svc
                .list_runs(tenant, 10)
                .await
                .unwrap()
                .iter()
                .any(|r| r.id == run_id));
            svc.delete_workflow(tenant, workflow_id)
                .await
                .expect("delete");
            assert!(matches!(
                svc.get_workflow(tenant, workflow_id).await,
                Err(SoarError::NotFound)
            ));
        }
    }
}
