//! `SoarService` — the multi-tenant facade the HTTP layer talks to.
//!
//! The trait bundles CRUD on [`Workflow`] (`POST /v1/soar/workflows`,
//! `GET /v1/soar/workflows/{id}`), the execution entrypoint
//! (`POST /v1/soar/workflows/{id}/run`), and the per-run log fetch
//! (`GET /v1/soar/runs/{id}`). Every operation takes the caller's tenant
//! id explicitly so the adapter never has to guess.
//!
//! ## MVP storage
//!
//! [`InMemorySoarService`] keeps workflows + runs in a single `Mutex`
//! keyed by `(tenant_id, id)`. Concrete Postgres-backed adapters land in
//! `services/sx-monolith`; the trait is the only thing the HTTP layer
//! ever sees so swapping storage is transparent.
//!
//! ## Audit
//!
//! The service emits a stable audit-line via the optional [`AuditHook`]
//! on workflow create / update / delete and on every terminal run. The
//! composition root wires this into `sx_audit::RecordAuditEventUseCase`;
//! the trait stays decoupled so the in-crate tests can record calls
//! without depending on the whole audit stack.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use uuid::Uuid;

use crate::action::ActionRegistry;
use crate::error::SoarError;
use crate::executor::{DagExecutor, WorkflowRun};
use crate::graph::WorkflowGraph;
use crate::trigger::TriggerEvent;
use crate::workflow::Workflow;

/// Audit hook the service calls on every workflow mutation and every
/// terminal run.
#[async_trait]
pub trait AuditHook: Send + Sync {
    /// Record `event` for `tenant_id`. `event` is one of:
    ///
    /// * `"workflow_created"`
    /// * `"workflow_updated"`
    /// * `"workflow_deleted"`
    /// * `"run_started"`
    /// * `"run_completed"`
    ///
    /// Implementations MUST be infallible from the caller's perspective.
    async fn emit(&self, tenant_id: Uuid, event: &str, detail: serde_json::Value);
}

/// Workflow CRUD + run dispatch facade.
#[async_trait]
pub trait SoarService: Send + Sync {
    /// Persist a new workflow for `tenant_id`.
    async fn create_workflow(
        &self,
        tenant_id: Uuid,
        draft: WorkflowDraft,
    ) -> Result<Workflow, SoarError>;

    /// Fetch a workflow scoped to `tenant_id`. Returns
    /// [`SoarError::NotFound`] when the uuid does not exist for the
    /// tenant.
    async fn get_workflow(&self, tenant_id: Uuid, workflow_id: Uuid)
        -> Result<Workflow, SoarError>;

    /// List every workflow for `tenant_id`.
    async fn list_workflows(&self, tenant_id: Uuid) -> Result<Vec<Workflow>, SoarError>;

    /// Replace an existing workflow's mutable fields.
    async fn update_workflow(
        &self,
        tenant_id: Uuid,
        workflow_id: Uuid,
        draft: WorkflowDraft,
    ) -> Result<Workflow, SoarError>;

    /// Delete a workflow.
    async fn delete_workflow(&self, tenant_id: Uuid, workflow_id: Uuid) -> Result<(), SoarError>;

    /// Execute `workflow_id` against `event` and return the run log row.
    async fn run_workflow(
        &self,
        tenant_id: Uuid,
        workflow_id: Uuid,
        event: TriggerEvent,
    ) -> Result<WorkflowRun, SoarError>;

    /// Fetch a previously executed run by uuid, scoped to `tenant_id`.
    async fn get_run(&self, tenant_id: Uuid, run_id: Uuid) -> Result<WorkflowRun, SoarError>;

    /// List runs for `tenant_id`, capped at `limit`. Newest-first by
    /// `started_at`.
    async fn list_runs(&self, tenant_id: Uuid, limit: usize)
        -> Result<Vec<WorkflowRun>, SoarError>;
}

/// Draft form of [`Workflow`] used at create + update time.
#[derive(Debug, Clone)]
pub struct WorkflowDraft {
    /// Human-readable display name.
    pub name: String,
    /// Persisted DAG definition.
    pub definition: WorkflowGraph,
    /// Whether the workflow is dispatched on inbound events.
    pub enabled: bool,
}

impl WorkflowDraft {
    /// Promote the draft into a full [`Workflow`] using the supplied
    /// uuid + tenant id. Runs the standard semantic validator.
    pub fn into_workflow(self, id: Uuid, tenant_id: Uuid) -> Result<Workflow, SoarError> {
        let wf = Workflow {
            id,
            tenant_id,
            name: self.name,
            definition: self.definition,
            enabled: self.enabled,
        };
        wf.validate()?;
        Ok(wf)
    }
}

/// MVP in-memory implementation of [`SoarService`].
#[derive(Clone)]
pub struct InMemorySoarService {
    inner: Arc<Mutex<State>>,
    executor: Arc<DagExecutor>,
    audit: Option<Arc<dyn AuditHook>>,
}

#[derive(Default)]
struct State {
    workflows: HashMap<(Uuid, Uuid), Workflow>,
    runs: HashMap<(Uuid, Uuid), WorkflowRun>,
}

impl std::fmt::Debug for InMemorySoarService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InMemorySoarService")
            .finish_non_exhaustive()
    }
}

impl InMemorySoarService {
    /// Build a fresh service wired to `registry`. `audit` is optional;
    /// tests can pass `None` for a quiet store.
    #[must_use]
    pub fn new(registry: Arc<ActionRegistry>, audit: Option<Arc<dyn AuditHook>>) -> Self {
        let executor = Arc::new(DagExecutor::new(registry));
        Self {
            inner: Arc::new(Mutex::new(State::default())),
            executor,
            audit,
        }
    }

    /// Tap into the shared inner executor — used by composition-root
    /// adapters that need to dispatch a workflow from an event bus
    /// without going through the trait interface.
    #[must_use]
    pub fn executor(&self) -> Arc<DagExecutor> {
        Arc::clone(&self.executor)
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, State>, SoarError> {
        self.inner
            .lock()
            .map_err(|_| SoarError::internal("soar state mutex poisoned"))
    }

    async fn emit_audit(&self, tenant_id: Uuid, event: &str, detail: serde_json::Value) {
        if let Some(hook) = self.audit.as_ref() {
            hook.emit(tenant_id, event, detail).await;
        }
    }
}

#[async_trait]
impl SoarService for InMemorySoarService {
    async fn create_workflow(
        &self,
        tenant_id: Uuid,
        draft: WorkflowDraft,
    ) -> Result<Workflow, SoarError> {
        let id = Uuid::now_v7();
        let wf = draft.into_workflow(id, tenant_id)?;
        {
            let mut state = self.lock()?;
            state.workflows.insert((tenant_id, id), wf.clone());
        }
        tracing::info!(
            target: "sx_soar.service",
            tenant_id = %tenant_id,
            workflow_id = %id,
            name = %wf.name,
            "workflow created",
        );
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
        let state = self.lock()?;
        state
            .workflows
            .get(&(tenant_id, workflow_id))
            .cloned()
            .ok_or(SoarError::NotFound)
    }

    async fn list_workflows(&self, tenant_id: Uuid) -> Result<Vec<Workflow>, SoarError> {
        let state = self.lock()?;
        Ok(state
            .workflows
            .iter()
            .filter(|((t, _), _)| *t == tenant_id)
            .map(|(_, wf)| wf.clone())
            .collect())
    }

    async fn update_workflow(
        &self,
        tenant_id: Uuid,
        workflow_id: Uuid,
        draft: WorkflowDraft,
    ) -> Result<Workflow, SoarError> {
        let wf = draft.into_workflow(workflow_id, tenant_id)?;
        {
            let mut state = self.lock()?;
            if !state.workflows.contains_key(&(tenant_id, workflow_id)) {
                return Err(SoarError::NotFound);
            }
            state.workflows.insert((tenant_id, workflow_id), wf.clone());
        }
        tracing::info!(
            target: "sx_soar.service",
            tenant_id = %tenant_id,
            workflow_id = %workflow_id,
            "workflow updated",
        );
        self.emit_audit(
            tenant_id,
            "workflow_updated",
            serde_json::json!({ "workflow_id": workflow_id }),
        )
        .await;
        Ok(wf)
    }

    async fn delete_workflow(&self, tenant_id: Uuid, workflow_id: Uuid) -> Result<(), SoarError> {
        {
            let mut state = self.lock()?;
            if state.workflows.remove(&(tenant_id, workflow_id)).is_none() {
                return Err(SoarError::NotFound);
            }
        }
        tracing::info!(
            target: "sx_soar.service",
            tenant_id = %tenant_id,
            workflow_id = %workflow_id,
            "workflow deleted",
        );
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
        let wf = self.get_workflow(tenant_id, workflow_id).await?;
        self.emit_audit(
            tenant_id,
            "run_started",
            serde_json::json!({ "workflow_id": workflow_id }),
        )
        .await;
        let run = self.executor.execute(&wf, &event).await?;
        {
            let mut state = self.lock()?;
            state.runs.insert((tenant_id, run.id), run.clone());
        }
        tracing::info!(
            target: "sx_soar.service",
            tenant_id = %tenant_id,
            workflow_id = %workflow_id,
            run_id = %run.id,
            status = ?run.status,
            "workflow run completed",
        );
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
        let state = self.lock()?;
        state
            .runs
            .get(&(tenant_id, run_id))
            .cloned()
            .ok_or(SoarError::NotFound)
    }

    async fn list_runs(
        &self,
        tenant_id: Uuid,
        limit: usize,
    ) -> Result<Vec<WorkflowRun>, SoarError> {
        let state = self.lock()?;
        let mut rows: Vec<WorkflowRun> = state
            .runs
            .iter()
            .filter(|((t, _), _)| *t == tenant_id)
            .map(|(_, r)| r.clone())
            .collect();
        rows.sort_by(|a, b| b.started_at.cmp(&a.started_at));
        rows.truncate(limit);
        Ok(rows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::{Action, ActionExecutor};
    use crate::executor::WorkflowRunStatus;
    use crate::graph::{Edge, Node, WorkflowGraph};
    use crate::trigger::{Severity, Trigger, TriggerEvent};
    use std::sync::Mutex as StdMutex;

    struct EchoExec;
    #[async_trait]
    impl ActionExecutor for EchoExec {
        async fn execute(
            &self,
            action: &Action,
            _payload: &serde_json::Value,
        ) -> Result<serde_json::Value, SoarError> {
            Ok(serde_json::json!({ "kind": action.kind() }))
        }
    }

    fn registry() -> Arc<ActionRegistry> {
        Arc::new(
            ActionRegistry::new()
                .register("http_request", Arc::new(EchoExec))
                .register("emit_webhook", Arc::new(EchoExec))
                .register("run_remediation_play", Arc::new(EchoExec))
                .register("noop", Arc::new(EchoExec)),
        )
    }

    #[derive(Default)]
    struct RecordingAudit {
        events: StdMutex<Vec<(Uuid, String)>>,
    }
    #[async_trait]
    impl AuditHook for RecordingAudit {
        async fn emit(&self, tenant_id: Uuid, event: &str, _detail: serde_json::Value) {
            self.events
                .lock()
                .unwrap()
                .push((tenant_id, event.to_owned()));
        }
    }

    fn three_step_graph() -> WorkflowGraph {
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
                        url: "https://example.com".into(),
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

    fn sample_draft() -> WorkflowDraft {
        WorkflowDraft {
            name: "demo".into(),
            definition: three_step_graph(),
            enabled: true,
        }
    }

    fn critical_event() -> TriggerEvent {
        TriggerEvent::FindingCreated {
            finding_id: "F-1".into(),
            severity: Severity::Critical,
            payload: serde_json::json!({}),
        }
    }

    #[tokio::test]
    async fn create_then_get_round_trips_within_tenant() {
        let svc = InMemorySoarService::new(registry(), None);
        let tenant = Uuid::new_v4();
        let wf = svc.create_workflow(tenant, sample_draft()).await.unwrap();
        let back = svc.get_workflow(tenant, wf.id).await.unwrap();
        assert_eq!(wf, back);
    }

    #[tokio::test]
    async fn other_tenant_cannot_see_workflow() {
        let svc = InMemorySoarService::new(registry(), None);
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let wf = svc.create_workflow(a, sample_draft()).await.unwrap();
        let err = svc.get_workflow(b, wf.id).await.unwrap_err();
        assert!(matches!(err, SoarError::NotFound));
    }

    #[tokio::test]
    async fn run_persists_and_audit_records_start_and_finish() {
        let audit = Arc::new(RecordingAudit::default());
        let svc =
            InMemorySoarService::new(registry(), Some(Arc::clone(&audit) as Arc<dyn AuditHook>));
        let tenant = Uuid::new_v4();
        let wf = svc.create_workflow(tenant, sample_draft()).await.unwrap();
        let run = svc
            .run_workflow(tenant, wf.id, critical_event())
            .await
            .unwrap();
        assert!(matches!(run.status, WorkflowRunStatus::Ok));
        let back = svc.get_run(tenant, run.id).await.unwrap();
        assert_eq!(back, run);
        let events: Vec<String> = audit
            .events
            .lock()
            .unwrap()
            .iter()
            .map(|(_, e)| e.clone())
            .collect();
        assert!(events.contains(&"workflow_created".to_owned()));
        assert!(events.contains(&"run_started".to_owned()));
        assert!(events.contains(&"run_completed".to_owned()));
    }

    #[tokio::test]
    async fn invalid_draft_rejected_with_invalid_definition() {
        let svc = InMemorySoarService::new(registry(), None);
        let tenant = Uuid::new_v4();
        let mut bad = sample_draft();
        bad.definition.nodes.clear();
        let err = svc.create_workflow(tenant, bad).await.unwrap_err();
        assert!(matches!(err, SoarError::InvalidDefinition(_)));
    }

    #[tokio::test]
    async fn list_runs_returns_newest_first_and_caps_at_limit() {
        let svc = InMemorySoarService::new(registry(), None);
        let tenant = Uuid::new_v4();
        let wf = svc.create_workflow(tenant, sample_draft()).await.unwrap();
        for _ in 0..3 {
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
            let _ = svc
                .run_workflow(tenant, wf.id, critical_event())
                .await
                .unwrap();
        }
        let rows = svc.list_runs(tenant, 2).await.unwrap();
        assert_eq!(rows.len(), 2);
        assert!(rows[0].started_at >= rows[1].started_at);
    }

    #[tokio::test]
    async fn delete_removes_workflow_and_is_idempotent() {
        let svc = InMemorySoarService::new(registry(), None);
        let tenant = Uuid::new_v4();
        let wf = svc.create_workflow(tenant, sample_draft()).await.unwrap();
        svc.delete_workflow(tenant, wf.id).await.unwrap();
        let err = svc.delete_workflow(tenant, wf.id).await.unwrap_err();
        assert!(matches!(err, SoarError::NotFound));
    }
}
