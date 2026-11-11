//! SOAR low-code workflow builder (P3-005) view layer.
//!
//! Wire shapes for the MVP endpoints:
//!
//! * `POST /v1/soar/workflows`          — create a workflow.
//! * `GET  /v1/soar/workflows/{id}`     — fetch a workflow.
//! * `POST /v1/soar/workflows/{id}/run` — execute a workflow once against a
//!   caller-supplied trigger event.
//! * `GET  /v1/soar/runs/{id}`          — fetch a previously executed run.
//!
//! The view types deliberately mirror the in-crate domain shapes from
//! [`sx_soar`] but live behind the standard serde wire envelope so the
//! HTTP schema can evolve independently of the engine.

use serde::{Deserialize, Serialize};
use sx_soar::executor::WorkflowRunStatus;
use sx_soar::{ActionResult, ActionStatus, TriggerEvent, Workflow, WorkflowGraph, WorkflowRun};
use validator::Validate;

/// Body accepted by `POST /v1/soar/workflows`.
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct CreateWorkflowRequest {
    /// Human-readable display name. Bounded `1..=200` chars.
    #[validate(length(min = 1, max = 200))]
    pub name: String,
    /// DAG definition: nodes + edges.
    pub definition: WorkflowGraph,
    /// Whether the workflow is dispatched on inbound events. Defaults to
    /// `true` when omitted so the most common shape (always enabled) does
    /// not require an extra field.
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

const fn default_enabled() -> bool {
    true
}

/// Body accepted by `POST /v1/soar/workflows/{id}/run`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunWorkflowRequest {
    /// The trigger event to dispatch the workflow against.
    pub event: TriggerEvent,
}

/// Wire form of an [`sx_soar::Workflow`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkflowView {
    /// Workflow uuid.
    pub id: String,
    /// Tenant uuid.
    pub tenant_id: String,
    /// Display name.
    pub name: String,
    /// DAG definition.
    pub definition: WorkflowGraph,
    /// Whether the workflow is enabled.
    pub enabled: bool,
}

impl From<Workflow> for WorkflowView {
    fn from(w: Workflow) -> Self {
        Self {
            id: w.id.to_string(),
            tenant_id: w.tenant_id.to_string(),
            name: w.name,
            definition: w.definition,
            enabled: w.enabled,
        }
    }
}

/// Wire form of an [`sx_soar::WorkflowRun`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkflowRunView {
    /// Run uuid.
    pub id: String,
    /// Tenant uuid.
    pub tenant_id: String,
    /// Workflow uuid.
    pub workflow_id: String,
    /// JSON snapshot of the trigger event.
    pub trigger_payload: serde_json::Value,
    /// Terminal run status: `ok` / `failed` / `skipped`.
    pub status: String,
    /// Per-node outcomes in visit order.
    pub node_results: Vec<ActionResultView>,
    /// RFC 3339 timestamp at dispatch.
    pub started_at: String,
    /// RFC 3339 timestamp at terminal status.
    pub finished_at: String,
}

impl From<WorkflowRun> for WorkflowRunView {
    fn from(r: WorkflowRun) -> Self {
        Self {
            id: r.id.to_string(),
            tenant_id: r.tenant_id.to_string(),
            workflow_id: r.workflow_id.to_string(),
            trigger_payload: r.trigger_payload,
            status: status_label(r.status).to_owned(),
            node_results: r.node_results.into_iter().map(Into::into).collect(),
            started_at: r.started_at,
            finished_at: r.finished_at,
        }
    }
}

const fn status_label(s: WorkflowRunStatus) -> &'static str {
    match s {
        WorkflowRunStatus::Ok => "ok",
        WorkflowRunStatus::Failed => "failed",
        WorkflowRunStatus::Skipped => "skipped",
    }
}

/// Narrow projection of a workflow used by the dashboard list view.
///
/// Backs `GET /v1/soar/workflows`. Carries only the columns the list UI
/// renders — full graph definitions are excluded so the list response
/// stays small even when the engine holds thousands of workflows.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkflowSummaryView {
    /// Workflow uuid.
    pub id: String,
    /// Display name (1..=200 chars, validated at create time).
    pub name: String,
    /// Schema version of the workflow definition. The engine is
    /// single-version today; the field is always `1` so the wire shape
    /// is forward-compatible with a future migration.
    pub version: u32,
    /// RFC 3339 timestamp the workflow was first persisted.
    pub created_at: String,
    /// Whether the workflow is currently enabled.
    pub enabled: bool,
}

impl WorkflowSummaryView {
    /// Project a [`Workflow`] into the narrow summary used by the list
    /// endpoint. The engine does not retain a per-row creation
    /// timestamp today; callers must supply one (the adapter passes
    /// the wall-clock now at fetch time, which keeps the wire shape
    /// stable until the persisted column lands).
    #[must_use]
    pub fn from_workflow(w: &Workflow, created_at: String) -> Self {
        Self {
            id: w.id.to_string(),
            name: w.name.clone(),
            version: 1,
            created_at,
            enabled: w.enabled,
        }
    }
}

/// Wire form of an [`sx_soar::ActionResult`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActionResultView {
    /// Node id whose action produced this result.
    pub node_id: String,
    /// Node kind label.
    pub kind: String,
    /// Status label: `ok` / `failed`.
    pub status: String,
    /// Free-form per-action detail.
    pub detail: serde_json::Value,
}

impl From<ActionResult> for ActionResultView {
    fn from(r: ActionResult) -> Self {
        Self {
            node_id: r.node_id,
            kind: r.kind,
            status: match r.status {
                ActionStatus::Ok => "ok".to_owned(),
                ActionStatus::Failed => "failed".to_owned(),
            },
            detail: r.detail,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use sx_soar::{Action, Edge, Node, Trigger};

    fn trivial_graph() -> WorkflowGraph {
        WorkflowGraph {
            nodes: vec![
                Node::Trigger {
                    id: "t".into(),
                    trigger: Trigger::Any,
                },
                Node::Action {
                    id: "a".into(),
                    action: Action::Noop { tag: "x".into() },
                },
            ],
            edges: vec![Edge {
                from: "t".into(),
                to: "a".into(),
            }],
        }
    }

    #[test]
    fn create_request_validates_name_length() {
        let req = CreateWorkflowRequest {
            name: String::new(),
            definition: trivial_graph(),
            enabled: true,
        };
        assert!(req.validate().is_err());
    }

    #[test]
    fn workflow_run_status_label_mapping() {
        assert_eq!(status_label(WorkflowRunStatus::Ok), "ok");
        assert_eq!(status_label(WorkflowRunStatus::Failed), "failed");
        assert_eq!(status_label(WorkflowRunStatus::Skipped), "skipped");
    }
}
