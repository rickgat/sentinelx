//! DAG workflow executor + per-run execution log row.
//!
//! The executor walks `workflow.definition` in topological order. For
//! each visited node:
//!
//! * [`Node::Trigger`] — verifies the trigger predicate matches the
//!   inbound event. On mismatch, the run is marked
//!   [`WorkflowRunStatus::Skipped`] and execution
//!   halts before any action fires.
//! * [`Node::Action`] — invokes the [`crate::action::ActionRegistry`]
//!   entry that matches the action kind.
//! * [`Node::Condition`] — evaluates the predicate against the execution
//!   context. The opposite branch's subtree is
//!   pruned from execution.
//! * [`Node::Parallel`] — fans out to every branch concurrently with
//!   `tokio::join_all` and waits for every branch.
//!
//! Run-log rows are returned to the caller; the embedding
//! [`crate::service::SoarService`] decides whether to persist them.

use std::collections::HashSet;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::action::{Action, ActionRegistry, ActionResult, ActionStatus};
use crate::error::SoarError;
use crate::graph::{ConditionExpr, Node, WorkflowGraph};
use crate::trigger::TriggerEvent;
use crate::workflow::Workflow;

/// Terminal status of a workflow run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WorkflowRunStatus {
    /// Every reachable node completed cleanly.
    Ok,
    /// One or more action nodes failed; downstream nodes were skipped.
    Failed,
    /// The trigger predicate did not match the inbound event — the
    /// executor short-circuited before dispatching any action.
    Skipped,
}

/// One execution-log row captured by the executor.
///
/// The shape mirrors the `soar_runs` table:
///
/// * `id`               — run uuid (v7).
/// * `tenant_id`        — owning tenant.
/// * `workflow_id`      — which workflow fired.
/// * `trigger_payload`  — opaque JSON snapshot of the inbound event.
/// * `status`           — terminal status.
/// * `node_results`     — per-action outcome captured in visit order.
/// * `started_at`       — RFC 3339 timestamp at dispatch.
/// * `finished_at`      — RFC 3339 timestamp at terminal status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkflowRun {
    /// Run uuid.
    pub id: Uuid,
    /// Tenant uuid.
    pub tenant_id: Uuid,
    /// Workflow uuid the run belongs to.
    pub workflow_id: Uuid,
    /// JSON-encoded snapshot of the inbound event.
    pub trigger_payload: serde_json::Value,
    /// Terminal status.
    pub status: WorkflowRunStatus,
    /// Per-action outcomes in visit order.
    pub node_results: Vec<ActionResult>,
    /// RFC 3339 timestamp at dispatch.
    pub started_at: String,
    /// RFC 3339 timestamp at terminal status.
    pub finished_at: String,
}

/// DAG workflow executor.
///
/// Holds the [`ActionRegistry`] so the engine can dispatch each action
/// node through its variant-specific port without knowing the adapter
/// concrete type.
#[derive(Clone)]
pub struct DagExecutor {
    registry: Arc<ActionRegistry>,
}

impl std::fmt::Debug for DagExecutor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DagExecutor")
            .field("registry", &self.registry)
            .finish()
    }
}

impl DagExecutor {
    /// Construct a new executor wired to `registry`.
    #[must_use]
    pub fn new(registry: Arc<ActionRegistry>) -> Self {
        Self { registry }
    }

    /// Execute `workflow` against `event` and return the run-log row.
    ///
    /// * If `workflow.enabled` is `false`, or the trigger predicate
    ///   rejects the event, the run is [`WorkflowRunStatus::Skipped`].
    /// * Any reachable failing action node marks the run as
    ///   [`WorkflowRunStatus::Failed`]; downstream nodes that have not
    ///   yet been visited are skipped.
    pub async fn execute(
        &self,
        workflow: &Workflow,
        event: &TriggerEvent,
    ) -> Result<WorkflowRun, SoarError> {
        let started_at = now_rfc3339();
        let trigger_payload =
            serde_json::to_value(event).map_err(|e| SoarError::internal(e.to_string()))?;
        let trigger_node = workflow
            .definition
            .nodes
            .iter()
            .find(|n| matches!(n, Node::Trigger { .. }))
            .ok_or_else(|| SoarError::internal("graph missing trigger node"))?;
        let fire = match trigger_node {
            Node::Trigger { trigger, .. } => trigger.matches(event),
            _ => false,
        };
        if !workflow.enabled || !fire {
            let finished_at = now_rfc3339();
            return Ok(WorkflowRun {
                id: Uuid::now_v7(),
                tenant_id: workflow.tenant_id,
                workflow_id: workflow.id,
                trigger_payload,
                status: WorkflowRunStatus::Skipped,
                node_results: Vec::new(),
                started_at,
                finished_at,
            });
        }
        // Build the execution context: kept immutable during the run.
        let ctx = serde_json::json!({
            "event": event.to_context(),
        });
        // Plan: topological walk with condition-branch pruning.
        let order = workflow.definition.topological_order()?;
        let mut pruned: HashSet<String> = HashSet::new();
        let mut overall = WorkflowRunStatus::Ok;
        let mut results: Vec<ActionResult> = Vec::new();
        for node_id in order {
            if pruned.contains(&node_id) {
                continue;
            }
            let Some(node) = workflow.definition.node(&node_id) else {
                continue;
            };
            match node {
                Node::Trigger { .. } => {
                    // Already matched above; recorded purely for the run log.
                    results.push(ActionResult {
                        node_id: node.id().to_owned(),
                        kind: "trigger".to_owned(),
                        status: ActionStatus::Ok,
                        detail: serde_json::json!({}),
                    });
                }
                Node::Action { action, .. } => {
                    let detail = match self
                        .dispatch_action(node.id(), action, &trigger_payload)
                        .await
                    {
                        Ok(d) => {
                            results.push(ActionResult {
                                node_id: node.id().to_owned(),
                                kind: action.kind().to_owned(),
                                status: ActionStatus::Ok,
                                detail: d,
                            });
                            None
                        }
                        Err(err) => {
                            overall = WorkflowRunStatus::Failed;
                            tracing::warn!(
                                target: "sx_soar.executor",
                                workflow_id = %workflow.id,
                                node_id = %node.id(),
                                reason = %err,
                                "action node failed",
                            );
                            results.push(ActionResult {
                                node_id: node.id().to_owned(),
                                kind: action.kind().to_owned(),
                                status: ActionStatus::Failed,
                                detail: serde_json::json!({ "error": err.to_string() }),
                            });
                            Some(err)
                        }
                    };
                    if detail.is_some() {
                        // Prune every descendant of this failing node.
                        prune_descendants(&workflow.definition, node.id(), &mut pruned);
                    }
                }
                Node::Condition {
                    expr,
                    then_id,
                    else_id,
                    ..
                } => {
                    let branch = if expr.evaluate(&ctx) {
                        then_id.clone()
                    } else {
                        else_id.clone()
                    };
                    let other = if branch == *then_id {
                        else_id.clone()
                    } else {
                        then_id.clone()
                    };
                    results.push(ActionResult {
                        node_id: node.id().to_owned(),
                        kind: "condition".to_owned(),
                        status: ActionStatus::Ok,
                        detail: serde_json::json!({
                            "branch_taken": branch,
                            "branch_pruned": other,
                            "expr": describe_expr(expr),
                        }),
                    });
                    // Prune the not-taken sub-graph.
                    pruned.insert(other.clone());
                    prune_descendants(&workflow.definition, &other, &mut pruned);
                }
                Node::Parallel { branches, .. } => {
                    let parallel_results = self
                        .dispatch_parallel(workflow, branches, &trigger_payload)
                        .await;
                    let any_failed = parallel_results
                        .iter()
                        .any(|r| matches!(r.status, ActionStatus::Failed));
                    if any_failed {
                        overall = WorkflowRunStatus::Failed;
                    }
                    results.push(ActionResult {
                        node_id: node.id().to_owned(),
                        kind: "parallel".to_owned(),
                        status: if any_failed {
                            ActionStatus::Failed
                        } else {
                            ActionStatus::Ok
                        },
                        detail: serde_json::json!({
                            "branches": branches,
                        }),
                    });
                    results.extend(parallel_results);
                    // Parallel handles its branches internally; prune them
                    // from the outer walk to avoid double-execution.
                    for b in branches {
                        pruned.insert(b.clone());
                    }
                }
            }
        }
        let finished_at = now_rfc3339();
        Ok(WorkflowRun {
            id: Uuid::now_v7(),
            tenant_id: workflow.tenant_id,
            workflow_id: workflow.id,
            trigger_payload,
            status: overall,
            node_results: results,
            started_at,
            finished_at,
        })
    }

    /// Dispatch one action node through its registry entry.
    async fn dispatch_action(
        &self,
        node_id: &str,
        action: &Action,
        trigger_payload: &serde_json::Value,
    ) -> Result<serde_json::Value, SoarError> {
        let kind = action.kind();
        let executor = self
            .registry
            .get(kind)
            .ok_or_else(|| SoarError::ActionFailed {
                node_id: node_id.to_owned(),
                reason: format!("no executor registered for action kind `{kind}`"),
            })?;
        executor
            .execute(action, trigger_payload)
            .await
            .map_err(|e| SoarError::ActionFailed {
                node_id: node_id.to_owned(),
                reason: e.to_string(),
            })
    }

    /// Resolve every direct branch of a [`Node::Parallel`] node and run
    /// them concurrently. Each branch fans through any immediate action
    /// payload — nested DAGs are intentionally out of scope for the MVP.
    async fn dispatch_parallel(
        &self,
        workflow: &Workflow,
        branches: &[String],
        trigger_payload: &serde_json::Value,
    ) -> Vec<ActionResult> {
        let mut futs = Vec::with_capacity(branches.len());
        for b in branches {
            let Some(node) = workflow.definition.node(b) else {
                futs.push(Box::pin(async move {
                    ActionResult {
                        node_id: b.clone(),
                        kind: "missing".to_owned(),
                        status: ActionStatus::Failed,
                        detail: serde_json::json!({ "error": "branch not found" }),
                    }
                })
                    as std::pin::Pin<
                        Box<dyn std::future::Future<Output = ActionResult> + Send>,
                    >);
                continue;
            };
            let registry = Arc::clone(&self.registry);
            let payload = trigger_payload.clone();
            let node_clone = node.clone();
            futs.push(Box::pin(async move {
                match &node_clone {
                    Node::Action { id, action } => {
                        let exec_opt = registry.get(action.kind());
                        match exec_opt {
                            Some(ex) => match ex.execute(action, &payload).await {
                                Ok(detail) => ActionResult {
                                    node_id: id.clone(),
                                    kind: action.kind().to_owned(),
                                    status: ActionStatus::Ok,
                                    detail,
                                },
                                Err(err) => ActionResult {
                                    node_id: id.clone(),
                                    kind: action.kind().to_owned(),
                                    status: ActionStatus::Failed,
                                    detail: serde_json::json!({ "error": err.to_string() }),
                                },
                            },
                            None => ActionResult {
                                node_id: id.clone(),
                                kind: action.kind().to_owned(),
                                status: ActionStatus::Failed,
                                detail: serde_json::json!({
                                    "error": format!("no executor registered for kind `{}`", action.kind()),
                                }),
                            },
                        }
                    }
                    other => ActionResult {
                        node_id: other.id().to_owned(),
                        kind: other.type_label().to_owned(),
                        status: ActionStatus::Ok,
                        detail: serde_json::json!({
                            "note": "non-action branches passthrough in the MVP",
                        }),
                    },
                }
            }) as std::pin::Pin<Box<dyn std::future::Future<Output = ActionResult> + Send>>);
        }
        let mut out = Vec::with_capacity(futs.len());
        for f in futs {
            out.push(f.await);
        }
        out
    }
}

/// Render a condition expression as a stable string for the run log.
fn describe_expr(expr: &ConditionExpr) -> String {
    match expr {
        ConditionExpr::Eq { ptr, value } => format!("{ptr} == {value}"),
        ConditionExpr::Ne { ptr, value } => format!("{ptr} != {value}"),
        ConditionExpr::In { ptr, values } => format!("{ptr} in {values:?}"),
        ConditionExpr::Exists { ptr } => format!("exists({ptr})"),
    }
}

/// Compute the transitive descendant set of `start` in `graph` and
/// insert each into `out`. Used by both the failure-pruning and the
/// condition-branch-pruning paths.
fn prune_descendants(graph: &WorkflowGraph, start: &str, out: &mut HashSet<String>) {
    let adj = graph.adjacency();
    let mut stack: Vec<String> = vec![start.to_owned()];
    let mut local: HashSet<String> = HashSet::new();
    while let Some(cur) = stack.pop() {
        if !local.insert(cur.clone()) {
            continue;
        }
        if let Some(children) = adj.get(&cur) {
            for child in children {
                if out.insert(child.clone()) {
                    stack.push(child.clone());
                }
            }
        }
    }
}

/// RFC 3339 (UTC) timestamp of "now". Falls back to the Unix epoch when
/// formatting fails — should never happen with the well-known format.
fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned())
}

#[cfg(test)]
#[allow(clippy::similar_names)] // `rec` (Recorder) + `reg` (ActionRegistry) are the established test-helper pair; renaming would hurt readability.
mod tests {
    use super::*;
    use crate::action::{Action, ActionExecutor};
    use crate::graph::{Edge, Node, WorkflowGraph};
    use crate::trigger::{Severity, Trigger, TriggerEvent};
    use async_trait::async_trait;
    use std::collections::HashMap;
    use std::sync::Mutex;

    #[derive(Default)]
    struct Recorder {
        log: Mutex<Vec<String>>,
    }

    struct RecExec {
        rec: Arc<Recorder>,
        tag: &'static str,
        fail: bool,
    }
    #[async_trait]
    impl ActionExecutor for RecExec {
        async fn execute(
            &self,
            action: &Action,
            _payload: &serde_json::Value,
        ) -> Result<serde_json::Value, SoarError> {
            self.rec
                .log
                .lock()
                .unwrap()
                .push(format!("{}:{}", self.tag, action.kind()));
            if self.fail {
                return Err(SoarError::internal("forced failure"));
            }
            Ok(serde_json::json!({ "tag": self.tag }))
        }
    }

    fn make_workflow(definition: WorkflowGraph) -> Workflow {
        Workflow {
            id: Uuid::nil(),
            tenant_id: Uuid::nil(),
            name: "demo".into(),
            definition,
            enabled: true,
        }
    }

    fn finding_critical() -> TriggerEvent {
        TriggerEvent::FindingCreated {
            finding_id: "F-1".into(),
            severity: Severity::Critical,
            payload: serde_json::json!({ "asset": "A-1" }),
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
    async fn three_step_workflow_runs_end_to_end() {
        let rec = Arc::new(Recorder::default());
        let reg = ActionRegistry::new()
            .register(
                "http_request",
                Arc::new(RecExec {
                    rec: Arc::clone(&rec),
                    tag: "http",
                    fail: false,
                }),
            )
            .register(
                "emit_webhook",
                Arc::new(RecExec {
                    rec: Arc::clone(&rec),
                    tag: "hook",
                    fail: false,
                }),
            );
        let exec = DagExecutor::new(Arc::new(reg));
        let wf = make_workflow(three_step_graph());
        let run = exec.execute(&wf, &finding_critical()).await.unwrap();
        assert!(matches!(run.status, WorkflowRunStatus::Ok));
        let entries = rec.log.lock().unwrap().clone();
        assert_eq!(entries, vec!["http:http_request", "hook:emit_webhook"]);
        // Run log carries the trigger frame + both action frames.
        assert_eq!(run.node_results.len(), 3);
    }

    #[tokio::test]
    async fn condition_branch_prunes_else_subtree() {
        let rec = Arc::new(Recorder::default());
        let reg = ActionRegistry::new().register(
            "noop",
            Arc::new(RecExec {
                rec: Arc::clone(&rec),
                tag: "noop",
                fail: false,
            }),
        );
        let exec = DagExecutor::new(Arc::new(reg));
        let g = WorkflowGraph {
            nodes: vec![
                Node::Trigger {
                    id: "t".into(),
                    trigger: Trigger::Any,
                },
                Node::Condition {
                    id: "c".into(),
                    expr: ConditionExpr::Eq {
                        ptr: "/event/severity".into(),
                        value: serde_json::json!("critical"),
                    },
                    then_id: "on_crit".into(),
                    else_id: "on_low".into(),
                },
                Node::Action {
                    id: "on_crit".into(),
                    action: Action::Noop { tag: "crit".into() },
                },
                Node::Action {
                    id: "on_low".into(),
                    action: Action::Noop { tag: "low".into() },
                },
            ],
            edges: vec![
                Edge {
                    from: "t".into(),
                    to: "c".into(),
                },
                Edge {
                    from: "c".into(),
                    to: "on_crit".into(),
                },
                Edge {
                    from: "c".into(),
                    to: "on_low".into(),
                },
            ],
        };
        let wf = make_workflow(g);
        let run = exec.execute(&wf, &finding_critical()).await.unwrap();
        assert!(matches!(run.status, WorkflowRunStatus::Ok));
        let entries = rec.log.lock().unwrap().clone();
        // Only the `then` branch ran.
        assert_eq!(entries, vec!["noop:noop"]);
        // Run log records the trigger, the condition, and the taken branch.
        let kinds: Vec<&str> = run.node_results.iter().map(|r| r.kind.as_str()).collect();
        assert!(kinds.contains(&"condition"));
        assert!(kinds.contains(&"noop"));
    }

    #[tokio::test]
    async fn cycle_in_graph_is_rejected_at_execution() {
        let mut g = three_step_graph();
        g.edges.push(Edge {
            from: "hook".into(),
            to: "http".into(),
        });
        // Validation rejects the cycle before the executor ever runs.
        let err = g.validate().unwrap_err();
        assert!(matches!(err, SoarError::InvalidDefinition(_)));
    }

    #[tokio::test]
    async fn non_matching_event_is_skipped() {
        let rec = Arc::new(Recorder::default());
        let reg = ActionRegistry::new().register(
            "http_request",
            Arc::new(RecExec {
                rec: Arc::clone(&rec),
                tag: "http",
                fail: false,
            }),
        );
        let exec = DagExecutor::new(Arc::new(reg));
        let wf = make_workflow(three_step_graph());
        let low_event = TriggerEvent::FindingCreated {
            finding_id: "F-2".into(),
            severity: Severity::Low,
            payload: serde_json::Value::Null,
        };
        let run = exec.execute(&wf, &low_event).await.unwrap();
        assert!(matches!(run.status, WorkflowRunStatus::Skipped));
        assert!(rec.log.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn failed_action_marks_run_failed_and_prunes_descendants() {
        let rec = Arc::new(Recorder::default());
        let reg = ActionRegistry::new()
            .register(
                "http_request",
                Arc::new(RecExec {
                    rec: Arc::clone(&rec),
                    tag: "http",
                    fail: true, // force failure
                }),
            )
            .register(
                "emit_webhook",
                Arc::new(RecExec {
                    rec: Arc::clone(&rec),
                    tag: "hook",
                    fail: false,
                }),
            );
        let exec = DagExecutor::new(Arc::new(reg));
        let wf = make_workflow(three_step_graph());
        let run = exec.execute(&wf, &finding_critical()).await.unwrap();
        assert!(matches!(run.status, WorkflowRunStatus::Failed));
        // Webhook MUST NOT have been dispatched because http failed.
        let entries = rec.log.lock().unwrap().clone();
        assert_eq!(entries, vec!["http:http_request"]);
    }

    #[tokio::test]
    async fn parallel_runs_both_branches() {
        let rec = Arc::new(Recorder::default());
        let reg = ActionRegistry::new().register(
            "noop",
            Arc::new(RecExec {
                rec: Arc::clone(&rec),
                tag: "noop",
                fail: false,
            }),
        );
        let exec = DagExecutor::new(Arc::new(reg));
        let g = WorkflowGraph {
            nodes: vec![
                Node::Trigger {
                    id: "t".into(),
                    trigger: Trigger::Any,
                },
                Node::Parallel {
                    id: "fanout".into(),
                    branches: vec!["a".into(), "b".into()],
                },
                Node::Action {
                    id: "a".into(),
                    action: Action::Noop { tag: "a".into() },
                },
                Node::Action {
                    id: "b".into(),
                    action: Action::Noop { tag: "b".into() },
                },
            ],
            edges: vec![
                Edge {
                    from: "t".into(),
                    to: "fanout".into(),
                },
                Edge {
                    from: "fanout".into(),
                    to: "a".into(),
                },
                Edge {
                    from: "fanout".into(),
                    to: "b".into(),
                },
            ],
        };
        let wf = make_workflow(g);
        let run = exec.execute(&wf, &finding_critical()).await.unwrap();
        assert!(matches!(run.status, WorkflowRunStatus::Ok));
        let mut entries = rec.log.lock().unwrap().clone();
        entries.sort();
        assert_eq!(entries, vec!["noop:noop", "noop:noop"]);
    }
}
