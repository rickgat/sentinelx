//! Workflow DAG model — nodes + edges + topological order with cycle
//! detection.
//!
//! A [`WorkflowGraph`] describes the dataflow of a SOAR workflow as a
//! directed acyclic graph keyed on string node ids. The MVP supports four
//! node kinds:
//!
//! * [`Node::Trigger`] — entry point; carries a [`crate::trigger::Trigger`]
//!   predicate.
//! * [`Node::Action`] — invokes an [`crate::action::Action`] through the
//!   [`crate::action::ActionRegistry`].
//! * [`Node::Condition`] — branches to one of two child nodes based on a
//!   JSON-pointer expression evaluated against the
//!   current execution context.
//! * [`Node::Parallel`] — fans out to N child branches and waits for all
//!   to terminate.
//!
//! Validation is run by [`WorkflowGraph::validate`] at create + update
//! time and guarantees:
//!
//! * exactly one [`Node::Trigger`];
//! * every edge target exists;
//! * every condition node references real branches;
//! * no cycles (Kahn topological sort).

use std::collections::{HashMap, HashSet, VecDeque};

use serde::{Deserialize, Serialize};

use crate::action::Action;
use crate::error::SoarError;
use crate::trigger::Trigger;

/// Minimum node count a workflow graph MUST declare (the trigger alone).
pub const MIN_NODES: usize = 1;

/// Maximum node count a workflow graph MAY declare.
///
/// Caps the executor's worst-case fan-out so a single workflow cannot run
/// indefinitely against the downstream ports.
pub const MAX_NODES: usize = 64;

/// One node in the workflow DAG.
///
/// Each variant carries the node-specific payload; all variants share a
/// `node_id` field used as the edge endpoint and execution-frame key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Node {
    /// Workflow entry point. There MUST be exactly one trigger node per
    /// graph.
    Trigger {
        /// Stable node id used by edges.
        id: String,
        /// Trigger predicate fired against the inbound event.
        trigger: Trigger,
    },
    /// Action node — invokes one [`Action`] through the
    /// [`crate::action::ActionRegistry`].
    Action {
        /// Stable node id used by edges.
        id: String,
        /// Action payload.
        action: Action,
    },
    /// Condition node — evaluates [`expr`](ConditionExpr) against the
    /// execution context and forwards to `then_id` or `else_id`.
    Condition {
        /// Stable node id used by edges.
        id: String,
        /// Predicate evaluated against the execution context.
        expr: ConditionExpr,
        /// Child branch followed when the predicate evaluates to `true`.
        then_id: String,
        /// Child branch followed when the predicate evaluates to `false`.
        else_id: String,
    },
    /// Parallel node — fans out to every `branches` id and waits for the
    /// full set to reach a terminal state before continuing.
    Parallel {
        /// Stable node id used by edges.
        id: String,
        /// Sibling node ids that all run concurrently.
        branches: Vec<String>,
    },
}

impl Node {
    /// Stable node id (matches the `id` field on every variant).
    #[must_use]
    pub fn id(&self) -> &str {
        match self {
            Self::Trigger { id, .. }
            | Self::Action { id, .. }
            | Self::Condition { id, .. }
            | Self::Parallel { id, .. } => id.as_str(),
        }
    }

    /// Stable variant label (`"trigger"`, `"action"`, `"condition"`,
    /// `"parallel"`). Used by the run log so the dashboard can render the
    /// node type without parsing the payload.
    #[must_use]
    pub const fn type_label(&self) -> &'static str {
        match self {
            Self::Trigger { .. } => "trigger",
            Self::Action { .. } => "action",
            Self::Condition { .. } => "condition",
            Self::Parallel { .. } => "parallel",
        }
    }
}

/// Condition predicate evaluated against the execution context.
///
/// The MVP supports four pointer-based predicates so a dashboard editor
/// can render checkbox + dropdown UI without arbitrary expression
/// support (which would invite injection bugs).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum ConditionExpr {
    /// JSON pointer + literal string equality.
    Eq {
        /// JSON pointer (RFC 6901) into the context, e.g. `/event/severity`.
        ptr: String,
        /// Literal value to compare against, as a JSON value.
        value: serde_json::Value,
    },
    /// JSON pointer's value must NOT equal the literal.
    Ne {
        /// JSON pointer (RFC 6901) into the context.
        ptr: String,
        /// Literal value to compare against.
        value: serde_json::Value,
    },
    /// Pointer's resolved value must be a string contained in `values`.
    In {
        /// JSON pointer (RFC 6901) into the context.
        ptr: String,
        /// Allowed string values.
        values: Vec<String>,
    },
    /// Pointer must resolve to a non-null, non-empty value.
    Exists {
        /// JSON pointer (RFC 6901) into the context.
        ptr: String,
    },
}

impl ConditionExpr {
    /// Evaluate the predicate against `context`. Missing pointers
    /// resolve to JSON `null`; comparisons against `null` return `false`
    /// except for [`ConditionExpr::Exists`] which returns `false`.
    #[must_use]
    pub fn evaluate(&self, context: &serde_json::Value) -> bool {
        match self {
            Self::Eq { ptr, value } => context.pointer(ptr) == Some(value),
            Self::Ne { ptr, value } => match context.pointer(ptr) {
                Some(v) => v != value,
                None => true,
            },
            Self::In { ptr, values } => match context.pointer(ptr).and_then(|v| v.as_str()) {
                Some(s) => values.iter().any(|cand| cand == s),
                None => false,
            },
            Self::Exists { ptr } => match context.pointer(ptr) {
                Some(serde_json::Value::Null) | None => false,
                Some(serde_json::Value::String(s)) => !s.is_empty(),
                Some(serde_json::Value::Array(a)) => !a.is_empty(),
                Some(serde_json::Value::Object(o)) => !o.is_empty(),
                Some(_) => true,
            },
        }
    }
}

/// Directed edge from `from` to `to`.
///
/// Edges form the DAG's adjacency list. Parallel / condition wiring is
/// also expressed as plain edges from the parent — the executor walks
/// both the edge list and the per-node child references.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Edge {
    /// Source node id.
    pub from: String,
    /// Target node id.
    pub to: String,
}

/// Persisted DAG definition.
///
/// `Serialize + Deserialize` so it round-trips through the JSON DSL stored
/// in `soar_workflows.definition` (Postgres) and the HTTP wire form.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkflowGraph {
    /// All nodes keyed by `Node::id`. Order is preserved on disk so a
    /// dashboard editor can reconstruct the user's intent.
    pub nodes: Vec<Node>,
    /// Directed edges between node ids.
    pub edges: Vec<Edge>,
}

impl WorkflowGraph {
    /// Stable lookup of `node_id` → [`Node`]. Returns `None` when the id
    /// is not declared.
    #[must_use]
    pub fn node(&self, id: &str) -> Option<&Node> {
        self.nodes.iter().find(|n| n.id() == id)
    }

    /// Adjacency list keyed by node id. Useful for the DAG executor and
    /// for the cycle-detection routine.
    pub fn adjacency(&self) -> HashMap<String, Vec<String>> {
        let mut adj: HashMap<String, Vec<String>> = HashMap::new();
        for node in &self.nodes {
            adj.entry(node.id().to_owned()).or_default();
        }
        for edge in &self.edges {
            adj.entry(edge.from.clone())
                .or_default()
                .push(edge.to.clone());
        }
        adj
    }

    /// Semantic validator.
    ///
    /// Enforces:
    ///
    /// * `nodes.len() ∈ MIN_NODES..=MAX_NODES`;
    /// * exactly one [`Node::Trigger`];
    /// * every node id is unique;
    /// * every edge endpoint references a real node;
    /// * every [`Node::Condition::then_id`] / `else_id` references a
    ///   real node;
    /// * every [`Node::Parallel::branches`] id references a real node
    ///   and the branches set is non-empty;
    /// * the graph is acyclic (Kahn topological sort consumes every
    ///   node).
    pub fn validate(&self) -> Result<(), SoarError> {
        if self.nodes.len() < MIN_NODES {
            return Err(SoarError::invalid(format!(
                "graph must have at least {MIN_NODES} node",
            )));
        }
        if self.nodes.len() > MAX_NODES {
            return Err(SoarError::invalid(format!(
                "graph must have at most {MAX_NODES} nodes",
            )));
        }
        // Unique ids.
        let mut seen = HashSet::new();
        for node in &self.nodes {
            let id = node.id();
            if id.trim().is_empty() {
                return Err(SoarError::invalid("node id must not be empty"));
            }
            if !seen.insert(id.to_owned()) {
                return Err(SoarError::invalid(format!("duplicate node id: {id}")));
            }
        }
        // Exactly one trigger.
        let triggers = self
            .nodes
            .iter()
            .filter(|n| matches!(n, Node::Trigger { .. }))
            .count();
        if triggers != 1 {
            return Err(SoarError::invalid(format!(
                "graph must declare exactly one trigger node, got {triggers}",
            )));
        }
        // Per-node consistency.
        let ids: HashSet<&str> = self.nodes.iter().map(Node::id).collect();
        for node in &self.nodes {
            match node {
                Node::Condition {
                    id,
                    then_id,
                    else_id,
                    ..
                } => {
                    if !ids.contains(then_id.as_str()) {
                        return Err(SoarError::invalid(format!(
                            "node {id}: then_id {then_id} does not exist",
                        )));
                    }
                    if !ids.contains(else_id.as_str()) {
                        return Err(SoarError::invalid(format!(
                            "node {id}: else_id {else_id} does not exist",
                        )));
                    }
                }
                Node::Parallel { id, branches } => {
                    if branches.is_empty() {
                        return Err(SoarError::invalid(format!(
                            "node {id}: parallel branches must not be empty",
                        )));
                    }
                    for b in branches {
                        if !ids.contains(b.as_str()) {
                            return Err(SoarError::invalid(format!(
                                "node {id}: branch {b} does not exist",
                            )));
                        }
                    }
                }
                Node::Action { action, id } => {
                    validate_action(id, action)?;
                }
                Node::Trigger { .. } => {}
            }
        }
        // Edge endpoints must reference real nodes.
        for edge in &self.edges {
            if !ids.contains(edge.from.as_str()) {
                return Err(SoarError::invalid(format!(
                    "edge from {} references unknown node",
                    edge.from
                )));
            }
            if !ids.contains(edge.to.as_str()) {
                return Err(SoarError::invalid(format!(
                    "edge to {} references unknown node",
                    edge.to
                )));
            }
        }
        // Cycle detection via Kahn topological sort.
        detect_cycles(self)?;
        Ok(())
    }

    /// Kahn topological sort. Returns node ids in execution order — the
    /// trigger is guaranteed to be first.
    ///
    /// MUST be called after [`Self::validate`]; otherwise the cycle
    /// detector inside this function returns [`SoarError::InvalidDefinition`].
    pub fn topological_order(&self) -> Result<Vec<String>, SoarError> {
        let mut in_degree: HashMap<String, usize> = HashMap::new();
        let adj = self.adjacency();
        for node in &self.nodes {
            in_degree.entry(node.id().to_owned()).or_insert(0);
        }
        for edge in &self.edges {
            *in_degree.entry(edge.to.clone()).or_insert(0) += 1;
        }
        // Make order deterministic — trigger first, then alphabetical.
        let mut ordered: Vec<String> = in_degree
            .iter()
            .filter(|(_, deg)| **deg == 0)
            .map(|(id, _)| id.clone())
            .collect();
        ordered.sort();
        if let Some(trigger_id) = self
            .nodes
            .iter()
            .find(|n| matches!(n, Node::Trigger { .. }))
            .map(|n| n.id().to_owned())
        {
            ordered.sort_by(|a, b| {
                if a == &trigger_id {
                    std::cmp::Ordering::Less
                } else if b == &trigger_id {
                    std::cmp::Ordering::Greater
                } else {
                    a.cmp(b)
                }
            });
        }
        let mut queue: VecDeque<String> = ordered.into();
        let mut out: Vec<String> = Vec::with_capacity(self.nodes.len());
        while let Some(id) = queue.pop_front() {
            out.push(id.clone());
            if let Some(children) = adj.get(&id) {
                let mut next_ready: Vec<String> = Vec::new();
                for child in children {
                    if let Some(deg) = in_degree.get_mut(child) {
                        *deg = deg.saturating_sub(1);
                        if *deg == 0 {
                            next_ready.push(child.clone());
                        }
                    }
                }
                next_ready.sort();
                for r in next_ready {
                    queue.push_back(r);
                }
            }
        }
        if out.len() != self.nodes.len() {
            return Err(SoarError::invalid("graph contains a cycle"));
        }
        Ok(out)
    }
}

/// Per-action shape validator. Surfaces the offending node id in the
/// error message so the dashboard can highlight the failing step.
fn validate_action(node_id: &str, action: &Action) -> Result<(), SoarError> {
    match action {
        Action::HttpRequest { method, url, .. } => {
            if method.trim().is_empty() {
                return Err(SoarError::invalid(format!(
                    "node {node_id}: http_request.method must not be empty",
                )));
            }
            if url.trim().is_empty() {
                return Err(SoarError::invalid(format!(
                    "node {node_id}: http_request.url must not be empty",
                )));
            }
        }
        Action::RunRemediationPlay { play_id, .. } => {
            if play_id.trim().is_empty() {
                return Err(SoarError::invalid(format!(
                    "node {node_id}: run_remediation_play.play_id must not be empty",
                )));
            }
        }
        Action::EmitWebhook { topic, .. } => {
            if topic.trim().is_empty() {
                return Err(SoarError::invalid(format!(
                    "node {node_id}: emit_webhook.topic must not be empty",
                )));
            }
        }
        Action::Noop { .. } => {}
    }
    Ok(())
}

/// Free-standing Kahn cycle check used by [`WorkflowGraph::validate`].
fn detect_cycles(graph: &WorkflowGraph) -> Result<(), SoarError> {
    let mut in_degree: HashMap<String, usize> = HashMap::new();
    let adj = graph.adjacency();
    for node in &graph.nodes {
        in_degree.entry(node.id().to_owned()).or_insert(0);
    }
    for edge in &graph.edges {
        *in_degree.entry(edge.to.clone()).or_insert(0) += 1;
    }
    let mut queue: VecDeque<String> = in_degree
        .iter()
        .filter(|(_, d)| **d == 0)
        .map(|(id, _)| id.clone())
        .collect();
    let mut visited = 0usize;
    while let Some(id) = queue.pop_front() {
        visited += 1;
        if let Some(children) = adj.get(&id) {
            for child in children {
                if let Some(deg) = in_degree.get_mut(child) {
                    *deg = deg.saturating_sub(1);
                    if *deg == 0 {
                        queue.push_back(child.clone());
                    }
                }
            }
        }
    }
    if visited != graph.nodes.len() {
        return Err(SoarError::invalid("graph contains a cycle"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trigger::Severity;

    fn three_step() -> WorkflowGraph {
        WorkflowGraph {
            nodes: vec![
                Node::Trigger {
                    id: "t1".into(),
                    trigger: Trigger::Any,
                },
                Node::Action {
                    id: "a1".into(),
                    action: Action::HttpRequest {
                        method: "POST".into(),
                        url: "https://example.com".into(),
                        headers: HashMap::new(),
                        body: None,
                    },
                },
                Node::Action {
                    id: "a2".into(),
                    action: Action::EmitWebhook {
                        topic: "soar.demo".into(),
                        payload: None,
                    },
                },
            ],
            edges: vec![
                Edge {
                    from: "t1".into(),
                    to: "a1".into(),
                },
                Edge {
                    from: "a1".into(),
                    to: "a2".into(),
                },
            ],
        }
    }

    #[test]
    fn three_step_graph_validates() {
        let g = three_step();
        assert!(g.validate().is_ok());
        let order = g.topological_order().unwrap();
        assert_eq!(order, vec!["t1".to_owned(), "a1".into(), "a2".into()]);
    }

    #[test]
    fn cycle_is_detected() {
        let mut g = three_step();
        g.edges.push(Edge {
            from: "a2".into(),
            to: "a1".into(),
        });
        let err = g.validate().unwrap_err();
        match err {
            SoarError::InvalidDefinition(msg) => assert!(msg.contains("cycle")),
            other => panic!("expected InvalidDefinition, got {other:?}"),
        }
    }

    #[test]
    fn missing_trigger_rejected() {
        let g = WorkflowGraph {
            nodes: vec![Node::Action {
                id: "a1".into(),
                action: Action::Noop { tag: "x".into() },
            }],
            edges: vec![],
        };
        let err = g.validate().unwrap_err();
        assert!(matches!(err, SoarError::InvalidDefinition(_)));
    }

    #[test]
    fn duplicate_id_rejected() {
        let g = WorkflowGraph {
            nodes: vec![
                Node::Trigger {
                    id: "x".into(),
                    trigger: Trigger::Any,
                },
                Node::Action {
                    id: "x".into(),
                    action: Action::Noop { tag: "y".into() },
                },
            ],
            edges: vec![],
        };
        let err = g.validate().unwrap_err();
        match err {
            SoarError::InvalidDefinition(msg) => assert!(msg.contains("duplicate")),
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn dangling_edge_rejected() {
        let mut g = three_step();
        g.edges.push(Edge {
            from: "a2".into(),
            to: "ghost".into(),
        });
        let err = g.validate().unwrap_err();
        assert!(matches!(err, SoarError::InvalidDefinition(_)));
    }

    #[test]
    fn condition_branch_validation() {
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
                    then_id: "ok".into(),
                    else_id: "bad".into(),
                },
                Node::Action {
                    id: "ok".into(),
                    action: Action::Noop { tag: "ok".into() },
                },
            ],
            edges: vec![Edge {
                from: "t".into(),
                to: "c".into(),
            }],
        };
        let err = g.validate().unwrap_err();
        assert!(matches!(err, SoarError::InvalidDefinition(_)));
    }

    #[test]
    fn condition_eq_evaluates() {
        let ctx = serde_json::json!({"event": {"severity": "critical"}});
        let e = ConditionExpr::Eq {
            ptr: "/event/severity".into(),
            value: serde_json::json!("critical"),
        };
        assert!(e.evaluate(&ctx));
        let e2 = ConditionExpr::Eq {
            ptr: "/event/severity".into(),
            value: serde_json::json!("low"),
        };
        assert!(!e2.evaluate(&ctx));
    }

    #[test]
    fn condition_exists_treats_empty_as_false() {
        let ctx = serde_json::json!({"a": "", "b": "x"});
        assert!(!ConditionExpr::Exists { ptr: "/a".into() }.evaluate(&ctx));
        assert!(ConditionExpr::Exists { ptr: "/b".into() }.evaluate(&ctx));
        assert!(!ConditionExpr::Exists {
            ptr: "/missing".into()
        }
        .evaluate(&ctx));
    }

    #[test]
    fn finding_severity_filter_still_works() {
        let t = Trigger::FindingCreated {
            min_severity: Severity::High,
        };
        assert!(t.matches(&crate::trigger::TriggerEvent::FindingCreated {
            finding_id: "f".into(),
            severity: Severity::Critical,
            payload: serde_json::Value::Null,
        }));
    }
}
