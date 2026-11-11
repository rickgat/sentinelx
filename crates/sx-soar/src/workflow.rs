//! `Workflow` — the persisted unit produced by the SOAR builder.
//!
//! A workflow couples an operator-defined [`WorkflowGraph`] to multi-tenant
//! ownership metadata. The semantic validator delegates to
//! [`WorkflowGraph::validate`] for structural checks and adds the
//! display-name length bound.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::SoarError;
use crate::graph::WorkflowGraph;

/// Maximum length of a workflow's display name.
pub const MAX_NAME_LEN: usize = 200;

/// A persisted SOAR workflow.
///
/// `Serialize + Deserialize` so it round-trips through the JSON DSL stored
/// in `soar_workflows.definition` (Postgres) and the HTTP wire form.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Workflow {
    /// Stable workflow uuid. Set by the [`crate::service::SoarService`]
    /// adapter at creation time.
    pub id: Uuid,
    /// Tenant uuid that owns the workflow. Backs the Postgres RLS policy
    /// (`soar_workflows.tenant_id`) when persistence lands.
    pub tenant_id: Uuid,
    /// Human-readable display name. Bounded `1..=MAX_NAME_LEN` chars at
    /// validation time.
    pub name: String,
    /// Persisted DAG definition.
    pub definition: WorkflowGraph,
    /// Whether the workflow is dispatched on inbound events.
    pub enabled: bool,
}

impl Workflow {
    /// Semantic validator.
    ///
    /// Enforces:
    /// * `name` is non-empty and at most `MAX_NAME_LEN` chars.
    /// * The DAG passes [`WorkflowGraph::validate`].
    ///
    /// Run by both the HTTP controller (after `serde` succeeds) and the
    /// in-memory store (defence in depth).
    pub fn validate(&self) -> Result<(), SoarError> {
        let trimmed = self.name.trim().len();
        if trimmed == 0 {
            return Err(SoarError::invalid("name must not be empty"));
        }
        if self.name.len() > MAX_NAME_LEN {
            return Err(SoarError::invalid(format!(
                "name must be at most {MAX_NAME_LEN} chars",
            )));
        }
        self.definition.validate()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::Action;
    use crate::graph::{Edge, Node};
    use crate::trigger::Trigger;

    fn linear_graph() -> WorkflowGraph {
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
    fn empty_name_rejected() {
        let w = Workflow {
            id: Uuid::nil(),
            tenant_id: Uuid::nil(),
            name: "  ".into(),
            definition: linear_graph(),
            enabled: true,
        };
        assert!(matches!(w.validate(), Err(SoarError::InvalidDefinition(_))));
    }

    #[test]
    fn good_workflow_passes() {
        let w = Workflow {
            id: Uuid::nil(),
            tenant_id: Uuid::nil(),
            name: "demo".into(),
            definition: linear_graph(),
            enabled: true,
        };
        assert!(w.validate().is_ok());
    }
}
