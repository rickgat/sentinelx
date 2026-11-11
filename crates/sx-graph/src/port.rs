//! Port: abstraction over a knowledge-graph backend.
//!
//! The [`KnowledgeGraph`] trait is the boundary between application
//! logic (the [`crate::controller`] layer) and a concrete graph store
//! ([`crate::service::Neo4jKnowledgeGraph`] or
//! [`crate::service::InMemoryKnowledgeGraph`]).

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sx_core::value_object::ids::TenantId;

use crate::error::GraphError;
use crate::model::attack_path::{AttackPath, PropagatedRisk};
use crate::model::edge::GraphEdge;
use crate::model::node::{GraphNode, NodeId, NodeKind};

/// Hard upper bound on the requested traversal depth in
/// [`AttackPathQuery`].
pub const MAX_ATTACK_PATH_DEPTH: u8 = 10;

/// Hard upper bound on the number of paths the backend will return
/// for one [`AttackPathQuery`].
pub const MAX_ATTACK_PATHS: u32 = 200;

/// Parameters for [`KnowledgeGraph::find_attack_paths`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttackPathQuery {
    /// Tenant to scope the query to.
    pub tenant_id: TenantId,
    /// Kind of node to use as the path entry — typically
    /// [`NodeKind::Asset`] with `exposure='EXTERNAL'`.
    pub entry_kind: NodeKind,
    /// Kind of node the path must terminate on — typically
    /// [`NodeKind::Asset`] with `criticality='CROWN_JEWEL'`.
    pub target_kind: NodeKind,
    /// Maximum traversal depth (edges). MUST be `<= 10`.
    pub max_depth: u8,
    /// Maximum number of paths to return. MUST be `<= 200`.
    pub max_paths: u32,
}

impl AttackPathQuery {
    /// Validate the user-supplied bounds.
    ///
    /// Returns [`GraphError::InvalidQuery`] if `max_depth >
    /// MAX_ATTACK_PATH_DEPTH` or `max_paths > MAX_ATTACK_PATHS`.
    pub fn validate(&self) -> Result<(), GraphError> {
        if self.max_depth == 0 {
            return Err(GraphError::invalid_query("max_depth must be >= 1"));
        }
        if self.max_depth > MAX_ATTACK_PATH_DEPTH {
            return Err(GraphError::invalid_query(format!(
                "max_depth {} exceeds limit {MAX_ATTACK_PATH_DEPTH}",
                self.max_depth,
            )));
        }
        if self.max_paths == 0 {
            return Err(GraphError::invalid_query("max_paths must be >= 1"));
        }
        if self.max_paths > MAX_ATTACK_PATHS {
            return Err(GraphError::invalid_query(format!(
                "max_paths {} exceeds limit {MAX_ATTACK_PATHS}",
                self.max_paths,
            )));
        }
        Ok(())
    }
}

/// Async port over a knowledge-graph backend.
#[async_trait]
pub trait KnowledgeGraph: Send + Sync + std::fmt::Debug {
    /// Upsert a node, keyed by `node.id()`.
    async fn upsert_node(&self, node: &GraphNode) -> Result<(), GraphError>;

    /// Upsert an edge between two existing nodes.
    async fn upsert_edge(&self, edge: &GraphEdge) -> Result<(), GraphError>;

    /// Find attack paths matching `query`.
    async fn find_attack_paths(
        &self,
        query: &AttackPathQuery,
    ) -> Result<Vec<AttackPath>, GraphError>;

    /// Compute the propagated-risk roll-up for a specific previously
    /// discovered path.
    async fn compute_risk_propagation(&self, path_id: &str) -> Result<PropagatedRisk, GraphError>;

    /// Return all nodes reachable from `node_id` within `depth` hops.
    /// The returned list includes `node_id` itself.
    async fn neighbors(&self, node_id: &NodeId, depth: u8) -> Result<Vec<GraphNode>, GraphError>;
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn base_query() -> AttackPathQuery {
        AttackPathQuery {
            tenant_id: TenantId::new(),
            entry_kind: NodeKind::Asset,
            target_kind: NodeKind::Asset,
            max_depth: 5,
            max_paths: 100,
        }
    }

    #[test]
    fn attack_path_query_accepts_valid() {
        assert!(base_query().validate().is_ok());
    }

    #[test]
    fn attack_path_query_rejects_excessive_depth() {
        let mut q = base_query();
        q.max_depth = 11;
        assert!(q.validate().is_err());
    }

    #[test]
    fn attack_path_query_rejects_excessive_paths() {
        let mut q = base_query();
        q.max_paths = 201;
        assert!(q.validate().is_err());
    }

    #[test]
    fn attack_path_query_rejects_zero_depth() {
        let mut q = base_query();
        q.max_depth = 0;
        assert!(q.validate().is_err());
    }

    #[test]
    fn attack_path_query_rejects_zero_paths() {
        let mut q = base_query();
        q.max_paths = 0;
        assert!(q.validate().is_err());
    }
}
