//! Attack-path domain types.
//!
//! An [`AttackPath`] is a sequence of [`NodeId`]s in
//! traversal order, together with a numeric score that the use-case
//! layer interprets (lower-better for "shortest path", higher-better
//! for "highest-risk path").

use serde::{Deserialize, Serialize};

use crate::model::node::NodeId;

/// One concrete attack path discovered by a [`crate::port::KnowledgeGraph`]
/// implementation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AttackPath {
    /// Stable identifier for the path. Adapters typically hash the
    /// concatenated node ids; tests rely on equality, not on a
    /// particular hash function.
    pub id: String,
    /// Ordered sequence of nodes from the entry asset (front) to the
    /// crown-jewel target (back).
    pub nodes: Vec<NodeId>,
    /// Backend-computed score. Larger values denote riskier paths in
    /// the canonical Cypher query.
    pub score: f64,
}

impl AttackPath {
    /// Number of hops (edges) in the path. For a path with `n` nodes,
    /// the hop count is `n - 1` (saturating, so the empty/single-node
    /// case returns `0`).
    #[must_use]
    pub const fn hop_count(&self) -> usize {
        self.nodes.len().saturating_sub(1)
    }

    /// Build a deterministic path identifier by joining node ids with
    /// `"->"`.
    #[must_use]
    pub fn synthesize_id(nodes: &[NodeId]) -> String {
        nodes
            .iter()
            .map(NodeId::as_str)
            .collect::<Vec<_>>()
            .join("->")
    }
}

/// Result of a risk-propagation computation along an attack path.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PropagatedRisk {
    /// Identifier of the path the score belongs to.
    pub path_id: String,
    /// Composite score for the whole path.
    pub composite_score: f64,
    /// Id of the bottleneck node — the single highest-risk node along
    /// the path. Removing this node typically yields the largest
    /// reduction in composite risk.
    pub bottleneck_node_id: NodeId,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn hop_count_basic() {
        let p = AttackPath {
            id: "p".into(),
            nodes: vec![NodeId::new("a"), NodeId::new("b"), NodeId::new("c")],
            score: 1.0,
        };
        assert_eq!(p.hop_count(), 2);
    }

    #[test]
    fn synthesize_id_uses_arrow() {
        let nodes = vec![NodeId::new("a"), NodeId::new("b"), NodeId::new("c")];
        assert_eq!(AttackPath::synthesize_id(&nodes), "a->b->c");
    }

    #[test]
    fn empty_path_hop_count_is_zero() {
        let p = AttackPath {
            id: "x".into(),
            nodes: vec![],
            score: 0.0,
        };
        assert_eq!(p.hop_count(), 0);
    }
}
