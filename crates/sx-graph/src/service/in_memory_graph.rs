//! In-memory implementation of [`KnowledgeGraph`].
//!
//! Backed by [`tokio::sync::RwLock`] over a node table plus an
//! adjacency list. Used by unit tests across the workspace and by the
//! single-binary dev mode where running Neo4j is unwanted.
//!
//! ## Attack-path discovery
//!
//! The in-memory adapter implements a bounded breadth-first search
//! that pattern-matches the same canonical chain as the production
//! Cypher query:
//!
//! `Asset(entry, exposure=Internet) -[HAS_FINDING]→ Finding(Critical)
//!   -[ENABLES]→ Technique -[CHAINS_TO]→* Technique
//!   -[REACHES]→* Asset(target, criticality=CrownJewel)`
//!
//! The depth bound applies to the number of `CHAINS_TO` hops plus the
//! `REACHES` tail, matching the Neo4j semantics closely enough for
//! tests and small dev graphs.

// The intentional drop-scope blocks below hold an RwLock guard for
// the body that needs synchronized access; clippy's
// `significant_drop_tightening` suggestion does not apply because we
// already wrap the guard in a tight `{ ... }` block.
#![allow(clippy::significant_drop_tightening)]

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::RwLock;
use tracing::{debug, instrument};

use sx_core::value_object::criticality::AssetCriticality;
use sx_core::value_object::exposure::ExposureLevel;
use sx_core::value_object::severity::Severity;

use crate::error::GraphError;
use crate::model::attack_path::{AttackPath, PropagatedRisk};
use crate::model::edge::{EdgeKind, GraphEdge};
use crate::model::node::{GraphNode, NodeId};
use crate::port::{AttackPathQuery, KnowledgeGraph};

/// Internal record of a stored edge — `kind` plus destination, with
/// the optional property bag.
#[derive(Debug, Clone, PartialEq)]
struct EdgeRecord {
    kind: EdgeKind,
    to: NodeId,
    properties: Option<serde_json::Value>,
}

/// In-memory graph store.
///
/// Cloning the value is cheap: the underlying maps live behind an
/// [`Arc<RwLock<_>>`].
#[derive(Debug, Clone, Default)]
pub struct InMemoryKnowledgeGraph {
    inner: Arc<RwLock<Inner>>,
}

#[derive(Debug, Default)]
struct Inner {
    nodes: HashMap<NodeId, GraphNode>,
    /// `from -> [EdgeRecord(to)]`.
    edges_out: HashMap<NodeId, Vec<EdgeRecord>>,
    /// Stored paths keyed by [`AttackPath::id`] so
    /// `compute_risk_propagation` has something to roll up.
    paths: HashMap<String, AttackPath>,
}

impl InMemoryKnowledgeGraph {
    /// Build an empty in-memory graph.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot the number of nodes currently stored. Test helper.
    pub async fn node_count(&self) -> usize {
        self.inner.read().await.nodes.len()
    }

    /// Snapshot the number of edges currently stored. Test helper.
    pub async fn edge_count(&self) -> usize {
        self.inner
            .read()
            .await
            .edges_out
            .values()
            .map(Vec::len)
            .sum()
    }

    /// Convenience accessor used by the risk-propagation use-case
    /// when the path was discovered in this same process.
    pub async fn store_path(&self, path: AttackPath) {
        self.inner.write().await.paths.insert(path.id.clone(), path);
    }
}

#[async_trait]
impl KnowledgeGraph for InMemoryKnowledgeGraph {
    #[instrument(skip(self), fields(kind = %node.kind(), id = %node.id()))]
    async fn upsert_node(&self, node: &GraphNode) -> Result<(), GraphError> {
        {
            let mut g = self.inner.write().await;
            g.nodes.insert(node.id().clone(), node.clone());
        }
        debug!("upsert_node");
        Ok(())
    }

    #[instrument(skip(self), fields(kind = %edge.kind, from = %edge.from, to = %edge.to))]
    async fn upsert_edge(&self, edge: &GraphEdge) -> Result<(), GraphError> {
        {
            let mut g = self.inner.write().await;
            let bucket = g.edges_out.entry(edge.from.clone()).or_default();
            if let Some(slot) = bucket
                .iter_mut()
                .find(|e| e.kind == edge.kind && e.to == edge.to)
            {
                slot.properties.clone_from(&edge.properties);
            } else {
                bucket.push(EdgeRecord {
                    kind: edge.kind,
                    to: edge.to.clone(),
                    properties: edge.properties.clone(),
                });
            }
        }
        debug!("upsert_edge");
        Ok(())
    }

    #[instrument(skip(self))]
    async fn find_attack_paths(
        &self,
        query: &AttackPathQuery,
    ) -> Result<Vec<AttackPath>, GraphError> {
        query.validate()?;
        let max_paths_usize = query.max_paths as usize;
        let max_depth_usize = query.max_depth as usize;
        let mut found: Vec<AttackPath> = {
            let snapshot = self.inner.read().await;
            let mut acc: Vec<AttackPath> = Vec::new();

            // Collect candidate entry assets: matching tenant +
            // Internet-exposed (closest analogue of EXTERNAL).
            let entries: Vec<&GraphNode> = snapshot
                .nodes
                .values()
                .filter(|n| match n {
                    GraphNode::Asset(a) => {
                        a.tenant_id == query.tenant_id
                            && a.exposure == ExposureLevel::Internet
                            && n.kind() == query.entry_kind
                    }
                    _ => false,
                })
                .collect();

            for entry in entries {
                let entry_id = entry.id().clone();
                let mut queue: VecDeque<(Vec<NodeId>, usize)> = VecDeque::new();
                queue.push_back((vec![entry_id], 0));

                while let Some((path, depth)) = queue.pop_front() {
                    if acc.len() >= max_paths_usize {
                        break;
                    }
                    if depth >= max_depth_usize {
                        continue;
                    }
                    let Some(last) = path.last().cloned() else {
                        continue;
                    };
                    let outgoing = snapshot.edges_out.get(&last).cloned().unwrap_or_default();
                    for e in outgoing {
                        if path.contains(&e.to) {
                            continue;
                        }
                        let Some(next_node) = snapshot.nodes.get(&e.to) else {
                            continue;
                        };
                        if !path_step_allowed(&path, &snapshot, e.kind, next_node) {
                            continue;
                        }
                        let mut new_path = path.clone();
                        new_path.push(e.to.clone());

                        if next_node.kind() == query.target_kind
                            && is_crown_jewel(next_node, &query.tenant_id)
                        {
                            let score = score_path(&snapshot, &new_path);
                            let id = AttackPath::synthesize_id(&new_path);
                            acc.push(AttackPath {
                                id,
                                nodes: new_path,
                                score,
                            });
                            continue;
                        }
                        queue.push_back((new_path, depth + 1));
                    }
                }
            }
            acc
        };

        found.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        found.truncate(max_paths_usize);

        {
            let mut writer = self.inner.write().await;
            for p in &found {
                writer.paths.insert(p.id.clone(), p.clone());
            }
        }
        Ok(found)
    }

    #[instrument(skip(self))]
    async fn compute_risk_propagation(&self, path_id: &str) -> Result<PropagatedRisk, GraphError> {
        let (path, scores): (AttackPath, Vec<(NodeId, f64)>) = {
            let snapshot = self.inner.read().await;
            let path =
                snapshot
                    .paths
                    .get(path_id)
                    .cloned()
                    .ok_or_else(|| GraphError::NotFound {
                        kind: "AttackPath",
                        id: path_id.to_owned(),
                    })?;
            if path.nodes.is_empty() {
                return Err(GraphError::invalid_query("path has no nodes"));
            }
            let scores: Vec<(NodeId, f64)> = path
                .nodes
                .iter()
                .map(|id| {
                    let s = snapshot.nodes.get(id).map_or(0.0, GraphNode::risk_score);
                    (id.clone(), s)
                })
                .collect();
            (path, scores)
        };

        let mut composite = 0.0_f64;
        let mut bottleneck_id: Option<NodeId> = None;
        let mut bottleneck_score = f64::NEG_INFINITY;
        for (id, s) in &scores {
            composite += *s;
            if *s > bottleneck_score {
                bottleneck_score = *s;
                bottleneck_id = Some(id.clone());
            }
        }
        let bottleneck_node_id = bottleneck_id.unwrap_or_else(|| {
            path.nodes
                .first()
                .cloned()
                .unwrap_or_else(|| NodeId::new(""))
        });
        Ok(PropagatedRisk {
            path_id: path.id,
            composite_score: composite,
            bottleneck_node_id,
        })
    }

    #[instrument(skip(self))]
    async fn neighbors(&self, node_id: &NodeId, depth: u8) -> Result<Vec<GraphNode>, GraphError> {
        let out: Vec<GraphNode> = {
            let snapshot = self.inner.read().await;
            if !snapshot.nodes.contains_key(node_id) {
                return Err(GraphError::NotFound {
                    kind: "Node",
                    id: node_id.to_string(),
                });
            }
            let mut visited: Vec<NodeId> = vec![node_id.clone()];
            let mut frontier: Vec<NodeId> = vec![node_id.clone()];
            for _ in 0..depth {
                let mut next: Vec<NodeId> = Vec::new();
                for f in &frontier {
                    if let Some(edges) = snapshot.edges_out.get(f) {
                        for e in edges {
                            if !visited.contains(&e.to) {
                                visited.push(e.to.clone());
                                next.push(e.to.clone());
                            }
                        }
                    }
                }
                if next.is_empty() {
                    break;
                }
                frontier = next;
            }
            let mut collected = Vec::with_capacity(visited.len());
            for id in &visited {
                if let Some(n) = snapshot.nodes.get(id) {
                    collected.push(n.clone());
                }
            }
            collected
        };
        Ok(out)
    }
}

fn is_crown_jewel(node: &GraphNode, tenant_id: &sx_core::value_object::ids::TenantId) -> bool {
    matches!(
        node,
        GraphNode::Asset(a)
            if a.tenant_id == *tenant_id
                && a.criticality == AssetCriticality::CrownJewel
    )
}

/// Lightweight pattern check on path edges. Encodes the
/// `Asset → Finding(Critical) → Technique → … → Asset(CrownJewel)`
/// shape from the production Cypher.
fn path_step_allowed(
    current_path: &[NodeId],
    snapshot: &Inner,
    next_kind: EdgeKind,
    next_node: &GraphNode,
) -> bool {
    let is_first_hop = current_path.len() == 1;
    match (is_first_hop, next_kind, next_node) {
        // First hop: Asset -[HAS_FINDING]-> Finding(Critical)
        (true, EdgeKind::HasFinding, GraphNode::Finding(f)) => f.severity == Severity::Critical,
        // Second hop: Finding -[ENABLES]-> Technique
        (false, EdgeKind::Enables, GraphNode::Technique(_))
            if previous_is_finding(current_path, snapshot) =>
        {
            true
        }
        // Technique chain or closing reach edge.
        (
            false,
            EdgeKind::ChainsTo | EdgeKind::Reaches,
            GraphNode::Technique(_) | GraphNode::Asset(_),
        ) => true,
        _ => false,
    }
}

fn previous_is_finding(path: &[NodeId], snapshot: &Inner) -> bool {
    let Some(last) = path.last() else {
        return false;
    };
    matches!(snapshot.nodes.get(last), Some(GraphNode::Finding(_)))
}

fn score_path(snapshot: &Inner, path: &[NodeId]) -> f64 {
    path.iter()
        .filter_map(|id| snapshot.nodes.get(id))
        .map(GraphNode::risk_score)
        .sum()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::collections::BTreeMap;

    use sx_core::value_object::ids::TenantId;

    use super::*;
    use crate::model::node::{GraphAsset, GraphFinding, GraphTechnique, NodeKind};

    fn tenant() -> TenantId {
        TenantId::new()
    }

    fn entry_asset(t: TenantId, id: &str) -> GraphNode {
        GraphNode::Asset(GraphAsset {
            id: NodeId::new(id),
            tenant_id: t,
            name: "entry".into(),
            exposure: ExposureLevel::Internet,
            criticality: AssetCriticality::Production,
            risk_score: Some(1.0),
            properties: BTreeMap::new(),
        })
    }

    fn crown_asset(t: TenantId, id: &str) -> GraphNode {
        GraphNode::Asset(GraphAsset {
            id: NodeId::new(id),
            tenant_id: t,
            name: "crown".into(),
            exposure: ExposureLevel::Internal,
            criticality: AssetCriticality::CrownJewel,
            risk_score: Some(5.0),
            properties: BTreeMap::new(),
        })
    }

    fn finding(t: TenantId, id: &str, asset_id: &str) -> GraphNode {
        GraphNode::Finding(GraphFinding {
            id: NodeId::new(id),
            tenant_id: t,
            asset_id: NodeId::new(asset_id),
            rule_id: "r1".into(),
            title: "critical".into(),
            severity: Severity::Critical,
            risk_score: 9.0,
        })
    }

    fn technique(id: &str) -> GraphNode {
        GraphNode::Technique(GraphTechnique {
            id: NodeId::new(id),
            name: "exploit_public_facing".into(),
            tactic: "initial_access".into(),
        })
    }

    #[tokio::test]
    async fn in_memory_upsert_node_idempotent() {
        let g = InMemoryKnowledgeGraph::new();
        let n = entry_asset(tenant(), "a1");
        g.upsert_node(&n).await.unwrap();
        g.upsert_node(&n).await.unwrap();
        assert_eq!(g.node_count().await, 1);
    }

    #[tokio::test]
    async fn in_memory_upsert_edge_idempotent() {
        let g = InMemoryKnowledgeGraph::new();
        let t = tenant();
        g.upsert_node(&entry_asset(t, "a")).await.unwrap();
        g.upsert_node(&finding(t, "f", "a")).await.unwrap();
        let edge = GraphEdge::new(EdgeKind::HasFinding, NodeId::new("a"), NodeId::new("f"));
        g.upsert_edge(&edge).await.unwrap();
        g.upsert_edge(&edge).await.unwrap();
        assert_eq!(g.edge_count().await, 1);
    }

    fn build_simple_chain(t: TenantId) -> InMemoryKnowledgeGraph {
        let g = InMemoryKnowledgeGraph::new();
        let entry = entry_asset(t, "entry");
        let f = finding(t, "find1", "entry");
        let tech = technique("T1");
        let crown = crown_asset(t, "crown");

        let entry_id = entry.id().clone();
        let f_id = f.id().clone();
        let t_id = tech.id().clone();
        let crown_id = crown.id().clone();

        let g_clone = g.clone();
        tokio::task::block_in_place(|| {
            let rt = tokio::runtime::Handle::current();
            rt.block_on(async {
                g_clone.upsert_node(&entry).await.unwrap();
                g_clone.upsert_node(&f).await.unwrap();
                g_clone.upsert_node(&tech).await.unwrap();
                g_clone.upsert_node(&crown).await.unwrap();
                g_clone
                    .upsert_edge(&GraphEdge::new(
                        EdgeKind::HasFinding,
                        entry_id.clone(),
                        f_id.clone(),
                    ))
                    .await
                    .unwrap();
                g_clone
                    .upsert_edge(&GraphEdge::new(EdgeKind::Enables, f_id, t_id.clone()))
                    .await
                    .unwrap();
                g_clone
                    .upsert_edge(&GraphEdge::reaches(t_id, crown_id, 443, "tcp"))
                    .await
                    .unwrap();
            });
        });
        g
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn in_memory_find_attack_paths_basic() {
        let t = tenant();
        let g = build_simple_chain(t);
        let query = AttackPathQuery {
            tenant_id: t,
            entry_kind: NodeKind::Asset,
            target_kind: NodeKind::Asset,
            max_depth: 5,
            max_paths: 10,
        };
        let paths = g.find_attack_paths(&query).await.unwrap();
        assert_eq!(paths.len(), 1, "expected one path, got {paths:?}");
        let p = paths.first().expect("at least one path");
        assert_eq!(p.nodes.len(), 4);
        assert_eq!(p.nodes.first().unwrap().as_str(), "entry");
        assert_eq!(p.nodes.last().unwrap().as_str(), "crown");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn in_memory_find_attack_paths_respects_max_paths() {
        let t = tenant();
        let g = InMemoryKnowledgeGraph::new();
        for i in 0..3 {
            let entry_id = format!("entry-{i}");
            let f_id = format!("find-{i}");
            let crown_id = format!("crown-{i}");
            let tech_id = format!("T-{i}");
            g.upsert_node(&entry_asset(t, &entry_id)).await.unwrap();
            g.upsert_node(&finding(t, &f_id, &entry_id)).await.unwrap();
            g.upsert_node(&technique(&tech_id)).await.unwrap();
            g.upsert_node(&crown_asset(t, &crown_id)).await.unwrap();
            g.upsert_edge(&GraphEdge::new(
                EdgeKind::HasFinding,
                NodeId::new(&entry_id),
                NodeId::new(&f_id),
            ))
            .await
            .unwrap();
            g.upsert_edge(&GraphEdge::new(
                EdgeKind::Enables,
                NodeId::new(&f_id),
                NodeId::new(&tech_id),
            ))
            .await
            .unwrap();
            g.upsert_edge(&GraphEdge::reaches(
                NodeId::new(&tech_id),
                NodeId::new(&crown_id),
                443,
                "tcp",
            ))
            .await
            .unwrap();
        }
        let query = AttackPathQuery {
            tenant_id: t,
            entry_kind: NodeKind::Asset,
            target_kind: NodeKind::Asset,
            max_depth: 5,
            max_paths: 2,
        };
        let paths = g.find_attack_paths(&query).await.unwrap();
        assert_eq!(paths.len(), 2);
    }

    #[tokio::test]
    async fn in_memory_neighbors_returns_expected_at_depth_2() {
        let t = tenant();
        let g = InMemoryKnowledgeGraph::new();
        g.upsert_node(&entry_asset(t, "a")).await.unwrap();
        g.upsert_node(&finding(t, "f", "a")).await.unwrap();
        g.upsert_node(&technique("T1")).await.unwrap();
        g.upsert_edge(&GraphEdge::new(
            EdgeKind::HasFinding,
            NodeId::new("a"),
            NodeId::new("f"),
        ))
        .await
        .unwrap();
        g.upsert_edge(&GraphEdge::new(
            EdgeKind::Enables,
            NodeId::new("f"),
            NodeId::new("T1"),
        ))
        .await
        .unwrap();
        let n1 = g.neighbors(&NodeId::new("a"), 1).await.unwrap();
        assert_eq!(n1.len(), 2);
        let n2 = g.neighbors(&NodeId::new("a"), 2).await.unwrap();
        assert_eq!(n2.len(), 3);
    }

    #[tokio::test]
    async fn neighbors_rejects_missing_root() {
        let g = InMemoryKnowledgeGraph::new();
        let r = g.neighbors(&NodeId::new("nope"), 1).await;
        assert!(r.is_err());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn compute_risk_propagation_uses_max_node_score_as_bottleneck() {
        let t = tenant();
        let g = build_simple_chain(t);
        let query = AttackPathQuery {
            tenant_id: t,
            entry_kind: NodeKind::Asset,
            target_kind: NodeKind::Asset,
            max_depth: 5,
            max_paths: 10,
        };
        let paths = g.find_attack_paths(&query).await.unwrap();
        let p = paths.first().expect("one path");
        let risk = g.compute_risk_propagation(&p.id).await.unwrap();
        // entry 1.0 + finding 9.0 + technique 0.0 + crown 5.0 = 15.0
        assert!((risk.composite_score - 15.0).abs() < 1e-9);
        // The Finding has the highest individual score (9.0), so it
        // must be the bottleneck.
        assert_eq!(risk.bottleneck_node_id.as_str(), "find1");
    }
}
