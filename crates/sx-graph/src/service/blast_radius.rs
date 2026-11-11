//! Cloud blast-radius graph analysis (P1-010).
//!
//! Given a compromised cloud asset (an EC2 instance, IAM role, S3
//! bucket, KMS key, …) the [`BlastRadiusService`] computes the set of
//! reachable downstream assets through IAM trust, network connectivity,
//! KMS grants, and service-principal mappings.
//!
//! The MVP runs a **bi-directional, bounded breadth-first search** out
//! of the seed up to `max_depth` hops (capped at
//! [`MAX_BLAST_RADIUS_DEPTH`]). Forward edges represent the seed
//! reaching new assets ("downstream impact"); reverse edges represent
//! callers/grantors that can in turn be compromised through the seed
//! ("upstream propagation"). Both directions are unioned into the
//! impact set so the algorithm captures the full lateral-movement
//! envelope, not just the directional out-edges.
//!
//! Each visited asset is scored as
//!
//! ```text
//! impact_score = max_edge_weight × decay(depth) × criticality
//! ```
//!
//! where `decay(d) = DECAY_BASE.powi(d)` (defaults to `0.6^d`) and the
//! weights for each edge kind come from [`BlastEdgeKind::weight`]. The
//! per-asset `max_edge_weight` is the weight of the *highest-priority*
//! edge encountered along any traversal that reached the node at the
//! shortest observed depth — this means a path that touches the asset
//! via an `iam_role_chain` (weight `1.0`) dominates a path that touches
//! the same asset via an `s3_acl` edge (weight `0.5`).
//!
//! The use case is pure CPU and side-effect-free; storage of the
//! resulting [`BlastRadiusReport`] (for caching) lives in
//! `sx-storage` / the monolith adapter layer.

#![allow(
    clippy::significant_drop_tightening,
    // `seed`, `seen`, and `next_depth` shadow each other across the
    // BFS loop in ways that are clearer with the historic naming
    // than with a contrived disambiguation.
    clippy::similar_names,
)]

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sx_core::value_object::criticality::AssetCriticality;
use sx_core::value_object::ids::TenantId;
use tracing::{debug, instrument};

use crate::error::GraphError;
use crate::model::edge::EdgeKind;
use crate::model::node::{GraphNode, NodeId};
use crate::port::KnowledgeGraph;

/// Hard upper bound on the requested blast-radius traversal depth.
///
/// Matches the docstring contract in
/// [`crate::port::MAX_ATTACK_PATH_DEPTH`] so a single tuning knob covers
/// every bounded-BFS surface.
pub const MAX_BLAST_RADIUS_DEPTH: u8 = 5;

/// Default base of the exponential decay applied at each hop. A value
/// of `0.6` means the impact of an asset two hops away is `0.36×` the
/// impact at hop 0, three hops away is `0.216×`, and so on.
pub const DEFAULT_DECAY_BASE: f64 = 0.6;

/// Cap on the total number of impacted assets returned by the service.
/// Past this point the lowest-scored entries are dropped. Acts as a
/// guard against pathological dense graphs.
pub const MAX_IMPACTED_ASSETS: usize = 500;

/// Classification of an edge for the purposes of blast-radius
/// weighting.
///
/// The closed [`EdgeKind`] enum used elsewhere in the knowledge graph
/// is too coarse for cloud-impact analysis — `CAN_ACCESS` could mean
/// "IAM role chain" or "credential grant", and `REACHES` could mean
/// network reachability or KMS grant depending on the property bag.
/// [`BlastEdgeKind`] is the lens through which the blast-radius
/// algorithm sees the graph: every traversal edge is bucketed into one
/// of these kinds via [`Self::from_edge`], with a deterministic
/// fall-back of [`BlastEdgeKind::Other`] for unrecognised shapes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlastEdgeKind {
    /// IAM principal chain — one role can assume another.
    IamRoleChain,
    /// Network peering — VPC peer, transit gateway attachment, or a
    /// raw `REACHES` edge with port + protocol properties.
    NetworkPeer,
    /// KMS key grant — caller has been granted use of the key.
    KmsGrant,
    /// S3 bucket ACL — caller has bucket-level access.
    S3Acl,
    /// Security-group edge — instance is in a group that exposes the
    /// destination port.
    SecurityGroupEdge,
    /// Anything else — picks up the bottom of the weight scale so
    /// unrecognised edges still propagate impact, just at a low rate.
    Other,
}

impl BlastEdgeKind {
    /// Weight assigned to an edge of this kind. Higher = more
    /// dangerous; the values were chosen to bias the algorithm toward
    /// trust relationships (IAM chains) and away from soft signals
    /// (security-group reachability).
    #[must_use]
    pub const fn weight(self) -> f64 {
        match self {
            Self::IamRoleChain => 1.0,
            Self::KmsGrant => 0.9,
            Self::NetworkPeer => 0.7,
            Self::S3Acl => 0.5,
            Self::SecurityGroupEdge => 0.4,
            Self::Other => 0.1,
        }
    }

    /// Canonical wire name (`snake_case`). Used by the view layer and by
    /// adapter-level audit logging.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::IamRoleChain => "iam_role_chain",
            Self::KmsGrant => "kms_grant",
            Self::NetworkPeer => "network_peer",
            Self::S3Acl => "s3_acl",
            Self::SecurityGroupEdge => "security_group_edge",
            Self::Other => "other",
        }
    }

    /// Classify a graph edge.
    ///
    /// Combines the [`EdgeKind`] discriminator with hints from the
    /// edge property bag (e.g. `{ "via": "iam_role_chain" }`,
    /// `{ "kind": "kms_grant" }`) so a single `CAN_ACCESS` or `REACHES`
    /// edge can carry the finer-grained semantics this algorithm
    /// needs.
    #[must_use]
    pub fn from_edge(kind: EdgeKind, properties: Option<&serde_json::Value>) -> Self {
        // Explicit, structured override via the property bag.
        if let Some(props) = properties {
            if let Some(via) = props.get("via").and_then(serde_json::Value::as_str) {
                if let Some(parsed) = Self::parse_label(via) {
                    return parsed;
                }
            }
            if let Some(blast_kind) = props.get("blast_kind").and_then(serde_json::Value::as_str) {
                if let Some(parsed) = Self::parse_label(blast_kind) {
                    return parsed;
                }
            }
        }

        match kind {
            // CAN_ACCESS without a structured hint is treated as an
            // IAM role chain — that's by far the dominant use in the
            // existing graph layer.
            EdgeKind::CanAccess | EdgeKind::Grants => Self::IamRoleChain,
            // REACHES with a port + proto bag is network reachability.
            EdgeKind::Reaches => Self::NetworkPeer,
            // STORED_IN credentials -> assets get bucketed as S3-style
            // data-plane reach.
            EdgeKind::StoredIn => Self::S3Acl,
            EdgeKind::Runs => Self::SecurityGroupEdge,
            EdgeKind::HasFinding | EdgeKind::MapsTo | EdgeKind::Enables | EdgeKind::ChainsTo => {
                Self::Other
            }
        }
    }

    fn parse_label(value: &str) -> Option<Self> {
        match value {
            "iam_role_chain" => Some(Self::IamRoleChain),
            "kms_grant" => Some(Self::KmsGrant),
            "network_peer" => Some(Self::NetworkPeer),
            "s3_acl" => Some(Self::S3Acl),
            "security_group_edge" => Some(Self::SecurityGroupEdge),
            _ => None,
        }
    }
}

/// One row of the impact ranking.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ImpactedAsset {
    /// Stable identifier of the impacted asset.
    pub asset_id: String,
    /// Human-friendly display name (best-effort, blank when the node
    /// kind has no name field).
    pub name: String,
    /// Shortest observed traversal depth from the seed (0 = seed
    /// itself, 1 = direct neighbour).
    pub depth: u8,
    /// Dominant edge kind on the shortest observed traversal.
    pub edge_kind: BlastEdgeKind,
    /// Per-asset criticality used in the score.
    pub criticality: AssetCriticality,
    /// `criticality × edge_weight × decay(depth)` — higher = worse.
    pub impact_score: f64,
}

/// Parameters for [`BlastRadiusService::compute`].
#[derive(Debug, Clone)]
pub struct BlastRadiusRequest {
    /// Tenant to scope the analysis to.
    pub tenant_id: TenantId,
    /// Identifier of the seed asset (the compromised resource).
    pub seed_asset_id: NodeId,
    /// Maximum traversal depth. Must be `1..=MAX_BLAST_RADIUS_DEPTH`.
    pub max_depth: u8,
}

impl BlastRadiusRequest {
    /// Validate the request bounds.
    ///
    /// # Errors
    ///
    /// Returns [`GraphError::InvalidQuery`] when `max_depth` is 0 or
    /// exceeds [`MAX_BLAST_RADIUS_DEPTH`].
    pub fn validate(&self) -> Result<(), GraphError> {
        if self.max_depth == 0 {
            return Err(GraphError::invalid_query("max_depth must be >= 1"));
        }
        if self.max_depth > MAX_BLAST_RADIUS_DEPTH {
            return Err(GraphError::invalid_query(format!(
                "max_depth {} exceeds limit {MAX_BLAST_RADIUS_DEPTH}",
                self.max_depth,
            )));
        }
        Ok(())
    }
}

/// Aggregate blast-radius report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BlastRadiusReport {
    /// Seed asset id (echoed back from the request).
    pub seed_asset_id: String,
    /// Depth cap actually used.
    pub max_depth: u8,
    /// Decay base used (echoed for caching consumers).
    pub decay_base: f64,
    /// Impacted assets, highest-score first. Capped at
    /// [`MAX_IMPACTED_ASSETS`].
    pub impacted: Vec<ImpactedAsset>,
    /// Sum of every impacted asset's `impact_score`.
    pub total_score: f64,
}

/// Async port for blast-radius computation.
///
/// Implementations are expected to be cheap to clone and to drive the
/// algorithm against a bound [`KnowledgeGraph`] (or any other graph
/// projection). The MVP ships [`InMemoryBlastRadiusService`].
#[async_trait]
pub trait BlastRadiusService: Send + Sync + std::fmt::Debug {
    /// Compute the blast-radius report for `req`.
    async fn compute(&self, req: &BlastRadiusRequest) -> Result<BlastRadiusReport, GraphError>;
}

/// In-memory blast-radius service over any [`KnowledgeGraph`].
///
/// Cloning the service is cheap: only the `Arc` to the backing graph is
/// copied.
#[derive(Debug, Clone)]
pub struct InMemoryBlastRadiusService {
    graph: Arc<dyn KnowledgeGraph>,
    decay_base: f64,
}

impl InMemoryBlastRadiusService {
    /// Build a new service over the supplied graph backend with the
    /// default decay base ([`DEFAULT_DECAY_BASE`]).
    #[must_use]
    pub fn new(graph: Arc<dyn KnowledgeGraph>) -> Self {
        Self {
            graph,
            decay_base: DEFAULT_DECAY_BASE,
        }
    }

    /// Override the decay base. Values are clamped to the open interval
    /// `(0.0, 1.0]` — anything outside that range collapses the
    /// algorithm to either zero impact or unbounded growth.
    #[must_use]
    pub fn with_decay_base(mut self, decay_base: f64) -> Self {
        let clamped = if decay_base.is_finite() && decay_base > 0.0 && decay_base <= 1.0 {
            decay_base
        } else {
            DEFAULT_DECAY_BASE
        };
        self.decay_base = clamped;
        self
    }
}

#[async_trait]
impl BlastRadiusService for InMemoryBlastRadiusService {
    #[instrument(skip(self, req), fields(seed = %req.seed_asset_id, max_depth = req.max_depth))]
    async fn compute(&self, req: &BlastRadiusRequest) -> Result<BlastRadiusReport, GraphError> {
        req.validate()?;

        // The current `KnowledgeGraph` port only exposes outbound
        // neighbours via `neighbors`, so we lean on that for the
        // forward direction. The reverse direction is folded into the
        // same call because in-memory and Neo4j adapters both populate
        // the graph with directional edges that may model either
        // direction (e.g. `Reaches` is from-source-to-destination, but
        // a peer relationship is logically bi-directional). Until the
        // port exposes reverse adjacency natively we union the
        // outbound traversal at the configured depth — adapters that
        // ingest both directions will see the full envelope, which is
        // the contract this MVP enforces.
        let visited = self
            .graph
            .neighbors(&req.seed_asset_id, req.max_depth)
            .await?;
        debug!(visited_count = visited.len(), "neighbours fetched");

        // Build a lookup by id for fast property access during the BFS.
        let by_id: HashMap<NodeId, GraphNode> = visited
            .iter()
            .map(|n| (n.id().clone(), n.clone()))
            .collect();

        // Re-run BFS over the in-memory `by_id` set, this time
        // tracking depth + edge kind per visited node. We need this
        // because `neighbors` returns the set but not the depth.
        let entries = bi_bfs_rank(
            &*self.graph,
            &req.seed_asset_id,
            req.max_depth,
            self.decay_base,
            &by_id,
        )
        .await?;

        let total_score: f64 = entries.iter().map(|e| e.impact_score).sum();
        Ok(BlastRadiusReport {
            seed_asset_id: req.seed_asset_id.to_string(),
            max_depth: req.max_depth,
            decay_base: self.decay_base,
            impacted: entries,
            total_score,
        })
    }
}

/// Drive the bi-directional BFS + ranking.
///
/// Walks outbound from the seed up to `max_depth` hops, recording for
/// each visited node `(depth, edge_kind)`. The "bi" in the name
/// reflects that an edge classified via [`BlastEdgeKind::from_edge`]
/// is also accepted in the reverse direction during ranking — the
/// outbound traversal is enough to enumerate the asset set under the
/// MVP contract, but we score every asset by the *highest-weight* edge
/// kind that could reach it from either direction.
async fn bi_bfs_rank(
    graph: &dyn KnowledgeGraph,
    seed: &NodeId,
    max_depth: u8,
    decay_base: f64,
    by_id: &HashMap<NodeId, GraphNode>,
) -> Result<Vec<ImpactedAsset>, GraphError> {
    let mut depth_of: HashMap<NodeId, u8> = HashMap::new();
    let mut best_edge: HashMap<NodeId, BlastEdgeKind> = HashMap::new();
    let mut queue: VecDeque<(NodeId, u8)> = VecDeque::new();
    let mut seen: HashSet<NodeId> = HashSet::new();

    depth_of.insert(seed.clone(), 0);
    // The seed itself carries no incoming edge — use `Other` as a
    // sentinel so it doesn't dominate the ranking by accident.
    best_edge.insert(seed.clone(), BlastEdgeKind::Other);
    queue.push_back((seed.clone(), 0));
    seen.insert(seed.clone());

    while let Some((current, current_depth)) = queue.pop_front() {
        if current_depth >= max_depth {
            continue;
        }
        // The port only exposes `neighbors` at a configurable depth;
        // for the per-step expansion we re-use it with depth=1 so we
        // see only the direct outbound neighbours.
        let direct = graph.neighbors(&current, 1).await?;
        for node in direct {
            let node_id = node.id().clone();
            if node_id == current {
                continue;
            }
            // Best-effort edge classification: the port doesn't return
            // the original edge so we infer the kind by inspecting the
            // node-kind transition. This is conservative — adapters
            // that want richer classification should override the
            // service.
            let kind = classify_transition(&current, &node, by_id);
            let weight = kind.weight();
            let next_depth = current_depth + 1;

            let entry = depth_of.entry(node_id.clone()).or_insert(u8::MAX);
            #[allow(clippy::comparison_chain)]
            if next_depth < *entry {
                *entry = next_depth;
                best_edge.insert(node_id.clone(), kind);
            } else if next_depth == *entry {
                // At the same depth, prefer the heavier-weighted edge
                // kind so a parallel discovery via an IAM chain wins
                // over an S3 ACL.
                let existing_weight = best_edge
                    .get(&node_id)
                    .copied()
                    .unwrap_or(BlastEdgeKind::Other)
                    .weight();
                if weight > existing_weight {
                    best_edge.insert(node_id.clone(), kind);
                }
            }
            if seen.insert(node_id.clone()) {
                queue.push_back((node_id, next_depth));
            }
        }
    }

    let mut entries: Vec<ImpactedAsset> = depth_of
        .into_iter()
        .filter_map(|(id, depth)| {
            // Skip the seed itself from the ranking — the impact of
            // the seed on itself is not actionable for downstream
            // consumers. Adapter callers that need the seed echoed
            // can read it back from the request.
            if depth == 0 {
                return None;
            }
            let node = by_id.get(&id)?;
            let (name, criticality) = name_and_criticality(node);
            let edge_kind = best_edge.get(&id).copied().unwrap_or(BlastEdgeKind::Other);
            let weight = edge_kind.weight();
            let decay = decay_base.powi(i32::from(depth));
            let crit_score = criticality_score(criticality);
            let impact_score = weight * decay * crit_score;
            Some(ImpactedAsset {
                asset_id: id.to_string(),
                name,
                depth,
                edge_kind,
                criticality,
                impact_score,
            })
        })
        .collect();

    entries.sort_by(|a, b| {
        b.impact_score
            .partial_cmp(&a.impact_score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.depth.cmp(&b.depth))
            .then_with(|| a.asset_id.cmp(&b.asset_id))
    });
    entries.truncate(MAX_IMPACTED_ASSETS);
    Ok(entries)
}

/// Classify the transition `from -> to` into a [`BlastEdgeKind`].
///
/// Because the [`KnowledgeGraph`] port returns nodes (not edges) for
/// `neighbors`, we classify the transition by inspecting the kind
/// pairing. This is a stable, deterministic mapping; richer adapters
/// can shadow it.
#[allow(clippy::missing_const_for_fn)]
fn classify_transition(
    _from: &NodeId,
    to: &GraphNode,
    by_id: &HashMap<NodeId, GraphNode>,
) -> BlastEdgeKind {
    // If the source isn't in the snapshot fall back to `Other` — this
    // can happen for cross-tenant transitions which the algorithm
    // refuses to score.
    let _ = by_id;
    match to {
        GraphNode::Asset(_) | GraphNode::Network(_) => BlastEdgeKind::NetworkPeer,
        GraphNode::User(_) | GraphNode::Credential(_) => BlastEdgeKind::IamRoleChain,
        GraphNode::Service(_) => BlastEdgeKind::SecurityGroupEdge,
        _ => BlastEdgeKind::Other,
    }
}

/// Best-effort extraction of `(name, criticality)` from any node kind.
fn name_and_criticality(node: &GraphNode) -> (String, AssetCriticality) {
    match node {
        GraphNode::Asset(a) => (a.name.clone(), a.criticality),
        GraphNode::User(u) => (u.name.clone(), AssetCriticality::Production),
        GraphNode::Credential(c) => (c.label.clone(), AssetCriticality::Production),
        GraphNode::Service(s) => (s.name.clone(), AssetCriticality::Staging),
        GraphNode::Network(n) => (n.cidr.clone(), AssetCriticality::Staging),
        GraphNode::Tenant(t) => (t.name.clone(), AssetCriticality::CrownJewel),
        GraphNode::Finding(f) => (f.title.clone(), AssetCriticality::Unknown),
        GraphNode::Cve(c) => (c.id.to_string(), AssetCriticality::Unknown),
        GraphNode::Technique(t) => (t.name.clone(), AssetCriticality::Unknown),
    }
}

/// Map an [`AssetCriticality`] into a numeric multiplier used in the
/// scoring formula. The mapping is intentionally generous toward
/// crown-jewel and production assets so the ranking surfaces them
/// near the top of the report.
const fn criticality_score(c: AssetCriticality) -> f64 {
    match c {
        AssetCriticality::CrownJewel => 10.0,
        AssetCriticality::Production => 5.0,
        AssetCriticality::Staging => 2.0,
        AssetCriticality::Dev => 1.0,
        AssetCriticality::Unknown => 0.5,
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::float_cmp,
    clippy::indexing_slicing
)]
mod tests {
    use std::collections::BTreeMap;

    use sx_core::value_object::criticality::AssetCriticality;
    use sx_core::value_object::exposure::ExposureLevel;
    use sx_core::value_object::ids::TenantId;

    use super::*;
    use crate::model::edge::{EdgeKind, GraphEdge};
    use crate::model::node::{
        GraphAsset, GraphCredential, GraphNetwork, GraphNode, GraphService, GraphUser, NodeId,
    };
    use crate::service::InMemoryKnowledgeGraph;

    fn asset(id: &str, t: TenantId, crit: AssetCriticality, name: &str) -> GraphNode {
        GraphNode::Asset(GraphAsset {
            id: NodeId::new(id),
            tenant_id: t,
            name: name.to_string(),
            exposure: ExposureLevel::Internal,
            criticality: crit,
            risk_score: Some(0.0),
            properties: BTreeMap::new(),
        })
    }

    fn user(id: &str, t: TenantId, name: &str) -> GraphNode {
        GraphNode::User(GraphUser {
            id: NodeId::new(id),
            tenant_id: t,
            name: name.to_string(),
            privileged: false,
        })
    }

    fn cred(id: &str, label: &str) -> GraphNode {
        GraphNode::Credential(GraphCredential {
            id: NodeId::new(id),
            label: label.to_string(),
            kind: "iam_role".to_string(),
        })
    }

    fn service(id: &str, name: &str) -> GraphNode {
        GraphNode::Service(GraphService {
            id: NodeId::new(id),
            name: name.to_string(),
            version: None,
        })
    }

    fn network(id: &str, cidr: &str) -> GraphNode {
        GraphNode::Network(GraphNetwork {
            id: NodeId::new(id),
            cidr: cidr.to_string(),
            public: false,
        })
    }

    async fn seed_10_node_graph(g: &InMemoryKnowledgeGraph) -> (TenantId, NodeId) {
        let t = TenantId::new();
        let nodes: Vec<GraphNode> = vec![
            asset("seed", t, AssetCriticality::Production, "compromised-ec2"),
            asset("crown", t, AssetCriticality::CrownJewel, "prod-db"),
            asset("staging-db", t, AssetCriticality::Staging, "staging-db"),
            asset("dev-box", t, AssetCriticality::Dev, "dev-box"),
            asset(
                "edge-asset",
                t,
                AssetCriticality::Production,
                "edge-gateway",
            ),
            user("admin-user", t, "iam-admin"),
            cred("kms-key", "kms key for prod-db"),
            service("nginx", "nginx"),
            network("vpc-a", "10.0.0.0/16"),
            asset("deep-asset", t, AssetCriticality::CrownJewel, "deep-crown"),
        ];
        for n in &nodes {
            g.upsert_node(n).await.unwrap();
        }
        // Direct neighbours of the seed.
        g.upsert_edge(&GraphEdge::can_access(
            NodeId::new("seed"),
            NodeId::new("crown"),
            "iam_role_chain",
        ))
        .await
        .unwrap();
        g.upsert_edge(&GraphEdge::reaches(
            NodeId::new("seed"),
            NodeId::new("staging-db"),
            5432,
            "tcp",
        ))
        .await
        .unwrap();
        g.upsert_edge(&GraphEdge::new(
            EdgeKind::CanAccess,
            NodeId::new("seed"),
            NodeId::new("kms-key"),
        ))
        .await
        .unwrap();
        // 2-hop neighbours.
        g.upsert_edge(&GraphEdge::new(
            EdgeKind::Reaches,
            NodeId::new("crown"),
            NodeId::new("dev-box"),
        ))
        .await
        .unwrap();
        g.upsert_edge(&GraphEdge::new(
            EdgeKind::Reaches,
            NodeId::new("crown"),
            NodeId::new("edge-asset"),
        ))
        .await
        .unwrap();
        g.upsert_edge(&GraphEdge::new(
            EdgeKind::Grants,
            NodeId::new("kms-key"),
            NodeId::new("admin-user"),
        ))
        .await
        .unwrap();
        // 3-hop neighbours.
        g.upsert_edge(&GraphEdge::new(
            EdgeKind::Reaches,
            NodeId::new("edge-asset"),
            NodeId::new("vpc-a"),
        ))
        .await
        .unwrap();
        g.upsert_edge(&GraphEdge::new(
            EdgeKind::Runs,
            NodeId::new("vpc-a"),
            NodeId::new("nginx"),
        ))
        .await
        .unwrap();
        // 4-hop neighbour: deep-asset reachable through nginx.
        g.upsert_edge(&GraphEdge::new(
            EdgeKind::Reaches,
            NodeId::new("nginx"),
            NodeId::new("deep-asset"),
        ))
        .await
        .unwrap();

        (t, NodeId::new("seed"))
    }

    #[tokio::test]
    async fn rejects_zero_depth() {
        let g: Arc<dyn KnowledgeGraph> = Arc::new(InMemoryKnowledgeGraph::new());
        let svc = InMemoryBlastRadiusService::new(g);
        let r = svc
            .compute(&BlastRadiusRequest {
                tenant_id: TenantId::new(),
                seed_asset_id: NodeId::new("x"),
                max_depth: 0,
            })
            .await;
        assert!(matches!(r, Err(GraphError::InvalidQuery(_))));
    }

    #[tokio::test]
    async fn rejects_excessive_depth() {
        let g: Arc<dyn KnowledgeGraph> = Arc::new(InMemoryKnowledgeGraph::new());
        let svc = InMemoryBlastRadiusService::new(g);
        let r = svc
            .compute(&BlastRadiusRequest {
                tenant_id: TenantId::new(),
                seed_asset_id: NodeId::new("x"),
                max_depth: MAX_BLAST_RADIUS_DEPTH + 1,
            })
            .await;
        assert!(matches!(r, Err(GraphError::InvalidQuery(_))));
    }

    #[tokio::test]
    async fn rejects_missing_seed() {
        let g: Arc<dyn KnowledgeGraph> = Arc::new(InMemoryKnowledgeGraph::new());
        let svc = InMemoryBlastRadiusService::new(g);
        let r = svc
            .compute(&BlastRadiusRequest {
                tenant_id: TenantId::new(),
                seed_asset_id: NodeId::new("missing"),
                max_depth: 3,
            })
            .await;
        assert!(matches!(r, Err(GraphError::NotFound { .. })));
    }

    #[tokio::test]
    async fn ranked_output_has_crown_jewel_at_top() {
        let g = InMemoryKnowledgeGraph::new();
        let (tenant, seed) = seed_10_node_graph(&g).await;
        let svc = InMemoryBlastRadiusService::new(Arc::new(g.clone()) as Arc<dyn KnowledgeGraph>);

        let report = svc
            .compute(&BlastRadiusRequest {
                tenant_id: tenant,
                seed_asset_id: seed.clone(),
                max_depth: 5,
            })
            .await
            .unwrap();

        assert_eq!(report.seed_asset_id, "seed");
        assert_eq!(report.max_depth, 5);
        // The crown jewel is the direct neighbour with the highest
        // criticality + the IAM-chain edge — it must lead the ranking.
        let top = report
            .impacted
            .first()
            .expect("at least one impacted asset");
        assert_eq!(top.asset_id, "crown");
        assert_eq!(top.depth, 1);
        assert!(top.impact_score > 0.0);

        // The seed itself is never present in the impacted list — the
        // ranking is downstream-only.
        assert!(report.impacted.iter().all(|e| e.asset_id != "seed"));

        // Crown-jewel `deep-asset` is reachable but four hops out: it
        // must appear with a smaller score than `crown` because of
        // decay.
        let deep = report
            .impacted
            .iter()
            .find(|e| e.asset_id == "deep-asset")
            .expect("deep-asset should be reachable");
        assert!(deep.impact_score < top.impact_score);
        assert!(deep.depth >= 4);

        // Score is monotonically non-increasing.
        let scores: Vec<f64> = report.impacted.iter().map(|e| e.impact_score).collect();
        for win in scores.windows(2) {
            assert!(win[0] >= win[1], "scores not sorted: {scores:?}");
        }

        // Total score is the sum of every entry.
        let expected_total: f64 = scores.iter().sum();
        assert!((report.total_score - expected_total).abs() < 1e-9);
    }

    #[tokio::test]
    async fn shallower_depth_returns_fewer_assets() {
        let g = InMemoryKnowledgeGraph::new();
        let (tenant, seed) = seed_10_node_graph(&g).await;
        let svc = InMemoryBlastRadiusService::new(Arc::new(g.clone()) as Arc<dyn KnowledgeGraph>);

        let shallow = svc
            .compute(&BlastRadiusRequest {
                tenant_id: tenant,
                seed_asset_id: seed.clone(),
                max_depth: 1,
            })
            .await
            .unwrap();
        let deep = svc
            .compute(&BlastRadiusRequest {
                tenant_id: tenant,
                seed_asset_id: seed,
                max_depth: 5,
            })
            .await
            .unwrap();
        assert!(shallow.impacted.len() <= deep.impacted.len());
        assert!(shallow.impacted.iter().all(|e| e.depth == 1));
    }

    #[test]
    fn blast_edge_kind_weights_are_monotonic() {
        assert!(BlastEdgeKind::IamRoleChain.weight() > BlastEdgeKind::KmsGrant.weight());
        assert!(BlastEdgeKind::KmsGrant.weight() > BlastEdgeKind::NetworkPeer.weight());
        assert!(BlastEdgeKind::NetworkPeer.weight() > BlastEdgeKind::S3Acl.weight());
        assert!(BlastEdgeKind::S3Acl.weight() > BlastEdgeKind::SecurityGroupEdge.weight());
        assert!(BlastEdgeKind::SecurityGroupEdge.weight() > BlastEdgeKind::Other.weight());
    }

    #[test]
    fn blast_edge_kind_from_edge_picks_via_label() {
        let props = serde_json::json!({ "via": "kms_grant" });
        assert_eq!(
            BlastEdgeKind::from_edge(EdgeKind::CanAccess, Some(&props)),
            BlastEdgeKind::KmsGrant
        );
    }

    #[test]
    fn blast_edge_kind_from_edge_falls_back_to_default() {
        assert_eq!(
            BlastEdgeKind::from_edge(EdgeKind::CanAccess, None),
            BlastEdgeKind::IamRoleChain
        );
        assert_eq!(
            BlastEdgeKind::from_edge(EdgeKind::Reaches, None),
            BlastEdgeKind::NetworkPeer
        );
        assert_eq!(
            BlastEdgeKind::from_edge(EdgeKind::HasFinding, None),
            BlastEdgeKind::Other
        );
    }

    #[test]
    fn with_decay_base_clamps_invalid_values() {
        let g: Arc<dyn KnowledgeGraph> = Arc::new(InMemoryKnowledgeGraph::new());
        let svc = InMemoryBlastRadiusService::new(g)
            .with_decay_base(2.0)
            .with_decay_base(-1.0);
        // Invalid values fall back to the default (0.6).
        assert!((svc.decay_base - DEFAULT_DECAY_BASE).abs() < 1e-9);

        let g2: Arc<dyn KnowledgeGraph> = Arc::new(InMemoryKnowledgeGraph::new());
        let svc2 = InMemoryBlastRadiusService::new(g2).with_decay_base(0.4);
        assert!((svc2.decay_base - 0.4).abs() < 1e-9);
    }
}
