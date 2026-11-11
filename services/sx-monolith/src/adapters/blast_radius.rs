//! Blast-radius port adapter (P1-010).
//!
//! Wraps [`sx_graph::service::blast_radius::InMemoryBlastRadiusService`]
//! behind the [`BlastRadiusPort`] trait so the HTTP layer can request a
//! ranked impact set for a compromised seed asset.
//!
//! ## Caching contract
//!
//! Each `(tenant_id, seed_asset_id, max_depth)` triple is memoised in a
//! mutex-guarded `HashMap`. A cached entry is considered fresh while its
//! `computed_at` timestamp sits within `CACHE_TTL` of "now"; older
//! entries fall through and are recomputed in-place. The adapter never
//! evicts in the background — the next request for an asset triggers
//! re-execution.
//!
//! ## Concurrency
//!
//! The mutex is held only for the cache read/write critical section;
//! the underlying graph BFS runs without the lock held so multiple
//! tenants cannot serialise on each other. A duplicate concurrent
//! request for the same seed may run the BFS twice — that is an
//! acceptable trade-off for the MVP and avoids holding the mutex
//! across an `await`.

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use sx_api::port::{BlastRadiusPort, Phase3PortError};
use sx_api::view::blast_radius_view::{
    BlastRadiusResponseView, ImpactedAssetView, MAX_BLAST_RADIUS_DEPTH as VIEW_MAX_DEPTH,
};
use sx_core::value_object::ids::TenantId;
use sx_graph::error::GraphError;
use sx_graph::model::node::NodeId;
use sx_graph::port::KnowledgeGraph;
use sx_graph::service::{
    BlastRadiusRequest, BlastRadiusService, ImpactedAsset, InMemoryBlastRadiusService,
};
use tokio::sync::Mutex;
use tracing::{debug, instrument};

/// Cache freshness window. Any entry computed more than [`CACHE_TTL`]
/// ago is recomputed on the next request.
const CACHE_TTL: Duration = Duration::from_secs(3600);

/// Cached report — pairs the wire view with the wall-clock instant it
/// was materialised so the TTL check can be done lock-free in O(1).
#[derive(Debug, Clone)]
struct CachedReport {
    view: BlastRadiusResponseView,
    computed_at: Instant,
}

/// In-process blast-radius adapter.
#[derive(Debug)]
pub(crate) struct BlastRadiusAdapter {
    service: InMemoryBlastRadiusService,
    cache: Mutex<HashMap<(String, String, u8), CachedReport>>,
}

impl BlastRadiusAdapter {
    /// Build a new adapter over the supplied graph backend.
    pub(crate) fn new(graph: Arc<dyn KnowledgeGraph>) -> Self {
        Self {
            service: InMemoryBlastRadiusService::new(graph),
            cache: Mutex::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl BlastRadiusPort for BlastRadiusAdapter {
    #[instrument(skip(self), fields(tenant_id = %tenant_id, seed = %seed_asset_id, max_depth))]
    async fn compute(
        &self,
        tenant_id: &str,
        seed_asset_id: &str,
        max_depth: u8,
    ) -> Result<BlastRadiusResponseView, Phase3PortError> {
        // Defensive: the HTTP validator already clamps `max_depth` into
        // `1..=MAX_BLAST_RADIUS_DEPTH`, but treat anything outside the
        // window as `Invalid` rather than letting it reach the service
        // layer.
        if max_depth == 0 || max_depth > VIEW_MAX_DEPTH {
            return Err(Phase3PortError::Invalid(format!(
                "max_depth must be 1..={VIEW_MAX_DEPTH}"
            )));
        }

        let tenant = TenantId::from_str(tenant_id)
            .map_err(|e| Phase3PortError::Invalid(format!("invalid tenant_id: {e}")))?;
        let cache_key = (tenant_id.to_owned(), seed_asset_id.to_owned(), max_depth);

        // Cache lookup. The mutex is dropped before we run the BFS.
        {
            let guard = self.cache.lock().await;
            if let Some(entry) = guard.get(&cache_key) {
                if entry.computed_at.elapsed() < CACHE_TTL {
                    debug!("blast-radius cache hit");
                    let mut hit = entry.view.clone();
                    hit.cached = true;
                    return Ok(hit);
                }
                debug!("blast-radius cache stale; recomputing");
            }
        }

        let req = BlastRadiusRequest {
            tenant_id: tenant,
            seed_asset_id: NodeId::new(seed_asset_id),
            max_depth,
        };
        let report = self.service.compute(&req).await.map_err(map_graph_error)?;

        let view = BlastRadiusResponseView {
            seed_asset_id: report.seed_asset_id,
            max_depth: report.max_depth,
            decay_base: report.decay_base,
            impacted: report.impacted.into_iter().map(translate_entry).collect(),
            total_score: report.total_score,
            cached: false,
        };

        {
            let mut guard = self.cache.lock().await;
            guard.insert(
                cache_key,
                CachedReport {
                    view: view.clone(),
                    computed_at: Instant::now(),
                },
            );
        }

        Ok(view)
    }
}

fn translate_entry(entry: ImpactedAsset) -> ImpactedAssetView {
    ImpactedAssetView {
        asset_id: entry.asset_id,
        name: entry.name,
        depth: entry.depth,
        edge_kind: entry.edge_kind.as_str().to_owned(),
        criticality: entry.criticality.to_string(),
        impact_score: entry.impact_score,
    }
}

fn map_graph_error(err: GraphError) -> Phase3PortError {
    match err {
        GraphError::NotFound { .. } => Phase3PortError::NotFound,
        GraphError::Conflict { kind, id } => {
            Phase3PortError::Invalid(format!("conflict: {kind} id={id}"))
        }
        GraphError::InvalidQuery(msg) => Phase3PortError::Invalid(msg),
        GraphError::Config(msg)
        | GraphError::Connection(msg)
        | GraphError::Query(msg)
        | GraphError::Cypher(msg) => Phase3PortError::Dependency(msg),
        GraphError::TenantBoundary {
            kind,
            caller_tenant,
            resource_tenant,
        } => Phase3PortError::Invalid(format!(
            "tenant boundary: caller={caller_tenant} resource={resource_tenant} ({kind})"
        )),
        GraphError::Internal(msg) => Phase3PortError::Internal(msg),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::float_cmp)]
mod tests {
    use std::collections::BTreeMap;

    use sx_core::value_object::criticality::AssetCriticality;
    use sx_core::value_object::exposure::ExposureLevel;
    use sx_core::value_object::ids::TenantId;
    use sx_graph::model::edge::{EdgeKind, GraphEdge};
    use sx_graph::model::node::{GraphAsset, GraphNode, NodeId};
    use sx_graph::service::InMemoryKnowledgeGraph;

    use super::*;

    fn asset(id: &str, t: TenantId, crit: AssetCriticality) -> GraphNode {
        GraphNode::Asset(GraphAsset {
            id: NodeId::new(id),
            tenant_id: t,
            name: format!("name-{id}"),
            exposure: ExposureLevel::Internal,
            criticality: crit,
            risk_score: Some(0.0),
            properties: BTreeMap::new(),
        })
    }

    async fn seed_simple_graph(g: &InMemoryKnowledgeGraph) -> (TenantId, String) {
        let t = TenantId::new();
        g.upsert_node(&asset("seed", t, AssetCriticality::Production))
            .await
            .unwrap();
        g.upsert_node(&asset("crown", t, AssetCriticality::CrownJewel))
            .await
            .unwrap();
        g.upsert_edge(&GraphEdge::new(
            EdgeKind::CanAccess,
            NodeId::new("seed"),
            NodeId::new("crown"),
        ))
        .await
        .unwrap();
        (t, "seed".to_owned())
    }

    #[tokio::test]
    async fn adapter_returns_ranked_impact_set() {
        let g = InMemoryKnowledgeGraph::new();
        let (tenant, seed) = seed_simple_graph(&g).await;
        let graph: Arc<dyn KnowledgeGraph> = Arc::new(g);
        let adapter = BlastRadiusAdapter::new(graph);

        let resp = adapter
            .compute(&tenant.to_string(), &seed, 3)
            .await
            .unwrap();
        assert_eq!(resp.seed_asset_id, "seed");
        assert_eq!(resp.max_depth, 3);
        assert!(resp.cached.eq(&false));
        assert!(!resp.impacted.is_empty(), "expected at least one entry");
        let first = resp.impacted.first().unwrap();
        assert_eq!(first.asset_id, "crown");
        assert!(first.impact_score > 0.0);
    }

    #[tokio::test]
    async fn adapter_caches_recent_computations() {
        let g = InMemoryKnowledgeGraph::new();
        let (tenant, seed) = seed_simple_graph(&g).await;
        let graph: Arc<dyn KnowledgeGraph> = Arc::new(g);
        let adapter = BlastRadiusAdapter::new(graph);

        let first = adapter
            .compute(&tenant.to_string(), &seed, 3)
            .await
            .unwrap();
        let second = adapter
            .compute(&tenant.to_string(), &seed, 3)
            .await
            .unwrap();
        assert!(!first.cached);
        assert!(second.cached, "second hit must surface as cached");
        // Stored payload (sans the cached flag) must match.
        assert_eq!(first.seed_asset_id, second.seed_asset_id);
        assert_eq!(first.total_score, second.total_score);
        assert_eq!(first.impacted, second.impacted);
    }

    #[tokio::test]
    async fn adapter_rejects_invalid_depth() {
        let graph: Arc<dyn KnowledgeGraph> = Arc::new(InMemoryKnowledgeGraph::new());
        let adapter = BlastRadiusAdapter::new(graph);
        let tenant = TenantId::new();
        let r = adapter.compute(&tenant.to_string(), "x", 0).await;
        assert!(matches!(r, Err(Phase3PortError::Invalid(_))));
        let r2 = adapter
            .compute(&tenant.to_string(), "x", VIEW_MAX_DEPTH + 1)
            .await;
        assert!(matches!(r2, Err(Phase3PortError::Invalid(_))));
    }

    #[tokio::test]
    async fn adapter_rejects_invalid_tenant_id() {
        let graph: Arc<dyn KnowledgeGraph> = Arc::new(InMemoryKnowledgeGraph::new());
        let adapter = BlastRadiusAdapter::new(graph);
        let r = adapter.compute("not-a-uuid", "seed", 1).await;
        assert!(matches!(r, Err(Phase3PortError::Invalid(_))));
    }

    #[tokio::test]
    async fn adapter_translates_not_found() {
        let graph: Arc<dyn KnowledgeGraph> = Arc::new(InMemoryKnowledgeGraph::new());
        let adapter = BlastRadiusAdapter::new(graph);
        let tenant = TenantId::new();
        let r = adapter.compute(&tenant.to_string(), "missing", 2).await;
        assert!(matches!(r, Err(Phase3PortError::NotFound)));
    }
}
