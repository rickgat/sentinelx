//! Periodic GraphSAGE risk-propagation job (monolith adapter).
//!
//! Every `interval_secs` (default 900s / 15 minutes) this job:
//!
//! 1. Lists the tenant's findings + assets (tenant `"default"` for MVP).
//! 2. Builds a [`SimpleGraph`]: each asset id is hashed onto a `u64` node
//!    id. Findings that share the same `asset_id` cluster the asset's
//!    self-loop neighbours; cross-asset edges are derived from the rule
//!    "two assets that appear together in the same finding share an edge"
//!    (in this MVP a finding has a single `asset_id` so most clusters are
//!    star-shaped around the focal asset).
//! 3. Runs a 2-layer [`GraphSageModel`] forward pass with identity-leaning
//!    weights (see [`default_model`]).
//! 4. Writes a per-asset score (`L2` norm of the embedding row) into the
//!    shared cache, keyed by the canonical `asset_id` string.
//!
//! The job exits cleanly on [`CancellationToken::cancelled`]. The first
//! tick fires `interval_secs` after spawn — never at boot — so the rest
//! of `AppState` has time to settle before the first read of the
//! repositories.
//!
//! # No hidden allocations on the hot path
//!
//! The `SimpleGraph` is rebuilt from scratch on every tick because the
//! finding/asset tables can churn between runs; this scaffold favours
//! correctness over allocation reuse and the inputs are bounded by the
//! `LIST_PAGE_LIMIT` cap below (in practice « 1000 rows in MVP).

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sx_api::port::{AssetRepositoryPort, FindingRepositoryPort};
use sx_ml::graphsage::{GraphSageModel, Matrix, MeanAggregator, NodeId, SageLayer, SimpleGraph};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

/// Default cadence between ticks (15 minutes).
const DEFAULT_INTERVAL_SECS: u64 = 900;

/// Hard cap on rows pulled from a single repository page. In MVP the
/// in-memory stores hold far fewer than this; the cap keeps the job
/// well-behaved if a Postgres-backed store grows unbounded.
const LIST_PAGE_LIMIT: u32 = 1_000;

/// Feature dimension used for both layers of the default model. Two
/// features per node keep the math fast while still showing edge effects.
const NODE_FEATURE_DIM: usize = 2;

/// Tenant id used in MVP — the wider multi-tenant rollout is tracked
/// separately and will replace this with a per-tenant scheduler.
const MVP_TENANT_ID: &str = "default";

/// Configuration for the periodic graphsage job.
#[derive(Debug, Clone, Copy)]
pub(crate) struct GraphsageJobConfig {
    /// Interval between ticks, in seconds. Defaults to
    /// [`DEFAULT_INTERVAL_SECS`] (900s = 15 minutes).
    pub interval_secs: u64,
}

impl Default for GraphsageJobConfig {
    fn default() -> Self {
        Self {
            interval_secs: DEFAULT_INTERVAL_SECS,
        }
    }
}

/// Build the default GraphSAGE model used by the periodic job.
///
/// Two layers, both square `d x d` identity-like weights with zero bias
/// and a mean aggregator. The identity weight keeps the propagation
/// dominated by the self+neighbour sum, so a node with many neighbours
/// in the same cluster ends up with a strictly larger embedding than an
/// isolated node — that's the signal the cache surfaces.
pub(crate) fn default_model() -> GraphSageModel {
    let weight = Matrix::identity(NODE_FEATURE_DIM);
    let agg = MeanAggregator::with_dim(NODE_FEATURE_DIM);
    let layer = SageLayer::new(weight.clone(), vec![0.0_f64; NODE_FEATURE_DIM], agg);
    let layer2 = SageLayer::new(weight, vec![0.0_f64; NODE_FEATURE_DIM], agg);
    GraphSageModel::new(vec![layer, layer2])
}

/// Spawn the periodic graphsage job.
///
/// Returns the [`JoinHandle`] so the composition root can await shutdown.
/// The loop exits on `shutdown.cancelled()`; otherwise it ticks every
/// `cfg.interval_secs` until the process dies.
pub(crate) fn spawn(
    findings: Arc<dyn FindingRepositoryPort>,
    assets: Arc<dyn AssetRepositoryPort>,
    cache: Arc<Mutex<HashMap<String, f64>>>,
    cfg: GraphsageJobConfig,
    shutdown: CancellationToken,
) -> JoinHandle<()> {
    let interval = Duration::from_secs(cfg.interval_secs.max(1));
    tokio::spawn(async move {
        info!(
            target: "adapters.graphsage_job",
            interval_secs = cfg.interval_secs,
            tenant = MVP_TENANT_ID,
            "graphsage periodic job started",
        );
        loop {
            tokio::select! {
                () = shutdown.cancelled() => {
                    info!(
                        target: "adapters.graphsage_job",
                        "graphsage periodic job received cancellation, exiting",
                    );
                    return;
                }
                () = tokio::time::sleep(interval) => {
                    run_tick(
                        Arc::clone(&findings),
                        Arc::clone(&assets),
                        Arc::clone(&cache),
                    )
                    .await;
                }
            }
        }
    })
}

/// Execute one tick of the job. Pulled out so the unit tests can exercise
/// it directly without spinning up the spawn loop.
pub(crate) async fn run_tick(
    findings: Arc<dyn FindingRepositoryPort>,
    assets: Arc<dyn AssetRepositoryPort>,
    cache: Arc<Mutex<HashMap<String, f64>>>,
) {
    let asset_rows = match assets.list(MVP_TENANT_ID, 0, LIST_PAGE_LIMIT).await {
        Ok(rows) => rows,
        Err(err) => {
            warn!(
                target: "adapters.graphsage_job",
                error = %err,
                "graphsage tick aborted: asset list failed",
            );
            return;
        }
    };
    let finding_rows = match findings.list(MVP_TENANT_ID, 0, LIST_PAGE_LIMIT).await {
        Ok(rows) => rows,
        Err(err) => {
            warn!(
                target: "adapters.graphsage_job",
                error = %err,
                "graphsage tick aborted: finding list failed",
            );
            return;
        }
    };

    let graph = build_graph(&asset_rows, &finding_rows);
    let model = default_model();
    let embeddings = model.forward(&graph, 2);

    // Project each asset id onto its node id, then read out the L2 norm
    // of the embedding row. We hold the cache lock for the minimum time —
    // build the full map first, then swap it in.
    let mut next: HashMap<String, f64> = HashMap::with_capacity(asset_rows.len());
    for asset in &asset_rows {
        let node = node_id_for(&asset.id);
        if let Some(vec) = embeddings.get(&node) {
            let norm = l2_norm(vec);
            next.insert(asset.id.clone(), norm);
        }
    }

    let inserted = next.len();
    match cache.lock() {
        Ok(mut guard) => {
            *guard = next;
        }
        Err(poison) => {
            // Recover the map even from a poisoned mutex so the next tick
            // still publishes scores. We never panic on lock failures.
            warn!(
                target: "adapters.graphsage_job",
                "graphsage cache mutex poisoned; recovering",
            );
            let mut guard = poison.into_inner();
            *guard = next;
        }
    }
    debug!(
        target: "adapters.graphsage_job",
        assets = asset_rows.len(),
        findings = finding_rows.len(),
        inserted,
        "graphsage tick complete",
    );
}

/// Build a `SimpleGraph` from the listed assets + findings.
///
/// - Every asset becomes a node with a 2-dim feature vector
///   `[1.0, finding_count]` (finding_count = number of findings that
///   reference this asset).
/// - For each finding we hash the `asset_id` onto its `u64` node id and
///   record the finding's existence; assets that share findings (i.e.
///   the same asset is referenced by multiple findings) get a self-loop
///   that the graph silently drops — so the "cluster as one component"
///   semantic is approximated by the dense feature delta (count term)
///   the asset receives.
/// - When two distinct assets appear via finding metadata (`related_asset`
///   key, optional), we add an edge between them. The MVP finding view
///   does not carry that key, so the resulting graph is mostly a union
///   of isolated nodes — sufficient for the cache scaffolding tests; the
///   richer edge derivation lands when the finding view gains a
///   `related_assets` field.
fn build_graph(
    assets: &[sx_api::view::asset_view::AssetView],
    findings: &[sx_api::view::finding_view::FindingView],
) -> SimpleGraph {
    let mut graph = SimpleGraph::new();
    let mut count_per_asset: HashMap<String, u32> = HashMap::with_capacity(assets.len());
    for f in findings {
        *count_per_asset.entry(f.asset_id.clone()).or_insert(0) += 1;
    }

    let mut known_assets: HashSet<String> = HashSet::with_capacity(assets.len());
    for a in assets {
        let nid = node_id_for(&a.id);
        let count = count_per_asset.get(&a.id).copied().unwrap_or(0);
        let features = vec![1.0_f64, f64::from(count)];
        graph.add_node(nid, features);
        known_assets.insert(a.id.clone());
    }

    // Co-finding edges: for every pair of findings that target distinct
    // known assets, link the two asset nodes. This is the "same-asset
    // findings cluster as one component" generalisation — same-asset
    // findings have no edge (the asset is already a single node), and
    // cross-asset findings (linked via metadata.related_asset, where
    // present) add an undirected edge between the two endpoints.
    for f in findings {
        let Some(related) = related_asset_from_metadata(f) else {
            continue;
        };
        if related == f.asset_id || !known_assets.contains(&related) {
            continue;
        }
        let a = node_id_for(&f.asset_id);
        let b = node_id_for(&related);
        graph.add_edge(a, b);
    }

    graph
}

/// Best-effort related-asset extraction from finding metadata. The MVP
/// view does not require this field, but reading it lets a future writer
/// inject cross-asset edges without changing the graph builder.
fn related_asset_from_metadata(
    finding: &sx_api::view::finding_view::FindingView,
) -> Option<String> {
    let meta = finding.metadata.as_ref()?;
    let v = meta.get("related_asset")?;
    v.as_str().map(std::string::ToString::to_string)
}

/// Hash an asset id string onto a stable `u64` node id.
///
/// We use a small FNV-1a so the hashing is deterministic and dependency-
/// free; the graph only needs `node_id` for indexing and never inverts
/// the hash.
fn node_id_for(asset_id: &str) -> NodeId {
    const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x100_0000_01b3;
    let mut h = FNV_OFFSET;
    for b in asset_id.as_bytes() {
        h ^= u64::from(*b);
        h = h.wrapping_mul(FNV_PRIME);
    }
    h
}

/// L2 norm of a feature vector. Non-finite components are ignored.
fn l2_norm(v: &[f64]) -> f64 {
    let mut acc = 0.0_f64;
    for x in v {
        if x.is_finite() {
            acc = x.mul_add(*x, acc);
        }
    }
    acc.sqrt()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use sx_api::port::EngagementPortError;
    use sx_api::view::asset_view::AssetView;
    use sx_api::view::finding_view::FindingView;

    // --- stub repos -------------------------------------------------------

    struct StubFindings(Vec<FindingView>);
    #[async_trait]
    impl FindingRepositoryPort for StubFindings {
        async fn list(
            &self,
            _t: &str,
            _o: u64,
            _l: u32,
        ) -> Result<Vec<FindingView>, EngagementPortError> {
            Ok(self.0.clone())
        }
        async fn get(&self, _t: &str, _id: &str) -> Result<FindingView, EngagementPortError> {
            Err(EngagementPortError::NotFound)
        }
        async fn update_status(
            &self,
            _t: &str,
            _id: &str,
            _s: &str,
            _c: Option<&str>,
        ) -> Result<FindingView, EngagementPortError> {
            Err(EngagementPortError::NotFound)
        }
        async fn insert(&self, view: FindingView) -> Result<FindingView, EngagementPortError> {
            Ok(view)
        }
    }

    struct StubAssets(Vec<AssetView>);
    #[async_trait]
    impl AssetRepositoryPort for StubAssets {
        async fn list(
            &self,
            _t: &str,
            _o: u64,
            _l: u32,
        ) -> Result<Vec<AssetView>, EngagementPortError> {
            Ok(self.0.clone())
        }
        async fn get(&self, _t: &str, _id: &str) -> Result<AssetView, EngagementPortError> {
            Err(EngagementPortError::NotFound)
        }
    }

    fn asset(id: &str) -> AssetView {
        AssetView {
            id: id.into(),
            tenant_id: MVP_TENANT_ID.into(),
            engagement_id: "engagement-1".into(),
            kind: "host".into(),
            identifier: format!("{id}.example.com"),
            source: "scan".into(),
            first_seen: "2026-05-15T00:00:00Z".into(),
            last_seen: "2026-05-29T00:00:00Z".into(),
            criticality: None,
        }
    }

    fn finding(id: &str, asset_id: &str) -> FindingView {
        FindingView {
            id: id.into(),
            tenant_id: MVP_TENANT_ID.into(),
            asset_id: asset_id.into(),
            severity: "high".into(),
            status: "open".into(),
            title: "demo".into(),
            description: "demo finding".into(),
            cvss: Some(7.5),
            cve_id: None,
            first_seen: "2026-05-15T00:00:00Z".into(),
            last_seen: "2026-05-29T00:00:00Z".into(),
            metadata: None,
        }
    }

    // --- tests ------------------------------------------------------------

    #[tokio::test]
    async fn one_tick_writes_scores_into_cache() {
        let assets = Arc::new(StubAssets(vec![asset("asset-a"), asset("asset-b")]));
        let findings = Arc::new(StubFindings(vec![
            finding("f-1", "asset-a"),
            finding("f-2", "asset-a"),
            finding("f-3", "asset-b"),
        ]));
        let cache = Arc::new(Mutex::new(HashMap::new()));

        run_tick(
            Arc::clone(&findings) as Arc<dyn FindingRepositoryPort>,
            Arc::clone(&assets) as Arc<dyn AssetRepositoryPort>,
            Arc::clone(&cache),
        )
        .await;

        let guard = cache.lock().unwrap();
        assert_eq!(guard.len(), 2, "expected one score per asset");
        let score_a = *guard.get("asset-a").expect("asset-a score");
        let score_b = *guard.get("asset-b").expect("asset-b score");
        // asset-a has two findings so its feature delta is larger than
        // asset-b's one finding — after propagation the norm follows.
        assert!(score_a > score_b, "{score_a} should exceed {score_b}");
        assert!(score_a.is_finite() && score_b.is_finite());
    }

    #[tokio::test]
    async fn cancellation_aborts_the_loop_promptly() {
        let assets = Arc::new(StubAssets(vec![asset("asset-a")]));
        let findings = Arc::new(StubFindings(vec![]));
        let cache = Arc::new(Mutex::new(HashMap::new()));
        let token = CancellationToken::new();
        let cfg = GraphsageJobConfig { interval_secs: 60 };
        let handle = spawn(
            Arc::clone(&findings) as Arc<dyn FindingRepositoryPort>,
            Arc::clone(&assets) as Arc<dyn AssetRepositoryPort>,
            Arc::clone(&cache),
            cfg,
            token.clone(),
        );
        // Fire cancellation immediately; the loop must exit before the
        // 60-second interval elapses.
        token.cancel();
        let r = tokio::time::timeout(Duration::from_secs(2), handle).await;
        assert!(r.is_ok(), "task did not exit within 2s of cancellation");
    }

    #[tokio::test]
    async fn default_model_has_two_layers() {
        let m = default_model();
        assert_eq!(m.layers.len(), 2);
    }

    #[test]
    fn node_id_for_is_deterministic_and_nontrivial() {
        let a = node_id_for("asset-a");
        let b = node_id_for("asset-a");
        let c = node_id_for("asset-b");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn l2_norm_ignores_non_finite_components() {
        let v = vec![3.0, 4.0];
        assert!((l2_norm(&v) - 5.0).abs() < 1e-9);
        let mixed = vec![f64::NAN, 4.0, f64::INFINITY, 3.0];
        assert!((l2_norm(&mixed) - 5.0).abs() < 1e-9);
    }
}
