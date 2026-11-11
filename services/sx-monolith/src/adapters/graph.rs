#![allow(dead_code)] // Phase-3.5: many fields are reserved for the next-turn wire-up.
//! Knowledge-graph adapter.
//!
//! Builds the `sx-graph` composition-root bundle.
//!
//! When `graph.neo4j_enabled = false` (the default), the bundle is
//! backed by [`InMemoryKnowledgeGraph`] — useful for dev and tests.
//!
//! When `graph.neo4j_enabled = true`, the bundle is backed by
//! [`Neo4jKnowledgeGraph`], constructed from the operator-supplied
//! Bolt URI, user, password and database name. Boot tracing emits only
//! `"neo4j connected to <host>"` — the password is never logged.

use std::sync::Arc;

use secrecy::{ExposeSecret, SecretString};
use sx_config::GraphConfig;
use sx_graph::controller::{FindAttackPathsUseCase, IngestFindingUseCase};
use sx_graph::neo4j as neo4j_mvp;
use sx_graph::port::KnowledgeGraph;
use sx_graph::service::{
    FallbackKnowledgeGraph, GraphEngine, InMemoryKnowledgeGraph, Neo4jConfig, Neo4jKnowledgeGraph,
    ReconnectProbe, ReconnectProbeHandle,
};
use tracing::info;

/// Bundle returned by [`build`].
pub(crate) struct GraphBundle {
    /// Shared graph backend.
    pub graph: Arc<dyn KnowledgeGraph>,
    /// Ingest-one-finding use case.
    pub ingest_use_case: Arc<IngestFindingUseCase>,
    /// Attack-path discovery use case.
    pub find_paths_use_case: Arc<FindAttackPathsUseCase>,
    /// HIGH-007 — present when the primary Neo4j backend has been
    /// wrapped in [`FallbackKnowledgeGraph`]. The Phase-3 adapter prefers
    /// the wrapper-aware API so the wire DTO can carry the
    /// `engine`/`degraded` markers.
    pub fallback: Option<Arc<FallbackKnowledgeGraph>>,
    /// HIGH-007 — engine tag for the *default* (healthy) path. The
    /// adapter falls back to this when the wrapper is absent (in-memory
    /// dev builds report `memory`).
    pub default_engine: GraphEngine,
    /// HIGH-007 — handle for the background reconnect probe. Held by
    /// the bundle so it is dropped (and the probe aborted) when the
    /// process tears down. `_` prefix keeps clippy quiet about the
    /// otherwise-unused field.
    pub _probe: Option<ReconnectProbeHandle>,
}

/// Build the graph bundle.
///
/// Routes between the in-memory stub and the production Neo4j adapter
/// based on `cfg.neo4j_enabled`. When enabled, the function opens a
/// Bolt connection against `cfg.neo4j_uri` — failures bubble up to
/// the composition root, which aborts boot.
///
/// # Errors
///
/// When `cfg.neo4j_enabled` is `true`, returns an [`anyhow::Error`] if
/// the Bolt handshake fails or the supplied URI / credentials are
/// rejected by the driver.
#[allow(dead_code)] // parent composition root wires this in
pub(crate) async fn build(cfg: &GraphConfig) -> anyhow::Result<GraphBundle> {
    if cfg.neo4j_enabled && cfg.neo4j_use_mvp_engine {
        // P1-001 MVP attack-graph adapter: `UNWIND`-batched ingest at
        // 5k nodes / 10k edges per tx, bi-BFS attack-path search, audit
        // log on schema bootstrap / bulk writes / tenant deletes.
        let neo_cfg = neo4j_mvp::Neo4jConfig::new(
            cfg.neo4j_uri.clone(),
            cfg.neo4j_user.clone(),
            SecretString::from(cfg.neo4j_password.expose_secret().to_owned()),
            Some(cfg.neo4j_database.clone()),
        );
        let neo = neo4j_mvp::Neo4jKnowledgeGraph::new(neo_cfg)
            .await
            .map_err(|e| anyhow::anyhow!("neo4j (mvp) connect failed: {e}"))?;
        neo.ensure_schema()
            .await
            .map_err(|e| anyhow::anyhow!("neo4j (mvp) ensure_schema failed: {e}"))?;

        let host = extract_host(&cfg.neo4j_uri).unwrap_or_else(|| "<unknown>".to_owned());
        info!(
            target = "adapters.graph.built",
            backend = "neo4j_mvp",
            host = %host,
            "neo4j (P1-001 MVP) connected to {host}",
        );

        let graph: Arc<dyn KnowledgeGraph> = Arc::new(neo);
        let ingest_use_case = Arc::new(IngestFindingUseCase::new(Arc::clone(&graph)));
        let find_paths_use_case = Arc::new(FindAttackPathsUseCase::new(Arc::clone(&graph)));
        // HIGH-007: MVP engine keeps the simple (unwrapped) shape — the
        // experimental adapter is dev-only and not on the live API path.
        return Ok(GraphBundle {
            graph,
            ingest_use_case,
            find_paths_use_case,
            fallback: None,
            default_engine: GraphEngine::Neo4j,
            _probe: None,
        });
    }

    if cfg.neo4j_enabled {
        let neo_cfg = Neo4jConfig::new(
            cfg.neo4j_uri.clone(),
            cfg.neo4j_user.clone(),
            SecretString::from(cfg.neo4j_password.expose_secret().to_owned()),
            Some(cfg.neo4j_database.clone()),
        );
        let neo = Neo4jKnowledgeGraph::connect(&neo_cfg)
            .await
            .map_err(|e| anyhow::anyhow!("neo4j connect failed: {e}"))?;
        // Best-effort schema bootstrap: idempotent CREATE INDEX IF NOT
        // EXISTS statements. A failure here is fatal because the
        // adapter cannot guarantee correctness without its indexes.
        neo.ensure_indexes()
            .await
            .map_err(|e| anyhow::anyhow!("neo4j ensure_indexes failed: {e}"))?;

        let host = extract_host(&cfg.neo4j_uri).unwrap_or_else(|| "<unknown>".to_owned());
        info!(
            target = "adapters.graph.built",
            backend = "neo4j",
            host = %host,
            "neo4j connected to {host}"
        );

        // HIGH-007 — wrap the production Neo4j adapter behind
        // `FallbackKnowledgeGraph`. The secondary in-memory backend
        // serves degraded reads when the bolt connection misbehaves;
        // writes still go to Neo4j (and fail-fast when the breaker is
        // open). A background `ReconnectProbe` polls the primary every
        // 30 s and closes the breaker on first success.
        let primary: Arc<dyn KnowledgeGraph> = Arc::new(neo);
        let secondary: Arc<dyn KnowledgeGraph> = Arc::new(InMemoryKnowledgeGraph::new());
        let wrapper = Arc::new(FallbackKnowledgeGraph::new(
            Arc::clone(&primary),
            Arc::clone(&secondary),
        ));
        let probe = ReconnectProbe::spawn(Arc::clone(&wrapper));
        let graph: Arc<dyn KnowledgeGraph> = Arc::clone(&wrapper) as Arc<dyn KnowledgeGraph>;
        let ingest_use_case = Arc::new(IngestFindingUseCase::new(Arc::clone(&graph)));
        let find_paths_use_case = Arc::new(FindAttackPathsUseCase::new(Arc::clone(&graph)));
        return Ok(GraphBundle {
            graph,
            ingest_use_case,
            find_paths_use_case,
            fallback: Some(wrapper),
            default_engine: GraphEngine::Neo4j,
            _probe: Some(probe),
        });
    }

    let graph: Arc<dyn KnowledgeGraph> = Arc::new(InMemoryKnowledgeGraph::new());
    let ingest_use_case = Arc::new(IngestFindingUseCase::new(Arc::clone(&graph)));
    let find_paths_use_case = Arc::new(FindAttackPathsUseCase::new(Arc::clone(&graph)));

    info!(
        target = "adapters.graph.built",
        backend = "in_memory",
        "graph bundle constructed",
    );

    Ok(GraphBundle {
        graph,
        ingest_use_case,
        find_paths_use_case,
        // Dev/test path: no fallback wrapper because there is no
        // primary to fail. The adapter reports `engine="memory"` so
        // dashboards never see a misleading `neo4j` tag.
        fallback: None,
        default_engine: GraphEngine::Memory,
        _probe: None,
    })
}

/// Extract the host component from a Bolt URI without leaking the
/// password (the URI never contains user-info, but we still extract
/// only the host so future schema changes can't accidentally leak it).
fn extract_host(uri: &str) -> Option<String> {
    // `bolt://`, `neo4j+s://`, etc. — strip the scheme, then take
    // everything before the next '/' (path) or end of string. Drop
    // any embedded user-info just in case.
    let after_scheme = uri.split_once("://").map(|(_, rest)| rest)?;
    let authority = after_scheme.split('/').next()?;
    // Strip any `user:pass@` prefix (Bolt URIs shouldn't have one, but
    // be defensive).
    let host_port = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    if host_port.is_empty() {
        None
    } else {
        Some(host_port.to_owned())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    use secrecy::SecretString;
    use sx_config::GraphConfig;
    use sx_core::value_object::ids::TenantId;

    fn disabled_cfg() -> GraphConfig {
        GraphConfig::default()
    }

    fn enabled_cfg() -> GraphConfig {
        GraphConfig {
            neo4j_enabled: true,
            neo4j_uri: "bolt://127.0.0.1:7687".to_string(),
            neo4j_user: "neo4j".to_string(),
            neo4j_password: SecretString::from("test1234".to_owned()),
            neo4j_database: "neo4j".to_string(),
            neo4j_use_mvp_engine: false,
        }
    }

    fn enabled_mvp_cfg() -> GraphConfig {
        let mut c = enabled_cfg();
        c.neo4j_use_mvp_engine = true;
        c
    }

    #[tokio::test]
    async fn disabled_config_builds_in_memory_stub() {
        let bundle = build(&disabled_cfg())
            .await
            .expect("disabled build must succeed without any I/O");
        // The stub adapter must answer attack-path queries without
        // ever touching the network. Routing the request through the
        // use case is the cleanest way to confirm the wiring.
        let tenant = TenantId::new();
        let q = sx_graph::port::AttackPathQuery {
            tenant_id: tenant,
            entry_kind: sx_graph::model::node::NodeKind::Asset,
            target_kind: sx_graph::model::node::NodeKind::Asset,
            max_depth: 3,
            max_paths: 5,
        };
        let paths = bundle
            .find_paths_use_case
            .execute(&q)
            .await
            .expect("in-memory query must not fail");
        // No nodes seeded → empty result, but the call returned cleanly.
        assert!(paths.is_empty());
    }

    #[test]
    fn extract_host_handles_bolt_uri() {
        assert_eq!(
            extract_host("bolt://127.0.0.1:7687"),
            Some("127.0.0.1:7687".to_owned())
        );
        assert_eq!(
            extract_host("neo4j+s://graph.example.com:7687/database"),
            Some("graph.example.com:7687".to_owned())
        );
        // Defensive: even if user-info ever sneaks in, we strip it.
        assert_eq!(
            extract_host("bolt://neo4j:secret@10.0.0.1:7687"),
            Some("10.0.0.1:7687".to_owned())
        );
        assert_eq!(extract_host("garbage"), None);
        assert_eq!(extract_host(""), None);
    }

    /// Live integration test against a developer-supplied Neo4j on
    /// `bolt://127.0.0.1:7687` with credentials `neo4j/test1234` and
    /// database `neo4j`.
    ///
    /// Run with:
    ///
    /// ```text
    /// cargo test -p sx-monolith --release -- --ignored
    /// ```
    #[tokio::test]
    #[ignore = "Requires live Neo4j on bolt://127.0.0.1:7687"]
    async fn live_neo4j_add_asset_and_attack_paths() {
        let bundle = build(&enabled_cfg())
            .await
            .expect("live Neo4j must be reachable");
        // Down-cast to the concrete Neo4j adapter via the KnowledgeGraph
        // port: we use the use-case-level surface to seed and query.
        let tenant = TenantId::new();
        let entry = sx_graph::model::node::GraphNode::Asset(sx_graph::model::node::GraphAsset {
            id: sx_graph::model::node::NodeId::new("integ-entry"),
            tenant_id: tenant,
            name: "integ-entry".into(),
            exposure: sx_core::value_object::exposure::ExposureLevel::Internet,
            criticality: sx_core::value_object::criticality::AssetCriticality::Production,
            risk_score: Some(1.0),
            properties: std::collections::BTreeMap::new(),
        });
        let crown = sx_graph::model::node::GraphNode::Asset(sx_graph::model::node::GraphAsset {
            id: sx_graph::model::node::NodeId::new("integ-crown"),
            tenant_id: tenant,
            name: "integ-crown".into(),
            exposure: sx_core::value_object::exposure::ExposureLevel::Internal,
            criticality: sx_core::value_object::criticality::AssetCriticality::CrownJewel,
            risk_score: Some(5.0),
            properties: std::collections::BTreeMap::new(),
        });
        bundle.graph.upsert_node(&entry).await.unwrap();
        bundle.graph.upsert_node(&crown).await.unwrap();
        let q = sx_graph::port::AttackPathQuery {
            tenant_id: tenant,
            entry_kind: sx_graph::model::node::NodeKind::Asset,
            target_kind: sx_graph::model::node::NodeKind::Asset,
            max_depth: 3,
            max_paths: 5,
        };
        // We don't assert non-empty: the production pattern requires
        // a Finding+Technique chain we didn't seed. The point is that
        // the plumbing reaches Neo4j and returns without error.
        let _paths = bundle.find_paths_use_case.execute(&q).await.unwrap();
    }
}
