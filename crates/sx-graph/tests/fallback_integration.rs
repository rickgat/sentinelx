// LOW-009: integration test uses must-succeed unwraps + direct indexing into the asserted-non-empty result vec.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

//! HIGH-007 — integration test for [`FallbackKnowledgeGraph`].
//!
//! Simulates a Neo4j primary that starts healthy, fails mid-request,
//! recovers, and confirms the wrapper:
//!
//! 1. Returns `engine=Neo4j, degraded=false` while the primary is up.
//! 2. Returns `engine=Memory, degraded=true` after the primary starts
//!    failing — i.e. the wire shape stays the same and the dashboard
//!    can show the degraded badge.
//! 3. Trips the circuit breaker after 5 consecutive primary failures
//!    and short-circuits to the secondary thereafter.
//! 4. Allows a probe to close the breaker when the primary recovers,
//!    and the next call returns `engine=Neo4j, degraded=false` again.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use sx_core::value_object::ids::TenantId;
use sx_graph::error::GraphError;
use sx_graph::model::attack_path::{AttackPath, PropagatedRisk};
use sx_graph::model::edge::GraphEdge;
use sx_graph::model::node::{GraphNode, NodeId, NodeKind};
use sx_graph::port::{AttackPathQuery, KnowledgeGraph};
use sx_graph::service::{
    BreakerState, CircuitBreaker, Clock, FallbackKnowledgeGraph, GraphEngine,
    InMemoryKnowledgeGraph, ReconnectProbe, SystemClock,
};
use tokio::sync::RwLock;

/// A mock "Neo4j" graph that toggles between healthy / unhealthy under
/// test control. When unhealthy, every call returns a `Connection`
/// error shaped like a bolt timeout (so the wrapper classifies it as a
/// fallback-eligible failure).
#[derive(Debug)]
struct MockNeo4j {
    healthy: RwLock<bool>,
    /// Optional seeded result so the healthy path returns a non-trivial
    /// `engine=Neo4j` answer.
    seeded_paths: RwLock<Vec<AttackPath>>,
}

impl MockNeo4j {
    fn new(healthy: bool) -> Self {
        Self {
            healthy: RwLock::new(healthy),
            seeded_paths: RwLock::new(Vec::new()),
        }
    }

    async fn set_healthy(&self, v: bool) {
        *self.healthy.write().await = v;
    }

    async fn seed_paths(&self, paths: Vec<AttackPath>) {
        *self.seeded_paths.write().await = paths;
    }
}

#[async_trait]
impl KnowledgeGraph for MockNeo4j {
    async fn upsert_node(&self, _node: &GraphNode) -> Result<(), GraphError> {
        if *self.healthy.read().await {
            Ok(())
        } else {
            Err(GraphError::connection("bolt timeout"))
        }
    }
    async fn upsert_edge(&self, _edge: &GraphEdge) -> Result<(), GraphError> {
        if *self.healthy.read().await {
            Ok(())
        } else {
            Err(GraphError::connection("bolt timeout"))
        }
    }
    async fn find_attack_paths(
        &self,
        _query: &AttackPathQuery,
    ) -> Result<Vec<AttackPath>, GraphError> {
        if *self.healthy.read().await {
            Ok(self.seeded_paths.read().await.clone())
        } else {
            Err(GraphError::connection("bolt timeout"))
        }
    }
    async fn compute_risk_propagation(&self, _path_id: &str) -> Result<PropagatedRisk, GraphError> {
        if *self.healthy.read().await {
            Ok(PropagatedRisk {
                path_id: "mock".to_owned(),
                composite_score: 0.0,
                bottleneck_node_id: NodeId::new("mock"),
            })
        } else {
            Err(GraphError::connection("bolt timeout"))
        }
    }
    async fn neighbors(&self, _node_id: &NodeId, _depth: u8) -> Result<Vec<GraphNode>, GraphError> {
        if *self.healthy.read().await {
            Ok(vec![])
        } else {
            Err(GraphError::connection("bolt timeout"))
        }
    }
}

fn sample_query() -> AttackPathQuery {
    AttackPathQuery {
        tenant_id: TenantId::new(),
        entry_kind: NodeKind::Asset,
        target_kind: NodeKind::Asset,
        max_depth: 3,
        max_paths: 10,
    }
}

#[tokio::test]
async fn mock_neo4j_fails_mid_request_and_wrapper_returns_degraded_shape() {
    let primary = Arc::new(MockNeo4j::new(true));
    let secondary: Arc<dyn KnowledgeGraph> = Arc::new(InMemoryKnowledgeGraph::new());
    let wrapper =
        FallbackKnowledgeGraph::new(Arc::clone(&primary) as Arc<dyn KnowledgeGraph>, secondary);

    // Healthy: wrapper reports Neo4j engine.
    let resp = wrapper
        .find_attack_paths_with_engine(&sample_query())
        .await
        .expect("healthy call must succeed");
    assert_eq!(resp.engine, GraphEngine::Neo4j);
    assert!(!resp.degraded);

    // Kill the primary mid-flight: subsequent call falls back.
    primary.set_healthy(false).await;
    let resp = wrapper
        .find_attack_paths_with_engine(&sample_query())
        .await
        .expect("fallback must succeed");
    assert_eq!(resp.engine, GraphEngine::Memory);
    assert!(resp.degraded);
    assert!(resp.paths.is_empty(), "empty secondary returns empty paths");

    // Heal the primary: wrapper still uses secondary until the breaker
    // probe (or a successful direct call) closes the breaker. We have
    // not tripped the breaker yet (only one failure < 5), so a direct
    // call recovers immediately.
    primary.set_healthy(true).await;
    let resp = wrapper
        .find_attack_paths_with_engine(&sample_query())
        .await
        .expect("primary recovered call must succeed");
    assert_eq!(resp.engine, GraphEngine::Neo4j);
    assert!(!resp.degraded);
}

#[tokio::test]
async fn breaker_opens_after_spec_five_failures_and_short_circuits() {
    let primary = Arc::new(MockNeo4j::new(false));
    let secondary: Arc<dyn KnowledgeGraph> = Arc::new(InMemoryKnowledgeGraph::new());
    let wrapper =
        FallbackKnowledgeGraph::new(Arc::clone(&primary) as Arc<dyn KnowledgeGraph>, secondary);

    // Five failing calls trip the breaker (HIGH-007 spec).
    for _ in 0..CircuitBreaker::FAILURE_THRESHOLD {
        let resp = wrapper
            .find_attack_paths_with_engine(&sample_query())
            .await
            .expect("call must succeed via fallback");
        assert!(resp.degraded);
    }
    let snap = wrapper.breaker().snapshot().await;
    assert_eq!(snap.state, BreakerState::Open);
    assert_eq!(snap.consecutive_failures, CircuitBreaker::FAILURE_THRESHOLD);

    // Heal the primary — without a probe, subsequent calls still
    // short-circuit because the breaker is Open.
    primary.set_healthy(true).await;
    let resp = wrapper
        .find_attack_paths_with_engine(&sample_query())
        .await
        .expect("breaker-open call must succeed via fallback");
    assert_eq!(resp.engine, GraphEngine::Memory);
    assert!(resp.degraded);
}

#[tokio::test]
async fn reconnect_probe_closes_breaker_and_restores_neo4j_engine() {
    let primary = Arc::new(MockNeo4j::new(false));
    let secondary: Arc<dyn KnowledgeGraph> = Arc::new(InMemoryKnowledgeGraph::new());
    // Tight thresholds so the test finishes in milliseconds, not minutes.
    let breaker = Arc::new(CircuitBreaker::with_thresholds(
        "high-007-integration",
        1,
        Duration::from_millis(50),
        Arc::new(SystemClock) as Arc<dyn Clock>,
    ));
    let wrapper = Arc::new(FallbackKnowledgeGraph::with_breaker(
        Arc::clone(&primary) as Arc<dyn KnowledgeGraph>,
        secondary,
        Arc::clone(&breaker),
    ));

    // First call trips the breaker.
    let _ = wrapper
        .find_attack_paths_with_engine(&sample_query())
        .await
        .unwrap();
    assert_eq!(breaker.snapshot().await.state, BreakerState::Open);

    // Heal the primary and start a fast probe.
    primary.set_healthy(true).await;
    let _probe =
        ReconnectProbe::spawn_with_interval(Arc::clone(&wrapper), Duration::from_millis(50));

    // Poll for the breaker to close.
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    while std::time::Instant::now() < deadline {
        if matches!(breaker.snapshot().await.state, BreakerState::Closed) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(breaker.snapshot().await.state, BreakerState::Closed);

    // Now the wrapper serves from Neo4j again.
    let resp = wrapper
        .find_attack_paths_with_engine(&sample_query())
        .await
        .unwrap();
    assert_eq!(resp.engine, GraphEngine::Neo4j);
    assert!(!resp.degraded);
}

#[tokio::test]
async fn seeded_primary_paths_round_trip_through_wrapper() {
    // Sanity: the wrapper does not mangle the primary's returned paths
    // when the primary is healthy. Without this guard the API could
    // accidentally drop scores or ids on the happy path.
    let primary = Arc::new(MockNeo4j::new(true));
    let seeded = vec![AttackPath {
        id: "p-1".into(),
        score: 7.5,
        nodes: vec![NodeId::new("n1"), NodeId::new("n2")],
    }];
    primary.seed_paths(seeded.clone()).await;

    let secondary: Arc<dyn KnowledgeGraph> = Arc::new(InMemoryKnowledgeGraph::new());
    let wrapper =
        FallbackKnowledgeGraph::new(Arc::clone(&primary) as Arc<dyn KnowledgeGraph>, secondary);
    let resp = wrapper
        .find_attack_paths_with_engine(&sample_query())
        .await
        .unwrap();
    assert_eq!(resp.engine, GraphEngine::Neo4j);
    assert!(!resp.degraded);
    assert_eq!(resp.paths.len(), 1);
    assert_eq!(resp.paths[0].id, "p-1");
    assert!((resp.paths[0].score - 7.5).abs() < f64::EPSILON);
}
