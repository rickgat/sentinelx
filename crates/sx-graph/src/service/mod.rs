//! Concrete implementations of [`crate::port::KnowledgeGraph`] plus
//! shared Cypher snippets.
//!
//! - [`Neo4jKnowledgeGraph`] — production adapter backed by
//!   [`Neo4jPool`].
//! - [`InMemoryKnowledgeGraph`] — test/dev adapter, no I/O.

pub mod blast_radius;
pub mod cypher;
pub mod fallback;
pub mod in_memory_graph;
pub mod neo4j_graph;
pub mod neo4j_pool;

pub use blast_radius::{
    BlastEdgeKind, BlastRadiusReport, BlastRadiusRequest, BlastRadiusService, ImpactedAsset,
    InMemoryBlastRadiusService, DEFAULT_DECAY_BASE, MAX_BLAST_RADIUS_DEPTH, MAX_IMPACTED_ASSETS,
};
pub use fallback::{
    classify_primary_error, AttackPathsResponse, BreakerSnapshot, BreakerState, CallDecision,
    CircuitBreaker, Clock, FallbackKnowledgeGraph, FallbackReason, GraphEngine, ManualClock,
    ReconnectProbe, ReconnectProbeHandle, SystemClock, METRIC_GRAPH_FALLBACK_ENGAGED,
    METRIC_GRAPH_RECOVERED,
};
pub use in_memory_graph::InMemoryKnowledgeGraph;
pub use neo4j_graph::{Neo4jConfig, Neo4jKnowledgeGraph};
pub use neo4j_pool::Neo4jPool;
