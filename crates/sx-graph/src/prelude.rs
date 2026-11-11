//! Convenience re-exports for typical call sites.
//!
//! ```rust,ignore
//! use sx_graph::prelude::*;
//! ```

pub use crate::controller::{
    ComputeRiskPropagationUseCase, FindAttackPathsUseCase, IngestFindingInput, IngestFindingOutput,
    IngestFindingUseCase,
};
pub use crate::error::GraphError;
pub use crate::model::{
    AttackPath, EdgeKind, GraphAsset, GraphCredential, GraphCve, GraphEdge, GraphFinding,
    GraphNetwork, GraphNode, GraphService, GraphTechnique, GraphTenant, GraphUser, NodeId,
    NodeKind, PropagatedRisk,
};
pub use crate::port::{AttackPathQuery, KnowledgeGraph, MAX_ATTACK_PATHS, MAX_ATTACK_PATH_DEPTH};
pub use crate::service::{InMemoryKnowledgeGraph, Neo4jConfig, Neo4jKnowledgeGraph, Neo4jPool};
