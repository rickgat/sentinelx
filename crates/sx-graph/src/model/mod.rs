//! Graph domain types.
//!
//! - [`node`] — [`node::GraphNode`] enum + per-kind structs.
//! - [`edge`] — [`edge::GraphEdge`] + [`edge::EdgeKind`].
//! - [`attack_path`] — [`attack_path::AttackPath`] plus scoring helpers.

pub mod attack_path;
pub mod edge;
pub mod node;

pub use attack_path::{AttackPath, PropagatedRisk};
pub use edge::{EdgeKind, GraphEdge};
pub use node::{
    GraphAsset, GraphCredential, GraphCve, GraphFinding, GraphNetwork, GraphNode, GraphService,
    GraphTechnique, GraphTenant, GraphUser, NodeId, NodeKind,
};
