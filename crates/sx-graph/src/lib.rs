//! # `sx-graph`
//!
//! Knowledge-graph crate for `SentinelX`.
//!
//! This crate models the security knowledge graph: assets, findings,
//! CVEs, MITRE ATT&CK techniques, users, credentials, services,
//! networks and tenants, plus the edges that connect them. It exposes
//! a port-and-adapter abstraction over the graph store
//! ([`port::KnowledgeGraph`]) and ships two concrete implementations:
//!
//! - [`service::Neo4jKnowledgeGraph`] — production adapter backed by a
//!   Neo4j `5.x` instance via [`neo4rs`].
//! - [`service::InMemoryKnowledgeGraph`] — pure-Rust, in-process
//!   adapter useful for unit tests and the dev-mode binary path.
//!
//! On top of the port the crate provides three use-cases:
//!
//! - [`controller::IngestFindingUseCase`] — fan-out one finding into
//!   the canonical asset/finding/CVE/technique sub-graph.
//! - [`controller::FindAttackPathsUseCase`] — query parametrised
//!   attack paths from external entry to crown-jewel targets.
//! - [`controller::ComputeRiskPropagationUseCase`] — fold per-node
//!   risk scores along a path into a composite score plus a
//!   bottleneck node.
//!
//! ## Design notes
//!
//! - All Cypher executed against Neo4j is **parametrised**. Identifier
//!   labels (node kinds, edge kinds) are produced from sealed enums via
//!   their `Display` impl — never from user input.
//! - The crate is `#![forbid(unsafe_code)]`.
//! - Every fallible API returns [`error::GraphError`].
//! - Use [`prelude`] for typical call sites.
//!
//! ## Crate layout
//!
//! - [`model`] — domain types (`GraphNode`, `GraphEdge`, `AttackPath`).
//! - [`port`] — the async [`port::KnowledgeGraph`] trait + query
//!   structs.
//! - [`service`] — port implementations and shared Cypher snippets.
//! - [`controller`] — application-level use-cases.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod controller;
pub mod error;
pub mod model;
pub mod neo4j;
pub mod port;
pub mod prelude;
pub mod service;

pub use crate::error::GraphError;
pub use crate::neo4j::{Neo4jConfig, Neo4jKnowledgeGraph};
