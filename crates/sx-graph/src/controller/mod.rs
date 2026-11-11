//! Use-cases (orchestrators) consumed by the API layer.
//!
//! Each use-case is a thin coordinator over the
//! [`crate::port::KnowledgeGraph`] port that injects validation,
//! tracing, and any cross-port wiring.

pub mod compute_risk_propagation;
pub mod find_attack_paths;
pub mod ingest_finding;

pub use compute_risk_propagation::ComputeRiskPropagationUseCase;
pub use find_attack_paths::FindAttackPathsUseCase;
pub use ingest_finding::{IngestFindingInput, IngestFindingOutput, IngestFindingUseCase};
