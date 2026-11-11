//! `sx-ml` — `SentinelX` machine-learning pipelines.
//!
//! This crate contains the small, pure-Rust ML primitives used by `SentinelX`:
//!
//! - [`service::decision_tree::CartTree`] — CART-style decision tree for
//!   finding-triage classification.
//! - [`service::isolation_forest::IsolationForest`] — pure-Rust Isolation
//!   Forest for anomaly detection.
//! - [`service::path_ranker::AttackPathRanker`] — composite scorer used as
//!   a Phase-3 approximation of GraphSAGE-style attack-path ranking until a
//!   Python sidecar is introduced.
//! - [`service::anonymiser::Anonymiser`] — anonymises feature rows before
//!   they ever reach a trainer.
//! - [`service::registry::ModelRegistry`] — in-memory model registry.
//!
//! ## Hard constraints
//!
//! - **No external ML library.** Pure-Rust algorithms only.
//! - **Determinism.** Every training routine is seeded; the same seed and
//!   the same input produces the same model.
//! - **Anonymisation first.** Training data is anonymised before it ever
//!   reaches the trainer. The trainer never sees raw PII (e-mail, IP, …).
//! - **JSON-serialisable models** for portability.
//!
//! See [`prelude`] for a convenience glob import.

#![forbid(unsafe_code)]

pub mod controller;
pub mod drift;
pub mod error;
pub mod graphsage;
pub mod model;
pub mod predictive;
pub mod prelude;
pub mod service;

pub use error::MlError;
