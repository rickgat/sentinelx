//! `graphsage` — pure-Rust GraphSAGE-style risk propagation.
//!
//! This module implements a small, dependency-free approximation of the
//! [GraphSAGE](https://arxiv.org/abs/1706.02216) inductive node-embedding
//! algorithm. It is intentionally minimal:
//!
//! - Only a **mean** neighbour aggregator is provided
//!   ([`aggregator::MeanAggregator`]).
//! - Each [`layer::SageLayer`] applies the canonical update
//!   `h_v^{k} = ReLU( W * concat(h_v^{k-1}, AGG({ h_u^{k-1} : u in N(v) })) + b )`.
//!   The concrete linear form chosen here is the symmetric variant
//!   `h_v^{k} = ReLU( W * (h_v^{k-1} + AGG(neighbours)) + b )` so the
//!   weight matrix is square (`d_out x d_in`) and the math composes cleanly
//!   across layers.
//! - [`model::GraphSageModel`] stacks `k` such layers and propagates per-node
//!   feature vectors through `k` hops on a [`model::SimpleGraph`].
//!
//! ## Hard constraints
//!
//! - **No external ML library.** Pure-Rust linear algebra only.
//! - **No `unsafe`.** Enforced by `#![forbid(unsafe_code)]` at the crate root.
//! - **NaN / infinity hygiene.** Non-finite inputs are clamped to `0.0` and a
//!   `tracing::warn!` is emitted so callers see the sanitisation in the logs.

pub mod aggregator;
pub mod layer;
pub mod model;

pub use aggregator::{Aggregator, MeanAggregator};
pub use layer::{Matrix, SageLayer};
pub use model::{GraphSageModel, NodeId, SimpleGraph};
