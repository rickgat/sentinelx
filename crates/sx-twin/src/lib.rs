//! `sx-twin` — Cyber Digital Twin for `SentinelX`.
//!
//! This crate provides an **in-memory replica** of the production asset+edge
//! graph and a **deterministic tick-based state machine** that simulates how
//! a compromise propagates without ever touching production state.
//!
//! # Why a digital twin?
//!
//! Breach & Attack Simulation in production is dangerous. The twin lets the
//! platform answer "what happens if attacker pivots from node A?" by stepping
//! a fully isolated mirror of the graph one [`tick::advance`] at a time. The
//! advance step is:
//!
//! - **Pure**: no I/O, no global state, no clock dependency.
//! - **Deterministic**: same `(Twin, RNG seed)` produces the same event list,
//!   in the same order, every time.
//! - **Bounded**: walks edges at most once per compromised seed per tick;
//!   cycles cannot loop forever.
//!
//! # Layout
//!
//! ```text
//! src/
//! ├── error.rs   TwinError
//! ├── state.rs   AssetId, AssetKind, AssetState, CompromiseState
//! ├── twin.rs    Twin, Edge, EdgeId
//! └── tick.rs    Event, advance(twin, rng) -> Vec<Event>
//! ```
//!
//! # Example
//!
//! ```
//! use rand::rngs::StdRng;
//! use rand::SeedableRng;
//! use sx_twin::state::{AssetId, AssetKind, AssetState, CompromiseState};
//! use sx_twin::tick::advance;
//! use sx_twin::twin::{Edge, Twin};
//!
//! let mut twin = Twin::new();
//! let a = AssetId::new();
//! let b = AssetId::new();
//! twin.add_asset(AssetState::new(a, AssetKind::Host, 0.1)).unwrap();
//! twin.add_asset(AssetState::new(b, AssetKind::Host, 0.1)).unwrap();
//! twin.add_edge(Edge::new(a, b, 1.0)).unwrap();
//! twin.mark_compromised(a).unwrap();
//!
//! let mut rng = StdRng::seed_from_u64(42);
//! let events = advance(&mut twin, &mut rng);
//! assert!(twin.is_compromised(b));
//! assert!(!events.is_empty());
//! ```

#![forbid(unsafe_code)]
#![deny(missing_docs)]
// Module-level docs use prose with shorthand like "RNG"; backticking every
// acronym hurts readability without improving correctness.
#![allow(clippy::doc_markdown)]

pub mod error;
pub mod state;
pub mod tick;
pub mod twin;

pub use error::TwinError;
