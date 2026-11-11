//! `drift` — empirical distribution drift detection.
//!
//! Two small primitives:
//!
//! - [`histogram::Histogram`] — a binned empirical distribution built from a
//!   slice of `f64` samples and a strictly increasing `bin_edges` array.
//! - [`kl::kl_divergence`] — Kullback–Leibler divergence between two
//!   histograms over the same bin edges, with Laplace smoothing so the
//!   formula is finite even when some bins are empty.
//!
//! The top-level [`kl::DriftReport`] bundles the divergence with a
//! caller-supplied threshold and an `exceeds_threshold` flag for ergonomic
//! consumption by detectors elsewhere in `SentinelX`.

pub mod histogram;
pub mod kl;

pub use histogram::Histogram;
pub use kl::{kl_divergence, DriftReport};
