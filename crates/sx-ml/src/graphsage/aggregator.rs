//! Neighbour aggregators for `GraphSAGE`.
//!
//! An aggregator collapses an arbitrary-length set of neighbour feature
//! vectors into a single fixed-dimensional vector. The only aggregator
//! provided here is the **mean** aggregator:
//!
//! ```text
//! AGG_mean({ h_u : u in N(v) }) = (1 / |N(v)|) * sum_{u in N(v)} h_u
//! ```
//!
//! For a node with no neighbours the aggregator returns the zero vector.
//! The dimension of that zero vector is taken from the caller's
//! configuration via [`MeanAggregator::with_dim`] so that downstream layers
//! always see a vector of the expected width.

use serde::{Deserialize, Serialize};

use super::layer::sanitise_in_place;

/// Trait that every neighbour aggregator must implement.
///
/// Implementors are responsible for sanitising non-finite inputs. The
/// blanket sanitisation provided by [`MeanAggregator`] uses
/// [`super::layer::sanitise_in_place`].
pub trait Aggregator {
    /// Collapse `neighbours` into a single vector.
    ///
    /// The length of the returned vector must equal the dimension that the
    /// downstream [`super::layer::SageLayer`] expects; an empty
    /// neighbourhood therefore yields the zero vector of that length.
    fn aggregate(&self, neighbours: &[Vec<f64>]) -> Vec<f64>;
}

/// Mean aggregator.
///
/// `aggregate(neighbours)` returns the per-coordinate mean of the input
/// vectors, or the zero vector of length [`MeanAggregator::dim`] when the
/// neighbourhood is empty.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct MeanAggregator {
    /// Output dimension. Used to size the zero vector returned for empty
    /// neighbourhoods so callers never see a length mismatch.
    pub dim: usize,
}

impl MeanAggregator {
    /// Build a mean aggregator that produces vectors of length `dim`.
    #[must_use]
    pub const fn with_dim(dim: usize) -> Self {
        Self { dim }
    }
}

impl Aggregator for MeanAggregator {
    fn aggregate(&self, neighbours: &[Vec<f64>]) -> Vec<f64> {
        if neighbours.is_empty() {
            return vec![0.0_f64; self.dim];
        }

        // Pick the output dimension from the first neighbour; subsequent
        // neighbours are truncated or zero-padded to that width so a
        // ragged input cannot panic the indexing below. If the configured
        // `dim` is non-zero we prefer it (this keeps layers composable).
        let target_dim = if self.dim == 0 {
            neighbours.first().map_or(0, Vec::len)
        } else {
            self.dim
        };

        if target_dim == 0 {
            return Vec::new();
        }

        let mut acc = vec![0.0_f64; target_dim];
        for neighbour in neighbours {
            let mut row = neighbour.clone();
            // Normalise width: truncate long rows, zero-pad short rows.
            match row.len().cmp(&target_dim) {
                std::cmp::Ordering::Less => row.resize(target_dim, 0.0),
                std::cmp::Ordering::Greater => row.truncate(target_dim),
                std::cmp::Ordering::Equal => {}
            }
            sanitise_in_place(&mut row, "MeanAggregator::aggregate");
            for (a, r) in acc.iter_mut().zip(row.iter()) {
                *a += *r;
            }
        }

        #[allow(clippy::cast_precision_loss)]
        let denom = neighbours.len() as f64;
        for a in &mut acc {
            *a /= denom;
        }
        acc
    }
}
