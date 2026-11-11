//! One layer of a GraphSAGE-style network.
//!
//! Forward equation (symmetric variant):
//!
//! ```text
//! h_v^{out} = ReLU( W * ( x_self + AGG(neighbours) ) + b )
//! ```
//!
//! `W` is `d_out x d_in`, `b` has length `d_out`. The mean aggregator is
//! the default; any other [`super::aggregator::Aggregator`] can be plugged
//! in by type parameter.

use serde::{Deserialize, Serialize};
use tracing::warn;

use super::aggregator::Aggregator;

/// Dense row-major matrix used for the linear projection inside a
/// [`SageLayer`].
///
/// The flat `data` buffer is laid out row-major: `data[row * cols + col]`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Matrix {
    /// Number of rows (`d_out`).
    pub rows: usize,
    /// Number of columns (`d_in`).
    pub cols: usize,
    /// Flat row-major buffer of length `rows * cols`.
    pub data: Vec<f64>,
}

impl Matrix {
    /// Build a matrix from a `rows x cols` row-major buffer.
    ///
    /// Returns `None` if `data.len() != rows * cols`.
    #[must_use]
    pub fn new(rows: usize, cols: usize, data: Vec<f64>) -> Option<Self> {
        if data.len() == rows.saturating_mul(cols) {
            Some(Self { rows, cols, data })
        } else {
            None
        }
    }

    /// Identity matrix of size `n x n`.
    #[must_use]
    pub fn identity(n: usize) -> Self {
        let mut data = vec![0.0_f64; n.saturating_mul(n)];
        for i in 0..n {
            // Safe: `i * n + i < n * n`.
            if let Some(slot) = data.get_mut(i.saturating_mul(n).saturating_add(i)) {
                *slot = 1.0;
            }
        }
        Self {
            rows: n,
            cols: n,
            data,
        }
    }

    /// Zero matrix of shape `rows x cols`.
    #[must_use]
    pub fn zeros(rows: usize, cols: usize) -> Self {
        Self {
            rows,
            cols,
            data: vec![0.0_f64; rows.saturating_mul(cols)],
        }
    }

    /// `y = W * x`. The result vector has length `self.rows`. If the input
    /// width disagrees with `self.cols`, the shorter dimension dictates the
    /// inner loop and missing entries are treated as `0`.
    #[must_use]
    pub fn matvec(&self, x: &[f64]) -> Vec<f64> {
        let mut out = vec![0.0_f64; self.rows];
        let inner = self.cols.min(x.len());
        for r in 0..self.rows {
            let base = r.saturating_mul(self.cols);
            let mut acc = 0.0_f64;
            for c in 0..inner {
                let w = self
                    .data
                    .get(base.saturating_add(c))
                    .copied()
                    .unwrap_or(0.0);
                let xc = x.get(c).copied().unwrap_or(0.0);
                acc = w.mul_add(xc, acc);
            }
            if let Some(slot) = out.get_mut(r) {
                *slot = acc;
            }
        }
        out
    }
}

/// One `GraphSAGE` layer.
///
/// `weight` has shape `d_out x d_in`, `bias` has length `d_out`. The
/// aggregator must produce vectors of length `d_in` so that the symmetric
/// update `W * (x_self + agg)` is well-defined.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SageLayer<A: Aggregator> {
    /// Linear projection applied after the self+neighbour sum.
    pub weight: Matrix,
    /// Bias added to the projection.
    pub bias: Vec<f64>,
    /// Neighbour aggregator (e.g. mean).
    pub aggregator: A,
}

impl<A: Aggregator> SageLayer<A> {
    /// Build a layer from explicit weight, bias and aggregator.
    pub const fn new(weight: Matrix, bias: Vec<f64>, aggregator: A) -> Self {
        Self {
            weight,
            bias,
            aggregator,
        }
    }

    /// Forward pass for a single node.
    ///
    /// Computes `ReLU( W * (x_self + AGG(neighbours)) + b )`.
    ///
    /// Non-finite values in `x_self` are clamped to `0.0`. The aggregator
    /// is expected to sanitise its own inputs.
    #[must_use]
    pub fn propagate(&self, x_self: &[f64], x_neighbours: &[Vec<f64>]) -> Vec<f64> {
        let mut self_clean = x_self.to_vec();
        sanitise_in_place(&mut self_clean, "SageLayer::propagate(x_self)");

        let agg = self.aggregator.aggregate(x_neighbours);

        // Self + neighbour aggregate.
        let merged_len = self_clean.len().max(agg.len());
        let mut merged = vec![0.0_f64; merged_len];
        for i in 0..merged_len {
            let s = self_clean.get(i).copied().unwrap_or(0.0);
            let a = agg.get(i).copied().unwrap_or(0.0);
            if let Some(slot) = merged.get_mut(i) {
                *slot = s + a;
            }
        }

        let mut projected = self.weight.matvec(&merged);

        // Bias.
        for (i, p) in projected.iter_mut().enumerate() {
            let b = self.bias.get(i).copied().unwrap_or(0.0);
            *p += b;
        }

        // ReLU + final sanitisation.
        sanitise_in_place(&mut projected, "SageLayer::propagate(output)");
        for p in &mut projected {
            if *p < 0.0 {
                *p = 0.0;
            }
        }
        projected
    }
}

/// Clamp NaN / infinite values to `0.0` in place and emit a `warn` log on
/// the first sanitisation in each call site.
pub fn sanitise_in_place(v: &mut [f64], site: &str) {
    let mut bad = 0_usize;
    for x in v.iter_mut() {
        if !x.is_finite() {
            *x = 0.0;
            bad = bad.saturating_add(1);
        }
    }
    if bad > 0 {
        warn!(
            target: "sx_ml::graphsage",
            site = site,
            clamped = bad,
            "non-finite values clamped to 0.0"
        );
    }
}
