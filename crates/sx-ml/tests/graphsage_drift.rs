//! Integration tests for the `GraphSAGE` and drift detector scaffolds.
//!
//! Test plan (≥12 cases, mirroring the agent spec):
//!
//! ## `MeanAggregator`
//! 1. Three neighbours with the equal vector → identity output.
//! 2. Empty neighbourhood → zero vector of the configured dim.
//!
//! ## `SageLayer`
//! 3. Weight = identity, bias = 0 → `x_self + mean(neighbours)` (`ReLU` clip).
//! 4. `ReLU` clamps negatives to `0`.
//!
//! ## `GraphSageModel`
//! 5. Two-layer composition.
//! 6. Disconnected (degree-0) node is passed through unchanged when
//!    `weight = I` and `bias = 0`.
//!
//! ## `Histogram`
//! 7. Bin counts correct on a known sample.
//! 8. NaN samples are skipped.
//!
//! ## `kl_divergence` / `DriftReport`
//! 9. Identical distributions → divergence = `0`.
//! 10. Maximally disjoint distributions → strictly positive divergence.
//! 11. `divergence > threshold` → `exceeds_threshold = true`.
//! 12. Empty histograms → divergence = `0` and `exceeds_threshold = false`.

// Integration tests: `expect` on Option is a deliberate assertion style.
#![allow(clippy::expect_used)]

use std::collections::HashMap;

use sx_ml::drift::{kl_divergence, DriftReport, Histogram};
use sx_ml::graphsage::{
    Aggregator, GraphSageModel, Matrix, MeanAggregator, NodeId, SageLayer, SimpleGraph,
};

// --- shared helpers -------------------------------------------------------

fn approx_eq(a: f64, b: f64, tol: f64) -> bool {
    (a - b).abs() <= tol
}

fn assert_vec_close(actual: &[f64], expected: &[f64], tol: f64) {
    assert_eq!(actual.len(), expected.len(), "length mismatch");
    for (i, (a, e)) in actual.iter().zip(expected.iter()).enumerate() {
        assert!(approx_eq(*a, *e, tol), "index {i}: {a} != {e} (tol {tol})");
    }
}

// --- MeanAggregator -------------------------------------------------------

#[test]
fn mean_aggregator_three_equal_neighbours_returns_same_vector() {
    let agg = MeanAggregator::with_dim(3);
    let neighbours = vec![
        vec![1.0, 2.0, 3.0],
        vec![1.0, 2.0, 3.0],
        vec![1.0, 2.0, 3.0],
    ];
    let out = agg.aggregate(&neighbours);
    assert_vec_close(&out, &[1.0, 2.0, 3.0], 1e-12);
}

#[test]
fn mean_aggregator_empty_neighbourhood_returns_zero_vector() {
    let agg = MeanAggregator::with_dim(4);
    let out = agg.aggregate(&[]);
    assert_eq!(out, vec![0.0, 0.0, 0.0, 0.0]);
}

// --- SageLayer ------------------------------------------------------------

#[test]
fn sage_layer_identity_weight_yields_self_plus_mean() {
    let weight = Matrix::identity(3);
    let bias = vec![0.0, 0.0, 0.0];
    let agg = MeanAggregator::with_dim(3);
    let layer = SageLayer::new(weight, bias, agg);

    let x_self = vec![0.5, 1.0, 2.0];
    let neighbours = vec![vec![1.0, 1.0, 1.0], vec![3.0, 3.0, 3.0]];
    // mean neighbours = (2, 2, 2); self + mean = (2.5, 3, 4); ReLU(I*x) = x.
    let out = layer.propagate(&x_self, &neighbours);
    assert_vec_close(&out, &[2.5, 3.0, 4.0], 1e-12);
}

#[test]
fn sage_layer_relu_clamps_negatives_to_zero() {
    // weight = -I so that the projected output is the negation of the sum.
    let neg_identity = Matrix::new(2, 2, vec![-1.0, 0.0, 0.0, -1.0]).expect("shape");
    let bias = vec![0.0, 0.0];
    let agg = MeanAggregator::with_dim(2);
    let layer = SageLayer::new(neg_identity, bias, agg);

    let x_self = vec![1.0, 2.0];
    let neighbours = vec![vec![0.5, 0.5]];
    // sum = (1.5, 2.5); W*sum = (-1.5, -2.5); after ReLU → (0, 0).
    let out = layer.propagate(&x_self, &neighbours);
    assert_eq!(out, vec![0.0, 0.0]);
}

// --- GraphSageModel ------------------------------------------------------

fn identity_layer(dim: usize) -> SageLayer<MeanAggregator> {
    SageLayer::new(
        Matrix::identity(dim),
        vec![0.0_f64; dim],
        MeanAggregator::with_dim(dim),
    )
}

#[test]
fn graphsage_model_two_layers_compose() {
    // Triangle: 1 — 2 — 3 — 1. Features one-hot per node.
    let mut graph = SimpleGraph::new();
    graph.add_node(1, vec![1.0, 0.0, 0.0]);
    graph.add_node(2, vec![0.0, 1.0, 0.0]);
    graph.add_node(3, vec![0.0, 0.0, 1.0]);
    graph.add_edge(1, 2);
    graph.add_edge(2, 3);
    graph.add_edge(1, 3);

    let model = GraphSageModel::new(vec![identity_layer(3), identity_layer(3)]);
    let embeddings: HashMap<NodeId, Vec<f64>> = model.forward(&graph, 2);

    // After one hop, each node sees self + mean(neighbours) = e_v + 0.5(e_a + e_b).
    // After a second hop, every coordinate is strictly positive — every node
    // can reach every other node in <= 2 hops in this fully-connected K3.
    for id in [1_u64, 2, 3] {
        let v = embeddings.get(&id).expect("embedding present");
        assert_eq!(v.len(), 3);
        assert!(
            v.iter().all(|x| *x > 0.0),
            "node {id} should be dense: {v:?}"
        );
    }
}

#[test]
fn graphsage_model_disconnected_node_passes_through_relu_only() {
    // Isolated node with positive features.
    let mut graph = SimpleGraph::new();
    graph.add_node(42, vec![0.25, 0.75, 1.5]);

    let model = GraphSageModel::new(vec![identity_layer(3)]);
    let embeddings = model.forward(&graph, 1);
    let v = embeddings.get(&42).expect("embedding present");
    // No neighbours → mean = 0; W = I, b = 0; ReLU(x_self) = x_self (already
    // non-negative).
    assert_vec_close(v, &[0.25, 0.75, 1.5], 1e-12);
}

// --- Histogram -----------------------------------------------------------

#[test]
fn histogram_bin_counts_correct_for_known_distribution() {
    // Edges: [0, 1, 2, 3] → 3 bins: [0,1), [1,2), [2,3].
    let edges = vec![0.0, 1.0, 2.0, 3.0];
    let samples = vec![0.1, 0.5, 1.0, 1.9, 2.0, 2.5, 3.0];
    let h = Histogram::from_samples(&samples, &edges);
    // bin 0: 0.1, 0.5 → 2
    // bin 1: 1.0, 1.9 → 2
    // bin 2: 2.0, 2.5, 3.0 → 3 (last-edge inclusive)
    assert_eq!(h.counts, vec![2, 2, 3]);
    assert_eq!(h.total(), 7);
}

#[test]
fn histogram_nan_samples_are_skipped() {
    let edges = vec![0.0, 1.0, 2.0];
    let samples = vec![0.5, f64::NAN, 1.5, f64::NAN];
    let h = Histogram::from_samples(&samples, &edges);
    assert_eq!(h.counts, vec![1, 1]);
    assert_eq!(h.total(), 2);
}

// --- KL divergence / DriftReport ----------------------------------------

#[test]
fn kl_identical_distributions_is_zero() {
    let edges = vec![0.0, 1.0, 2.0, 3.0];
    let samples = vec![0.1, 0.5, 1.5, 2.5];
    let h = Histogram::from_samples(&samples, &edges);
    let div = kl_divergence(&h, &h);
    assert!(approx_eq(div, 0.0, 1e-9), "expected 0, got {div}");
}

#[test]
fn kl_disjoint_distributions_has_strictly_positive_divergence() {
    let edges = vec![0.0, 1.0, 2.0, 3.0];
    // P: all mass in the first bin.
    let p = Histogram::from_samples(&[0.1, 0.2, 0.3, 0.4, 0.5], &edges);
    // Q: all mass in the last bin.
    let q = Histogram::from_samples(&[2.1, 2.2, 2.3, 2.4, 2.5], &edges);
    let div = kl_divergence(&p, &q);
    assert!(div > 1.0, "expected large divergence, got {div}");
    assert!(div.is_finite(), "expected finite divergence");
}

#[test]
fn drift_report_flags_exceeding_threshold() {
    let edges = vec![0.0, 1.0, 2.0];
    let p = Histogram::from_samples(&[0.1, 0.2, 0.3], &edges);
    let q = Histogram::from_samples(&[1.5, 1.6, 1.7], &edges);
    let report = DriftReport::from_histograms(&p, &q, 0.01);
    assert!(report.divergence > 0.01, "div = {}", report.divergence);
    assert!(report.exceeds_threshold);

    // Same distribution → no drift.
    let report_same = DriftReport::from_histograms(&p, &p, 0.01);
    assert!(approx_eq(report_same.divergence, 0.0, 1e-9));
    assert!(!report_same.exceeds_threshold);
}

#[test]
fn drift_report_empty_histograms_yields_zero_divergence() {
    let empty = Histogram {
        bins: Vec::new(),
        counts: Vec::new(),
    };
    let report = DriftReport::from_histograms(&empty, &empty, 0.1);
    assert!(approx_eq(report.divergence, 0.0, 1e-12));
    assert!(!report.exceeds_threshold);
}
