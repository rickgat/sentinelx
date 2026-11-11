//! Multi-layer `GraphSAGE` model and the [`SimpleGraph`] container it runs on.
//!
//! [`GraphSageModel::forward`] propagates per-node features through `k`
//! hops by applying the model's [`SageLayer`]s in order. Each layer reads
//! the current per-node embedding table and writes the next one; nodes
//! with no neighbours fall back to the [`MeanAggregator`]'s zero vector
//! (which, with `weight = I` and `bias = 0`, leaves them at `ReLU(x_self)`).

use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};

use super::aggregator::MeanAggregator;
use super::layer::SageLayer;

/// Stable node identifier.
///
/// We use `u64` so the graph can be built deterministically from any source
/// (UUIDs hashed to `u64`, asset row ids, etc.).
pub type NodeId = u64;

/// Minimal undirected adjacency container.
///
/// The graph stores per-node neighbour lists and per-node feature vectors.
/// Neighbour lists are sorted on insertion so [`GraphSageModel::forward`]
/// is deterministic across runs.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct SimpleGraph {
    /// Adjacency: `node -> sorted neighbour ids`. Self-loops are ignored.
    adjacency: BTreeMap<NodeId, Vec<NodeId>>,
    /// Per-node feature vectors. Nodes without a vector default to the
    /// zero vector of the layer's input dimension during the forward pass.
    features: BTreeMap<NodeId, Vec<f64>>,
}

impl SimpleGraph {
    /// Build an empty graph.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert (or overwrite) the feature vector for `node`.
    pub fn add_node(&mut self, node: NodeId, features: Vec<f64>) {
        self.adjacency.entry(node).or_default();
        self.features.insert(node, features);
    }

    /// Add an undirected edge `(a, b)`. Self-loops are silently ignored.
    /// Both endpoints become known nodes (with empty feature vectors if
    /// they did not exist).
    pub fn add_edge(&mut self, a: NodeId, b: NodeId) {
        if a == b {
            return;
        }
        let entry_a = self.adjacency.entry(a).or_default();
        if !entry_a.contains(&b) {
            entry_a.push(b);
            entry_a.sort_unstable();
        }
        let entry_b = self.adjacency.entry(b).or_default();
        if !entry_b.contains(&a) {
            entry_b.push(a);
            entry_b.sort_unstable();
        }
    }

    /// Iterate over `(node_id, feature_vector)` pairs in ascending id order.
    pub fn nodes(&self) -> impl Iterator<Item = (NodeId, &Vec<f64>)> {
        self.features.iter().map(|(k, v)| (*k, v))
    }

    /// All known node ids, ascending. Includes nodes that only appear as
    /// edge endpoints.
    #[must_use]
    pub fn node_ids(&self) -> Vec<NodeId> {
        let mut ids: Vec<NodeId> = self.adjacency.keys().copied().collect();
        for k in self.features.keys() {
            if !ids.contains(k) {
                ids.push(*k);
            }
        }
        ids.sort_unstable();
        ids
    }

    /// Neighbours of `node` (empty slice if the node is unknown or isolated).
    #[must_use]
    pub fn neighbours(&self, node: NodeId) -> &[NodeId] {
        self.adjacency
            .get(&node)
            .map_or(&[] as &[NodeId], Vec::as_slice)
    }

    /// Feature vector for `node`, or an empty slice if none was stored.
    #[must_use]
    pub fn features(&self, node: NodeId) -> &[f64] {
        self.features
            .get(&node)
            .map_or(&[] as &[f64], Vec::as_slice)
    }
}

/// A stack of [`SageLayer`]s using the mean aggregator.
///
/// The model is parameterised over the **type** of aggregator (always
/// [`MeanAggregator`] in this scaffold) so the same struct can be reused
/// if alternate aggregators are added later.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GraphSageModel {
    /// One [`SageLayer`] per hop. `forward(graph, k)` applies the first
    /// `min(k, layers.len())` layers.
    pub layers: Vec<SageLayer<MeanAggregator>>,
}

impl GraphSageModel {
    /// Build a model from a list of layers.
    #[must_use]
    pub const fn new(layers: Vec<SageLayer<MeanAggregator>>) -> Self {
        Self { layers }
    }

    /// Propagate features through up to `k` hops.
    ///
    /// Returns the per-node embedding table after the last applied layer.
    /// `k = 0` returns the (sanitised) input features unchanged.
    #[must_use]
    pub fn forward(&self, graph: &SimpleGraph, k: u8) -> HashMap<NodeId, Vec<f64>> {
        // Initial embedding table = per-node features.
        let ids = graph.node_ids();
        let mut current: HashMap<NodeId, Vec<f64>> = ids
            .iter()
            .map(|id| (*id, graph.features(*id).to_vec()))
            .collect();

        let hops = usize::from(k).min(self.layers.len());
        for layer_idx in 0..hops {
            let Some(layer) = self.layers.get(layer_idx) else {
                break;
            };

            let mut next: HashMap<NodeId, Vec<f64>> = HashMap::with_capacity(ids.len());
            for id in &ids {
                let self_vec = current.get(id).cloned().unwrap_or_default();
                let neighbour_vecs: Vec<Vec<f64>> = graph
                    .neighbours(*id)
                    .iter()
                    .map(|n| current.get(n).cloned().unwrap_or_default())
                    .collect();
                let updated = layer.propagate(&self_vec, &neighbour_vecs);
                next.insert(*id, updated);
            }
            current = next;
        }

        current
    }
}
