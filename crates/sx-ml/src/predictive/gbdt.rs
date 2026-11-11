//! Self-contained gradient-boosted decision tree (GBDT) inference.
//!
//! This module deliberately implements only what the predictive risk
//! classifier needs at *inference* time: a stack of regression trees whose
//! leaf values are summed to produce a single raw score. Training is
//! intentionally out of scope — the MVP loads a pre-baked
//! [`Forest`] from JSON.
//!
//! ## Design
//!
//! Each [`Tree`] stores its nodes in two parallel structures:
//!
//! - `splits: Vec<Split>` — internal nodes. `feature_idx`/`threshold`
//!   define the test, `left` and `right` are indices into either the
//!   `splits` vector (when the value is non-negative) or the `leaves`
//!   vector (encoded as `-(leaf_index + 1)`).
//! - `leaves: Vec<f64>` — terminal values added into the running raw
//!   score.
//!
//! Inference walks from node `0`; if `splits` is empty the tree is a
//! single leaf and we read `leaves[0]` directly. An empty forest returns
//! `0.0` — the uninformative prior that
//! [`super::model::PredictiveModel`] subsequently squashes into the
//! `0.5` probability mid-point through its sigmoid.
//!
//! No third-party GBDT crate is used. No `unsafe` is used.

use serde::{Deserialize, Serialize};

/// Encodes one split test inside a tree.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Split {
    /// Index into the feature vector this split tests.
    pub feature_idx: usize,
    /// Split threshold — rows where `feature[feature_idx] <= threshold`
    /// follow the `left` link.
    pub threshold: f64,
    /// Left successor.
    ///
    /// A non-negative value is an index into the owning tree's `splits`.
    /// A negative value `n` is encoded as `-(leaf_index + 1)` — recover
    /// `leaf_index` with `(-n - 1) as usize`.
    pub left: i32,
    /// Right successor — same encoding as [`Split::left`].
    pub right: i32,
}

impl Split {
    /// Convenience constructor.
    #[must_use]
    pub const fn new(feature_idx: usize, threshold: f64, left: i32, right: i32) -> Self {
        Self {
            feature_idx,
            threshold,
            left,
            right,
        }
    }
}

/// One regression tree inside the forest.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Tree {
    /// Internal split nodes. Empty when the tree is a single leaf.
    #[serde(default)]
    pub splits: Vec<Split>,
    /// Terminal leaf values. At least one leaf must exist for the tree
    /// to be evaluable.
    #[serde(default)]
    pub leaves: Vec<f64>,
}

impl Tree {
    /// Build a tree of a single leaf with the given value.
    #[must_use]
    pub fn single_leaf(value: f64) -> Self {
        Self {
            splits: Vec::new(),
            leaves: vec![value],
        }
    }

    /// Evaluate the tree against `features`, returning the matched leaf
    /// value.
    ///
    /// If the tree is malformed (no leaves, dangling indices, …) the
    /// evaluator falls back to `0.0` — the same neutral value as an
    /// empty forest. Doing so keeps inference total and side-effect-free.
    #[must_use]
    pub fn predict(&self, features: &[f64]) -> f64 {
        let Some(first_leaf) = self.leaves.first().copied() else {
            return 0.0;
        };
        if self.splits.is_empty() {
            return first_leaf;
        }
        let mut cursor: i32 = 0;
        let max_steps = self.splits.len().saturating_add(1);
        for _ in 0..=max_steps {
            if cursor < 0 {
                let leaf_idx = leaf_index_from(cursor);
                return self.leaves.get(leaf_idx).copied().unwrap_or(first_leaf);
            }
            let Ok(idx) = usize::try_from(cursor) else {
                return first_leaf;
            };
            let Some(split) = self.splits.get(idx) else {
                return first_leaf;
            };
            let value = features.get(split.feature_idx).copied().unwrap_or(0.0);
            cursor = if value <= split.threshold {
                split.left
            } else {
                split.right
            };
        }
        // Defensive: if the walk failed to terminate within bounds, treat
        // the tree as neutral. This branch is unreachable for well-formed
        // input but keeps clippy happy without panicking.
        first_leaf
    }
}

const fn leaf_index_from(encoded: i32) -> usize {
    // `encoded` is negative: leaf index is `-(encoded + 1)`.
    let raw = encoded.saturating_add(1).saturating_neg();
    if raw < 0 {
        0
    } else {
        #[allow(clippy::cast_sign_loss)]
        let idx = raw as usize;
        idx
    }
}

/// Encode a leaf index as a child pointer suitable for [`Split::left`] or
/// [`Split::right`].
///
/// `leaf_pointer(0) = -1`, `leaf_pointer(1) = -2`, and so on. The first
/// `i32::MAX as usize` leaves are addressable.
#[must_use]
pub const fn leaf_pointer(leaf_index: usize) -> i32 {
    let bounded = if leaf_index >= i32::MAX as usize {
        (i32::MAX as usize) - 1
    } else {
        leaf_index
    };
    // Safe: `bounded < i32::MAX`, so `bounded as i32` does not overflow.
    #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
    let as_i32 = bounded as i32;
    -(as_i32 + 1)
}

/// A forest of regression trees whose outputs sum to a raw score.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Forest {
    /// Trees in evaluation order. Result is the sum of every
    /// [`Tree::predict`].
    #[serde(default)]
    pub trees: Vec<Tree>,
    /// Bias term added once after the per-tree sum. Defaults to zero.
    #[serde(default)]
    pub bias: f64,
}

impl Forest {
    /// Build a forest from a list of trees with no bias.
    #[must_use]
    pub const fn from_trees(trees: Vec<Tree>) -> Self {
        Self { trees, bias: 0.0 }
    }

    /// Number of trees in the forest.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.trees.len()
    }

    /// Returns `true` when the forest contains no trees.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.trees.is_empty()
    }

    /// Sum every [`Tree::predict`] and add the [`Self::bias`].
    ///
    /// Returns `0.0` for an empty forest (i.e. when `bias` defaults to
    /// zero) — the uninformative prior. Callers that want a probability
    /// should pass the raw score through a sigmoid; see
    /// [`super::model::PredictiveModel::predict`].
    #[must_use]
    pub fn predict(&self, features: &[f64]) -> f64 {
        if self.trees.is_empty() {
            return self.bias;
        }
        let mut acc = self.bias;
        for tree in &self.trees {
            acc += tree.predict(features);
        }
        acc
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn leaf_pointer_round_trips() {
        for idx in 0..5_usize {
            let ptr = leaf_pointer(idx);
            assert!(ptr < 0);
            assert_eq!(leaf_index_from(ptr), idx);
        }
    }

    #[test]
    fn empty_forest_returns_zero() {
        let forest = Forest::default();
        assert!((forest.predict(&[0.0_f64; 4]) - 0.0).abs() < f64::EPSILON);
        assert!(forest.is_empty());
    }

    #[test]
    fn single_leaf_tree_returns_leaf_value() {
        let tree = Tree::single_leaf(0.42);
        let forest = Forest::from_trees(vec![tree]);
        assert!((forest.predict(&[0.0; 1]) - 0.42).abs() < f64::EPSILON);
    }

    #[test]
    fn binary_split_routes_left_for_low_values() {
        // Single split on feature 0: <= 0.5 → leaf 0 (-1.0), else → leaf 1 (2.0).
        let tree = Tree {
            splits: vec![Split::new(0, 0.5, leaf_pointer(0), leaf_pointer(1))],
            leaves: vec![-1.0, 2.0],
        };
        let forest = Forest::from_trees(vec![tree]);
        assert!((forest.predict(&[0.1, 0.0]) + 1.0).abs() < f64::EPSILON);
        assert!((forest.predict(&[0.9, 0.0]) - 2.0).abs() < f64::EPSILON);
    }
}
