//! Pure-Rust Isolation Forest implementation.
//!
//! Reference: Liu, Ting, Zhou — "Isolation Forest" (ICDM 2008).
//!
//! Only [`FeatureValue::Number`](crate::model::feature::FeatureValue::Number)
//! features participate in splits. Boolean and categorical features are
//! coerced to numeric (`0.0` / `1.0` and a stable hash of the category
//! respectively) so anomalous categorical values still influence the score.

use crate::error::MlError;
use crate::model::feature::{FeatureValue, FeatureVector};
use rand::rngs::StdRng;
use rand::seq::SliceRandom;
use rand::Rng;
use rand::SeedableRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

/// One node of an isolation tree (recursive).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ITreeNode {
    /// `None` at a leaf (external node); `Some` at an internal node.
    pub split: Option<ITreeSplit>,
    /// Number of rows that reached this node during training (used for the
    /// average-path-length estimate on early-terminated branches).
    pub size: usize,
    /// Left child (rows where `value < threshold`).
    pub left: Option<Box<Self>>,
    /// Right child.
    pub right: Option<Box<Self>>,
}

/// Internal-node split rule.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ITreeSplit {
    /// Feature name to split on.
    pub feature: String,
    /// Threshold; rows with `value < threshold` go left.
    pub threshold: f64,
}

/// A single isolation tree.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ITree {
    /// Root of the tree.
    pub root: ITreeNode,
}

/// An Isolation Forest — a collection of isolation trees and the parameters
/// needed to score new rows.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IsolationForest {
    /// The trained trees.
    pub trees: Vec<ITree>,
    /// Sub-sample size used per tree at training time. Needed at score time
    /// for the average-path-length normalisation constant `c(n)`.
    pub sample_size: usize,
    /// Maximum depth a tree was allowed to grow.
    pub height_limit: u32,
    /// Seed used for training (for reproducibility).
    pub seed: u64,
}

impl IsolationForest {
    /// Train a forest of `n_trees` isolation trees, each on `sample_size`
    /// rows sampled without replacement.
    pub fn train(
        rows: &[FeatureVector],
        n_trees: usize,
        sample_size: usize,
        seed: u64,
    ) -> Result<Self, MlError> {
        if rows.is_empty() {
            return Err(MlError::EmptyTrainingSet);
        }
        if n_trees == 0 {
            return Err(MlError::InvalidConfig("n_trees must be >= 1".into()));
        }
        if sample_size == 0 {
            return Err(MlError::InvalidConfig("sample_size must be >= 1".into()));
        }

        let height_limit = log2_ceil(sample_size);
        let mut rng = StdRng::seed_from_u64(seed);

        // Collect numeric coordinates for every row once up-front. This
        // also yields the universe of feature names.
        let numeric_rows: Vec<Vec<(String, f64)>> = rows.iter().map(numeric_projection).collect();
        let feature_universe = feature_universe_from(&numeric_rows);

        let mut trees = Vec::with_capacity(n_trees);
        for _ in 0..n_trees {
            let sample = sample_indices(&mut rng, rows.len(), sample_size);
            let tree = build_itree(
                &numeric_rows,
                &sample,
                &feature_universe,
                0,
                height_limit,
                &mut rng,
            );
            trees.push(ITree { root: tree });
        }

        Ok(Self {
            trees,
            sample_size,
            height_limit,
            seed,
        })
    }

    /// Anomaly score for a row, in `[0.0, 1.0]`. Higher = more anomalous.
    #[must_use]
    pub fn score(&self, row: &FeatureVector) -> f64 {
        if self.trees.is_empty() {
            return 0.0;
        }
        let numeric = numeric_projection(row);
        let mut total_path = 0.0_f64;
        for tree in &self.trees {
            total_path += path_length(&tree.root, &numeric, 0);
        }
        #[allow(clippy::cast_precision_loss)]
        let avg = total_path / self.trees.len() as f64;
        let c_n = average_path_constant(self.sample_size);
        if c_n <= 0.0 {
            return 0.0;
        }
        let exponent = -avg / c_n;
        exponent.exp2()
    }

    /// Serialise as JSON.
    pub fn to_json(&self) -> Result<String, MlError> {
        Ok(serde_json::to_string(self)?)
    }

    /// Deserialise from JSON.
    pub fn from_json(json: &str) -> Result<Self, MlError> {
        Ok(serde_json::from_str(json)?)
    }
}

fn log2_ceil(n: usize) -> u32 {
    if n <= 1 {
        return 1;
    }
    let n_u32 = u32::try_from(n).unwrap_or(u32::MAX);
    32_u32.saturating_sub(n_u32.saturating_sub(1).leading_zeros())
}

#[allow(clippy::cast_precision_loss)]
fn average_path_constant(n: usize) -> f64 {
    if n <= 1 {
        return 0.0;
    }
    let n_f = n as f64;
    let h = harmonic(n - 1);
    2.0_f64.mul_add(h, -(2.0 * (n_f - 1.0) / n_f))
}

#[allow(clippy::cast_precision_loss)]
fn harmonic(n: usize) -> f64 {
    if n == 0 {
        return 0.0;
    }
    // ln(n) + euler_mascheroni + 1/(2n) is a good approximation for large n,
    // but for our small sample sizes the exact sum is cheap and accurate.
    let mut s = 0.0_f64;
    for k in 1..=n {
        s += 1.0 / (k as f64);
    }
    s
}

fn category_to_f64(s: &str) -> f64 {
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    let digest = hasher.finalize();
    // Take 8 bytes, interpret as u64, map to [0, 1).
    let mut bytes = [0_u8; 8];
    for (i, b) in digest.iter().take(8).enumerate() {
        if let Some(slot) = bytes.get_mut(i) {
            *slot = *b;
        }
    }
    let raw = u64::from_be_bytes(bytes);
    #[allow(clippy::cast_precision_loss)]
    let denom = u64::MAX as f64;
    #[allow(clippy::cast_precision_loss)]
    let num = raw as f64;
    num / denom
}

fn numeric_projection(row: &FeatureVector) -> Vec<(String, f64)> {
    let mut out = Vec::with_capacity(row.len());
    for (k, v) in row {
        let coord = match v {
            FeatureValue::Number(n) if n.is_finite() => *n,
            FeatureValue::Number(_) | FeatureValue::Bool(false) => 0.0,
            FeatureValue::Bool(true) => 1.0,
            FeatureValue::Category(c) => category_to_f64(c),
        };
        out.push((k.clone(), coord));
    }
    out
}

fn feature_universe_from(numeric_rows: &[Vec<(String, f64)>]) -> Vec<String> {
    let mut set: BTreeSet<String> = BTreeSet::new();
    for row in numeric_rows {
        for (k, _) in row {
            set.insert(k.clone());
        }
    }
    set.into_iter().collect()
}

fn sample_indices(rng: &mut StdRng, pop: usize, k: usize) -> Vec<usize> {
    let mut all: Vec<usize> = (0..pop).collect();
    all.shuffle(rng);
    let take = k.min(pop);
    all.into_iter().take(take).collect()
}

fn value_for(row: &[(String, f64)], feature: &str) -> f64 {
    for (k, v) in row {
        if k == feature {
            return *v;
        }
    }
    0.0
}

fn build_itree(
    numeric_rows: &[Vec<(String, f64)>],
    indices: &[usize],
    feature_universe: &[String],
    depth: u32,
    height_limit: u32,
    rng: &mut StdRng,
) -> ITreeNode {
    if depth >= height_limit || indices.len() <= 1 || feature_universe.is_empty() {
        return ITreeNode {
            split: None,
            size: indices.len(),
            left: None,
            right: None,
        };
    }

    // Try up to `feature_universe.len()` random features looking for one
    // with a non-degenerate value range across the current sample. If none
    // exists, we terminate as an external node.
    let mut tries = feature_universe.len();
    while tries > 0 {
        tries -= 1;
        let pick = rng.gen_range(0..feature_universe.len());
        let Some(feature) = feature_universe.get(pick) else {
            continue;
        };
        let mut min_v = f64::INFINITY;
        let mut max_v = f64::NEG_INFINITY;
        for &i in indices {
            if let Some(row) = numeric_rows.get(i) {
                let v = value_for(row, feature);
                if v < min_v {
                    min_v = v;
                }
                if v > max_v {
                    max_v = v;
                }
            }
        }
        if !(min_v.is_finite() && max_v.is_finite()) || max_v - min_v <= f64::EPSILON {
            continue;
        }
        let threshold = rng.gen_range(min_v..max_v);
        let mut left = Vec::new();
        let mut right = Vec::new();
        for &i in indices {
            if let Some(row) = numeric_rows.get(i) {
                let v = value_for(row, feature);
                if v < threshold {
                    left.push(i);
                } else {
                    right.push(i);
                }
            }
        }
        if left.is_empty() || right.is_empty() {
            // Degenerate split despite range — try another feature.
            continue;
        }
        let l_node = build_itree(
            numeric_rows,
            &left,
            feature_universe,
            depth + 1,
            height_limit,
            rng,
        );
        let r_node = build_itree(
            numeric_rows,
            &right,
            feature_universe,
            depth + 1,
            height_limit,
            rng,
        );
        return ITreeNode {
            split: Some(ITreeSplit {
                feature: feature.clone(),
                threshold,
            }),
            size: indices.len(),
            left: Some(Box::new(l_node)),
            right: Some(Box::new(r_node)),
        };
    }

    ITreeNode {
        split: None,
        size: indices.len(),
        left: None,
        right: None,
    }
}

fn path_length(node: &ITreeNode, row: &[(String, f64)], depth: u32) -> f64 {
    let Some(split) = node.split.as_ref() else {
        return f64::from(depth) + average_path_constant(node.size);
    };
    let v = value_for(row, &split.feature);
    let next = if v < split.threshold {
        node.left.as_deref()
    } else {
        node.right.as_deref()
    };
    next.map_or_else(
        || f64::from(depth) + average_path_constant(node.size),
        |child| path_length(child, row, depth + 1),
    )
}
