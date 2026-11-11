//! Tiny, pure-Rust CART decision tree for binary triage classification.
//!
//! The positive class is [`Label::FalsePositive`]. The tree supports
//! numeric, boolean and categorical features; the best split is chosen by
//! gini impurity at each node. Tree depth and minimum-samples-per-split
//! are user-configurable. Training is deterministic and seedable.

use crate::error::MlError;
use crate::model::feature::{FeatureValue, FeatureVector};
use crate::model::label::Label;
use rand::rngs::StdRng;
use rand::SeedableRng;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// The splitting rule attached to an internal tree node.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Split {
    /// Numeric split: rows where `value <= threshold` go left.
    Number {
        /// Feature name.
        feature: String,
        /// Split threshold.
        threshold: f64,
    },
    /// Boolean split: rows where `value == false` go left.
    Bool {
        /// Feature name.
        feature: String,
    },
    /// Categorical split: rows where `value == category` go left.
    Category {
        /// Feature name.
        feature: String,
        /// Reference category for the equality test.
        category: String,
    },
}

/// One node of the tree (recursive).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Node {
    /// Probability that a row reaching this node is `FalsePositive`. Used
    /// at leaves and also surfaced for soft-prediction.
    pub p_false_positive: f64,
    /// `None` at a leaf, `Some` at an internal node.
    pub split: Option<Split>,
    /// Left child, if any.
    pub left: Option<Box<Self>>,
    /// Right child, if any.
    pub right: Option<Box<Self>>,
}

impl Node {
    const fn leaf(p_false_positive: f64) -> Self {
        Self {
            p_false_positive,
            split: None,
            left: None,
            right: None,
        }
    }

    const fn is_leaf(&self) -> bool {
        self.split.is_none()
    }
}

/// CART-style decision tree.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CartTree {
    /// Root of the tree (always populated).
    pub root: Node,
    /// `max_depth` the tree was trained with.
    pub max_depth: u8,
    /// `min_samples_split` the tree was trained with.
    pub min_samples_split: usize,
    /// Seed used at training time.
    pub seed: u64,
}

impl CartTree {
    /// Train a new tree from labelled rows.
    ///
    /// `seed` is currently unused by the algorithm (the split search is
    /// deterministic) but is recorded on the model so callers can reproduce
    /// experiments and so future tie-breaking randomness stays seedable.
    pub fn train(
        samples: &[(FeatureVector, Label)],
        seed: u64,
        max_depth: u8,
        min_samples_split: usize,
    ) -> Result<Self, MlError> {
        if samples.is_empty() {
            return Err(MlError::EmptyTrainingSet);
        }
        if min_samples_split < 2 {
            return Err(MlError::InvalidConfig(
                "min_samples_split must be >= 2".into(),
            ));
        }

        // Determinism: pre-shuffling is sometimes used for tie-breaking. We
        // currently sort splits deterministically, but we still seed and
        // hold the rng for future use / reproducibility.
        let _rng = StdRng::seed_from_u64(seed);

        let indices: Vec<usize> = (0..samples.len()).collect();
        let root = build_node(samples, &indices, 0, max_depth, min_samples_split);

        Ok(Self {
            root,
            max_depth,
            min_samples_split,
            seed,
        })
    }

    /// Predict the most-likely label for `row`.
    #[must_use]
    pub fn predict(&self, row: &FeatureVector) -> Label {
        let p = self.predict_proba(row);
        if p >= 0.5 {
            Label::FalsePositive
        } else {
            Label::TruePositive
        }
    }

    /// Return `P(label = FalsePositive | row)`.
    #[must_use]
    pub fn predict_proba(&self, row: &FeatureVector) -> f64 {
        let mut node = &self.root;
        while !node.is_leaf() {
            let Some(split) = node.split.as_ref() else {
                break;
            };
            let go_left = match split {
                Split::Number { feature, threshold } => match row.get(feature) {
                    Some(FeatureValue::Number(v)) => v <= threshold,
                    _ => true,
                },
                Split::Bool { feature } => match row.get(feature) {
                    Some(FeatureValue::Bool(v)) => !v,
                    _ => true,
                },
                Split::Category { feature, category } => match row.get(feature) {
                    Some(FeatureValue::Category(v)) => v == category,
                    _ => false,
                },
            };
            let next = if go_left {
                node.left.as_deref()
            } else {
                node.right.as_deref()
            };
            match next {
                Some(n) => node = n,
                None => break,
            }
        }
        node.p_false_positive
    }

    /// Serialise the tree as JSON.
    pub fn to_json(&self) -> Result<String, MlError> {
        Ok(serde_json::to_string(self)?)
    }

    /// Deserialise a tree from JSON.
    pub fn from_json(json: &str) -> Result<Self, MlError> {
        Ok(serde_json::from_str(json)?)
    }
}

fn class_proportion(samples: &[(FeatureVector, Label)], indices: &[usize]) -> f64 {
    if indices.is_empty() {
        return 0.0;
    }
    let mut fp = 0_usize;
    for &i in indices {
        if let Some((_, lbl)) = samples.get(i) {
            if lbl.is_false_positive() {
                fp += 1;
            }
        }
    }
    #[allow(clippy::cast_precision_loss)]
    let n = indices.len() as f64;
    #[allow(clippy::cast_precision_loss)]
    let f = fp as f64;
    f / n
}

fn gini_from_proportion(p: f64) -> f64 {
    1.0 - p.mul_add(p, (1.0 - p) * (1.0 - p))
}

fn weighted_gini(samples: &[(FeatureVector, Label)], left: &[usize], right: &[usize]) -> f64 {
    let n_total = left.len() + right.len();
    if n_total == 0 {
        return 0.0;
    }
    let p_left = class_proportion(samples, left);
    let p_right = class_proportion(samples, right);
    #[allow(clippy::cast_precision_loss)]
    let n_l = left.len() as f64;
    #[allow(clippy::cast_precision_loss)]
    let n_r = right.len() as f64;
    #[allow(clippy::cast_precision_loss)]
    let n = n_total as f64;
    (n_l / n).mul_add(
        gini_from_proportion(p_left),
        (n_r / n) * gini_from_proportion(p_right),
    )
}

fn feature_names(samples: &[(FeatureVector, Label)], indices: &[usize]) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    for &i in indices {
        if let Some((row, _)) = samples.get(i) {
            for k in row.keys() {
                names.insert(k.clone());
            }
        }
    }
    names
}

fn candidate_thresholds(
    samples: &[(FeatureVector, Label)],
    indices: &[usize],
    feature: &str,
) -> Vec<f64> {
    let mut values: Vec<f64> = indices
        .iter()
        .filter_map(|&i| {
            samples
                .get(i)
                .and_then(|(row, _)| row.get(feature))
                .and_then(|v| {
                    if let FeatureValue::Number(n) = v {
                        Some(*n)
                    } else {
                        None
                    }
                })
        })
        .filter(|v| v.is_finite())
        .collect();
    values.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    values.dedup_by(|a, b| (*a - *b).abs() < f64::EPSILON);
    if values.len() < 2 {
        return Vec::new();
    }
    let mut thresholds = Vec::with_capacity(values.len().saturating_sub(1));
    for pair in values.windows(2) {
        if let [a, b] = pair {
            thresholds.push((a + b) / 2.0);
        }
    }
    thresholds
}

fn distinct_categories(
    samples: &[(FeatureVector, Label)],
    indices: &[usize],
    feature: &str,
) -> Vec<String> {
    let mut cats: BTreeSet<String> = BTreeSet::new();
    for &i in indices {
        if let Some((row, _)) = samples.get(i) {
            if let Some(FeatureValue::Category(c)) = row.get(feature) {
                cats.insert(c.clone());
            }
        }
    }
    cats.into_iter().collect()
}

fn partition_by_split(
    samples: &[(FeatureVector, Label)],
    indices: &[usize],
    split: &Split,
) -> (Vec<usize>, Vec<usize>) {
    let mut left = Vec::new();
    let mut right = Vec::new();
    for &i in indices {
        let Some((row, _)) = samples.get(i) else {
            continue;
        };
        let go_left = match split {
            Split::Number { feature, threshold } => match row.get(feature) {
                Some(FeatureValue::Number(v)) => v <= threshold,
                _ => true,
            },
            Split::Bool { feature } => match row.get(feature) {
                Some(FeatureValue::Bool(v)) => !v,
                _ => true,
            },
            Split::Category { feature, category } => match row.get(feature) {
                Some(FeatureValue::Category(v)) => v == category,
                _ => false,
            },
        };
        if go_left {
            left.push(i);
        } else {
            right.push(i);
        }
    }
    (left, right)
}

fn feature_type_for(
    samples: &[(FeatureVector, Label)],
    indices: &[usize],
    feature: &str,
) -> Option<FeatureValue> {
    for &i in indices {
        if let Some((row, _)) = samples.get(i) {
            if let Some(v) = row.get(feature) {
                return Some(v.clone());
            }
        }
    }
    None
}

#[allow(clippy::cognitive_complexity)]
fn find_best_split(
    samples: &[(FeatureVector, Label)],
    indices: &[usize],
) -> Option<(Split, f64, Vec<usize>, Vec<usize>)> {
    let mut best: Option<(Split, f64, Vec<usize>, Vec<usize>)> = None;
    let names = feature_names(samples, indices);
    for name in names {
        let probe = feature_type_for(samples, indices, &name);
        let Some(probe) = probe else { continue };
        let candidates: Vec<Split> = match probe {
            FeatureValue::Bool(_) => vec![Split::Bool {
                feature: name.clone(),
            }],
            FeatureValue::Number(_) => candidate_thresholds(samples, indices, &name)
                .into_iter()
                .map(|t| Split::Number {
                    feature: name.clone(),
                    threshold: t,
                })
                .collect(),
            FeatureValue::Category(_) => distinct_categories(samples, indices, &name)
                .into_iter()
                .map(|c| Split::Category {
                    feature: name.clone(),
                    category: c,
                })
                .collect(),
        };
        for split in candidates {
            let (l, r) = partition_by_split(samples, indices, &split);
            if l.is_empty() || r.is_empty() {
                continue;
            }
            let score = weighted_gini(samples, &l, &r);
            let better = match &best {
                None => true,
                Some((_, s, _, _)) => score < *s - f64::EPSILON,
            };
            if better {
                best = Some((split, score, l, r));
            }
        }
    }
    best
}

fn build_node(
    samples: &[(FeatureVector, Label)],
    indices: &[usize],
    depth: u8,
    max_depth: u8,
    min_samples_split: usize,
) -> Node {
    let p = class_proportion(samples, indices);
    let pure = p < f64::EPSILON || (1.0 - p).abs() < f64::EPSILON;
    if pure || depth >= max_depth || indices.len() < min_samples_split {
        return Node::leaf(p);
    }
    let Some((split, child_gini, left, right)) = find_best_split(samples, indices) else {
        return Node::leaf(p);
    };
    let parent_gini = gini_from_proportion(p);
    // If no split improves on the parent, stop.
    if parent_gini - child_gini <= f64::EPSILON {
        return Node::leaf(p);
    }
    let left_node = build_node(samples, &left, depth + 1, max_depth, min_samples_split);
    let right_node = build_node(samples, &right, depth + 1, max_depth, min_samples_split);
    Node {
        p_false_positive: p,
        split: Some(split),
        left: Some(Box::new(left_node)),
        right: Some(Box::new(right_node)),
    }
}

/// Public helper: count tree depth from a root.
#[must_use]
pub fn tree_depth(root: &Node) -> u8 {
    fn rec(n: &Node, acc: u8) -> u8 {
        if n.is_leaf() {
            return acc;
        }
        let l = n.left.as_deref().map_or(acc, |c| rec(c, acc + 1));
        let r = n.right.as_deref().map_or(acc, |c| rec(c, acc + 1));
        l.max(r)
    }
    rec(root, 0)
}

// Silence a clippy warning that's only triggered by complex match arms above
// but not actually applicable here.
const _: fn() = || {
    let _: BTreeMap<String, FeatureValue> = BTreeMap::new();
};
