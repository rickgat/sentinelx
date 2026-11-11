//! Feature representation shared across all `sx-ml` algorithms.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// A single feature value.
///
/// Concrete features are limited to the three shapes that the bundled
/// algorithms know how to split on:
///
/// - [`FeatureValue::Bool`] — `0 | 1` binary feature.
/// - [`FeatureValue::Number`] — finite `f64` feature (split by threshold).
/// - [`FeatureValue::Category`] — categorical (split by `==`); hashed by
///   the [`crate::service::anonymiser::Anonymiser`] before training.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum FeatureValue {
    /// A boolean feature.
    Bool(bool),
    /// A finite-numeric feature.
    Number(f64),
    /// A categorical feature, after anonymisation typically a 16-hex digest.
    Category(String),
}

impl FeatureValue {
    /// Returns `true` when this value is suitable for ordered (numeric) splits.
    #[must_use]
    pub const fn is_numeric(&self) -> bool {
        matches!(self, Self::Number(_))
    }

    /// Returns `true` when this value is boolean.
    #[must_use]
    pub const fn is_bool(&self) -> bool {
        matches!(self, Self::Bool(_))
    }

    /// Returns `true` when this value is categorical.
    #[must_use]
    pub const fn is_category(&self) -> bool {
        matches!(self, Self::Category(_))
    }
}

/// An ordered map of feature name → value.
///
/// `BTreeMap` is chosen over `HashMap` so that serialisation, hashing and
/// tree-training are deterministic.
pub type FeatureVector = BTreeMap<String, FeatureValue>;

/// Describes which features a model expects. Used for schema validation
/// at predict time.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FeatureSchema {
    /// The required feature names.
    pub required: BTreeSet<String>,
}

impl FeatureSchema {
    /// Build a new schema from an iterator of required field names.
    pub fn new<I, S>(required: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            required: required.into_iter().map(Into::into).collect(),
        }
    }

    /// Returns `Ok(())` if every required field is present in `row`.
    pub fn validate(&self, row: &FeatureVector) -> Result<(), String> {
        for name in &self.required {
            if !row.contains_key(name) {
                return Err(format!("missing required feature `{name}`"));
            }
        }
        Ok(())
    }
}
