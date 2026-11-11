//! Predictive risk classification for `SentinelX` findings.
//!
//! This module implements a small, pure-Rust gradient-boosted decision
//! tree (GBDT) pipeline that takes a finding-plus-asset projection and
//! returns the probability that the finding will materialise into an
//! incident within the next 30 days (`risk_30d`).
//!
//! ## Pipeline
//!
//! 1. [`features::FindingFeatures`] is derived from a
//!    [`features::FindingViewLike`] + [`features::AssetViewLike`] pair via
//!    [`features::FindingFeatures::from_views`].
//! 2. The features are flattened into a fixed-layout `f64` vector via
//!    [`features::FindingFeatures::to_vector`].
//! 3. [`model::PredictiveModel::predict`] z-score normalises the vector,
//!    feeds it through the [`gbdt::Forest`], and squashes the raw score
//!    through a sigmoid into `[0, 1]`.
//!
//! ## Constraints
//!
//! - No third-party GBDT crate. The forest is implemented directly in
//!   [`gbdt`].
//! - No system libraries — the binary is fully self-contained.
//! - JSON-serialisable models for portability.
//! - `#![forbid(unsafe_code)]` is inherited from the crate root.

pub mod features;
pub mod gbdt;
pub mod model;

pub use features::{
    AssetKindEnum, AssetViewLike, FindingFeatures, FindingViewLike, SeverityEnum,
    FEATURE_VECTOR_LEN,
};
pub use gbdt::{Forest, Split, Tree};
pub use model::{FeatureScaler, PredictiveModel, RiskPrediction};
