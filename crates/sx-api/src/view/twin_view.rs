//! Cyber-digital-twin DTOs.
//!
//! Wire projections over the `sx-twin` in-memory simulation surface.
//! Controllers translate a `sx_twin::Twin` snapshot into a
//! [`TwinStateView`] without ever exposing the simulator's domain types
//! on the HTTP surface.
//!
//! The projection is intentionally string-typed: asset uuids, compromise
//! states, and asset kinds round-trip as canonical lowercase strings so
//! the JSON contract stays stable even if the sibling crate adds new
//! enum variants.

use serde::{Deserialize, Serialize};

/// Asset projection inside the digital twin.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TwinAssetView {
    /// Asset uuid (as produced by `sx_twin::state::AssetId::to_string`).
    pub id: String,
    /// Coarse asset kind: `host`, `network`, `identity`, `application`,
    /// `data`, or `other`.
    pub kind: String,
    /// Stable human-readable identifier (e.g. hostname, account name).
    pub identifier: String,
    /// Risk score in `[0.0, 1.0]`.
    pub risk_score: f64,
    /// Compromise state: `healthy`, `suspected`, `compromised`, or
    /// `contained`.
    pub compromise_state: String,
}

/// Directed edge projection inside the digital twin.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TwinEdgeView {
    /// Source asset id.
    pub from: String,
    /// Destination asset id.
    pub to: String,
    /// Exploit probability in `[0.0, 1.0]`.
    pub exploit_probability: f64,
}

/// Aggregate twin snapshot returned by `GET /v1/twin/engagement/{id}`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TwinStateView {
    /// Every asset registered in the twin.
    pub assets: Vec<TwinAssetView>,
    /// Every directed edge registered in the twin.
    pub edges: Vec<TwinEdgeView>,
    /// Ids of every asset currently in the `compromised` set. Mirrors the
    /// per-asset `compromise_state` for O(1) membership tests by the
    /// frontend.
    pub compromised_ids: Vec<String>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::float_cmp)]
mod tests {
    use super::*;

    fn sample() -> TwinStateView {
        TwinStateView {
            assets: vec![TwinAssetView {
                id: "a1".into(),
                kind: "host".into(),
                identifier: "host-1".into(),
                risk_score: 0.42,
                compromise_state: "suspected".into(),
            }],
            edges: vec![TwinEdgeView {
                from: "a1".into(),
                to: "a2".into(),
                exploit_probability: 0.7,
            }],
            compromised_ids: vec!["a1".into()],
        }
    }

    #[test]
    fn round_trips_through_json() {
        let view = sample();
        let wire = serde_json::to_string(&view).unwrap();
        let back: TwinStateView = serde_json::from_str(&wire).unwrap();
        assert_eq!(view, back);
    }

    #[test]
    fn empty_view_is_well_formed_json() {
        let view = TwinStateView {
            assets: vec![],
            edges: vec![],
            compromised_ids: vec![],
        };
        let wire = serde_json::to_string(&view).unwrap();
        assert!(wire.contains("\"assets\":[]"));
        assert!(wire.contains("\"edges\":[]"));
        assert!(wire.contains("\"compromised_ids\":[]"));
    }
}
