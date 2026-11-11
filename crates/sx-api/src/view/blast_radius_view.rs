//! Cloud blast-radius DTOs (P1-010).
//!
//! Backs `POST /v1/cloud/blast-radius`. The request supplies a seed
//! asset id (the compromised resource) and a maximum traversal depth;
//! the response carries the ranked impact set computed by
//! [`sx_graph::service::blast_radius::InMemoryBlastRadiusService`].

use serde::{Deserialize, Serialize};
use validator::Validate;

/// Hard upper bound on the requested traversal depth.
///
/// Kept in lock-step with
/// `sx_graph::service::blast_radius::MAX_BLAST_RADIUS_DEPTH` — the wire
/// schema must surface this so dashboards can clamp client side before
/// issuing a doomed request.
pub const MAX_BLAST_RADIUS_DEPTH: u8 = 5;

/// `POST /v1/cloud/blast-radius` request body.
#[derive(Debug, Clone, Deserialize, Serialize, Validate)]
pub struct BlastRadiusRequestView {
    /// Stable identifier of the seed (compromised) asset.
    #[validate(length(min = 1, max = 512))]
    pub seed_asset_id: String,
    /// Maximum traversal depth. Server clamps at
    /// [`MAX_BLAST_RADIUS_DEPTH`].
    #[validate(range(min = 1, max = 5))]
    pub max_depth: u8,
}

/// One row of the impacted-assets ranking.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct ImpactedAssetView {
    /// Stable identifier of the impacted asset.
    pub asset_id: String,
    /// Human-friendly display name (best-effort).
    pub name: String,
    /// Shortest observed traversal depth from the seed (1 = direct
    /// neighbour).
    pub depth: u8,
    /// Canonical edge kind on the shortest observed traversal — one of
    /// `iam_role_chain`, `kms_grant`, `network_peer`, `s3_acl`,
    /// `security_group_edge`, `other`.
    pub edge_kind: String,
    /// Asset criticality classification.
    pub criticality: String,
    /// `criticality × edge_weight × decay(depth)` — higher = worse.
    pub impact_score: f64,
}

/// `POST /v1/cloud/blast-radius` response body.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct BlastRadiusResponseView {
    /// Seed asset id (echoed from the request).
    pub seed_asset_id: String,
    /// Depth cap actually used.
    pub max_depth: u8,
    /// Decay base used by the scoring formula.
    pub decay_base: f64,
    /// Impacted assets, highest-score first.
    pub impacted: Vec<ImpactedAssetView>,
    /// Sum of every impacted asset's `impact_score`.
    pub total_score: f64,
    /// Whether this response was satisfied from a cached report
    /// computed within the last hour.
    pub cached: bool,
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn accepts_in_range_request() {
        let r = BlastRadiusRequestView {
            seed_asset_id: "asset-1".into(),
            max_depth: 3,
        };
        assert!(r.validate().is_ok());
    }

    #[test]
    fn rejects_zero_depth() {
        let r = BlastRadiusRequestView {
            seed_asset_id: "asset-1".into(),
            max_depth: 0,
        };
        assert!(r.validate().is_err());
    }

    #[test]
    fn rejects_excessive_depth() {
        let r = BlastRadiusRequestView {
            seed_asset_id: "asset-1".into(),
            max_depth: 6,
        };
        assert!(r.validate().is_err());
    }

    #[test]
    fn rejects_empty_seed() {
        let r = BlastRadiusRequestView {
            seed_asset_id: String::new(),
            max_depth: 3,
        };
        assert!(r.validate().is_err());
    }

    #[test]
    fn response_roundtrips_through_serde() {
        let r = BlastRadiusResponseView {
            seed_asset_id: "seed".into(),
            max_depth: 3,
            decay_base: 0.6,
            impacted: vec![ImpactedAssetView {
                asset_id: "a1".into(),
                name: "n1".into(),
                depth: 1,
                edge_kind: "iam_role_chain".into(),
                criticality: "crown_jewel".into(),
                impact_score: 6.0,
            }],
            total_score: 6.0,
            cached: false,
        };
        let s = serde_json::to_string(&r).expect("serialise");
        let back: BlastRadiusResponseView = serde_json::from_str(&s).expect("deserialise");
        assert_eq!(back, r);
    }
}
