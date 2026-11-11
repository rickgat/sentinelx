//! Attack-graph DTOs.

use serde::{Deserialize, Serialize};
use validator::Validate;

/// `POST /v1/graph/attack-paths` request body.
#[derive(Debug, Clone, Deserialize, Serialize, Validate)]
pub struct GraphAttackPathsRequestView {
    /// Tenant uuid scoping the search.
    #[validate(length(min = 1))]
    pub tenant_id: String,
    /// Maximum hop-depth (≤ 10) to explore.
    #[validate(range(min = 1, max = 10))]
    pub max_depth: u8,
    /// Maximum number of paths (≤ 200) to return.
    #[validate(range(min = 1, max = 200))]
    pub max_paths: u32,
}

/// A single attack path projection.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AttackPathView {
    /// Stable path identifier.
    pub id: String,
    /// Composite risk score (higher = more dangerous).
    pub score: f64,
    /// Number of edges in the path.
    pub length: usize,
}

/// `POST /v1/graph/attack-paths` response body.
///
/// `engine` + `degraded` surface the HIGH-007 graceful-degrade signal:
/// when the primary Neo4j backend is unreachable the API auto-fails-over
/// to the in-memory adjacency-list backend so the endpoint never 500s,
/// and the response carries the markers so callers can distinguish a
/// fully-trusted (`engine="neo4j", degraded=false`) result from a
/// best-effort one (`engine="memory", degraded=true`).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GraphAttackPathsResponseView {
    /// Top-k attack paths, highest-score first.
    pub paths: Vec<AttackPathView>,
    /// Backend that produced the result — `"neo4j"` or `"memory"`. See
    /// [`sx_graph::service::GraphEngine`].
    #[serde(default = "default_engine_tag")]
    pub engine: String,
    /// `true` when `engine == "memory"` because the primary Neo4j
    /// backend was unhealthy. Convenience flag for the dashboard; it is
    /// strictly equivalent to `engine == "memory"`.
    #[serde(default)]
    pub degraded: bool,
}

/// Wire-format default for [`GraphAttackPathsResponseView::engine`] when
/// callers (e.g. legacy clients, openapi-generated stubs) omit the
/// field on deserialise.
fn default_engine_tag() -> String {
    "neo4j".to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_excessive_depth() {
        let r = GraphAttackPathsRequestView {
            tenant_id: "t".into(),
            max_depth: 11,
            max_paths: 10,
        };
        assert!(r.validate().is_err());
    }

    #[test]
    fn rejects_excessive_paths() {
        let r = GraphAttackPathsRequestView {
            tenant_id: "t".into(),
            max_depth: 5,
            max_paths: 201,
        };
        assert!(r.validate().is_err());
    }

    #[test]
    fn accepts_in_range_values() {
        let r = GraphAttackPathsRequestView {
            tenant_id: "t".into(),
            max_depth: 10,
            max_paths: 200,
        };
        assert!(r.validate().is_ok());
    }
}
