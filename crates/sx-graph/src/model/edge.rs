//! Edge types for the knowledge graph.
//!
//! Like [`crate::model::node::NodeKind`], [`EdgeKind`]'s `Display` impl
//! is the canonical Neo4j relationship string. Adapters MUST funnel
//! relationship-type interpolation through this enum, never through
//! caller-supplied strings.

use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::model::node::NodeId;

/// Closed set of edge / relationship kinds.
///
/// Property semantics:
///
/// - [`EdgeKind::CanAccess`] carries `{ via: "<credential or technique>" }`.
/// - [`EdgeKind::Reaches`] carries `{ port: u16, proto: "tcp"|"udp" }`.
/// - The remaining kinds have no required properties; adapters MAY
///   still attach free-form properties via [`GraphEdge::properties`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum EdgeKind {
    /// Asset → Finding: a finding was observed on the asset.
    HasFinding,
    /// Finding → CVE / Finding → Technique: the finding maps to a
    /// canonical taxonomy entry.
    MapsTo,
    /// Finding/CVE → Technique: the issue enables a technique.
    Enables,
    /// Technique → Technique: technique chains to a follow-on technique.
    ChainsTo,
    /// User → Asset / Credential → Asset: the principal can access the
    /// asset (carries a `via` property).
    CanAccess,
    /// Credential → Asset / Credential → Service: the credential is
    /// stored on the asset / service.
    StoredIn,
    /// Role / Credential → User: grants permission to the principal.
    Grants,
    /// Asset → Asset / Network: network reachability (port + proto
    /// properties).
    Reaches,
    /// Asset → Service: the asset runs the service.
    Runs,
}

impl fmt::Display for EdgeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::HasFinding => "HAS_FINDING",
            Self::MapsTo => "MAPS_TO",
            Self::Enables => "ENABLES",
            Self::ChainsTo => "CHAINS_TO",
            Self::CanAccess => "CAN_ACCESS",
            Self::StoredIn => "STORED_IN",
            Self::Grants => "GRANTS",
            Self::Reaches => "REACHES",
            Self::Runs => "RUNS",
        };
        f.write_str(s)
    }
}

/// A directed edge in the knowledge graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphEdge {
    /// Relationship kind.
    pub kind: EdgeKind,
    /// Source node id.
    pub from: NodeId,
    /// Destination node id.
    pub to: NodeId,
    /// Optional structured properties for the edge.
    ///
    /// Adapter code only writes JSON objects (`{}`); arbitrary
    /// scalars are accepted from constructors but the Neo4j adapter
    /// MAY refuse them at write time.
    #[serde(default)]
    pub properties: Option<Value>,
}

impl GraphEdge {
    /// Build a simple property-less edge.
    #[must_use]
    pub const fn new(kind: EdgeKind, from: NodeId, to: NodeId) -> Self {
        Self {
            kind,
            from,
            to,
            properties: None,
        }
    }

    /// Build a `CAN_ACCESS { via: <via> }` edge.
    #[must_use]
    pub fn can_access(from: NodeId, to: NodeId, via: impl Into<String>) -> Self {
        Self {
            kind: EdgeKind::CanAccess,
            from,
            to,
            properties: Some(serde_json::json!({ "via": via.into() })),
        }
    }

    /// Build a `REACHES { port, proto }` edge.
    #[must_use]
    pub fn reaches(from: NodeId, to: NodeId, port: u16, proto: impl Into<String>) -> Self {
        Self {
            kind: EdgeKind::Reaches,
            from,
            to,
            properties: Some(serde_json::json!({ "port": port, "proto": proto.into() })),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn edge_kind_serialises_to_relationship_string() {
        assert_eq!(EdgeKind::HasFinding.to_string(), "HAS_FINDING");
        assert_eq!(EdgeKind::MapsTo.to_string(), "MAPS_TO");
        assert_eq!(EdgeKind::Enables.to_string(), "ENABLES");
        assert_eq!(EdgeKind::ChainsTo.to_string(), "CHAINS_TO");
        assert_eq!(EdgeKind::CanAccess.to_string(), "CAN_ACCESS");
        assert_eq!(EdgeKind::StoredIn.to_string(), "STORED_IN");
        assert_eq!(EdgeKind::Grants.to_string(), "GRANTS");
        assert_eq!(EdgeKind::Reaches.to_string(), "REACHES");
        assert_eq!(EdgeKind::Runs.to_string(), "RUNS");
    }

    #[test]
    fn reaches_constructor_sets_properties() {
        let e = GraphEdge::reaches(NodeId::new("a"), NodeId::new("b"), 443, "tcp");
        let v = e.properties.as_ref().unwrap();
        assert_eq!(v["port"], 443);
        assert_eq!(v["proto"], "tcp");
    }

    #[test]
    fn can_access_constructor_sets_via() {
        let e = GraphEdge::can_access(NodeId::new("u"), NodeId::new("a"), "ssh_key");
        let v = e.properties.as_ref().unwrap();
        assert_eq!(v["via"], "ssh_key");
    }
}
