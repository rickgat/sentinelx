//! Node types for the knowledge graph.
//!
//! The graph supports a closed set of node kinds enumerated by
//! [`NodeKind`]. Each variant has a per-kind property struct (e.g.
//! [`GraphAsset`], [`GraphFinding`]). The runtime container [`GraphNode`]
//! is a tagged enum over those property structs, plus a stable
//! [`NodeId`] used as the Neo4j `MERGE` key.
//!
//! [`NodeKind`]'s `Display` impl is the **only** source of the Neo4j
//! label string. Never interpolate user input into a label or
//! relationship name; always go through this enum.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use sx_core::value_object::criticality::AssetCriticality;
use sx_core::value_object::exposure::ExposureLevel;
use sx_core::value_object::ids::{AssetId, CveId, FindingId, TenantId, UserId};
use sx_core::value_object::severity::Severity;

/// Stable identifier for any graph node.
///
/// `NodeId` is opaque to the graph layer: the originating subsystem
/// (sx-discovery, sx-iam, etc.) provides it. Two nodes with the same
/// `NodeId` are considered the same vertex by the Neo4j `MERGE`
/// strategy this crate uses.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct NodeId(String);

impl NodeId {
    /// Wrap a pre-built string identifier.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Borrow the underlying string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<String> for NodeId {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for NodeId {
    fn from(value: &str) -> Self {
        Self(value.to_owned())
    }
}

impl From<AssetId> for NodeId {
    fn from(value: AssetId) -> Self {
        Self(value.to_string())
    }
}

impl From<FindingId> for NodeId {
    fn from(value: FindingId) -> Self {
        Self(value.to_string())
    }
}

impl From<UserId> for NodeId {
    fn from(value: UserId) -> Self {
        Self(value.to_string())
    }
}

impl From<CveId> for NodeId {
    fn from(value: CveId) -> Self {
        Self(value.to_string())
    }
}

impl From<TenantId> for NodeId {
    fn from(value: TenantId) -> Self {
        Self(value.to_string())
    }
}

/// Closed set of node kinds.
///
/// The string form (via [`fmt::Display`]) is the Neo4j label used by
/// the adapter. The serialised form ([`serde::Serialize`]) uses
/// `PascalCase` for the same reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum NodeKind {
    /// A host, container, service endpoint, or other technical asset.
    Asset,
    /// A security finding observed on an asset.
    Finding,
    /// A CVE (or other vulnerability identifier).
    Cve,
    /// A MITRE ATT&CK technique (or sub-technique).
    Technique,
    /// A human identity.
    User,
    /// A stored credential / secret.
    Credential,
    /// A running service (e.g. nginx on `:443`).
    Service,
    /// A network segment / CIDR block.
    Network,
    /// A tenant boundary.
    Tenant,
}

impl fmt::Display for NodeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Asset => "Asset",
            Self::Finding => "Finding",
            Self::Cve => "Cve",
            Self::Technique => "Technique",
            Self::User => "User",
            Self::Credential => "Credential",
            Self::Service => "Service",
            Self::Network => "Network",
            Self::Tenant => "Tenant",
        };
        f.write_str(s)
    }
}

/// An asset node in the knowledge graph.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GraphAsset {
    /// Stable identifier (typically an `sx_core::AssetId` rendered as
    /// its UUID string form).
    pub id: NodeId,
    /// Owning tenant.
    pub tenant_id: TenantId,
    /// Human-friendly display name.
    pub name: String,
    /// Where the asset sits relative to untrusted networks.
    pub exposure: ExposureLevel,
    /// How important the asset is to the business.
    pub criticality: AssetCriticality,
    /// Cached aggregate risk score for the asset, if computed.
    pub risk_score: Option<f64>,
    /// Free-form, schema-flexible properties (tags, labels, etc.).
    #[serde(default)]
    pub properties: BTreeMap<String, String>,
}

/// A finding node in the knowledge graph.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GraphFinding {
    /// Stable identifier (typically an `sx_core::FindingId`).
    pub id: NodeId,
    /// Owning tenant.
    pub tenant_id: TenantId,
    /// Affected asset (an [`GraphAsset::id`]).
    pub asset_id: NodeId,
    /// Identifier of the rule / detector that produced the finding.
    pub rule_id: String,
    /// Short title for lists.
    pub title: String,
    /// Severity.
    pub severity: Severity,
    /// Per-finding risk contribution used by the risk-propagation
    /// algorithm.
    pub risk_score: f64,
}

/// A CVE node in the knowledge graph.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GraphCve {
    /// Stable identifier — the canonical CVE id (e.g. `CVE-2024-12345`).
    pub id: NodeId,
    /// CVSS v3.x base score, if known.
    pub cvss: Option<f32>,
    /// EPSS probability score `[0.0, 1.0]`, if known.
    pub epss: Option<f32>,
    /// `true` iff the CVE is on a public Known-Exploited-Vulnerabilities list.
    #[serde(default)]
    pub kev: bool,
}

/// A MITRE ATT&CK technique node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphTechnique {
    /// Stable identifier (typically an ATT&CK ID like `T1190`).
    pub id: NodeId,
    /// Display name.
    pub name: String,
    /// Tactic name (e.g. `initial_access`).
    pub tactic: String,
}

/// A user / identity node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphUser {
    /// Stable identifier.
    pub id: NodeId,
    /// Owning tenant.
    pub tenant_id: TenantId,
    /// Display name or username.
    pub name: String,
    /// `true` iff the user holds privileged roles.
    #[serde(default)]
    pub privileged: bool,
}

/// A credential / secret node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphCredential {
    /// Stable identifier (deterministic hash of the credential
    /// reference; never the secret itself).
    pub id: NodeId,
    /// Human-readable label, e.g. `"AWS access key for build bot"`.
    pub label: String,
    /// Credential kind (e.g. `"ssh_key"`, `"password"`, `"api_token"`).
    pub kind: String,
}

/// A running service node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphService {
    /// Stable identifier.
    pub id: NodeId,
    /// Service name (e.g. `"nginx"`, `"openssh"`).
    pub name: String,
    /// Version string, if known.
    pub version: Option<String>,
}

/// A network segment node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphNetwork {
    /// Stable identifier.
    pub id: NodeId,
    /// CIDR block (e.g. `"10.0.0.0/16"`).
    pub cidr: String,
    /// `true` iff the network is publicly routable.
    #[serde(default)]
    pub public: bool,
}

/// A tenant node — every other tenant-scoped node carries the same
/// `tenant_id` and is logically rooted at a single [`GraphTenant`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphTenant {
    /// Stable identifier (the tenant uuid).
    pub id: NodeId,
    /// Human-friendly display name.
    pub name: String,
}

/// Runtime container over all node kinds.
///
/// The graph store keeps one row per `(NodeKind, NodeId)`. Comparing
/// variants discriminates the Neo4j label; comparing inner `id` fields
/// drives `MERGE`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "PascalCase")]
pub enum GraphNode {
    /// See [`GraphAsset`].
    Asset(GraphAsset),
    /// See [`GraphFinding`].
    Finding(GraphFinding),
    /// See [`GraphCve`].
    Cve(GraphCve),
    /// See [`GraphTechnique`].
    Technique(GraphTechnique),
    /// See [`GraphUser`].
    User(GraphUser),
    /// See [`GraphCredential`].
    Credential(GraphCredential),
    /// See [`GraphService`].
    Service(GraphService),
    /// See [`GraphNetwork`].
    Network(GraphNetwork),
    /// See [`GraphTenant`].
    Tenant(GraphTenant),
}

impl GraphNode {
    /// Discriminator for this node.
    #[must_use]
    pub const fn kind(&self) -> NodeKind {
        match self {
            Self::Asset(_) => NodeKind::Asset,
            Self::Finding(_) => NodeKind::Finding,
            Self::Cve(_) => NodeKind::Cve,
            Self::Technique(_) => NodeKind::Technique,
            Self::User(_) => NodeKind::User,
            Self::Credential(_) => NodeKind::Credential,
            Self::Service(_) => NodeKind::Service,
            Self::Network(_) => NodeKind::Network,
            Self::Tenant(_) => NodeKind::Tenant,
        }
    }

    /// Stable identifier of this node.
    #[must_use]
    pub const fn id(&self) -> &NodeId {
        match self {
            Self::Asset(a) => &a.id,
            Self::Finding(f) => &f.id,
            Self::Cve(c) => &c.id,
            Self::Technique(t) => &t.id,
            Self::User(u) => &u.id,
            Self::Credential(c) => &c.id,
            Self::Service(s) => &s.id,
            Self::Network(n) => &n.id,
            Self::Tenant(t) => &t.id,
        }
    }

    /// Per-node risk score used by [`crate::model::attack_path`] and
    /// the risk-propagation algorithm. Returns `0.0` for node kinds
    /// that have no intrinsic risk.
    #[must_use]
    pub fn risk_score(&self) -> f64 {
        match self {
            Self::Asset(a) => a.risk_score.unwrap_or(0.0),
            Self::Finding(f) => f.risk_score,
            Self::Cve(c) => c.cvss.map_or(0.0, f64::from),
            _ => 0.0,
        }
    }

    /// Owning tenant, if the node kind is tenant-scoped.
    #[must_use]
    pub const fn tenant_id(&self) -> Option<&TenantId> {
        match self {
            Self::Asset(a) => Some(&a.tenant_id),
            Self::Finding(f) => Some(&f.tenant_id),
            Self::User(u) => Some(&u.tenant_id),
            _ => None,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn tenant() -> TenantId {
        TenantId::new()
    }

    #[test]
    fn node_kind_serialises_to_label_string() {
        assert_eq!(NodeKind::Asset.to_string(), "Asset");
        assert_eq!(NodeKind::Finding.to_string(), "Finding");
        assert_eq!(NodeKind::Cve.to_string(), "Cve");
        assert_eq!(NodeKind::Technique.to_string(), "Technique");
        assert_eq!(NodeKind::User.to_string(), "User");
        assert_eq!(NodeKind::Credential.to_string(), "Credential");
        assert_eq!(NodeKind::Service.to_string(), "Service");
        assert_eq!(NodeKind::Network.to_string(), "Network");
        assert_eq!(NodeKind::Tenant.to_string(), "Tenant");
    }

    #[test]
    fn graph_node_kind_round_trips() {
        let asset = GraphNode::Asset(GraphAsset {
            id: NodeId::new("a1"),
            tenant_id: tenant(),
            name: "web-1".into(),
            exposure: ExposureLevel::Internet,
            criticality: AssetCriticality::CrownJewel,
            risk_score: Some(7.5),
            properties: BTreeMap::new(),
        });
        assert_eq!(asset.kind(), NodeKind::Asset);
        assert_eq!(asset.id().as_str(), "a1");
        assert!((asset.risk_score() - 7.5).abs() < f64::EPSILON);
    }

    #[test]
    fn node_id_constructors() {
        let a = NodeId::new("x");
        let b: NodeId = "x".into();
        let c: NodeId = String::from("x").into();
        assert_eq!(a, b);
        assert_eq!(a, c);
    }
}
