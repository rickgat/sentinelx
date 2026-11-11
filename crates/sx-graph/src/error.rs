//! Crate-level error type.
//!
//! Every fallible API in `sx-graph` returns [`GraphError`]. Variants are
//! deliberately coarse: adapters map their own backend errors into one
//! of these before crossing the port boundary.

use thiserror::Error;

/// All errors produced by the knowledge-graph crate.
#[derive(Debug, Error)]
pub enum GraphError {
    /// A required configuration field was missing or invalid.
    #[error("configuration error: {0}")]
    Config(String),

    /// Connection to the underlying graph store failed (handshake,
    /// pool acquisition, ping, etc.).
    #[error("connection error: {0}")]
    Connection(String),

    /// A query against the underlying graph store failed.
    ///
    /// Adapter code maps backend errors (e.g. `neo4rs::Error`) into
    /// this variant after scrubbing any sensitive bits.
    #[error("query error: {0}")]
    Query(String),

    /// A Cypher statement failed to compile, was malformed, or violated
    /// a constraint on the server.
    ///
    /// Distinct from [`GraphError::Query`] in that it specifically
    /// indicates a problem with the Cypher source (parse error,
    /// syntax error, constraint violation), not a transient query
    /// execution failure.
    #[error("cypher error: {0}")]
    Cypher(String),

    /// The requested node does not exist in the graph.
    #[error("not found: {kind} id={id}")]
    NotFound {
        /// Logical entity name (e.g. `"Asset"`, `"Finding"`).
        kind: &'static str,
        /// Identifier (as `Display`) of the missing record.
        id: String,
    },

    /// The requested write would create a duplicate or violate a
    /// uniqueness invariant on the graph store.
    #[error("conflict: {kind} id={id}")]
    Conflict {
        /// Logical entity name (e.g. `"Asset"`, `"Finding"`).
        kind: &'static str,
        /// Identifier of the conflicting record.
        id: String,
    },

    /// An operation attempted to read or write nodes/edges that belong
    /// to a different tenant than the one supplied in the call.
    ///
    /// This is the multi-tenant isolation guard fault. Production code
    /// MUST treat this as a hard failure: it indicates either a bug in
    /// the calling code or a deliberate attempt to cross a tenant
    /// boundary.
    #[error(
        "tenant boundary violation: caller tenant={caller_tenant} attempted access to \
         resource_tenant={resource_tenant} ({kind})"
    )]
    TenantBoundary {
        /// Logical entity name being accessed (e.g. `"Asset"`).
        kind: &'static str,
        /// Tenant id supplied by the caller.
        caller_tenant: String,
        /// Tenant id actually owning the resource.
        resource_tenant: String,
    },

    /// A query parameter or query struct violated its validation contract.
    #[error("invalid query: {0}")]
    InvalidQuery(String),

    /// An invariant in the graph layer was violated. Treat as a bug.
    #[error("internal: {0}")]
    Internal(String),
}

impl GraphError {
    /// Convenience constructor for [`GraphError::Config`].
    #[must_use]
    pub fn config(msg: impl Into<String>) -> Self {
        Self::Config(msg.into())
    }

    /// Convenience constructor for [`GraphError::Connection`].
    #[must_use]
    pub fn connection(msg: impl Into<String>) -> Self {
        Self::Connection(msg.into())
    }

    /// Convenience constructor for [`GraphError::Query`].
    #[must_use]
    pub fn query(msg: impl Into<String>) -> Self {
        Self::Query(msg.into())
    }

    /// Convenience constructor for [`GraphError::Cypher`].
    #[must_use]
    pub fn cypher(msg: impl Into<String>) -> Self {
        Self::Cypher(msg.into())
    }

    /// Convenience constructor for [`GraphError::TenantBoundary`].
    #[must_use]
    pub fn tenant_boundary(
        kind: &'static str,
        caller_tenant: impl Into<String>,
        resource_tenant: impl Into<String>,
    ) -> Self {
        Self::TenantBoundary {
            kind,
            caller_tenant: caller_tenant.into(),
            resource_tenant: resource_tenant.into(),
        }
    }

    /// Convenience constructor for [`GraphError::Conflict`].
    #[must_use]
    pub fn conflict(kind: &'static str, id: impl Into<String>) -> Self {
        Self::Conflict {
            kind,
            id: id.into(),
        }
    }

    /// Convenience constructor for [`GraphError::InvalidQuery`].
    #[must_use]
    pub fn invalid_query(msg: impl Into<String>) -> Self {
        Self::InvalidQuery(msg.into())
    }

    /// Convenience constructor for [`GraphError::Internal`].
    #[must_use]
    pub fn internal(msg: impl Into<String>) -> Self {
        Self::Internal(msg.into())
    }
}

#[cfg(test)]
mod tests {
    use super::GraphError;

    #[test]
    fn display_config() {
        assert_eq!(
            GraphError::config("missing uri").to_string(),
            "configuration error: missing uri",
        );
    }

    #[test]
    fn display_not_found() {
        let e = GraphError::NotFound {
            kind: "Asset",
            id: "abc".into(),
        };
        assert_eq!(e.to_string(), "not found: Asset id=abc");
    }

    #[test]
    fn display_invalid_query() {
        assert_eq!(
            GraphError::invalid_query("depth too big").to_string(),
            "invalid query: depth too big",
        );
    }

    #[test]
    fn display_cypher() {
        assert_eq!(
            GraphError::cypher("parse error at line 1").to_string(),
            "cypher error: parse error at line 1",
        );
    }

    #[test]
    fn display_conflict() {
        assert_eq!(
            GraphError::conflict("Asset", "asset-1").to_string(),
            "conflict: Asset id=asset-1",
        );
    }

    #[test]
    fn display_tenant_boundary() {
        let e = GraphError::tenant_boundary("Asset", "tenant-A", "tenant-B");
        let s = e.to_string();
        assert!(s.contains("tenant boundary"));
        assert!(s.contains("tenant-A"));
        assert!(s.contains("tenant-B"));
        assert!(s.contains("Asset"));
    }
}
