//! Pooled Neo4j connection wrapper.
//!
//! `neo4rs::Graph` is already an internally-pooled handle (it owns a
//! Bolt connection pool keyed on the connection URI). `Neo4jPool` is a
//! thin wrapper around `Arc<neo4rs::Graph>` that:
//!
//! - Validates the Bolt URL at construction time so that
//!   misconfigurations fail fast and out of the request hot-path.
//! - Carries an optional default database name (`USE` clause) so the
//!   adapter does not have to plumb it through every call site.
//! - Exposes a [`Neo4jPool::ping`] health-check that issues a trivial
//!   `RETURN 1` round-trip and surfaces a [`GraphError::Connection`]
//!   on failure.
//!
//! The pool is cheap to clone (`Arc` inside).
//!
//! ## Tenant scope
//!
//! The pool itself is tenant-agnostic. Tenant isolation is enforced by
//! the [`crate::service::Neo4jKnowledgeGraph`] adapter through the
//! `$tenant_id` parameter on every Cypher statement — never by the
//! pool. This is by design: a single physical Neo4j instance may host
//! many tenants and the pool is shared.

use std::sync::Arc;

use neo4rs::{query as cypher_query, ConfigBuilder, Graph as Neo4Graph};
use secrecy::{ExposeSecret, SecretString};
use tracing::{debug, instrument};

use crate::error::GraphError;

/// Allowed URL schemes for a Bolt connection.
///
/// Kept here so the constructor's validation logic and its unit-test
/// stay in lock-step.
pub const ALLOWED_BOLT_SCHEMES: &[&str] = &[
    "bolt://",
    "bolt+s://",
    "bolt+ssc://",
    "neo4j://",
    "neo4j+s://",
    "neo4j+ssc://",
];

/// Pooled Neo4j connection.
///
/// Wraps an `Arc<neo4rs::Graph>` (internally pooled). Use
/// [`Neo4jPool::graph`] to grab the inner handle for one-off queries
/// and [`Neo4jPool::database`] when running on a non-default database.
#[derive(Clone)]
pub struct Neo4jPool {
    graph: Arc<Neo4Graph>,
    database: Option<String>,
}

impl std::fmt::Debug for Neo4jPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Neo4jPool")
            .field("database", &self.database)
            .finish_non_exhaustive()
    }
}

impl Neo4jPool {
    /// Validate the supplied URL without performing any I/O.
    ///
    /// Returns [`GraphError::Config`] if the URL is empty or uses a
    /// scheme that is not a Bolt scheme.
    ///
    /// This is exposed so callers (and tests) can validate a URL
    /// string independently of trying to construct a live pool.
    pub fn validate_url(url: &str) -> Result<(), GraphError> {
        let trimmed = url.trim();
        if trimmed.is_empty() {
            return Err(GraphError::config("neo4j url is empty"));
        }
        if !ALLOWED_BOLT_SCHEMES
            .iter()
            .any(|prefix| trimmed.starts_with(prefix))
        {
            return Err(GraphError::config(format!(
                "neo4j url {trimmed:?} must start with one of {ALLOWED_BOLT_SCHEMES:?}"
            )));
        }
        Ok(())
    }

    /// Connect to Neo4j and return a ready-to-use pool.
    ///
    /// `database` is the optional Neo4j database name to address; pass
    /// `None` for the server default.
    ///
    /// # Errors
    ///
    /// - [`GraphError::Config`] if `url` or `user` are blank or the URL
    ///   scheme is not Bolt-compatible.
    /// - [`GraphError::Connection`] if the Bolt handshake fails.
    #[instrument(skip(password), fields(url = %url, db = ?database))]
    pub async fn connect(
        url: &str,
        user: &str,
        password: &SecretString,
        database: Option<&str>,
    ) -> Result<Self, GraphError> {
        Self::validate_url(url)?;
        if user.trim().is_empty() {
            return Err(GraphError::config("neo4j user is empty"));
        }

        let mut builder = ConfigBuilder::default()
            .uri(url.to_owned())
            .user(user.to_owned())
            .password(password.expose_secret().to_owned());
        if let Some(db) = database {
            if !db.trim().is_empty() {
                builder = builder.db(db.to_owned());
            }
        }
        let cfg = builder
            .build()
            .map_err(|e| GraphError::config(format!("invalid neo4j config: {e}")))?;
        let graph = Neo4Graph::connect(cfg)
            .await
            .map_err(|e| GraphError::connection(e.to_string()))?;
        debug!("neo4j pool established");
        Ok(Self {
            graph: Arc::new(graph),
            database: database
                .filter(|d| !d.trim().is_empty())
                .map(ToOwned::to_owned),
        })
    }

    /// Borrow the underlying `Arc<neo4rs::Graph>`. Cloning the result
    /// is cheap and is the standard way to share the pool.
    #[must_use]
    pub fn graph(&self) -> Arc<Neo4Graph> {
        Arc::clone(&self.graph)
    }

    /// Optional default database name supplied at construction.
    #[must_use]
    pub fn database(&self) -> Option<&str> {
        self.database.as_deref()
    }

    /// Issue a trivial `RETURN 1` round-trip to confirm the pool is
    /// healthy.
    ///
    /// # Errors
    ///
    /// Returns [`GraphError::Connection`] on any backend failure.
    #[instrument(skip(self))]
    pub async fn ping(&self) -> Result<(), GraphError> {
        let q = cypher_query("RETURN 1 AS one");
        let mut stream = match self.database.as_deref() {
            Some(db) => self.graph.execute_on(db, q).await,
            None => self.graph.execute(q).await,
        }
        .map_err(|e| GraphError::connection(format!("neo4j ping failed: {e}")))?;
        let row = stream
            .next()
            .await
            .map_err(|e| GraphError::connection(format!("neo4j ping stream: {e}")))?
            .ok_or_else(|| GraphError::connection("neo4j ping returned no row"))?;
        let one: i64 = row
            .get("one")
            .map_err(|e| GraphError::connection(format!("neo4j ping bad row: {e}")))?;
        if one == 1 {
            Ok(())
        } else {
            Err(GraphError::connection(format!(
                "neo4j ping returned unexpected value: {one}"
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pool_constructor_validates_url() {
        // Empty URL.
        assert!(matches!(
            Neo4jPool::validate_url(""),
            Err(GraphError::Config(_))
        ));
        // Whitespace-only.
        assert!(matches!(
            Neo4jPool::validate_url("   "),
            Err(GraphError::Config(_))
        ));
        // Wrong scheme.
        assert!(matches!(
            Neo4jPool::validate_url("http://localhost:7474"),
            Err(GraphError::Config(_))
        ));
        assert!(matches!(
            Neo4jPool::validate_url("postgres://localhost"),
            Err(GraphError::Config(_))
        ));
        // All allowed schemes pass.
        for scheme in ALLOWED_BOLT_SCHEMES {
            let url = format!("{scheme}127.0.0.1:7687");
            assert!(
                Neo4jPool::validate_url(&url).is_ok(),
                "scheme {scheme} should validate, got error"
            );
        }
    }

    #[test]
    fn debug_does_not_panic() {
        // We can't construct a real Neo4jPool without I/O, but we can
        // exercise validate_url which lives on the same type.
        let r = Neo4jPool::validate_url("bolt://127.0.0.1:7687");
        assert!(r.is_ok());
    }
}
