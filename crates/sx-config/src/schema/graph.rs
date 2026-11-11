//! Knowledge-graph (Neo4j) configuration.
//!
//! Configures the optional Neo4j-backed `KnowledgeGraph` adapter used by
//! the `sx-graph` crate. Ships **disabled** by default — a freshly
//! cloned checkout never reaches an external Neo4j instance and the
//! monolith composition root falls back to the in-memory adapter
//! (`InMemoryKnowledgeGraph`).
//!
//! When an operator flips `neo4j_enabled: true`, the loader requires
//! every connection parameter (URI, user, password, database) to be
//! non-empty so the adapter can successfully open a Bolt session.
//!
//! The `neo4j_password` is wrapped in [`secrecy::SecretString`] so it
//! never appears in `Debug` output, panic messages, or `tracing` records.
//! The monolith adapter only exposes the secret at the moment it builds
//! the `Neo4jConfig` for `Neo4jKnowledgeGraph::connect` — and even then,
//! the boot-time tracing event for the pool only logs the URI's host
//! component, never the password.

use secrecy::SecretString;
use serde::Deserialize;
use validator::Validate;

/// Knowledge-graph (Neo4j) configuration.
///
/// Disabled by default. When `neo4j_enabled` is `true`:
///   * `neo4j_uri` MUST be non-empty,
///   * `neo4j_user` MUST be non-empty,
///   * `neo4j_password` MUST be non-empty,
///   * `neo4j_database` MUST be non-empty.
///
/// All other fields are otherwise unused. The composition root reads
/// them only when `neo4j_enabled` is `true`.
#[derive(Debug, Clone, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
// The `neo4j_*` prefix is intentional: the spec mandates this exact
// naming for the operator-facing configuration keys.
#[allow(clippy::struct_field_names)]
pub struct GraphConfig {
    /// Whether the production Neo4j-backed `KnowledgeGraph` adapter
    /// should be wired in at boot.
    ///
    /// When `false`, every other field is ignored and the monolith's
    /// `adapters::graph::build` returns the in-memory adapter bundle.
    #[serde(default)]
    pub neo4j_enabled: bool,

    /// Bolt URI for the Neo4j server (e.g. `bolt://127.0.0.1:7687`).
    /// Mandatory iff `neo4j_enabled`.
    #[serde(default)]
    pub neo4j_uri: String,

    /// Username. Mandatory iff `neo4j_enabled`.
    #[serde(default)]
    pub neo4j_user: String,

    /// Password presented during the Bolt handshake. Mandatory iff
    /// `neo4j_enabled`.
    ///
    /// Wrapped in [`SecretString`] so the value never appears in
    /// `Debug` output, panic messages, or `tracing` records. The
    /// monolith adapter only exposes it inside the `Neo4jConfig` it
    /// hands to `Neo4jKnowledgeGraph::connect`.
    #[serde(default)]
    pub neo4j_password: SecretString,

    /// Neo4j database name to address (e.g. `neo4j`). Mandatory iff
    /// `neo4j_enabled`.
    #[serde(default)]
    pub neo4j_database: String,

    /// When `true`, the monolith composition root selects the
    /// **`P1-001` MVP attack-graph adapter** (`sx_graph::neo4j::
    /// Neo4jKnowledgeGraph`) instead of the legacy `sx_graph::service::
    /// Neo4jKnowledgeGraph`.
    ///
    /// The MVP adapter targets the production volume profile (1M assets,
    /// `UNWIND`-batched ingest at 5k nodes / 10k edges per transaction,
    /// bi-BFS attack-path search capped at 7 hops) and emits structured
    /// audit-log records on schema bootstrap, bulk writes, and tenant
    /// deletes. It is otherwise wire-compatible with the legacy adapter
    /// for the `KnowledgeGraph` port surface.
    ///
    /// Defaults to `false` so this flag is a strictly opt-in opt-in for
    /// operators that have already enabled `neo4j_enabled`.
    #[serde(default)]
    pub neo4j_use_mvp_engine: bool,
}

impl Default for GraphConfig {
    fn default() -> Self {
        Self {
            neo4j_enabled: false,
            neo4j_uri: String::new(),
            neo4j_user: String::new(),
            neo4j_password: SecretString::from(String::new()),
            neo4j_database: String::new(),
            neo4j_use_mvp_engine: false,
        }
    }
}

impl GraphConfig {
    /// Cross-field invariants. Disabled configs always pass; enabled
    /// configs must supply a non-empty URI, user, password and database
    /// name.
    pub(crate) fn check_invariants(&self) -> Result<(), crate::ConfigError> {
        if !self.neo4j_enabled {
            return Ok(());
        }
        if self.neo4j_uri.trim().is_empty() {
            return Err(crate::ConfigError::missing("graph.neo4j_uri"));
        }
        if self.neo4j_user.trim().is_empty() {
            return Err(crate::ConfigError::missing("graph.neo4j_user"));
        }
        if crate::secret::is_empty(&self.neo4j_password) {
            return Err(crate::ConfigError::missing("graph.neo4j_password"));
        }
        if self.neo4j_database.trim().is_empty() {
            return Err(crate::ConfigError::missing("graph.neo4j_database"));
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::GraphConfig;
    use crate::secret;

    fn enabled_baseline() -> GraphConfig {
        GraphConfig {
            neo4j_enabled: true,
            neo4j_uri: "bolt://127.0.0.1:7687".to_string(),
            neo4j_user: "neo4j".to_string(),
            neo4j_password: secret::wrap("test1234"),
            neo4j_database: "neo4j".to_string(),
            neo4j_use_mvp_engine: false,
        }
    }

    #[test]
    fn disabled_default_passes() {
        let cfg = GraphConfig::default();
        cfg.check_invariants()
            .expect("disabled default config must pass invariants");
    }

    #[test]
    fn enabled_baseline_passes() {
        enabled_baseline()
            .check_invariants()
            .expect("complete enabled baseline must pass");
    }

    #[test]
    fn enabled_without_uri_returns_missing() {
        let mut cfg = enabled_baseline();
        cfg.neo4j_uri = String::new();
        let err = cfg
            .check_invariants()
            .expect_err("missing uri must surface");
        match err {
            crate::ConfigError::MissingValue { key } => {
                assert_eq!(key, "graph.neo4j_uri");
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn enabled_without_user_returns_missing() {
        let mut cfg = enabled_baseline();
        cfg.neo4j_user = "   ".to_string();
        let err = cfg
            .check_invariants()
            .expect_err("missing user must surface");
        match err {
            crate::ConfigError::MissingValue { key } => {
                assert_eq!(key, "graph.neo4j_user");
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn enabled_without_password_returns_missing() {
        let mut cfg = enabled_baseline();
        cfg.neo4j_password = secret::wrap("");
        let err = cfg
            .check_invariants()
            .expect_err("missing password must surface");
        match err {
            crate::ConfigError::MissingValue { key } => {
                assert_eq!(key, "graph.neo4j_password");
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn enabled_without_database_returns_missing() {
        let mut cfg = enabled_baseline();
        cfg.neo4j_database = String::new();
        let err = cfg
            .check_invariants()
            .expect_err("missing database must surface");
        match err {
            crate::ConfigError::MissingValue { key } => {
                assert_eq!(key, "graph.neo4j_database");
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn debug_does_not_leak_password() {
        let cfg = enabled_baseline();
        let dbg = format!("{cfg:?}");
        assert!(!dbg.contains("test1234"), "password leaked in Debug: {dbg}");
    }

    #[test]
    fn defaults_match_documented_values() {
        let cfg = GraphConfig::default();
        assert!(!cfg.neo4j_enabled);
        assert!(cfg.neo4j_uri.is_empty());
        assert!(cfg.neo4j_user.is_empty());
        assert!(cfg.neo4j_database.is_empty());
        assert!(secret::is_empty(&cfg.neo4j_password));
        // The MVP engine flag must default to OFF: operators that
        // upgrade through a config-schema bump should not be silently
        // switched onto the new attack-graph adapter.
        assert!(!cfg.neo4j_use_mvp_engine);
    }

    #[test]
    fn mvp_engine_flag_does_not_change_invariants() {
        // Flipping `neo4j_use_mvp_engine` alone (with `neo4j_enabled`
        // false) must still pass invariants — it is a pure routing knob.
        let cfg = GraphConfig {
            neo4j_use_mvp_engine: true,
            ..GraphConfig::default()
        };
        cfg.check_invariants()
            .expect("MVP-flag-only config must still validate");
    }
}
