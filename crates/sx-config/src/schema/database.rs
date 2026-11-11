//! Primary relational database (`PostgreSQL`) configuration.

use std::time::Duration;

use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use serde_with::{serde_as, DurationSeconds};
use url::Url;
use validator::Validate;

/// Database connection-pool configuration.
///
/// `url` is wrapped in [`SecretString`] so it is redacted in `Debug` output
/// and zeroed on drop. The full URL contains credentials, so it must never
/// leak.
#[serde_as]
#[derive(Debug, Clone, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
pub struct DatabaseConfig {
    /// Full connection URL (e.g. `postgres://user:pw@host:5432/db`).
    pub url: SecretString,

    /// Upper bound on simultaneously open connections.
    #[validate(range(min = 1))]
    pub max_connections: u32,

    /// Pool warm-up size. Must be `<= max_connections`.
    #[validate(range(min = 0))]
    pub min_connections: u32,

    /// Time to wait for a connection to become available.
    #[serde_as(as = "DurationSeconds<u64>")]
    pub acquire_timeout: Duration,

    /// Idle connection eviction interval.
    #[serde_as(as = "DurationSeconds<u64>")]
    pub idle_timeout: Duration,

    /// Server-side per-statement timeout in milliseconds.
    #[validate(range(min = 1))]
    pub statement_timeout_ms: u64,

    /// Whether to run pending sqlx migrations at startup. Recommended for
    /// dev / single-instance deployments; in multi-instance production
    /// migrations are typically run out-of-band before rollout.
    pub migrate_on_start: bool,

    /// Whether the monolith should connect to Postgres at all. When `false`,
    /// the composition root falls back to the in-memory repositories. Set to
    /// `true` for any deployment that needs durability.
    pub enabled: bool,
}

impl DatabaseConfig {
    /// Cross-field invariants checked by the loader.
    pub(crate) fn check_invariants(&self) -> Result<(), crate::ConfigError> {
        let raw = self.url.expose_secret();
        if raw.is_empty() {
            return Err(crate::ConfigError::missing("database.url"));
        }
        let parsed = Url::parse(raw)
            .map_err(|_| crate::ConfigError::invalid("database.url", "not a valid URL"))?;
        let scheme = parsed.scheme();
        if scheme != "postgres" && scheme != "postgresql" {
            return Err(crate::ConfigError::invalid(
                "database.url",
                "scheme must be postgres or postgresql",
            ));
        }
        if self.min_connections > self.max_connections {
            return Err(crate::ConfigError::invalid(
                "database.min_connections",
                "must be <= max_connections",
            ));
        }
        if self.acquire_timeout.is_zero() {
            return Err(crate::ConfigError::invalid(
                "database.acquire_timeout",
                "must be greater than zero",
            ));
        }
        Ok(())
    }
}
