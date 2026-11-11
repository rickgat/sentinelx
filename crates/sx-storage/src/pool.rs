//! Connection-pool construction for Postgres.
//!
//! The builder reads from a [`PoolSettings`] struct that mirrors the
//! relevant subset of `sx_config::DatabaseConfig`. Once `sx-config`
//! publishes its `DatabaseConfig` type, callers in the composition
//! root can populate [`PoolSettings`] from it without this crate
//! needing to know.

use std::str::FromStr;
use std::time::Duration;

use secrecy::{ExposeSecret, SecretString};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{ConnectOptions, PgPool};

use crate::error::StorageError;

/// Settings consumed by [`build_pool`].
///
/// Mirrors the relevant fields of `sx_config::schema::database::DatabaseConfig`
/// so we don't take a build-time dependency on the (still in-flight)
/// concrete config type.
#[derive(Debug)]
pub struct PoolSettings<'a> {
    /// Full Postgres URL — held as a [`SecretString`] for the same
    /// rationale as `sx_config`: it contains credentials.
    pub url: &'a SecretString,
    /// Upper bound on simultaneously open connections.
    pub max_connections: u32,
    /// Pool warm-up size. Must be `<= max_connections`.
    pub min_connections: u32,
    /// Time to wait for a connection to become available.
    pub acquire_timeout: Duration,
    /// Idle connection eviction interval.
    pub idle_timeout: Duration,
    /// Server-side `statement_timeout`, in milliseconds, applied via
    /// `SET LOCAL statement_timeout` from
    /// [`crate::tenant_context::TenantContext::apply`].
    pub statement_timeout_ms: u64,
    /// Postgres `application_name` (sent on connect; appears in
    /// `pg_stat_activity` for traceability).
    pub application_name: &'a str,
}

/// Build a connected, validated [`PgPool`] from [`PoolSettings`].
///
/// # Errors
///
/// Returns [`StorageError::Config`] if `url` is empty or rejected by
/// [`PgConnectOptions::from_str`]; [`StorageError::Connection`] if the
/// initial `SELECT 1` ping fails.
pub async fn build_pool(settings: &PoolSettings<'_>) -> Result<PgPool, StorageError> {
    let raw_url = settings.url.expose_secret();
    if raw_url.is_empty() {
        return Err(StorageError::Config("database url is empty".to_owned()));
    }
    if settings.min_connections > settings.max_connections {
        return Err(StorageError::Config(
            "min_connections must be <= max_connections".to_owned(),
        ));
    }
    if settings.acquire_timeout.is_zero() {
        return Err(StorageError::Config(
            "acquire_timeout must be greater than zero".to_owned(),
        ));
    }

    let mut connect_opts = PgConnectOptions::from_str(raw_url)
        .map_err(|e| StorageError::Config(format!("invalid database url: {e}")))?
        .application_name(settings.application_name);

    // Log statement traces only at the most verbose level; never log
    // statement parameters (sqlx default is fine, but be explicit).
    connect_opts = connect_opts.log_statements(tracing::log::LevelFilter::Trace);

    // Pull host/port/dbname for non-secret logging.
    let host = connect_opts.get_host().to_owned();
    let port = connect_opts.get_port();
    let dbname = connect_opts
        .get_database()
        .unwrap_or("<default>")
        .to_owned();
    tracing::info!(
        host = %host,
        port = port,
        database = %dbname,
        max_connections = settings.max_connections,
        min_connections = settings.min_connections,
        "connecting to postgres",
    );

    let pool = PgPoolOptions::new()
        .max_connections(settings.max_connections)
        .min_connections(settings.min_connections)
        .acquire_timeout(settings.acquire_timeout)
        .idle_timeout(Some(settings.idle_timeout))
        .connect_with(connect_opts)
        .await
        .map_err(|e| StorageError::Connection(e.to_string()))?;

    // Ping.
    let row: (i32,) = sqlx::query_as("SELECT 1")
        .fetch_one(&pool)
        .await
        .map_err(StorageError::from)?;
    if row.0 != 1 {
        return Err(StorageError::Connection(
            "unexpected ping response".to_owned(),
        ));
    }

    Ok(pool)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn settings_with(url: SecretString) -> PoolSettings<'static> {
        // We need the `&SecretString` to outlive the struct; tests own
        // the string in a local then leak it. We control lifetime via
        // `Box::leak` deliberately — it's fine in tests.
        let leaked: &'static SecretString = Box::leak(Box::new(url));
        PoolSettings {
            url: leaked,
            max_connections: 4,
            min_connections: 1,
            acquire_timeout: Duration::from_secs(2),
            idle_timeout: Duration::from_secs(60),
            statement_timeout_ms: 5_000,
            application_name: "sx-storage-tests",
        }
    }

    #[tokio::test]
    async fn empty_url_is_rejected() {
        let s = settings_with(SecretString::from(String::new()));
        let r = build_pool(&s).await;
        assert!(matches!(r, Err(StorageError::Config(_))));
    }

    #[tokio::test]
    async fn min_greater_than_max_is_rejected() {
        let mut s = settings_with(SecretString::from(
            "postgres://u:p@127.0.0.1:5432/d".to_owned(),
        ));
        s.min_connections = 10;
        s.max_connections = 1;
        let r = build_pool(&s).await;
        assert!(matches!(r, Err(StorageError::Config(_))));
    }

    #[tokio::test]
    async fn zero_acquire_timeout_is_rejected() {
        let mut s = settings_with(SecretString::from(
            "postgres://u:p@127.0.0.1:5432/d".to_owned(),
        ));
        s.acquire_timeout = Duration::ZERO;
        let r = build_pool(&s).await;
        assert!(matches!(r, Err(StorageError::Config(_))));
    }

    #[tokio::test]
    async fn malformed_url_is_rejected() {
        let s = settings_with(SecretString::from("not a url".to_owned()));
        let r = build_pool(&s).await;
        assert!(matches!(r, Err(StorageError::Config(_))));
    }
}
