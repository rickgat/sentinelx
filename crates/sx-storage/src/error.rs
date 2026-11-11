//! Storage-layer error type and conversions.
//!
//! [`StorageError`] is the *internal* error type of this crate. It is
//! returned from low-level helpers ([`crate::pool::build_pool`],
//! [`crate::tenant_context::TenantContext::apply`]). Repository ports
//! translate [`StorageError`] into [`crate::domain::DomainError`] at the
//! boundary so the domain layer is never coupled to `sqlx`.

use thiserror::Error;

use crate::domain::DomainError;

/// Errors produced by the persistence adapter.
#[derive(Debug, Error)]
pub enum StorageError {
    /// Failed to open or maintain a database connection.
    #[error("database connection: {0}")]
    Connection(String),

    /// A SQL query or statement execution failed.
    #[error("query failed: {0}")]
    Query(String),

    /// The query succeeded but matched zero rows where one was expected.
    #[error("not found")]
    NotFound,

    /// A unique or exclusion constraint was violated (Postgres `23505`).
    #[error("conflict (unique violation): {0}")]
    Conflict(String),

    /// A value could not be (de)serialised between the database and the
    /// Rust representation (e.g. `JSONB` -> domain enum).
    #[error("serialization: {0}")]
    Serialization(String),

    /// The pool builder rejected a configuration field (e.g. empty URL).
    #[error("invalid config: {0}")]
    Config(String),

    /// The query exceeded its `statement_timeout`.
    #[error("timeout")]
    Timeout,
}

/// Postgres SQLSTATE for `unique_violation`.
const PG_UNIQUE_VIOLATION: &str = "23505";

/// Postgres SQLSTATE for `query_canceled` (`statement_timeout` fired).
const PG_QUERY_CANCELED: &str = "57014";

impl From<sqlx::Error> for StorageError {
    fn from(err: sqlx::Error) -> Self {
        match &err {
            sqlx::Error::RowNotFound => Self::NotFound,
            sqlx::Error::Database(db_err) => {
                let code = db_err.code().unwrap_or_default().into_owned();
                if code == PG_UNIQUE_VIOLATION {
                    Self::Conflict(db_err.message().to_owned())
                } else if code == PG_QUERY_CANCELED {
                    Self::Timeout
                } else {
                    Self::Query(format!("{code}: {}", db_err.message()))
                }
            }
            sqlx::Error::PoolTimedOut | sqlx::Error::PoolClosed => {
                Self::Connection(err.to_string())
            }
            sqlx::Error::Decode(_) | sqlx::Error::ColumnDecode { .. } => {
                Self::Serialization(err.to_string())
            }
            _ => Self::Query(err.to_string()),
        }
    }
}

impl From<StorageError> for DomainError {
    fn from(err: StorageError) -> Self {
        match err {
            StorageError::NotFound => {
                // Concrete entity name is set at the call site by the
                // repository; this fallback name is only used when
                // callers don't override.
                Self::Repository("not found".to_owned())
            }
            StorageError::Conflict(msg) => Self::Conflict(msg),
            other => Self::Repository(other.to_string()),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn row_not_found_maps_to_not_found() {
        let mapped: StorageError = sqlx::Error::RowNotFound.into();
        assert!(matches!(mapped, StorageError::NotFound));
    }

    #[test]
    fn pool_timed_out_maps_to_connection() {
        let mapped: StorageError = sqlx::Error::PoolTimedOut.into();
        assert!(matches!(mapped, StorageError::Connection(_)));
    }

    #[test]
    fn pool_closed_maps_to_connection() {
        let mapped: StorageError = sqlx::Error::PoolClosed.into();
        assert!(matches!(mapped, StorageError::Connection(_)));
    }

    #[test]
    fn storage_error_to_domain_error_conflict() {
        let s = StorageError::Conflict("dup".to_owned());
        let d: DomainError = s.into();
        assert!(matches!(d, DomainError::Conflict(_)));
    }

    #[test]
    fn storage_error_to_domain_error_repository() {
        let s = StorageError::Query("boom".to_owned());
        let d: DomainError = s.into();
        assert!(matches!(d, DomainError::Repository(_)));
    }

    #[test]
    fn timeout_displays_correctly() {
        assert_eq!(StorageError::Timeout.to_string(), "timeout");
    }

    #[test]
    fn not_found_displays_correctly() {
        assert_eq!(StorageError::NotFound.to_string(), "not found");
    }
}
