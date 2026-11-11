//! `ClickHouse` cold-storage projection link.
//!
//! ## Status — PARTIAL
//!
//! The single-shot HTTP / `JSONEachRow` client (TLS, credentials, connection
//! reuse) ships in [`crate::clickhouse_http`] — see
//! [`crate::HttpClickHouseLink`]. The trait + [`NoopClickHouseLink`] stub
//! defined here remain the stable surface.
//!
//! TODO(intel-ioc/clickhouse): async batching / back-pressure (tracked in
//! follow-up A3) and retry / circuit-breaker semantics (tracked in follow-up
//! A4) are intentionally **not** wired in this milestone. Schema migrations
//! continue to live in the deployment layer (see
//! `clickhouse/projections.sql`) and are out of scope for this crate.
//! Wrapping decorators landing in A3/A4 must not regress the trait surface
//! defined here.
//!
//! See `clickhouse/projections.sql` for the materialised-view schemas this
//! link is expected to populate.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// A finding row projected to `ClickHouse` for cold-storage analytics.
///
/// Field types match the column types declared in `projections.sql`. We use
/// `String` for `severity` here because the cold-storage projection stores
/// the canonical lowercase identifier; the hot path can carry richer types.
//
// `Eq` is intentionally not derived because [`Self::cvss`] is `f64` — strict
// equality on floats is rarely meaningful for downstream consumers.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FindingProjection {
    /// Stable finding identifier (UUID rendered as string).
    pub id: String,
    /// Owning tenant (UUID rendered as string).
    pub tenant_id: String,
    /// Severity bucket — one of `low|medium|high|critical`.
    pub severity: String,
    /// CVSS v3.1 base score (0.0 – 10.0).
    pub cvss: f64,
    /// Event timestamp (Unix epoch seconds, UTC).
    pub ts_epoch_secs: i64,
}

/// An audit-trail event projected to `ClickHouse` for compliance retention.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AuditProjection {
    /// Owning tenant (UUID rendered as string).
    pub tenant_id: String,
    /// Monotonic per-tenant sequence number (matches the hot audit log).
    pub seq: u64,
    /// Action identifier — e.g. `scan.start`, `finding.update`.
    pub action: String,
    /// Acting principal (user UUID or system service name).
    pub actor: String,
    /// Event timestamp (Unix epoch seconds, UTC).
    pub ts_epoch_secs: i64,
}

/// Errors surfaced by a [`ClickHouseLink`] implementation.
#[derive(Debug, thiserror::Error)]
pub enum ClickHouseError {
    /// The link is currently disabled (e.g. the noop stub).
    #[error("clickhouse link disabled: {0}")]
    Disabled(&'static str),
    /// Invalid configuration supplied at construction time (e.g. empty
    /// credentials, malformed endpoint, empty database string).
    #[error("clickhouse config error: {0}")]
    Config(&'static str),
    /// Failure serializing a row to `JSONEachRow`.
    #[error("clickhouse serialization error: {0}")]
    Serialization(String),
    /// Underlying transport or query failure (DNS, TLS, connect, body read).
    #[error("clickhouse transport error: {0}")]
    Transport(String),
    /// `ClickHouse` returned a non-2xx HTTP status. Body is captured verbatim
    /// for diagnostics; callers must treat it as untrusted user input when
    /// surfacing it onward.
    #[error("clickhouse http status {status}: {body}")]
    HttpStatus {
        /// HTTP status code returned by the server.
        status: u16,
        /// Response body (may be empty).
        body: String,
    },
}

/// Abstraction over the `ClickHouse` projection sink.
///
/// The trait is intentionally narrow: implementations only have to know how
/// to append rows. Schema management lives in `projections.sql` and is owned
/// by the deployment layer.
#[async_trait]
pub trait ClickHouseLink: Send + Sync + std::fmt::Debug {
    /// Append a batch of finding projection rows.
    async fn write_findings(&self, rows: &[FindingProjection]) -> Result<(), ClickHouseError>;

    /// Append a batch of audit projection rows.
    async fn write_audit(&self, rows: &[AuditProjection]) -> Result<(), ClickHouseError>;
}

/// No-op implementation that drops all rows on the floor.
///
/// Used by [`crate::IocStore::with_defaults`] so the type can be constructed
/// in tests and non-prod environments without a `ClickHouse` cluster. Writes
/// always succeed; nothing is persisted.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopClickHouseLink;

#[async_trait]
impl ClickHouseLink for NoopClickHouseLink {
    async fn write_findings(&self, rows: &[FindingProjection]) -> Result<(), ClickHouseError> {
        tracing::trace!(
            target: "sx_intel_ioc::clickhouse",
            row_count = rows.len(),
            "noop clickhouse link: dropping findings batch",
        );
        Ok(())
    }

    async fn write_audit(&self, rows: &[AuditProjection]) -> Result<(), ClickHouseError> {
        tracing::trace!(
            target: "sx_intel_ioc::clickhouse",
            row_count = rows.len(),
            "noop clickhouse link: dropping audit batch",
        );
        Ok(())
    }
}
