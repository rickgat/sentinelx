//! [`AuditSink`] — the persistence port for audit entries.

use async_trait::async_trait;

use sx_core::value_object::ids::TenantId;

use crate::error::AuditError;
use crate::model::entry::AuditEntry;

/// Persistence port for audit entries.
///
/// Implementations live outside this crate (typically in `sx-storage`).
///
/// # Concurrency
///
/// Implementations are responsible for serialising appends within a
/// tenant. A typical SQL implementation uses an
/// `INSERT ... WHERE NOT EXISTS prev_seq` pattern, or a `SERIALIZABLE`
/// transaction. Within a single process the
/// [`crate::controller::record_event::RecordAuditEventUseCase`] also
/// holds a per-tenant async mutex around the read-then-append path.
#[async_trait]
pub trait AuditSink: Send + Sync + std::fmt::Debug {
    /// Append a fully-formed entry. Implementations MUST reject entries
    /// whose `seq` is not exactly `last.seq + 1` for the tenant (or `1`
    /// when no prior entry exists).
    async fn append(&self, entry: &AuditEntry) -> Result<(), AuditError>;

    /// Return the most recent entry for `tenant_id`, or `None` if the
    /// chain has no entries yet.
    async fn last_entry_for_tenant(
        &self,
        tenant_id: TenantId,
    ) -> Result<Option<AuditEntry>, AuditError>;

    /// Return entries with `from_seq <= seq <= to_seq`, ordered by `seq`
    /// ascending. Both bounds are inclusive.
    async fn read_range(
        &self,
        tenant_id: TenantId,
        from_seq: u64,
        to_seq: u64,
    ) -> Result<Vec<AuditEntry>, AuditError>;
}
