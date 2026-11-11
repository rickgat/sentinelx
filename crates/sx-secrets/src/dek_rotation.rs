//! DEK rotation per-tenant (CRIT-003).
//!
//! Periodic re-encryption of every row that stores DEK-wrapped data so
//! a tenant migrates from `dek_version = N` to `dek_version = N+1`
//! without any application-visible downtime. PCI DSS 4.0 §3.7.4 requires
//! keys to be retired at the end of a defined cryptoperiod; without an
//! operational job tenants would remain on the original DEK forever and
//! the compliance posture would silently regress.
//!
//! ## Architecture
//!
//! The implementation is a small state machine driving four pluggable
//! collaborators:
//!
//! 1. [`RotationProgressStore`] — persists [`RotationCheckpoint`] rows
//!    in `dek_rotation_progress`. Each row carries
//!    `(tenant_id, target_dek_version, last_processed_row_id,
//!     processed_rows, status, …)` so the job can resume from the last
//!    checkpoint on restart.
//! 2. [`RotationPolicyStore`] — persists per-tenant `cadence_days` in
//!    `dek_rotation_policy`. The default cadence is 365 days; PCI
//!    tenants are seeded with 90.
//! 3. [`ReencryptionVisitor`] — per-table re-encryption hook. The
//!    visitor lists rows above a cursor, reads each row's ciphertext,
//!    unwraps with the old DEK, wraps with the new DEK, and persists the
//!    new ciphertext + new `dek_version` in a single SQL transaction.
//! 4. [`DekRotationAuditSink`] — receives one
//!    [`DekRotationAuditEvent`] per batch + lifecycle transition; in
//!    production this forwards to `sx-audit`. The crate ships an
//!    in-memory implementation for tests and diagnostics.
//!
//! [`DekRotationJob`] glues those together: it consumes a target
//! [`crate::dek::StoredDek`] (the new DEK), iterates each visitor, and
//! drives batches of [`RotationConfig::batch_size`] rows. Checkpoints
//! are written after every batch.
//!
//! [`DekRotationScheduler`] runs the periodic sweep — every 6h by
//! default — and auto-enqueues any tenant whose
//! `last_rotated_at + cadence_days` is in the past. Backpressure is
//! enforced via two [`tokio::sync::Semaphore`] permits:
//!
//! * a *per-tenant* permit — at most one rotation in flight per
//!   tenant. Acquired non-blocking; the scheduler treats contention as
//!   "already rotating, skip".
//! * a *cluster-wide* permit — caps the number of concurrent rotations
//!   to [`RotationConfig::max_concurrent`] (default 5). Acquired with
//!   `acquire`, so a tenant that wins a per-tenant permit but loses the
//!   cluster permit waits, it does not error.
//!
//! ## Invariants
//!
//! * **Idempotent resume.** Visitors MUST advance the cursor strictly
//!   monotonically; restarting a crashed job consumes the cursor and
//!   re-reads the next batch above it. Rows already at the new
//!   `dek_version` are skipped (`WHERE dek_version < $target`), so a
//!   row re-presented on resume is never double-encrypted.
//! * **Atomic per-row write.** Every row update happens inside the
//!   visitor's own transaction: read ciphertext + new `dek_version`,
//!   verify by reading back, COMMIT. A verification failure rolls back
//!   and emits a CRITICAL audit event.
//! * **No plaintext at rest.** Plaintext is wrapped in
//!   [`secrecy::SecretString`] for its entire lifetime; visitors are
//!   trait-bound to receive the secret rather than raw bytes.
//! * **Tenant scoping.** Every visitor call receives the
//!   [`crate::dek::TenantId`] and MUST scope its SQL with
//!   `WHERE tenant_id = $1`. The integration tests assert that a
//!   rotation in tenant A does not touch tenant B's rows.
//!
//! ## Failure recovery
//!
//! | Failure                              | Behaviour                                           |
//! |--------------------------------------|-----------------------------------------------------|
//! | Process crash mid-batch              | Resume from `last_processed_row_id` on next start.  |
//! | KMS error unwrapping old DEK         | `status = failed`, ERROR audit event, no advance.   |
//! | KMS error wrapping new DEK           | `status = failed`, ERROR audit event, no advance.   |
//! | Verification readback mismatch       | Visitor MUST rollback + emit CRITICAL audit event.  |
//! | Operator `--cancel`                  | `status = cancelled`, graceful exit at next batch.  |
//!
//! The crate never panics, never calls `unwrap`/`expect`, and never
//! logs ciphertext or plaintext bytes.

#![allow(clippy::module_name_repetitions)]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::{Mutex, RwLock, Semaphore};
use tracing::{debug, error, info, warn};

use crate::dek::{DekManager, DekStore, TenantId};
use crate::error::SecretsError;
use crate::kms::provider::KmsKeyProvider;

// =============================================================================
// Config / constants
// =============================================================================

/// Default batch size for [`DekRotationJob`].
///
/// Operators may override via [`RotationConfig::with_batch_size`]; the
/// `sx-cli` shipped binary exposes `--batch-size`. The configuration
/// schema key for the YAML/env layer is documented as
/// `secrets.dek_rotation_batch_size` in `docs/operations/dek-rotation.md`.
pub const DEFAULT_DEK_ROTATION_BATCH_SIZE: u32 = 1_000;

/// Default cluster-wide rotation concurrency.
pub const DEFAULT_DEK_ROTATION_MAX_CONCURRENT: usize = 5;

/// Default scheduler sweep interval — every 6 hours.
pub const DEFAULT_DEK_ROTATION_SWEEP_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);

/// Default cadence for non-PCI tenants — 365 days.
pub const DEFAULT_CADENCE_DAYS: i32 = 365;

/// PCI baseline cadence — 90 days (DSS 4.0 §3.7.4).
pub const PCI_CADENCE_DAYS: i32 = 90;

/// Tunables for [`DekRotationJob`].
///
/// All fields default to the operationally-validated values used by the
/// production scheduler. Override only when a specific tenant requires
/// it (large batches stress the connection pool; tiny batches dominate
/// the wall-clock cost with checkpoint overhead).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RotationConfig {
    /// Rows per batch.
    pub batch_size: u32,
    /// Max concurrent rotations cluster-wide.
    pub max_concurrent: usize,
    /// Periodic scheduler sweep interval.
    pub sweep_interval: Duration,
}

impl RotationConfig {
    /// Build the operator-facing defaults.
    #[must_use]
    pub const fn defaults() -> Self {
        Self {
            batch_size: DEFAULT_DEK_ROTATION_BATCH_SIZE,
            max_concurrent: DEFAULT_DEK_ROTATION_MAX_CONCURRENT,
            sweep_interval: DEFAULT_DEK_ROTATION_SWEEP_INTERVAL,
        }
    }

    /// Override the batch size. Values are clamped to `[1, 100_000]` so
    /// pathological configs cannot wedge a Postgres connection.
    #[must_use]
    pub const fn with_batch_size(mut self, n: u32) -> Self {
        let clamped = if n == 0 {
            1
        } else if n > 100_000 {
            100_000
        } else {
            n
        };
        self.batch_size = clamped;
        self
    }

    /// Override the cluster-wide concurrency.
    #[must_use]
    pub const fn with_max_concurrent(mut self, n: usize) -> Self {
        self.max_concurrent = if n == 0 { 1 } else { n };
        self
    }

    /// Override the scheduler sweep interval.
    #[must_use]
    pub const fn with_sweep_interval(mut self, d: Duration) -> Self {
        self.sweep_interval = d;
        self
    }
}

impl Default for RotationConfig {
    fn default() -> Self {
        Self::defaults()
    }
}

// =============================================================================
// State machine
// =============================================================================

/// Lifecycle status of a single rotation row.
///
/// Allowed transitions (anything else is rejected by
/// [`RotationJobStatus::can_transition_to`]):
///
/// ```text
///   pending  ──► in_progress ──► completed
///       │            │     ╲
///       │            │      ╲─► failed
///       │            │       ╲
///       │            └────────► cancelled
///       └──► cancelled
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RotationJobStatus {
    /// Row inserted, no work has started yet.
    Pending,
    /// Job is actively re-encrypting batches.
    InProgress,
    /// Every visitor has finished; the policy `last_rotated_at` has been
    /// stamped.
    Completed,
    /// Hard failure (KMS error, verification mismatch). Requires
    /// operator triage before resume.
    Failed,
    /// Operator-initiated cancellation. The job will not be resumed.
    Cancelled,
}

impl RotationJobStatus {
    /// Wire-shape string used by the DB schema and CLI output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::InProgress => "in_progress",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }

    /// Parse the wire-shape string, returning `None` on an unknown
    /// value.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "pending" => Some(Self::Pending),
            "in_progress" => Some(Self::InProgress),
            "completed" => Some(Self::Completed),
            "failed" => Some(Self::Failed),
            "cancelled" => Some(Self::Cancelled),
            _ => None,
        }
    }

    /// `true` once no further state transitions are possible.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Cancelled)
    }

    /// Returns `true` when `self → next` is a legal transition.
    ///
    /// The state machine is intentionally conservative: terminal states
    /// never transition (a `failed` rotation must be re-enqueued as a
    /// fresh row), and `Completed` is reachable only from `InProgress`.
    #[must_use]
    pub const fn can_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Pending, Self::InProgress | Self::Cancelled)
                | (
                    Self::InProgress,
                    Self::Completed | Self::Failed | Self::Cancelled
                )
        )
    }
}

/// Persisted checkpoint shared between the job and the progress store.
///
/// Fields mirror the `dek_rotation_progress` row 1:1 so the store impl
/// is a pure `SELECT` / `UPSERT` adapter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RotationCheckpoint {
    /// Tenant the rotation belongs to.
    pub tenant_id: TenantId,
    /// Target DEK version every row will be re-encrypted to.
    pub target_dek_version: u32,
    /// Opaque cursor — the highest `(visitor_id, row_id)` pair
    /// observed. Encoded as TEXT in the DB so visitors with different
    /// PK shapes (UUID / BIGINT / composite) can co-exist.
    pub last_processed_row_id: Option<String>,
    /// Best-effort row count snapshot taken at job start.
    pub total_rows: u64,
    /// Rows successfully re-encrypted so far.
    pub processed_rows: u64,
    /// Wall-clock job start time.
    pub started_at: DateTime<Utc>,
    /// Wall-clock stamp of the most recent successful checkpoint write.
    pub last_checkpoint_at: DateTime<Utc>,
    /// Current lifecycle status.
    pub status: RotationJobStatus,
    /// Redacted last error message, populated on `failed` only.
    pub last_error: Option<String>,
}

impl RotationCheckpoint {
    /// Construct a fresh `pending` checkpoint.
    #[must_use]
    pub fn new(tenant_id: TenantId, target_dek_version: u32) -> Self {
        let now = Utc::now();
        Self {
            tenant_id,
            target_dek_version,
            last_processed_row_id: None,
            total_rows: 0,
            processed_rows: 0,
            started_at: now,
            last_checkpoint_at: now,
            status: RotationJobStatus::Pending,
            last_error: None,
        }
    }
}

// =============================================================================
// Per-tenant policy
// =============================================================================

/// Per-tenant rotation policy row.
///
/// Mirrors the `dek_rotation_policy` table 1:1.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RotationPolicyRow {
    /// Tenant the policy applies to.
    pub tenant_id: TenantId,
    /// Number of days after `last_rotated_at` at which the scheduler
    /// auto-enqueues a rotation.
    pub cadence_days: i32,
    /// Stamp of the most recent successful rotation. `None` when the
    /// tenant has never rotated.
    pub last_rotated_at: Option<DateTime<Utc>>,
    /// Updated whenever the operator changes `cadence_days` or the
    /// scheduler stamps `last_rotated_at`.
    pub updated_at: DateTime<Utc>,
}

impl RotationPolicyRow {
    /// Default policy for a brand-new tenant — 365 days.
    #[must_use]
    pub fn default_for(tenant_id: TenantId) -> Self {
        Self {
            tenant_id,
            cadence_days: DEFAULT_CADENCE_DAYS,
            last_rotated_at: None,
            updated_at: Utc::now(),
        }
    }

    /// PCI baseline — 90 days.
    #[must_use]
    pub fn pci_for(tenant_id: TenantId) -> Self {
        Self {
            tenant_id,
            cadence_days: PCI_CADENCE_DAYS,
            last_rotated_at: None,
            updated_at: Utc::now(),
        }
    }

    /// `true` when the scheduler should auto-enqueue this tenant.
    ///
    /// A tenant that has never rotated (`last_rotated_at = None`) is
    /// always due — first-time rotation is a no-op when the DEK has
    /// never been minted, and is otherwise the correct response.
    #[must_use]
    pub fn is_due(&self, now: DateTime<Utc>) -> bool {
        let Some(last) = self.last_rotated_at else {
            return true;
        };
        let cadence = chrono::Duration::days(i64::from(self.cadence_days));
        now.signed_duration_since(last) >= cadence
    }
}

// =============================================================================
// Progress + policy storage ports
// =============================================================================

/// Persistence port for [`RotationCheckpoint`] rows.
///
/// Implementations live alongside the platform's RLS-aware repository
/// pattern; the crate ships an in-memory implementation for tests and
/// diagnostics.
#[async_trait]
pub trait RotationProgressStore: Send + Sync {
    /// Insert or update `checkpoint`. Implementations MUST reject
    /// illegal state transitions (see
    /// [`RotationJobStatus::can_transition_to`]) by returning
    /// [`DekRotationError::IllegalTransition`].
    async fn upsert(&self, checkpoint: &RotationCheckpoint) -> Result<(), DekRotationError>;

    /// Fetch the most recent row for `(tenant_id, target_dek_version)`,
    /// or `None` if absent.
    async fn get(
        &self,
        tenant_id: TenantId,
        target_dek_version: u32,
    ) -> Result<Option<RotationCheckpoint>, DekRotationError>;

    /// Fetch the latest row for `tenant_id` regardless of version.
    /// Used by the CLI `--status` flow and the scheduler's "already in
    /// progress?" check.
    async fn latest_for_tenant(
        &self,
        tenant_id: TenantId,
    ) -> Result<Option<RotationCheckpoint>, DekRotationError>;
}

/// Persistence port for [`RotationPolicyRow`] entries.
#[async_trait]
pub trait RotationPolicyStore: Send + Sync {
    /// Read the policy for `tenant_id`. Returns `Ok(None)` if no row
    /// exists; callers MUST fall back to
    /// [`RotationPolicyRow::default_for`] in that case.
    async fn get(&self, tenant_id: TenantId)
        -> Result<Option<RotationPolicyRow>, DekRotationError>;

    /// Insert or update `row`.
    async fn upsert(&self, row: &RotationPolicyRow) -> Result<(), DekRotationError>;

    /// List every tenant the scheduler should consider on the next
    /// sweep. The scheduler runs under a bypass-RLS service role; this
    /// method MAY return tenants the caller would otherwise not see.
    async fn list_all(&self) -> Result<Vec<RotationPolicyRow>, DekRotationError>;
}

/// In-memory [`RotationProgressStore`] for tests and ephemeral runs.
#[derive(Debug, Default, Clone)]
pub struct InMemoryRotationProgressStore {
    inner: Arc<RwLock<HashMap<(TenantId, u32), RotationCheckpoint>>>,
}

impl InMemoryRotationProgressStore {
    /// Construct an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot every checkpoint. Order is unspecified.
    pub async fn snapshot(&self) -> Vec<RotationCheckpoint> {
        self.inner.read().await.values().cloned().collect()
    }
}

#[async_trait]
impl RotationProgressStore for InMemoryRotationProgressStore {
    async fn upsert(&self, checkpoint: &RotationCheckpoint) -> Result<(), DekRotationError> {
        let key = (checkpoint.tenant_id, checkpoint.target_dek_version);
        let mut map = self.inner.write().await;
        if let Some(existing) = map.get(&key) {
            // Allow same-state idempotent re-writes (counter updates).
            if existing.status != checkpoint.status
                && !existing.status.can_transition_to(checkpoint.status)
            {
                return Err(DekRotationError::IllegalTransition {
                    from: existing.status,
                    to: checkpoint.status,
                });
            }
        }
        map.insert(key, checkpoint.clone());
        drop(map);
        Ok(())
    }

    async fn get(
        &self,
        tenant_id: TenantId,
        target_dek_version: u32,
    ) -> Result<Option<RotationCheckpoint>, DekRotationError> {
        Ok(self
            .inner
            .read()
            .await
            .get(&(tenant_id, target_dek_version))
            .cloned())
    }

    async fn latest_for_tenant(
        &self,
        tenant_id: TenantId,
    ) -> Result<Option<RotationCheckpoint>, DekRotationError> {
        Ok(self
            .inner
            .read()
            .await
            .values()
            .filter(|c| c.tenant_id == tenant_id)
            .max_by_key(|c| c.target_dek_version)
            .cloned())
    }
}

/// In-memory [`RotationPolicyStore`] for tests and ephemeral runs.
#[derive(Debug, Default, Clone)]
pub struct InMemoryRotationPolicyStore {
    inner: Arc<RwLock<HashMap<TenantId, RotationPolicyRow>>>,
}

impl InMemoryRotationPolicyStore {
    /// Construct an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl RotationPolicyStore for InMemoryRotationPolicyStore {
    async fn get(
        &self,
        tenant_id: TenantId,
    ) -> Result<Option<RotationPolicyRow>, DekRotationError> {
        Ok(self.inner.read().await.get(&tenant_id).cloned())
    }

    async fn upsert(&self, row: &RotationPolicyRow) -> Result<(), DekRotationError> {
        self.inner.write().await.insert(row.tenant_id, row.clone());
        Ok(())
    }

    async fn list_all(&self) -> Result<Vec<RotationPolicyRow>, DekRotationError> {
        Ok(self.inner.read().await.values().cloned().collect())
    }
}

// =============================================================================
// Per-table visitor
// =============================================================================

/// Outcome of a single [`ReencryptionVisitor::reencrypt_batch`] call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VisitorBatchOutcome {
    /// Rows the visitor actually re-encrypted. `0` indicates the table
    /// is exhausted (no more rows above the cursor).
    pub rows_reencrypted: u64,
    /// New cursor — the highest `row_id` the visitor advanced past. The
    /// scheduler propagates this back to the next batch. `None` when no
    /// rows were processed (table exhausted).
    pub next_cursor: Option<String>,
    /// `true` when the visitor has finished every row it owns.
    pub exhausted: bool,
}

/// Per-table re-encryption visitor.
///
/// A visitor encapsulates the knowledge of how *one* DEK-wrapped table
/// is shaped: which columns store ciphertext, which column stores the
/// `dek_version`, what the primary key looks like. The orchestrator
/// drives one or many visitors per job; the documentation in
/// `docs/operations/dek-rotation.md` lists the canonical visitor set.
///
/// Implementations MUST:
///
/// * scope every SQL query with `WHERE tenant_id = $1` so cross-tenant
///   reads are impossible even if a buggy caller wires a different
///   tenant id;
/// * skip rows already at the target version
///   (`WHERE dek_version < $target`) — this is the idempotence guard
///   that prevents double-encryption on resume;
/// * read back the row inside the same transaction and verify the
///   new ciphertext unwraps before COMMIT;
/// * advance the cursor strictly monotonically.
#[async_trait]
pub trait ReencryptionVisitor: Send + Sync {
    /// Stable identifier for this visitor (table name, used in audit
    /// events).
    fn visitor_id(&self) -> &'static str;

    /// Snapshot the total number of rows belonging to `tenant_id` below
    /// the target version. Used purely for the operator-facing
    /// `total_rows` counter; correctness does not depend on it.
    async fn count_remaining(
        &self,
        tenant_id: TenantId,
        target_version: u32,
    ) -> Result<u64, DekRotationError>;

    /// Re-encrypt up to `batch_size` rows above `cursor`, returning the
    /// new cursor and counter.
    ///
    /// Implementations receive the *plaintext* of the old DEK so they
    /// can perform the inner `decrypt(payload_ciphertext, old_dek)` →
    /// `encrypt(plaintext, new_dek)` step in-process without further
    /// KMS round-trips per row. The plaintext is wrapped in
    /// [`SecretString`] for its entire lifetime.
    async fn reencrypt_batch(
        &self,
        tenant_id: TenantId,
        cursor: Option<&str>,
        batch_size: u32,
        target_version: u32,
        old_dek_plaintext: &SecretString,
        new_dek_plaintext: &SecretString,
    ) -> Result<VisitorBatchOutcome, DekRotationError>;
}

// =============================================================================
// Audit
// =============================================================================

/// Audit event severity. The scheduler escalates KMS / verification
/// failures to `Critical` so on-call paging fires on the same channel
/// as the credential-rotation pipeline.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DekRotationSeverity {
    /// Routine progress / lifecycle events.
    Info,
    /// Recoverable warning (batch dropped to zero rows, etc.).
    Warn,
    /// Hard failure requiring operator action.
    Error,
    /// Verification mismatch — cryptographic invariant breach.
    Critical,
}

/// Canonical audit event types emitted by [`DekRotationJob`].
///
/// Stable string constants used as the event type on every audit emit.
/// Mirrors the credential-rotation pattern in `sx-intel-feeds::cred_rotation`.
pub mod audit_event_types {
    /// Job entered `in_progress`.
    pub const STARTED: &str = "audit.crypto.dek_rotation_started";
    /// One batch finished re-encrypting successfully.
    pub const BATCH_COMPLETED: &str = "audit.crypto.dek_rotation_batch_completed";
    /// Job reached `completed`.
    pub const COMPLETED: &str = "audit.crypto.dek_rotation_completed";
    /// Job reached `failed`.
    pub const FAILED: &str = "audit.crypto.dek_rotation_failed";
    /// Operator-initiated cancellation.
    pub const CANCELLED: &str = "audit.crypto.dek_rotation_cancelled";
}

/// Audit event emitted by [`DekRotationJob`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DekRotationAuditEvent {
    /// One of the constants in [`audit_event_types`].
    pub event_type: &'static str,
    /// Tenant the rotation belongs to.
    pub tenant_id: TenantId,
    /// Previous DEK version (the one being phased out).
    pub dek_version_old: u32,
    /// Target DEK version (the one being rotated to).
    pub dek_version_new: u32,
    /// Rows re-encrypted in this batch. `0` for lifecycle events.
    pub batch_rows: u64,
    /// Total rows processed so far across all batches.
    pub total_processed: u64,
    /// Estimated remaining rows.
    pub total_remaining: u64,
    /// Severity dial.
    pub severity: DekRotationSeverity,
    /// Redacted error message on failure. Never contains ciphertext or
    /// plaintext bytes.
    pub error_redacted: Option<String>,
    /// Wall-clock stamp.
    pub at: DateTime<Utc>,
}

/// Audit-sink port. Production wires this to `sx-audit`; the crate
/// ships an in-memory implementation for tests.
#[async_trait]
pub trait DekRotationAuditSink: Send + Sync {
    /// Record an event. MUST NOT block the caller.
    async fn record(&self, event: DekRotationAuditEvent);
}

/// In-memory audit sink — process-local buffer for tests + diagnostics.
#[derive(Debug, Default, Clone)]
pub struct InMemoryDekRotationAuditSink {
    events: Arc<Mutex<Vec<DekRotationAuditEvent>>>,
}

impl InMemoryDekRotationAuditSink {
    /// Empty sink.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot every recorded event.
    pub async fn snapshot(&self) -> Vec<DekRotationAuditEvent> {
        self.events.lock().await.clone()
    }
}

#[async_trait]
impl DekRotationAuditSink for InMemoryDekRotationAuditSink {
    async fn record(&self, event: DekRotationAuditEvent) {
        self.events.lock().await.push(event);
    }
}

// =============================================================================
// Errors
// =============================================================================

/// Errors surfaced by the rotation orchestrator and its collaborators.
#[derive(Debug, Error)]
pub enum DekRotationError {
    /// Wrapping/unwrapping a DEK round-trip failed.
    #[error("KMS error: {0}")]
    Kms(#[from] SecretsError),

    /// The progress / policy store rejected the operation. The string
    /// is pre-redacted — it surfaces in audit logs.
    #[error("store error: {0}")]
    Store(String),

    /// Visitor failed mid-batch. Pre-redacted message.
    #[error("visitor error: {0}")]
    Visitor(String),

    /// Verification readback did not match the new plaintext. CRITICAL.
    #[error("verification readback mismatch on visitor `{visitor_id}` row `{row_id}`")]
    VerificationMismatch {
        /// The visitor that detected the mismatch.
        visitor_id: &'static str,
        /// The row id (opaque) whose readback failed.
        row_id: String,
    },

    /// Rejected an illegal state transition (e.g. `failed → completed`).
    #[error("illegal status transition {from:?} → {to:?}")]
    IllegalTransition {
        /// Source state.
        from: RotationJobStatus,
        /// Target state the caller attempted to set.
        to: RotationJobStatus,
    },

    /// The orchestrator detected that the rotation row was cancelled
    /// while a batch was running. Reported as `Cancelled` to operators.
    #[error("rotation cancelled")]
    Cancelled,
}

impl DekRotationError {
    /// Build a store error from any [`std::fmt::Display`].
    pub fn store<E: std::fmt::Display>(err: E) -> Self {
        Self::Store(err.to_string())
    }

    /// Build a visitor error from any [`std::fmt::Display`].
    pub fn visitor<E: std::fmt::Display>(err: E) -> Self {
        Self::Visitor(err.to_string())
    }

    /// Severity classification used by the audit emitter.
    #[must_use]
    pub const fn severity(&self) -> DekRotationSeverity {
        match self {
            Self::Kms(_) | Self::Store(_) | Self::Visitor(_) | Self::IllegalTransition { .. } => {
                DekRotationSeverity::Error
            }
            Self::VerificationMismatch { .. } => DekRotationSeverity::Critical,
            Self::Cancelled => DekRotationSeverity::Info,
        }
    }
}

// =============================================================================
// Orchestrator
// =============================================================================

/// DEK rotation orchestrator.
///
/// Bound to a [`DekManager`] (for old/new DEK unwrap) plus a set of
/// [`ReencryptionVisitor`]s registered ahead of time. `run_for_tenant`
/// drives a single rotation; `cancel_for_tenant` transitions an
/// in-flight row to `cancelled`.
pub struct DekRotationJob<K, S> {
    manager: Arc<DekManager<K, S>>,
    progress: Arc<dyn RotationProgressStore>,
    policy: Arc<dyn RotationPolicyStore>,
    audit: Arc<dyn DekRotationAuditSink>,
    visitors: Vec<Arc<dyn ReencryptionVisitor>>,
    config: RotationConfig,
}

impl<K, S> std::fmt::Debug for DekRotationJob<K, S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DekRotationJob")
            .field("visitors", &self.visitors.len())
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl<K, S> DekRotationJob<K, S>
where
    K: KmsKeyProvider + 'static,
    S: DekStore + 'static,
{
    /// Construct a new orchestrator.
    pub fn new(
        manager: Arc<DekManager<K, S>>,
        progress: Arc<dyn RotationProgressStore>,
        policy: Arc<dyn RotationPolicyStore>,
        audit: Arc<dyn DekRotationAuditSink>,
        visitors: Vec<Arc<dyn ReencryptionVisitor>>,
        config: RotationConfig,
    ) -> Self {
        Self {
            manager,
            progress,
            policy,
            audit,
            visitors,
            config,
        }
    }

    /// The active configuration. Exposed for tests + admin endpoints.
    #[must_use]
    pub const fn config(&self) -> &RotationConfig {
        &self.config
    }

    /// Borrow the inner [`DekManager`] handle.
    ///
    /// Exposed so the [`crate::envelope::EnvelopeKeyManager`] facade can
    /// dispatch lower-level DEK operations (mint, KMS round-trips) on
    /// the same manager the orchestrator uses, without a second `Arc`
    /// being threaded through the composition root.
    #[must_use]
    pub const fn manager_handle(&self) -> &Arc<DekManager<K, S>> {
        &self.manager
    }

    /// Borrow the policy store. Exposed for the same reason as
    /// [`Self::manager_handle`].
    #[must_use]
    pub fn policy_handle(&self) -> &Arc<dyn RotationPolicyStore> {
        &self.policy
    }

    /// Borrow the progress store.
    #[must_use]
    pub fn progress_handle(&self) -> &Arc<dyn RotationProgressStore> {
        &self.progress
    }

    /// Register an additional visitor. The orchestrator drives visitors
    /// in registration order.
    pub fn register_visitor(&mut self, v: Arc<dyn ReencryptionVisitor>) {
        self.visitors.push(v);
    }

    /// Run a rotation for `tenant_id` to `target_version`.
    ///
    /// Behaviour matrix:
    ///
    /// | Existing checkpoint state | Behaviour                                   |
    /// |---------------------------|---------------------------------------------|
    /// | None                      | Insert `Pending`, transition to `InProgress`|
    /// | `Pending`                 | Transition to `InProgress`, start fresh.    |
    /// | `InProgress`              | Resume from `last_processed_row_id`.        |
    /// | `Completed`               | No-op, return existing checkpoint.          |
    /// | `Failed`                  | Operator must intervene; return error.      |
    /// | `Cancelled`               | Refuse; operator must enqueue a new target. |
    ///
    /// # Errors
    ///
    /// Returns [`DekRotationError`] on any KMS, store or visitor
    /// failure. The checkpoint row is left at `Failed` so the operator
    /// can triage.
    #[allow(clippy::too_many_lines, clippy::cognitive_complexity)] // orchestration: visitor loop + checkpointing + audit emit
    pub async fn run_for_tenant(
        &self,
        tenant_id: TenantId,
        target_version: u32,
    ) -> Result<RotationCheckpoint, DekRotationError> {
        let mut cp = self
            .load_or_init_checkpoint(tenant_id, target_version)
            .await?;

        match cp.status {
            RotationJobStatus::Completed => {
                debug!(
                    target: "sx_secrets::dek_rotation",
                    tenant_id = %tenant_id,
                    target_version,
                    "rotation already completed; noop"
                );
                return Ok(cp);
            }
            RotationJobStatus::Failed => {
                return Err(DekRotationError::Visitor(format!(
                    "rotation in failed state for tenant {tenant_id} — operator intervention required"
                )));
            }
            RotationJobStatus::Cancelled => {
                return Err(DekRotationError::Cancelled);
            }
            RotationJobStatus::Pending | RotationJobStatus::InProgress => {}
        }

        // Transition to InProgress (idempotent: from Pending or already
        // InProgress on resume).
        if cp.status == RotationJobStatus::Pending {
            cp.status = RotationJobStatus::InProgress;
            cp.started_at = Utc::now();
            cp.last_checkpoint_at = Utc::now();
            self.progress.upsert(&cp).await?;
            self.emit(
                audit_event_types::STARTED,
                &cp,
                0,
                DekRotationSeverity::Info,
                None,
            )
            .await;
        }

        // Snapshot total rows across every visitor.
        let mut total_rows: u64 = 0;
        for v in &self.visitors {
            total_rows =
                total_rows.saturating_add(v.count_remaining(tenant_id, target_version).await?);
        }
        if cp.total_rows == 0 {
            cp.total_rows = total_rows;
            cp.last_checkpoint_at = Utc::now();
            self.progress.upsert(&cp).await?;
        }

        // Resolve old/new DEK plaintexts once per job (the orchestrator
        // unwraps both at start; visitors receive the SecretString).
        // CRITICAL: capture the *old* DEK plaintext **before** the
        // rotation overwrites the stored slot. The "new" call below
        // mutates the manager's store; if we resolved old after new
        // we would be reading the new wrapped form and the unwrap of
        // every row would silently succeed against the wrong key.
        let old_dek_plaintext = self.resolve_old_dek_plaintext(tenant_id).await?;
        let new_dek_plaintext = self
            .resolve_new_dek_plaintext(tenant_id, target_version)
            .await?;

        // Drive visitors in registration order. Cursor is per-visitor:
        // the stored cursor encodes `visitor_id::row_id`.
        for visitor in &self.visitors {
            if let Err(err) = self
                .run_visitor(
                    Arc::clone(visitor),
                    &mut cp,
                    target_version,
                    &old_dek_plaintext,
                    &new_dek_plaintext,
                )
                .await
            {
                // Hard fail: stamp Failed + emit Error audit + propagate.
                cp.status = RotationJobStatus::Failed;
                cp.last_error = Some(format!("{err}"));
                cp.last_checkpoint_at = Utc::now();
                let _ = self.progress.upsert(&cp).await;
                self.emit(
                    audit_event_types::FAILED,
                    &cp,
                    0,
                    err.severity(),
                    Some(format!("{err}")),
                )
                .await;
                error!(
                    target: "sx_secrets::dek_rotation",
                    tenant_id = %tenant_id,
                    target_version,
                    %err,
                    "DEK rotation failed"
                );
                return Err(err);
            }
        }

        // Completion: stamp checkpoint + policy.
        cp.status = RotationJobStatus::Completed;
        cp.last_checkpoint_at = Utc::now();
        self.progress.upsert(&cp).await?;
        self.stamp_policy_last_rotated(tenant_id, cp.last_checkpoint_at)
            .await?;
        self.emit(
            audit_event_types::COMPLETED,
            &cp,
            0,
            DekRotationSeverity::Info,
            None,
        )
        .await;
        info!(
            target: "sx_secrets::dek_rotation",
            tenant_id = %tenant_id,
            target_version,
            processed = cp.processed_rows,
            total = cp.total_rows,
            "DEK rotation completed"
        );
        Ok(cp)
    }

    /// Mark the active rotation for `tenant_id` as cancelled.
    ///
    /// The orchestrator examines the cancellation flag between batches,
    /// so the in-flight batch finishes before exit. Cancelling an
    /// already-terminal row is a no-op.
    ///
    /// # Errors
    ///
    /// Returns [`DekRotationError::Store`] if the progress store
    /// rejects the upsert.
    pub async fn cancel_for_tenant(
        &self,
        tenant_id: TenantId,
    ) -> Result<Option<RotationCheckpoint>, DekRotationError> {
        let Some(mut cp) = self.progress.latest_for_tenant(tenant_id).await? else {
            return Ok(None);
        };
        if cp.status.is_terminal() {
            return Ok(Some(cp));
        }
        cp.status = RotationJobStatus::Cancelled;
        cp.last_checkpoint_at = Utc::now();
        self.progress.upsert(&cp).await?;
        self.emit(
            audit_event_types::CANCELLED,
            &cp,
            0,
            DekRotationSeverity::Info,
            None,
        )
        .await;
        Ok(Some(cp))
    }

    /// Return the latest checkpoint for `tenant_id`.
    ///
    /// # Errors
    ///
    /// Returns [`DekRotationError::Store`] on a progress-store failure.
    pub async fn status_for_tenant(
        &self,
        tenant_id: TenantId,
    ) -> Result<Option<RotationCheckpoint>, DekRotationError> {
        self.progress.latest_for_tenant(tenant_id).await
    }

    async fn load_or_init_checkpoint(
        &self,
        tenant_id: TenantId,
        target_version: u32,
    ) -> Result<RotationCheckpoint, DekRotationError> {
        if let Some(existing) = self.progress.get(tenant_id, target_version).await? {
            return Ok(existing);
        }
        let cp = RotationCheckpoint::new(tenant_id, target_version);
        self.progress.upsert(&cp).await?;
        Ok(cp)
    }

    /// Re-encrypt every row the visitor owns, advancing the checkpoint
    /// after each batch.
    async fn run_visitor(
        &self,
        visitor: Arc<dyn ReencryptionVisitor>,
        cp: &mut RotationCheckpoint,
        target_version: u32,
        old_dek_plaintext: &SecretString,
        new_dek_plaintext: &SecretString,
    ) -> Result<(), DekRotationError> {
        let visitor_id = visitor.visitor_id();
        let mut cursor: Option<String> =
            cursor_for(cp.last_processed_row_id.as_deref(), visitor_id);

        loop {
            // Cancellation check between batches — re-load the row.
            if let Some(fresh) = self
                .progress
                .get(cp.tenant_id, cp.target_dek_version)
                .await?
            {
                if fresh.status == RotationJobStatus::Cancelled {
                    return Err(DekRotationError::Cancelled);
                }
            }

            let outcome = visitor
                .reencrypt_batch(
                    cp.tenant_id,
                    cursor.as_deref(),
                    self.config.batch_size,
                    target_version,
                    old_dek_plaintext,
                    new_dek_plaintext,
                )
                .await?;

            // Account for the batch FIRST so the last (possibly
            // partial + exhausted) batch is counted before we exit.
            if outcome.rows_reencrypted > 0 {
                cursor.clone_from(&outcome.next_cursor);
                cp.last_processed_row_id = cursor.as_deref().map(|c| encode_cursor(visitor_id, c));
                cp.processed_rows = cp.processed_rows.saturating_add(outcome.rows_reencrypted);
                cp.last_checkpoint_at = Utc::now();
                self.progress.upsert(cp).await?;

                let remaining = cp.total_rows.saturating_sub(cp.processed_rows);
                self.emit_batch(cp, outcome.rows_reencrypted, remaining)
                    .await;
            }

            if outcome.rows_reencrypted == 0 || outcome.exhausted {
                break;
            }
        }
        Ok(())
    }

    async fn emit_batch(&self, cp: &RotationCheckpoint, batch_rows: u64, remaining: u64) {
        let evt = DekRotationAuditEvent {
            event_type: audit_event_types::BATCH_COMPLETED,
            tenant_id: cp.tenant_id,
            dek_version_old: cp.target_dek_version.saturating_sub(1),
            dek_version_new: cp.target_dek_version,
            batch_rows,
            total_processed: cp.processed_rows,
            total_remaining: remaining,
            severity: DekRotationSeverity::Info,
            error_redacted: None,
            at: Utc::now(),
        };
        self.audit.record(evt).await;
    }

    async fn emit(
        &self,
        event_type: &'static str,
        cp: &RotationCheckpoint,
        batch_rows: u64,
        severity: DekRotationSeverity,
        error: Option<String>,
    ) {
        let evt = DekRotationAuditEvent {
            event_type,
            tenant_id: cp.tenant_id,
            dek_version_old: cp.target_dek_version.saturating_sub(1),
            dek_version_new: cp.target_dek_version,
            batch_rows,
            total_processed: cp.processed_rows,
            total_remaining: cp.total_rows.saturating_sub(cp.processed_rows),
            severity,
            error_redacted: error,
            at: Utc::now(),
        };
        self.audit.record(evt).await;
    }

    async fn resolve_new_dek_plaintext(
        &self,
        tenant_id: TenantId,
        target_version: u32,
    ) -> Result<SecretString, DekRotationError> {
        // Ensure the store reflects the target version. If the current
        // stored DEK is older we rotate the manager to mint a fresh one
        // — the manager unconditionally bumps the KMS key version, so
        // the new DEK will be wrapped under at least `target_version`.
        let existing = self.manager.store().get(tenant_id).await?;
        let stored = match existing {
            Some(d) if d.version >= target_version => d,
            _ => self.manager.rotate_tenant(tenant_id).await?,
        };
        if stored.version < target_version {
            return Err(DekRotationError::Visitor(format!(
                "rotated DEK version {} below target {}",
                stored.version, target_version
            )));
        }
        let pt = self
            .manager
            .kms()
            .decrypt(&stored.key_id, &stored.wrapped)
            .await?;
        Ok(pt)
    }

    async fn resolve_old_dek_plaintext(
        &self,
        tenant_id: TenantId,
    ) -> Result<SecretString, DekRotationError> {
        // The "old" DEK is whatever the store had at the moment the job
        // started. Real deployments hold both versions inside the KMS;
        // we ask the KMS to decrypt the old wrapped form held by the
        // manager before rotation overwrote the slot. This is a
        // simplification — production wiring layers a `dek_history`
        // table to look up arbitrary historical versions; for the
        // single-step `N → N+1` flow the existing wrapped DEK is
        // sufficient.
        let stored = self.manager.store().get(tenant_id).await?.ok_or_else(|| {
            DekRotationError::Visitor(format!("no DEK stored for tenant {tenant_id}"))
        })?;
        let pt = self
            .manager
            .kms()
            .decrypt(&stored.key_id, &stored.wrapped)
            .await?;
        Ok(pt)
    }

    async fn stamp_policy_last_rotated(
        &self,
        tenant_id: TenantId,
        at: DateTime<Utc>,
    ) -> Result<(), DekRotationError> {
        let mut row = self
            .policy
            .get(tenant_id)
            .await?
            .unwrap_or_else(|| RotationPolicyRow::default_for(tenant_id));
        row.last_rotated_at = Some(at);
        row.updated_at = at;
        self.policy.upsert(&row).await
    }
}

/// Encode a per-visitor cursor as `<visitor_id>:<row_id>`. The DB stores
/// the encoded form so a multi-visitor rotation can record a single
/// `last_processed_row_id` value yet still resume each visitor at the
/// correct cursor on restart.
fn encode_cursor(visitor_id: &str, row_id: &str) -> String {
    format!("{visitor_id}:{row_id}")
}

/// Decode a per-visitor cursor. Returns the raw `row_id` if and only
/// if `encoded` was produced for the same `visitor_id`; otherwise
/// returns `None` (the visitor has not started yet).
fn cursor_for(encoded: Option<&str>, visitor_id: &str) -> Option<String> {
    let raw = encoded?;
    let (prefix, rest) = raw.split_once(':')?;
    if prefix == visitor_id {
        Some(rest.to_owned())
    } else {
        None
    }
}

// =============================================================================
// Scheduler
// =============================================================================

/// Periodic scheduler running on top of [`DekRotationJob`].
///
/// Every [`RotationConfig::sweep_interval`] the scheduler reads every
/// row from [`RotationPolicyStore::list_all`], checks each tenant for
/// `is_due`, and dispatches `run_for_tenant` under the backpressure
/// constraints (max 1 per tenant; max [`RotationConfig::max_concurrent`]
/// cluster-wide).
pub struct DekRotationScheduler<K, S> {
    job: Arc<DekRotationJob<K, S>>,
    cluster_permits: Arc<Semaphore>,
    per_tenant: Arc<Mutex<HashMap<TenantId, Arc<Semaphore>>>>,
}

impl<K, S> std::fmt::Debug for DekRotationScheduler<K, S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DekRotationScheduler")
            .finish_non_exhaustive()
    }
}

impl<K, S> DekRotationScheduler<K, S>
where
    K: KmsKeyProvider + 'static,
    S: DekStore + 'static,
{
    /// Construct from an existing job. The cluster-wide permits are
    /// sized from `job.config().max_concurrent`.
    #[must_use]
    pub fn new(job: Arc<DekRotationJob<K, S>>) -> Self {
        let cluster_permits = Arc::new(Semaphore::new(job.config().max_concurrent));
        Self {
            job,
            cluster_permits,
            per_tenant: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Run one sweep — scan policies, enqueue due tenants, return the
    /// number of rotations *enqueued* (not necessarily completed).
    ///
    /// Suitable for tests; production wires `run_loop`.
    ///
    /// # Errors
    ///
    /// Returns [`DekRotationError::Store`] on a policy-store failure.
    pub async fn run_once(&self) -> Result<u64, DekRotationError> {
        let now = Utc::now();
        let rows = self.job.policy.list_all().await?;
        let mut enqueued: u64 = 0;
        for row in rows {
            if !row.is_due(now) {
                continue;
            }
            // Skip tenants that already have an in-flight rotation.
            let in_flight = self.job.progress.latest_for_tenant(row.tenant_id).await?;
            if let Some(cp) = in_flight {
                if !cp.status.is_terminal() {
                    continue;
                }
            }
            if self.try_dispatch(row.tenant_id).await {
                enqueued = enqueued.saturating_add(1);
            }
        }
        Ok(enqueued)
    }

    /// Run the sweep loop forever, sleeping `sweep_interval` between
    /// passes.
    pub async fn run_loop(&self) {
        let interval = self.job.config().sweep_interval;
        loop {
            if let Err(err) = self.run_once().await {
                warn!(
                    target: "sx_secrets::dek_rotation",
                    %err,
                    "scheduler sweep failed"
                );
            }
            tokio::time::sleep(interval).await;
        }
    }

    /// Attempt to dispatch a rotation, returning `true` when the
    /// in-process backpressure budget admitted the job.
    async fn try_dispatch(&self, tenant_id: TenantId) -> bool {
        let per_tenant = self.per_tenant_semaphore(tenant_id).await;
        // Per-tenant must be non-blocking: contention means another
        // worker is already rotating this tenant.
        let Ok(permit_tenant) = Arc::clone(&per_tenant).try_acquire_owned() else {
            debug!(
                target: "sx_secrets::dek_rotation",
                tenant_id = %tenant_id,
                "skipped: per-tenant rotation already in flight"
            );
            return false;
        };

        let cluster = Arc::clone(&self.cluster_permits);
        let job = Arc::clone(&self.job);
        tokio::spawn(async move {
            let _permit_cluster = match cluster.acquire_owned().await {
                Ok(p) => p,
                Err(err) => {
                    warn!(
                        target: "sx_secrets::dek_rotation",
                        %err,
                        tenant_id = %tenant_id,
                        "cluster semaphore closed; dropping job"
                    );
                    return;
                }
            };
            // Resolve the next target version: bump the latest known
            // checkpoint version (or 1 on first rotation).
            let next_version = match job.progress.latest_for_tenant(tenant_id).await {
                Ok(Some(cp)) => cp.target_dek_version.saturating_add(1),
                Ok(None) => 1,
                Err(err) => {
                    warn!(
                        target: "sx_secrets::dek_rotation",
                        %err,
                        tenant_id = %tenant_id,
                        "could not resolve next version"
                    );
                    drop(permit_tenant);
                    return;
                }
            };
            if let Err(err) = job.run_for_tenant(tenant_id, next_version).await {
                warn!(
                    target: "sx_secrets::dek_rotation",
                    %err,
                    tenant_id = %tenant_id,
                    "scheduled rotation failed"
                );
            }
            drop(permit_tenant);
        });
        true
    }

    async fn per_tenant_semaphore(&self, tenant_id: TenantId) -> Arc<Semaphore> {
        let mut map = self.per_tenant.lock().await;
        Arc::clone(
            map.entry(tenant_id)
                .or_insert_with(|| Arc::new(Semaphore::new(1))),
        )
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;
    use crate::dek::InMemoryDekStore;
    use crate::kms::provider::{Ciphertext, KeyVersion, WrappedDek};
    use async_trait::async_trait;
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    use secrecy::ExposeSecret;
    use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
    use uuid::Uuid;

    // ---------------------------------------------------------------------
    // Mock KMS that envelope-encrypts a payload under the DEK plaintext.
    // We use a deterministic XOR-cipher for the per-row crypto (this is
    // a TEST stub; production callers use AES-GCM via their visitors).
    // ---------------------------------------------------------------------
    #[derive(Debug, Default)]
    struct MockKms {
        version: AtomicU32,
    }
    impl MockKms {
        fn new() -> Self {
            Self {
                version: AtomicU32::new(1),
            }
        }
    }

    #[async_trait]
    impl KmsKeyProvider for MockKms {
        async fn encrypt(
            &self,
            _key_id: &str,
            plaintext: &SecretString,
        ) -> Result<Ciphertext, SecretsError> {
            Ok(Ciphertext::new(format!(
                "mock:v{}:{}",
                self.version.load(Ordering::SeqCst),
                B64.encode(plaintext.expose_secret().as_bytes())
            )))
        }

        async fn decrypt(
            &self,
            _key_id: &str,
            ciphertext: &Ciphertext,
        ) -> Result<SecretString, SecretsError> {
            let parts: Vec<&str> = ciphertext.as_str().splitn(3, ':').collect();
            if parts.len() != 3 {
                return Err(SecretsError::format("bad mock ct"));
            }
            let bytes = B64
                .decode(parts[2])
                .map_err(|e| SecretsError::format(e.to_string()))?;
            let s = String::from_utf8(bytes).map_err(|e| SecretsError::format(e.to_string()))?;
            Ok(SecretString::new(s.into_boxed_str()))
        }

        async fn generate_dek(&self, key_id: &str) -> Result<WrappedDek, SecretsError> {
            let v = self.version.load(Ordering::SeqCst);
            let pt_str = format!("dek-bytes-v{v}");
            // Wrapped form must base64-decode back to the plaintext so
            // `decrypt` round-trips correctly in the orchestrator's
            // resolve-old/new DEK calls.
            let wrapped = Ciphertext::new(format!("mock:v{}:{}", v, B64.encode(pt_str.as_bytes())));
            Ok(WrappedDek::new(
                key_id,
                v,
                SecretString::new(pt_str.into_boxed_str()),
                wrapped,
            ))
        }

        async fn rotate(&self, _key_id: &str) -> Result<KeyVersion, SecretsError> {
            let v = self.version.fetch_add(1, Ordering::SeqCst) + 1;
            Ok(KeyVersion::now(v))
        }
    }

    // ---------------------------------------------------------------------
    // Mock row store: one tenant-scoped table of `(row_id, dek_version,
    // ciphertext)` rows. The visitor below operates on it.
    // ---------------------------------------------------------------------
    #[derive(Debug, Clone)]
    struct EncryptedRow {
        tenant_id: TenantId,
        row_id: u64,
        dek_version: u32,
        ciphertext: Vec<u8>,
        plaintext_hint: String,
    }

    #[derive(Debug, Default)]
    struct MockRowStore {
        rows: tokio::sync::RwLock<Vec<EncryptedRow>>,
        unwrap_failures: AtomicUsize,
        wrap_failures: AtomicUsize,
        // When >0, fail the Nth wrap call with KMS error.
        fail_wrap_after: AtomicUsize,
    }

    impl MockRowStore {
        fn new() -> Self {
            Self::default()
        }

        async fn seed(
            &self,
            tenant_id: TenantId,
            n: u64,
            dek_plaintext: &SecretString,
            initial_version: u32,
        ) {
            let mut rows = self.rows.write().await;
            for i in 0..n {
                let plaintext = format!("payload-{tenant_id}-{i}");
                let ct = xor_encrypt(
                    dek_plaintext.expose_secret().as_bytes(),
                    plaintext.as_bytes(),
                );
                rows.push(EncryptedRow {
                    tenant_id,
                    row_id: i,
                    dek_version: initial_version,
                    ciphertext: ct,
                    plaintext_hint: plaintext,
                });
            }
        }

        async fn rows_for(&self, tenant_id: TenantId) -> Vec<EncryptedRow> {
            self.rows
                .read()
                .await
                .iter()
                .filter(|r| r.tenant_id == tenant_id)
                .cloned()
                .collect()
        }

        async fn rows_below_version(&self, tenant_id: TenantId, target: u32) -> Vec<EncryptedRow> {
            self.rows
                .read()
                .await
                .iter()
                .filter(|r| r.tenant_id == tenant_id && r.dek_version < target)
                .cloned()
                .collect()
        }
    }

    fn xor_encrypt(key: &[u8], plaintext: &[u8]) -> Vec<u8> {
        if key.is_empty() {
            return plaintext.to_vec();
        }
        plaintext
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ key[i % key.len()])
            .collect()
    }

    fn xor_decrypt(key: &[u8], ciphertext: &[u8]) -> Vec<u8> {
        xor_encrypt(key, ciphertext)
    }

    struct MockVisitor {
        id: &'static str,
        store: Arc<MockRowStore>,
    }

    impl MockVisitor {
        fn new(id: &'static str, store: Arc<MockRowStore>) -> Self {
            Self { id, store }
        }
    }

    #[async_trait]
    impl ReencryptionVisitor for MockVisitor {
        fn visitor_id(&self) -> &'static str {
            self.id
        }

        async fn count_remaining(
            &self,
            tenant_id: TenantId,
            target_version: u32,
        ) -> Result<u64, DekRotationError> {
            Ok(self
                .store
                .rows_below_version(tenant_id, target_version)
                .await
                .len() as u64)
        }

        async fn reencrypt_batch(
            &self,
            tenant_id: TenantId,
            cursor: Option<&str>,
            batch_size: u32,
            target_version: u32,
            old_dek_plaintext: &SecretString,
            new_dek_plaintext: &SecretString,
        ) -> Result<VisitorBatchOutcome, DekRotationError> {
            let cursor_val: u64 = cursor.and_then(|c| c.parse::<u64>().ok()).unwrap_or(0);
            let mut rows = self.store.rows.write().await;
            let mut updated: u64 = 0;
            let mut next_cursor: Option<String> = None;

            let mut idx = 0usize;
            while idx < rows.len() && updated < u64::from(batch_size) {
                let take = {
                    let r = &rows[idx];
                    r.tenant_id == tenant_id
                        && r.dek_version < target_version
                        && (cursor.is_none() || r.row_id > cursor_val)
                };
                if !take {
                    idx += 1;
                    continue;
                }
                let r = &rows[idx];
                let row_id_snapshot = r.row_id;
                // Unwrap with old DEK.
                let plaintext_bytes =
                    xor_decrypt(old_dek_plaintext.expose_secret().as_bytes(), &r.ciphertext);
                if plaintext_bytes != r.plaintext_hint.as_bytes() {
                    self.store.unwrap_failures.fetch_add(1, Ordering::SeqCst);
                    return Err(DekRotationError::Visitor(format!(
                        "decrypt mismatch row {row_id_snapshot}"
                    )));
                }
                // Optional fault injection.
                let trigger = self.store.fail_wrap_after.load(Ordering::SeqCst);
                if trigger > 0 && updated >= trigger as u64 {
                    self.store.wrap_failures.fetch_add(1, Ordering::SeqCst);
                    return Err(DekRotationError::Kms(SecretsError::Unauthorized));
                }
                // Wrap with new DEK.
                let new_ct = xor_encrypt(
                    new_dek_plaintext.expose_secret().as_bytes(),
                    &plaintext_bytes,
                );
                // Verify readback before "commit".
                let verify = xor_decrypt(new_dek_plaintext.expose_secret().as_bytes(), &new_ct);
                if verify != plaintext_bytes {
                    return Err(DekRotationError::VerificationMismatch {
                        visitor_id: self.id,
                        row_id: row_id_snapshot.to_string(),
                    });
                }
                // Atomic per-row update.
                rows[idx].ciphertext = new_ct;
                rows[idx].dek_version = target_version;
                next_cursor = Some(row_id_snapshot.to_string());
                updated += 1;
                idx += 1;
            }

            // Check whether more rows remain.
            let exhausted = !rows.iter().any(|r| {
                r.tenant_id == tenant_id
                    && r.dek_version < target_version
                    && next_cursor
                        .as_deref()
                        .and_then(|c| c.parse::<u64>().ok())
                        .is_none_or(|cv| r.row_id > cv)
            });
            drop(rows);

            Ok(VisitorBatchOutcome {
                rows_reencrypted: updated,
                next_cursor,
                exhausted,
            })
        }
    }

    fn dek_pt(version: u32) -> SecretString {
        SecretString::new(format!("dek-bytes-v{version}").into_boxed_str())
    }

    async fn setup(
        n_rows_a: u64,
        n_rows_b: u64,
    ) -> (
        Arc<DekRotationJob<MockKms, InMemoryDekStore>>,
        Arc<MockRowStore>,
        Arc<InMemoryDekRotationAuditSink>,
        Arc<InMemoryRotationProgressStore>,
        Arc<InMemoryRotationPolicyStore>,
        Arc<MockKms>,
        TenantId,
        TenantId,
    ) {
        let kms = Arc::new(MockKms::new());
        let dek_store = Arc::new(InMemoryDekStore::new());
        let manager = Arc::new(DekManager::new(Arc::clone(&kms), dek_store, "tenant-kek"));
        let tenant_a = TenantId::new(Uuid::now_v7());
        let tenant_b = TenantId::new(Uuid::now_v7());
        let _ = manager.get_or_create(tenant_a).await.unwrap();
        let _ = manager.get_or_create(tenant_b).await.unwrap();

        let row_store = Arc::new(MockRowStore::new());
        row_store.seed(tenant_a, n_rows_a, &dek_pt(1), 1).await;
        row_store.seed(tenant_b, n_rows_b, &dek_pt(1), 1).await;

        let progress = Arc::new(InMemoryRotationProgressStore::new());
        let policy = Arc::new(InMemoryRotationPolicyStore::new());
        let audit = Arc::new(InMemoryDekRotationAuditSink::new());
        let visitor: Arc<dyn ReencryptionVisitor> =
            Arc::new(MockVisitor::new("mock_rows", Arc::clone(&row_store)));

        let job = Arc::new(DekRotationJob::new(
            manager,
            Arc::clone(&progress) as Arc<dyn RotationProgressStore>,
            Arc::clone(&policy) as Arc<dyn RotationPolicyStore>,
            Arc::clone(&audit) as Arc<dyn DekRotationAuditSink>,
            vec![visitor],
            RotationConfig::defaults().with_batch_size(128),
        ));
        (
            job, row_store, audit, progress, policy, kms, tenant_a, tenant_b,
        )
    }

    #[test]
    fn state_machine_transitions_allowed_and_denied() {
        use RotationJobStatus::*;
        assert!(Pending.can_transition_to(InProgress));
        assert!(Pending.can_transition_to(Cancelled));
        assert!(InProgress.can_transition_to(Completed));
        assert!(InProgress.can_transition_to(Failed));
        assert!(InProgress.can_transition_to(Cancelled));
        // Denied.
        assert!(!Pending.can_transition_to(Completed));
        assert!(!Pending.can_transition_to(Failed));
        assert!(!Completed.can_transition_to(InProgress));
        assert!(!Failed.can_transition_to(InProgress));
        assert!(!Cancelled.can_transition_to(InProgress));
        // Terminal classification.
        assert!(Completed.is_terminal());
        assert!(Failed.is_terminal());
        assert!(Cancelled.is_terminal());
        assert!(!Pending.is_terminal());
        assert!(!InProgress.is_terminal());
    }

    #[test]
    fn parse_round_trips_status_strings() {
        for s in [
            RotationJobStatus::Pending,
            RotationJobStatus::InProgress,
            RotationJobStatus::Completed,
            RotationJobStatus::Failed,
            RotationJobStatus::Cancelled,
        ] {
            assert_eq!(RotationJobStatus::parse(s.as_str()), Some(s));
        }
        assert!(RotationJobStatus::parse("bogus").is_none());
    }

    #[test]
    fn policy_is_due_first_time_and_after_cadence() {
        let t = TenantId::random();
        let mut row = RotationPolicyRow::default_for(t);
        assert!(row.is_due(Utc::now()));
        row.last_rotated_at = Some(Utc::now());
        assert!(!row.is_due(Utc::now()));
        row.last_rotated_at = Some(Utc::now() - chrono::Duration::days(400));
        assert!(row.is_due(Utc::now()));
        let pci = RotationPolicyRow::pci_for(t);
        assert_eq!(pci.cadence_days, PCI_CADENCE_DAYS);
    }

    #[test]
    fn progress_store_rejects_illegal_transition() {
        let store = InMemoryRotationProgressStore::new();
        let tenant = TenantId::random();
        let mut cp = RotationCheckpoint::new(tenant, 2);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            store.upsert(&cp).await.unwrap();
            cp.status = RotationJobStatus::Completed; // pending → completed not allowed
            let err = store.upsert(&cp).await.unwrap_err();
            assert!(matches!(err, DekRotationError::IllegalTransition { .. }));
        });
    }

    #[test]
    fn cursor_encoding_round_trips_per_visitor() {
        let enc = encode_cursor("visitor_a", "42");
        assert_eq!(cursor_for(Some(&enc), "visitor_a").as_deref(), Some("42"));
        // Other visitors do not see the cursor.
        assert_eq!(cursor_for(Some(&enc), "visitor_b"), None);
        assert_eq!(cursor_for(None, "visitor_a"), None);
    }

    #[tokio::test]
    async fn rotation_re_encrypts_every_row_for_tenant() {
        let (job, store, audit, progress, policy, _kms, tenant_a, tenant_b) = setup(300, 50).await;
        let cp = job.run_for_tenant(tenant_a, 2).await.unwrap();
        assert_eq!(cp.status, RotationJobStatus::Completed);
        // Every row for tenant_a is now at version 2.
        let rows = store.rows_for(tenant_a).await;
        assert_eq!(rows.len(), 300);
        assert!(rows.iter().all(|r| r.dek_version == 2));
        // Tenant B is untouched.
        let rows_b = store.rows_for(tenant_b).await;
        assert!(rows_b.iter().all(|r| r.dek_version == 1));
        // Policy is stamped.
        let p = policy.get(tenant_a).await.unwrap().unwrap();
        assert!(p.last_rotated_at.is_some());
        // Audit events shape.
        let events = audit.snapshot().await;
        assert!(events
            .iter()
            .any(|e| e.event_type == audit_event_types::STARTED));
        assert!(events
            .iter()
            .any(|e| e.event_type == audit_event_types::BATCH_COMPLETED));
        assert!(events
            .iter()
            .any(|e| e.event_type == audit_event_types::COMPLETED));
        // Final checkpoint reflects progress.
        let final_cp = progress.get(tenant_a, 2).await.unwrap().unwrap();
        assert_eq!(final_cp.processed_rows, 300);
    }

    #[tokio::test]
    async fn rotation_resumes_from_checkpoint_after_simulated_crash() {
        // Drive a partial rotation by registering only the first visitor
        // and stopping mid-way: we approximate the crash by manually
        // editing the in-memory checkpoint after a single batch.
        let (job, store, _audit, progress, _policy, _kms, tenant_a, _tenant_b) =
            setup(500, 0).await;
        // Force batch size to 50 so we get 10 batches.
        let job = Arc::new(DekRotationJob::new(
            Arc::clone(&job.manager),
            Arc::clone(&job.progress),
            Arc::clone(&job.policy),
            Arc::clone(&job.audit),
            job.visitors.clone(),
            RotationConfig::defaults().with_batch_size(50),
        ));

        // Pretend the process crashed after batch 3 (row_id = 149).
        let cp = RotationCheckpoint {
            tenant_id: tenant_a,
            target_dek_version: 2,
            last_processed_row_id: Some(encode_cursor("mock_rows", "149")),
            total_rows: 500,
            processed_rows: 150,
            started_at: Utc::now(),
            last_checkpoint_at: Utc::now(),
            status: RotationJobStatus::InProgress,
            last_error: None,
        };
        progress.upsert(&cp).await.unwrap();

        // Manually pre-rotate rows 0..150 so the world matches the
        // checkpoint state.
        let new_pt = dek_pt(2);
        for i in 0..150u64 {
            let mut rows = store.rows.write().await;
            if let Some(r) = rows
                .iter_mut()
                .find(|r| r.tenant_id == tenant_a && r.row_id == i)
            {
                let pt = r.plaintext_hint.clone();
                r.ciphertext = xor_encrypt(new_pt.expose_secret().as_bytes(), pt.as_bytes());
                r.dek_version = 2;
            }
        }

        // Resume.
        let final_cp = job.run_for_tenant(tenant_a, 2).await.unwrap();
        assert_eq!(final_cp.status, RotationJobStatus::Completed);
        // Every row is now at version 2 — no double-encryption.
        let rows = store.rows_for(tenant_a).await;
        assert_eq!(rows.len(), 500);
        assert!(rows.iter().all(|r| r.dek_version == 2));
        // Plaintexts decrypt cleanly under the new DEK.
        for r in rows {
            let pt = xor_decrypt(dek_pt(2).expose_secret().as_bytes(), &r.ciphertext);
            assert_eq!(pt, r.plaintext_hint.as_bytes());
        }
    }

    #[tokio::test]
    async fn rotation_failure_stamps_failed_status_and_audit() {
        let (job, store, audit, progress, _policy, _kms, tenant_a, _tenant_b) = setup(40, 0).await;
        // Cause the visitor to fail after 20 wraps.
        store.fail_wrap_after.store(20, Ordering::SeqCst);
        let err = job.run_for_tenant(tenant_a, 2).await.unwrap_err();
        assert!(matches!(err, DekRotationError::Kms(_)));
        let cp = progress.get(tenant_a, 2).await.unwrap().unwrap();
        assert_eq!(cp.status, RotationJobStatus::Failed);
        let events = audit.snapshot().await;
        assert!(events
            .iter()
            .any(|e| e.event_type == audit_event_types::FAILED
                && e.severity == DekRotationSeverity::Error));
    }

    #[tokio::test]
    async fn cancellation_halts_rotation_gracefully() {
        let (job, store, audit, progress, _policy, _kms, tenant_a, _tenant_b) = setup(200, 0).await;
        // Pre-cancel: insert a Cancelled checkpoint.
        let mut cp = RotationCheckpoint::new(tenant_a, 2);
        progress.upsert(&cp).await.unwrap();
        cp.status = RotationJobStatus::Cancelled;
        progress.upsert(&cp).await.unwrap();

        let result = job.run_for_tenant(tenant_a, 2).await;
        assert!(matches!(result, Err(DekRotationError::Cancelled)));
        // Rows untouched.
        let rows = store.rows_for(tenant_a).await;
        assert!(rows.iter().all(|r| r.dek_version == 1));
        // No completion audit.
        let events = audit.snapshot().await;
        assert!(events
            .iter()
            .all(|e| e.event_type != audit_event_types::COMPLETED));
    }

    #[tokio::test]
    async fn idempotent_completed_run_is_noop() {
        let (job, _store, _audit, _progress, _policy, _kms, tenant_a, _tenant_b) =
            setup(10, 0).await;
        let first = job.run_for_tenant(tenant_a, 2).await.unwrap();
        let second = job.run_for_tenant(tenant_a, 2).await.unwrap();
        assert_eq!(first.status, RotationJobStatus::Completed);
        assert_eq!(second.status, RotationJobStatus::Completed);
        assert_eq!(first.processed_rows, second.processed_rows);
    }

    #[tokio::test]
    async fn status_for_tenant_reflects_latest_checkpoint() {
        let (job, _store, _audit, _progress, _policy, _kms, tenant_a, _tenant_b) =
            setup(5, 0).await;
        assert!(job.status_for_tenant(tenant_a).await.unwrap().is_none());
        let _ = job.run_for_tenant(tenant_a, 2).await.unwrap();
        let cp = job.status_for_tenant(tenant_a).await.unwrap().unwrap();
        assert_eq!(cp.target_dek_version, 2);
        assert_eq!(cp.status, RotationJobStatus::Completed);
    }

    #[tokio::test]
    async fn cancel_for_tenant_transitions_in_progress_to_cancelled() {
        let (job, _store, audit, progress, _policy, _kms, tenant_a, _tenant_b) = setup(5, 0).await;
        // Seed an InProgress checkpoint.
        let mut cp = RotationCheckpoint::new(tenant_a, 2);
        progress.upsert(&cp).await.unwrap();
        cp.status = RotationJobStatus::InProgress;
        progress.upsert(&cp).await.unwrap();
        let result = job.cancel_for_tenant(tenant_a).await.unwrap().unwrap();
        assert_eq!(result.status, RotationJobStatus::Cancelled);
        let events = audit.snapshot().await;
        assert!(events
            .iter()
            .any(|e| e.event_type == audit_event_types::CANCELLED));
    }

    #[tokio::test]
    async fn cancel_for_tenant_is_noop_on_terminal_row() {
        let (job, _store, _audit, progress, _policy, _kms, tenant_a, _tenant_b) = setup(5, 0).await;
        let mut cp = RotationCheckpoint::new(tenant_a, 2);
        progress.upsert(&cp).await.unwrap();
        cp.status = RotationJobStatus::InProgress;
        progress.upsert(&cp).await.unwrap();
        cp.status = RotationJobStatus::Completed;
        progress.upsert(&cp).await.unwrap();
        // Cancelling a Completed row is a no-op (returns existing).
        let result = job.cancel_for_tenant(tenant_a).await.unwrap().unwrap();
        assert_eq!(result.status, RotationJobStatus::Completed);
    }

    #[tokio::test]
    async fn cross_tenant_rotation_does_not_touch_other_tenant_rows() {
        // 10k synthetic rows for tenant A, 10k for tenant B.
        let (job, store, _audit, _progress, _policy, _kms, tenant_a, tenant_b) =
            setup(10_000, 10_000).await;
        let cp = job.run_for_tenant(tenant_a, 2).await.unwrap();
        assert_eq!(cp.status, RotationJobStatus::Completed);
        let rows_a = store.rows_for(tenant_a).await;
        let rows_b = store.rows_for(tenant_b).await;
        assert!(rows_a.iter().all(|r| r.dek_version == 2));
        assert!(rows_b.iter().all(|r| r.dek_version == 1));
        // Every row in tenant B still decrypts under the original DEK.
        for r in rows_b {
            let pt = xor_decrypt(dek_pt(1).expose_secret().as_bytes(), &r.ciphertext);
            assert_eq!(pt, r.plaintext_hint.as_bytes());
        }
    }

    #[tokio::test]
    async fn config_with_batch_size_clamps_to_range() {
        let c = RotationConfig::defaults().with_batch_size(0);
        assert_eq!(c.batch_size, 1);
        let c = RotationConfig::defaults().with_batch_size(10_000_000);
        assert_eq!(c.batch_size, 100_000);
        let c = RotationConfig::defaults().with_batch_size(500);
        assert_eq!(c.batch_size, 500);
    }

    #[tokio::test]
    async fn scheduler_dispatches_due_tenants_only() {
        let (job, _store, _audit, _progress, policy, _kms, tenant_a, tenant_b) = setup(5, 5).await;
        // tenant_a due (never rotated), tenant_b not due (just rotated).
        let mut row_b = RotationPolicyRow::default_for(tenant_b);
        row_b.last_rotated_at = Some(Utc::now());
        policy.upsert(&row_b).await.unwrap();
        let row_a = RotationPolicyRow::default_for(tenant_a);
        policy.upsert(&row_a).await.unwrap();
        let scheduler = DekRotationScheduler::new(Arc::clone(&job));
        let enqueued = scheduler.run_once().await.unwrap();
        assert_eq!(enqueued, 1);
    }

    #[tokio::test]
    async fn scheduler_respects_cluster_concurrency_cap() {
        // Build a job with max_concurrent = 2 and 6 due tenants. The
        // scheduler must eventually finish every one.
        let kms = Arc::new(MockKms::new());
        let dek_store = Arc::new(InMemoryDekStore::new());
        let manager = Arc::new(DekManager::new(kms, dek_store, "tenant-kek"));
        let row_store = Arc::new(MockRowStore::new());
        let progress = Arc::new(InMemoryRotationProgressStore::new());
        let policy = Arc::new(InMemoryRotationPolicyStore::new());
        let audit = Arc::new(InMemoryDekRotationAuditSink::new());
        let visitor: Arc<dyn ReencryptionVisitor> =
            Arc::new(MockVisitor::new("mock_rows", Arc::clone(&row_store)));
        let job = Arc::new(DekRotationJob::new(
            manager,
            Arc::clone(&progress) as Arc<dyn RotationProgressStore>,
            Arc::clone(&policy) as Arc<dyn RotationPolicyStore>,
            audit,
            vec![visitor],
            RotationConfig::defaults()
                .with_batch_size(16)
                .with_max_concurrent(2),
        ));
        let mut tenants = Vec::new();
        for _ in 0..6 {
            let t = TenantId::random();
            row_store.seed(t, 1, &dek_pt(1), 1).await;
            let _ = job.manager.get_or_create(t).await.unwrap();
            policy
                .upsert(&RotationPolicyRow::default_for(t))
                .await
                .unwrap();
            tenants.push(t);
        }
        let scheduler = DekRotationScheduler::new(Arc::clone(&job));
        let enqueued = scheduler.run_once().await.unwrap();
        assert_eq!(enqueued, 6);
        // Cluster permits cap concurrent work at 2; the scheduler must
        // still eventually finish every tenant.
        for _ in 0..200 {
            tokio::time::sleep(Duration::from_millis(20)).await;
            let mut done = 0;
            for t in &tenants {
                if let Ok(Some(cp)) = progress.latest_for_tenant(*t).await {
                    if cp.status == RotationJobStatus::Completed {
                        done += 1;
                    }
                }
            }
            if done == 6 {
                return;
            }
        }
        panic!("scheduler should have finished all 6 tenants within the timeout");
    }
}
