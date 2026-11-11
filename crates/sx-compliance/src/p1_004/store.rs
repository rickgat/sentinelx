//! Storage layer for P1-004.
//!
//! Two row shapes, matched 1:1 with the migration
//! (`compliance_evidence_runs`, `compliance_evidence_files`):
//!
//! * `compliance_evidence_runs` — one row per evidence-collection run.
//!   A run is bundle-scoped: it groups every file produced for an
//!   audit period. Status transitions are append-only.
//! * `compliance_evidence_files` — one row per persisted evidence file
//!   produced inside a run.
//!
//! Both tables are tenant-scoped via `tenant_id` and the Postgres-side
//! RLS policy (`app_current_tenant()` GUC, defined in the platform's
//! global RLS migration). At the application layer the
//! [`EvidenceStore`] trait enforces the same constraint defensively —
//! every read takes a `tenant_id` argument and the implementation
//! filters on it.
//!
//! The in-memory implementation lives here and is shared by every
//! unit + integration test in this slice. Production wiring (a
//! sqlx-backed implementation) plugs into the same trait downstream
//! in `sx-storage` once the migration ships.

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::OffsetDateTime;
use uuid::Uuid;

/// Tenant identifier newtype. Wraps a `String` so we can use
/// any opaque tenant id (the platform-wide convention is a UUID,
/// but plumbing through `String` keeps the in-memory tests simple).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TenantId(pub String);

impl TenantId {
    /// Construct from any `Into<String>`.
    #[must_use]
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    /// Borrow the inner string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for TenantId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<&str> for TenantId {
    fn from(s: &str) -> Self {
        Self(s.to_owned())
    }
}

/// Lifecycle status of an [`EvidenceRunRow`].
///
/// Append-only: once a run is `Succeeded` or `Failed`, the row is
/// frozen. A new run is created if the operator wants to re-collect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceRunStatus {
    /// Run is in flight.
    Running,
    /// Run completed successfully (at least one file produced).
    Succeeded,
    /// Run failed before it could produce any file.
    Failed,
}

impl EvidenceRunStatus {
    /// Stable string form for the DB column.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
        }
    }
}

/// `compliance_evidence_runs` row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceRunRow {
    /// Primary key.
    pub id: Uuid,
    /// Owning tenant.
    pub tenant_id: TenantId,
    /// When the run started.
    pub started_at: OffsetDateTime,
    /// When the run finished (terminal states only).
    pub finished_at: Option<OffsetDateTime>,
    /// Current status.
    pub status: EvidenceRunStatus,
    /// Optional bundle key in the WORM store; populated once the
    /// bundle has been exported. We do *not* allow this field to be
    /// rewritten — see [`EvidenceStore::record_bundle_export`].
    pub bundle_key: Option<String>,
    /// HMAC-SHA256 of the bundle bytes, lowercase hex; populated
    /// when [`Self::bundle_key`] is.
    pub bundle_sha256: Option<String>,
}

/// `compliance_evidence_files` row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceFileRow {
    /// Primary key.
    pub id: Uuid,
    /// Owning tenant — kept here as well as on the run for RLS.
    pub tenant_id: TenantId,
    /// FK to [`EvidenceRunRow::id`].
    pub run_id: Uuid,
    /// SentinelX control id this file is evidence for.
    pub control_id: String,
    /// WORM-store key the bytes were written to.
    pub object_key: String,
    /// Lowercase hex SHA-256 of the file bytes.
    pub sha256: String,
    /// Bytes written.
    pub byte_len: u64,
    /// When the file was persisted.
    pub collected_at: OffsetDateTime,
}

/// Store errors.
#[derive(Debug, Error)]
pub enum StoreError {
    /// The requested row does not exist (or is owned by another tenant).
    #[error("not found")]
    NotFound,
    /// Attempt to overwrite an existing immutable field.
    #[error("conflict: {0}")]
    Conflict(String),
    /// Cross-tenant access attempt — explicitly rejected.
    #[error("forbidden: cross-tenant access denied")]
    Forbidden,
    /// Catch-all for transport / sqlx errors at the production edge.
    #[error("backend: {0}")]
    Backend(String),
}

/// Multi-tenant repository for evidence runs + files.
///
/// Every method takes a `tenant_id` and every implementation MUST
/// filter on it. Cross-tenant reads must surface as
/// [`StoreError::Forbidden`] (or [`StoreError::NotFound`] when the
/// row genuinely does not exist for the supplied tenant).
#[async_trait]
pub trait EvidenceStore: Send + Sync + std::fmt::Debug {
    /// Insert a fresh run row in `Running` state. Returns the row.
    async fn create_run(
        &self,
        tenant_id: &TenantId,
        started_at: OffsetDateTime,
    ) -> Result<EvidenceRunRow, StoreError>;

    /// Append a file row to a run.
    async fn append_file(&self, file: EvidenceFileRow) -> Result<(), StoreError>;

    /// Transition a run to a terminal status.
    async fn finish_run(
        &self,
        tenant_id: &TenantId,
        run_id: Uuid,
        status: EvidenceRunStatus,
        finished_at: OffsetDateTime,
    ) -> Result<(), StoreError>;

    /// Attach a bundle key + sha to a run. Must reject overwrite.
    async fn record_bundle_export(
        &self,
        tenant_id: &TenantId,
        run_id: Uuid,
        bundle_key: &str,
        bundle_sha256: &str,
    ) -> Result<(), StoreError>;

    /// List runs that have a bundle exported, newest first.
    async fn list_bundle_runs(
        &self,
        tenant_id: &TenantId,
    ) -> Result<Vec<EvidenceRunRow>, StoreError>;

    /// Load a single run row by id, scoped to the supplied tenant.
    async fn get_run(
        &self,
        tenant_id: &TenantId,
        run_id: Uuid,
    ) -> Result<EvidenceRunRow, StoreError>;

    /// List every file row in a run.
    async fn list_files(
        &self,
        tenant_id: &TenantId,
        run_id: Uuid,
    ) -> Result<Vec<EvidenceFileRow>, StoreError>;
}

/// Process-local reference implementation of [`EvidenceStore`].
///
/// Lock granularity is per-call; the implementation is correct under
/// concurrent test loads but is not optimised for production volume.
#[derive(Debug, Default)]
pub struct InMemoryEvidenceStore {
    runs: Mutex<HashMap<Uuid, EvidenceRunRow>>,
    files: Mutex<Vec<EvidenceFileRow>>,
}

impl InMemoryEvidenceStore {
    /// Construct an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl EvidenceStore for InMemoryEvidenceStore {
    async fn create_run(
        &self,
        tenant_id: &TenantId,
        started_at: OffsetDateTime,
    ) -> Result<EvidenceRunRow, StoreError> {
        let row = EvidenceRunRow {
            id: Uuid::new_v4(),
            tenant_id: tenant_id.clone(),
            started_at,
            finished_at: None,
            status: EvidenceRunStatus::Running,
            bundle_key: None,
            bundle_sha256: None,
        };
        let mut g = self
            .runs
            .lock()
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        g.insert(row.id, row.clone());
        Ok(row)
    }

    async fn append_file(&self, file: EvidenceFileRow) -> Result<(), StoreError> {
        // Cross-check: the run must exist and belong to the same tenant.
        let runs = self
            .runs
            .lock()
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        let Some(run) = runs.get(&file.run_id) else {
            return Err(StoreError::NotFound);
        };
        if run.tenant_id != file.tenant_id {
            return Err(StoreError::Forbidden);
        }
        drop(runs);
        let mut g = self
            .files
            .lock()
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        g.push(file);
        Ok(())
    }

    async fn finish_run(
        &self,
        tenant_id: &TenantId,
        run_id: Uuid,
        status: EvidenceRunStatus,
        finished_at: OffsetDateTime,
    ) -> Result<(), StoreError> {
        let mut g = self
            .runs
            .lock()
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        let Some(row) = g.get_mut(&run_id) else {
            return Err(StoreError::NotFound);
        };
        if row.tenant_id != *tenant_id {
            return Err(StoreError::Forbidden);
        }
        if row.status != EvidenceRunStatus::Running {
            return Err(StoreError::Conflict(format!(
                "run {run_id} already in terminal status {}",
                row.status.code()
            )));
        }
        row.status = status;
        row.finished_at = Some(finished_at);
        Ok(())
    }

    async fn record_bundle_export(
        &self,
        tenant_id: &TenantId,
        run_id: Uuid,
        bundle_key: &str,
        bundle_sha256: &str,
    ) -> Result<(), StoreError> {
        let mut g = self
            .runs
            .lock()
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        let Some(row) = g.get_mut(&run_id) else {
            return Err(StoreError::NotFound);
        };
        if row.tenant_id != *tenant_id {
            return Err(StoreError::Forbidden);
        }
        if row.bundle_key.is_some() {
            return Err(StoreError::Conflict(format!(
                "bundle for run {run_id} already exported"
            )));
        }
        row.bundle_key = Some(bundle_key.to_owned());
        row.bundle_sha256 = Some(bundle_sha256.to_owned());
        Ok(())
    }

    async fn list_bundle_runs(
        &self,
        tenant_id: &TenantId,
    ) -> Result<Vec<EvidenceRunRow>, StoreError> {
        let g = self
            .runs
            .lock()
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        let mut rows: Vec<EvidenceRunRow> = g
            .values()
            .filter(|r| r.tenant_id == *tenant_id && r.bundle_key.is_some())
            .cloned()
            .collect();
        rows.sort_by(|a, b| b.started_at.cmp(&a.started_at));
        Ok(rows)
    }

    async fn get_run(
        &self,
        tenant_id: &TenantId,
        run_id: Uuid,
    ) -> Result<EvidenceRunRow, StoreError> {
        let g = self
            .runs
            .lock()
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        let Some(row) = g.get(&run_id) else {
            return Err(StoreError::NotFound);
        };
        if row.tenant_id != *tenant_id {
            // Stronger signal than NotFound when the row exists but
            // belongs to someone else — required for the
            // tenant-isolation regression test.
            return Err(StoreError::Forbidden);
        }
        Ok(row.clone())
    }

    async fn list_files(
        &self,
        tenant_id: &TenantId,
        run_id: Uuid,
    ) -> Result<Vec<EvidenceFileRow>, StoreError> {
        // First verify the run is visible to this tenant.
        let _ = self.get_run(tenant_id, run_id).await?;
        let g = self
            .files
            .lock()
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        Ok(g.iter()
            .filter(|f| f.run_id == run_id && f.tenant_id == *tenant_id)
            .cloned()
            .collect())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use time::macros::datetime;

    fn now() -> OffsetDateTime {
        datetime!(2026-06-12 00:00:00 UTC)
    }

    #[tokio::test(flavor = "current_thread")]
    async fn create_then_finish_then_export_round_trip() {
        let store = InMemoryEvidenceStore::new();
        let t = TenantId::new("A");
        let run = store.create_run(&t, now()).await.unwrap();
        assert_eq!(run.status, EvidenceRunStatus::Running);
        store
            .finish_run(&t, run.id, EvidenceRunStatus::Succeeded, now())
            .await
            .unwrap();
        store
            .record_bundle_export(&t, run.id, "s3://b/a.zip", "deadbeef")
            .await
            .unwrap();
        let after = store.get_run(&t, run.id).await.unwrap();
        assert_eq!(after.status, EvidenceRunStatus::Succeeded);
        assert_eq!(after.bundle_key.as_deref(), Some("s3://b/a.zip"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn record_bundle_export_is_one_shot() {
        let store = InMemoryEvidenceStore::new();
        let t = TenantId::new("A");
        let run = store.create_run(&t, now()).await.unwrap();
        store
            .record_bundle_export(&t, run.id, "k1", "h1")
            .await
            .unwrap();
        let err = store
            .record_bundle_export(&t, run.id, "k2", "h2")
            .await
            .unwrap_err();
        assert!(matches!(err, StoreError::Conflict(_)));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cross_tenant_get_run_is_forbidden() {
        let store = InMemoryEvidenceStore::new();
        let a = TenantId::new("A");
        let b = TenantId::new("B");
        let run = store.create_run(&a, now()).await.unwrap();
        let err = store.get_run(&b, run.id).await.unwrap_err();
        assert!(matches!(err, StoreError::Forbidden));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cross_tenant_append_file_is_forbidden() {
        let store = InMemoryEvidenceStore::new();
        let a = TenantId::new("A");
        let b = TenantId::new("B");
        let run = store.create_run(&a, now()).await.unwrap();
        let bad = EvidenceFileRow {
            id: Uuid::new_v4(),
            tenant_id: b.clone(),
            run_id: run.id,
            control_id: "X".into(),
            object_key: "k".into(),
            sha256: "0".into(),
            byte_len: 0,
            collected_at: now(),
        };
        let err = store.append_file(bad).await.unwrap_err();
        assert!(matches!(err, StoreError::Forbidden));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn list_bundle_runs_filters_by_tenant() {
        let store = InMemoryEvidenceStore::new();
        let a = TenantId::new("A");
        let b = TenantId::new("B");
        let run_a = store.create_run(&a, now()).await.unwrap();
        let run_b = store.create_run(&b, now()).await.unwrap();
        store
            .record_bundle_export(&a, run_a.id, "ka", "ha")
            .await
            .unwrap();
        store
            .record_bundle_export(&b, run_b.id, "kb", "hb")
            .await
            .unwrap();
        let list_a = store.list_bundle_runs(&a).await.unwrap();
        assert_eq!(list_a.len(), 1);
        assert_eq!(list_a[0].id, run_a.id);
        let list_b = store.list_bundle_runs(&b).await.unwrap();
        assert_eq!(list_b.len(), 1);
        assert_eq!(list_b[0].id, run_b.id);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn finish_run_rejects_double_terminal() {
        let store = InMemoryEvidenceStore::new();
        let t = TenantId::new("A");
        let run = store.create_run(&t, now()).await.unwrap();
        store
            .finish_run(&t, run.id, EvidenceRunStatus::Succeeded, now())
            .await
            .unwrap();
        let err = store
            .finish_run(&t, run.id, EvidenceRunStatus::Failed, now())
            .await
            .unwrap_err();
        assert!(matches!(err, StoreError::Conflict(_)));
    }
}
