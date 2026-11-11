//! Persistence port for the HIGH-006 per-tenant Falco overrides table.
//!
//! The trait is intentionally narrow — the `FalcoIngestService` only needs
//! `list_for_tenant` at ingestion time. Admin mutations (`upsert`,
//! `delete`) live behind the same trait so the composition root can wire
//! a single concrete impl (`MemOverrideStore`, or a Postgres impl in a
//! follow-up commit) into both the ingest service and the HTTP admin
//! controller.
//!
//! The default in-process [`MemOverrideStore`] sits behind an `RwLock` so
//! reads at ingest-time do not block writes from the admin path.

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use time::OffsetDateTime;

use crate::error::RuntimeError;
use crate::overrides::{OverrideAction, RuleOverride};

/// Persistence port for [`RuleOverride`] rows.
///
/// Implementations must be Postgres-RLS-scoped — every read filters by
/// `tenant_id` and every write `SET LOCAL app.current_tenant_id` before
/// the SQL.
#[async_trait]
pub trait OverrideStore: Send + Sync + std::fmt::Debug {
    /// Load every override row for `tenant_id`. Order is unspecified;
    /// the evaluator handles wildcard-vs-exact precedence.
    async fn list_for_tenant(&self, tenant_id: &str) -> Result<Vec<RuleOverride>, RuntimeError>;

    /// Upsert a single override row. The `(tenant_id, rule_name,
    /// subkey)` triple is the primary key.
    async fn upsert(
        &self,
        tenant_id: &str,
        rule_name: &str,
        subkey: &str,
        action: OverrideAction,
        reason: &str,
        set_by: &str,
    ) -> Result<RuleOverride, RuntimeError>;

    /// Delete the row identified by `(tenant_id, rule_name, subkey)`.
    /// Idempotent — returns `Ok(false)` if the row was absent.
    async fn delete(
        &self,
        tenant_id: &str,
        rule_name: &str,
        subkey: &str,
    ) -> Result<bool, RuntimeError>;
}

/// Composite primary key `(tenant_id, rule_name, subkey)` used as the
/// in-memory `HashMap` key.
type OverrideKey = (String, String, String);
/// Shared in-memory storage handle for [`MemOverrideStore`].
type OverrideTable = Arc<RwLock<HashMap<OverrideKey, RuleOverride>>>;

/// In-process store backing both tests and the dev-mode composition root.
///
/// The data sits inside an `Arc<RwLock<HashMap<(tenant_id, rule, subkey),
/// row>>>` so every clone is cheap and the ingest path can `list_for_tenant`
/// without contending on the admin path.
#[derive(Debug, Default)]
pub struct MemOverrideStore {
    inner: OverrideTable,
}

impl Clone for MemOverrideStore {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl MemOverrideStore {
    /// Construct an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Bulk-seed the store with `rows`. Existing keys are overwritten —
    /// useful in tests.
    pub fn seed<I: IntoIterator<Item = RuleOverride>>(&self, rows: I) {
        if let Ok(mut g) = self.inner.write() {
            for r in rows {
                g.insert(
                    (r.tenant_id.clone(), r.rule_name.clone(), r.subkey.clone()),
                    r,
                );
            }
        }
    }
}

#[async_trait]
impl OverrideStore for MemOverrideStore {
    async fn list_for_tenant(&self, tenant_id: &str) -> Result<Vec<RuleOverride>, RuntimeError> {
        let g = self
            .inner
            .read()
            .map_err(|_| RuntimeError::Internal("override store mutex poisoned".to_owned()))?;
        Ok(g.values()
            .filter(|r| r.tenant_id == tenant_id)
            .cloned()
            .collect())
    }

    async fn upsert(
        &self,
        tenant_id: &str,
        rule_name: &str,
        subkey: &str,
        action: OverrideAction,
        reason: &str,
        set_by: &str,
    ) -> Result<RuleOverride, RuntimeError> {
        let row = RuleOverride {
            tenant_id: tenant_id.to_owned(),
            rule_name: rule_name.to_owned(),
            subkey: subkey.to_owned(),
            action,
            reason: reason.to_owned(),
            set_by: set_by.to_owned(),
            set_at: OffsetDateTime::now_utc(),
        };
        {
            let mut g = self
                .inner
                .write()
                .map_err(|_| RuntimeError::Internal("override store mutex poisoned".to_owned()))?;
            g.insert(
                (
                    tenant_id.to_owned(),
                    rule_name.to_owned(),
                    subkey.to_owned(),
                ),
                row.clone(),
            );
        }
        Ok(row)
    }

    async fn delete(
        &self,
        tenant_id: &str,
        rule_name: &str,
        subkey: &str,
    ) -> Result<bool, RuntimeError> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| RuntimeError::Internal("override store mutex poisoned".to_owned()))?;
        Ok(g.remove(&(
            tenant_id.to_owned(),
            rule_name.to_owned(),
            subkey.to_owned(),
        ))
        .is_some())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn upsert_then_list_returns_the_row() {
        let s = MemOverrideStore::new();
        let row = s
            .upsert(
                "t1",
                "rule-a",
                "execve",
                OverrideAction::Deny,
                "noisy",
                "u1",
            )
            .await
            .unwrap();
        assert_eq!(row.tenant_id, "t1");
        let list = s.list_for_tenant("t1").await.unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].rule_name, "rule-a");
        assert_eq!(list[0].action, OverrideAction::Deny);
    }

    #[tokio::test]
    async fn upsert_replaces_existing_row() {
        let s = MemOverrideStore::new();
        s.upsert("t1", "rule-a", "execve", OverrideAction::Deny, "v1", "u1")
            .await
            .unwrap();
        s.upsert(
            "t1",
            "rule-a",
            "execve",
            OverrideAction::Escalate,
            "v2",
            "u2",
        )
        .await
        .unwrap();
        let list = s.list_for_tenant("t1").await.unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].action, OverrideAction::Escalate);
        assert_eq!(list[0].reason, "v2");
    }

    #[tokio::test]
    async fn list_is_scoped_to_tenant() {
        let s = MemOverrideStore::new();
        s.upsert("t1", "rule-a", "execve", OverrideAction::Deny, "x", "u")
            .await
            .unwrap();
        s.upsert("t2", "rule-a", "execve", OverrideAction::Deny, "x", "u")
            .await
            .unwrap();
        let l1 = s.list_for_tenant("t1").await.unwrap();
        let l2 = s.list_for_tenant("t2").await.unwrap();
        assert_eq!(l1.len(), 1);
        assert_eq!(l2.len(), 1);
        assert_eq!(l1[0].tenant_id, "t1");
        assert_eq!(l2[0].tenant_id, "t2");
    }

    #[tokio::test]
    async fn delete_is_idempotent() {
        let s = MemOverrideStore::new();
        s.upsert("t1", "rule-a", "execve", OverrideAction::Deny, "x", "u")
            .await
            .unwrap();
        let removed = s.delete("t1", "rule-a", "execve").await.unwrap();
        assert!(removed);
        let removed_again = s.delete("t1", "rule-a", "execve").await.unwrap();
        assert!(!removed_again);
        let list = s.list_for_tenant("t1").await.unwrap();
        assert!(list.is_empty());
    }
}
