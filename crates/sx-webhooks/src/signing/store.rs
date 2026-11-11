//! Persistence port for the per-tenant signing-key history.
//!
//! - [`SigningKeyStore`] — async trait every signer / verifier / rotator
//!   depends on. The Postgres impl lives in `sx-storage`; this crate
//!   ships an [`InMemorySigningKeyStore`] for tests and the
//!   disabled-mode production wiring.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use thiserror::Error;

use super::key::{Kid, SigningKey};

/// Errors surfaced by [`SigningKeyStore`] implementations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum StoreError {
    /// Storage backend returned an error.
    #[error("signing-key store backend error: {0}")]
    Backend(String),
    /// Caller asked for a row that does not exist.
    #[error("signing-key not found")]
    NotFound,
}

impl StoreError {
    /// Build a backend error from any [`std::fmt::Display`].
    pub fn backend<E: std::fmt::Display>(err: E) -> Self {
        Self::Backend(err.to_string())
    }
}

/// Persistence port for the per-tenant signing-key history.
///
/// Implementations MUST be tenant-scoped: every method takes a
/// `tenant_id` argument and the backend (Postgres FORCE-RLS,
/// `DashMap<TenantId, Vec<SigningKey>>`, …) enforces strict isolation.
#[async_trait]
pub trait SigningKeyStore: Send + Sync + std::fmt::Debug {
    /// Persist a freshly minted key. Implementations MUST reject
    /// duplicate `(tenant_id, kid)` inserts.
    async fn insert(&self, key: &SigningKey) -> Result<(), StoreError>;

    /// Mark the row with `(tenant_id, kid)` retired at `retired_at`.
    /// Idempotent: re-stamping the same `retired_at` is a no-op; a
    /// later `retired_at` overrides an earlier one. Implementations
    /// MUST return [`StoreError::NotFound`] when the row does not
    /// exist.
    async fn retire(
        &self,
        tenant_id: &str,
        kid: &Kid,
        retired_at: DateTime<Utc>,
    ) -> Result<(), StoreError>;

    /// Return every key for `tenant_id` that is currently valid at
    /// `now` (i.e. `activated_at <= now AND (retired_at IS NULL OR
    /// retired_at > now)`). Ordered by `activated_at DESC` so the
    /// caller can pick `[0]` as the primary signer.
    async fn active(
        &self,
        tenant_id: &str,
        now: DateTime<Utc>,
    ) -> Result<Vec<SigningKey>, StoreError>;

    /// Return every key for `tenant_id`, regardless of state. Useful
    /// for the rotator's "ages past cadence" scan and for admin
    /// inspection. Ordered by `activated_at ASC`.
    async fn list(&self, tenant_id: &str) -> Result<Vec<SigningKey>, StoreError>;

    /// Return the kid of the latest (highest `activated_at`) key for
    /// `tenant_id`, or `Ok(None)` if the tenant has no keys yet.
    async fn latest_kid(&self, tenant_id: &str) -> Result<Option<Kid>, StoreError> {
        let now = Utc::now();
        let active = self.active(tenant_id, now).await?;
        Ok(active.into_iter().next().map(|k| k.kid))
    }
}

/// In-memory store. Holds the entire per-tenant key history; cheap to
/// clone (shared `Arc<Mutex<...>>` inside).
///
/// Used by tests + as the default until a deployment wires the
/// Postgres-backed store.
#[derive(Debug, Clone, Default)]
pub struct InMemorySigningKeyStore {
    inner: Arc<Mutex<HashMap<String, Vec<SigningKey>>>>,
}

impl InMemorySigningKeyStore {
    /// Construct an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl InMemorySigningKeyStore {
    /// Helper: run `f` against the locked inner map. Restricts the lock
    /// guard's lifetime to the synchronous closure so it never crosses
    /// an `.await` and the `Send` future stays clean.
    fn with_lock<R>(
        &self,
        f: impl FnOnce(&mut HashMap<String, Vec<SigningKey>>) -> Result<R, StoreError>,
    ) -> Result<R, StoreError> {
        let mut g = self
            .inner
            .lock()
            .map_err(|e| StoreError::backend(e.to_string()))?;
        f(&mut g)
    }
}

#[async_trait]
impl SigningKeyStore for InMemorySigningKeyStore {
    async fn insert(&self, key: &SigningKey) -> Result<(), StoreError> {
        self.with_lock(|map| {
            let bucket = map.entry(key.tenant_id.clone()).or_default();
            if bucket.iter().any(|k| k.kid == key.kid) {
                Err(StoreError::Backend(format!(
                    "duplicate (tenant_id, kid) for kid={}",
                    key.kid
                )))
            } else {
                bucket.push(key.clone());
                Ok(())
            }
        })
    }

    async fn retire(
        &self,
        tenant_id: &str,
        kid: &Kid,
        retired_at: DateTime<Utc>,
    ) -> Result<(), StoreError> {
        self.with_lock(|map| {
            let bucket = map.get_mut(tenant_id).ok_or(StoreError::NotFound)?;
            let row = bucket
                .iter_mut()
                .find(|k| k.kid == *kid)
                .ok_or(StoreError::NotFound)?;
            row.retired_at = Some(
                row.retired_at
                    .map_or(retired_at, |existing| existing.max(retired_at)),
            );
            Ok(())
        })
    }

    async fn active(
        &self,
        tenant_id: &str,
        now: DateTime<Utc>,
    ) -> Result<Vec<SigningKey>, StoreError> {
        let snapshot: Vec<SigningKey> =
            self.with_lock(|map| Ok(map.get(tenant_id).cloned().unwrap_or_default()))?;
        let mut active: Vec<SigningKey> = snapshot
            .into_iter()
            .filter(|k| k.is_active_at(now))
            .collect();
        // activated_at DESC.
        active.sort_by(|a, b| b.activated_at.cmp(&a.activated_at));
        Ok(active)
    }

    async fn list(&self, tenant_id: &str) -> Result<Vec<SigningKey>, StoreError> {
        let mut rows: Vec<SigningKey> =
            self.with_lock(|map| Ok(map.get(tenant_id).cloned().unwrap_or_default()))?;
        rows.sort_by(|a, b| a.activated_at.cmp(&b.activated_at));
        Ok(rows)
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::similar_names
)]
mod tests {
    use super::*;
    use secrecy::SecretString;

    fn key_for(tenant: &str, kid_text: &str, activated: DateTime<Utc>) -> SigningKey {
        SigningKey {
            tenant_id: tenant.to_owned(),
            kid: Kid::new(kid_text),
            secret: SecretString::new("s".to_owned().into_boxed_str()),
            created_at: activated,
            activated_at: activated,
            retired_at: None,
        }
    }

    #[tokio::test]
    async fn insert_then_active_round_trips() {
        let s = InMemorySigningKeyStore::new();
        let k = SigningKey::mint("tenant-a");
        s.insert(&k).await.unwrap();
        let active = s.active("tenant-a", Utc::now()).await.unwrap();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].kid, k.kid);
    }

    #[tokio::test]
    async fn insert_rejects_duplicate() {
        let s = InMemorySigningKeyStore::new();
        let k = SigningKey::mint("tenant-a");
        s.insert(&k).await.unwrap();
        let err = s.insert(&k).await.unwrap_err();
        assert!(matches!(err, StoreError::Backend(_)));
    }

    #[tokio::test]
    async fn retire_marks_row_and_filters_from_active_after_cutoff() {
        let s = InMemorySigningKeyStore::new();
        let now = Utc::now();
        let k = key_for("tenant-a", "kid_aa", now - chrono::Duration::hours(1));
        s.insert(&k).await.unwrap();
        // Retire 30 min from now.
        let retire_at = now + chrono::Duration::minutes(30);
        s.retire("tenant-a", &k.kid, retire_at).await.unwrap();
        // Still active right now (before retire).
        let active = s.active("tenant-a", now).await.unwrap();
        assert_eq!(active.len(), 1);
        // Past retire — not active.
        let active_later = s
            .active("tenant-a", retire_at + chrono::Duration::seconds(1))
            .await
            .unwrap();
        assert!(active_later.is_empty());
    }

    #[tokio::test]
    async fn retire_unknown_kid_returns_not_found() {
        let s = InMemorySigningKeyStore::new();
        let err = s
            .retire("tenant-a", &Kid::new("kid_zz"), Utc::now())
            .await
            .unwrap_err();
        assert!(matches!(err, StoreError::NotFound));
    }

    #[tokio::test]
    async fn active_ordered_by_activated_desc() {
        let s = InMemorySigningKeyStore::new();
        let now = Utc::now();
        let k1 = key_for("t", "kid_1", now - chrono::Duration::hours(2));
        let k2 = key_for("t", "kid_2", now - chrono::Duration::hours(1));
        s.insert(&k1).await.unwrap();
        s.insert(&k2).await.unwrap();
        let active = s.active("t", now).await.unwrap();
        assert_eq!(active.len(), 2);
        assert_eq!(active[0].kid.as_str(), "kid_2");
        assert_eq!(active[1].kid.as_str(), "kid_1");
    }

    #[tokio::test]
    async fn latest_kid_returns_newest_active() {
        let s = InMemorySigningKeyStore::new();
        let now = Utc::now();
        let k1 = key_for("t", "kid_1", now - chrono::Duration::hours(2));
        let k2 = key_for("t", "kid_2", now - chrono::Duration::hours(1));
        s.insert(&k1).await.unwrap();
        s.insert(&k2).await.unwrap();
        assert_eq!(s.latest_kid("t").await.unwrap().unwrap().as_str(), "kid_2");
    }

    #[tokio::test]
    async fn list_ascending_by_activated_at() {
        let s = InMemorySigningKeyStore::new();
        let now = Utc::now();
        let k1 = key_for("t", "kid_1", now - chrono::Duration::hours(2));
        let k2 = key_for("t", "kid_2", now - chrono::Duration::hours(1));
        s.insert(&k2).await.unwrap();
        s.insert(&k1).await.unwrap();
        let all = s.list("t").await.unwrap();
        assert_eq!(all[0].kid.as_str(), "kid_1");
        assert_eq!(all[1].kid.as_str(), "kid_2");
    }

    #[tokio::test]
    async fn cross_tenant_isolation() {
        let s = InMemorySigningKeyStore::new();
        s.insert(&SigningKey::mint("a")).await.unwrap();
        s.insert(&SigningKey::mint("b")).await.unwrap();
        assert_eq!(s.active("a", Utc::now()).await.unwrap().len(), 1);
        assert_eq!(s.active("c", Utc::now()).await.unwrap().len(), 0);
    }
}
