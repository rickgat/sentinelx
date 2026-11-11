//! Write-Once-Read-Many (WORM) object store abstraction.
//!
//! The production binding is S3 Object Lock in **Compliance mode** with
//! a 7-year retention (`WORM_RETENTION_DAYS`). The trait below intentionally
//! refuses to overwrite an existing key — even on the in-memory test
//! adapter — so any code path that would clobber prior evidence is caught
//! by `cargo test` rather than in production after S3 already rejected it.

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use thiserror::Error;

use crate::p1_004::store::TenantId;

/// Errors emitted by [`WormStore`] implementations.
#[derive(Debug, Error)]
pub enum ObjectStoreError {
    /// The supplied key already exists. WORM stores never overwrite —
    /// callers must pick a unique key per upload.
    #[error("object already exists: {0}")]
    AlreadyExists(String),
    /// Key was not found.
    #[error("not found: {0}")]
    NotFound(String),
    /// Cross-tenant access attempt.
    #[error("forbidden: cross-tenant object access")]
    Forbidden,
    /// Transport-level failure (S3 5xx, IAM denial, etc.).
    #[error("backend: {0}")]
    Backend(String),
}

/// A write-once, read-many object store. Every call is tenant-scoped:
/// the implementation must arrange that two tenants cannot read each
/// other's objects even if a key collision is engineered.
#[async_trait]
pub trait WormStore: Send + Sync + std::fmt::Debug {
    /// Persist `body` at `key` with WORM semantics.
    ///
    /// `retention_days` is the operator-supplied window the object must
    /// not be deletable for; production implementations set the S3
    /// Object Lock retention from this value. Implementations MUST
    /// reject any second `put_immutable` call with the same `key` and
    /// the same tenant.
    async fn put_immutable(
        &self,
        tenant_id: &TenantId,
        key: &str,
        body: &[u8],
        retention_days: i64,
    ) -> Result<(), ObjectStoreError>;

    /// Read the bytes at `key`. Cross-tenant reads must return
    /// [`ObjectStoreError::Forbidden`] (or [`ObjectStoreError::NotFound`]
    /// when the object genuinely does not exist for this tenant).
    async fn get(&self, tenant_id: &TenantId, key: &str) -> Result<Vec<u8>, ObjectStoreError>;

    /// Whether an object exists for this tenant + key.
    async fn exists(&self, tenant_id: &TenantId, key: &str) -> Result<bool, ObjectStoreError>;
}

/// Per-key value in the in-memory backing store.
#[derive(Debug, Clone, PartialEq, Eq)]
struct WormObject {
    owner: TenantId,
    body: Vec<u8>,
    retention_days: i64,
}

/// Process-local reference implementation of [`WormStore`].
///
/// Mirrors S3 Object Lock no-overwrite semantics exactly so unit tests
/// have a faithful environment.
#[derive(Debug, Default)]
pub struct InMemoryWormStore {
    objects: Mutex<HashMap<String, WormObject>>,
}

impl InMemoryWormStore {
    /// Construct empty.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of stored objects (across all tenants).
    #[must_use]
    pub fn len(&self) -> usize {
        self.objects.lock().map(|g| g.len()).unwrap_or(0)
    }

    /// Whether the store currently holds zero objects.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[async_trait]
impl WormStore for InMemoryWormStore {
    async fn put_immutable(
        &self,
        tenant_id: &TenantId,
        key: &str,
        body: &[u8],
        retention_days: i64,
    ) -> Result<(), ObjectStoreError> {
        let mut g = self
            .objects
            .lock()
            .map_err(|e| ObjectStoreError::Backend(e.to_string()))?;
        if g.contains_key(key) {
            return Err(ObjectStoreError::AlreadyExists(key.to_owned()));
        }
        g.insert(
            key.to_owned(),
            WormObject {
                owner: tenant_id.clone(),
                body: body.to_vec(),
                retention_days,
            },
        );
        Ok(())
    }

    async fn get(&self, tenant_id: &TenantId, key: &str) -> Result<Vec<u8>, ObjectStoreError> {
        let g = self
            .objects
            .lock()
            .map_err(|e| ObjectStoreError::Backend(e.to_string()))?;
        let Some(obj) = g.get(key) else {
            return Err(ObjectStoreError::NotFound(key.to_owned()));
        };
        if obj.owner != *tenant_id {
            return Err(ObjectStoreError::Forbidden);
        }
        Ok(obj.body.clone())
    }

    async fn exists(&self, tenant_id: &TenantId, key: &str) -> Result<bool, ObjectStoreError> {
        let g = self
            .objects
            .lock()
            .map_err(|e| ObjectStoreError::Backend(e.to_string()))?;
        match g.get(key) {
            Some(obj) if obj.owner == *tenant_id => Ok(true),
            Some(_) => Err(ObjectStoreError::Forbidden),
            None => Ok(false),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "current_thread")]
    async fn put_then_get_round_trip() {
        let s = InMemoryWormStore::new();
        let t = TenantId::new("A");
        s.put_immutable(&t, "k1", b"abc", 100).await.unwrap();
        let got = s.get(&t, "k1").await.unwrap();
        assert_eq!(got, b"abc");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn put_twice_to_same_key_is_rejected() {
        let s = InMemoryWormStore::new();
        let t = TenantId::new("A");
        s.put_immutable(&t, "k1", b"abc", 100).await.unwrap();
        let err = s.put_immutable(&t, "k1", b"xyz", 100).await.unwrap_err();
        assert!(matches!(err, ObjectStoreError::AlreadyExists(_)));
        // First write must still be readable, untouched.
        let got = s.get(&t, "k1").await.unwrap();
        assert_eq!(got, b"abc");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cross_tenant_get_is_forbidden() {
        let s = InMemoryWormStore::new();
        let a = TenantId::new("A");
        let b = TenantId::new("B");
        s.put_immutable(&a, "k1", b"secret", 100).await.unwrap();
        let err = s.get(&b, "k1").await.unwrap_err();
        assert!(matches!(err, ObjectStoreError::Forbidden));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn exists_reflects_tenant_scope() {
        let s = InMemoryWormStore::new();
        let a = TenantId::new("A");
        let b = TenantId::new("B");
        s.put_immutable(&a, "k1", b"x", 1).await.unwrap();
        assert!(s.exists(&a, "k1").await.unwrap());
        let err = s.exists(&b, "k1").await.unwrap_err();
        assert!(matches!(err, ObjectStoreError::Forbidden));
        assert!(!s.exists(&a, "missing").await.unwrap());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn put_records_retention() {
        // Smoke test that the retention value is captured — the
        // production binding maps this onto the S3 Object Lock
        // `RetainUntilDate`. We at least guarantee the value is
        // accepted and persisted.
        let s = InMemoryWormStore::new();
        let t = TenantId::new("A");
        s.put_immutable(&t, "k1", b"a", 2_557).await.unwrap();
        let g = s.objects.lock().unwrap();
        assert_eq!(g.get("k1").unwrap().retention_days, 2_557);
    }
}
