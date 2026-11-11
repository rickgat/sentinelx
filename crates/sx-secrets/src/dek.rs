//! Per-tenant Data Encryption Key (DEK) lifecycle.
//!
//! Envelope encryption splits the world in two:
//!
//! * The **KEK** (Key Encryption Key) lives inside the KMS and never
//!   leaves it. It wraps and unwraps DEKs on demand.
//! * The **DEK** (Data Encryption Key) is generated locally (with a
//!   round-trip to the KMS) and is what actually encrypts tenant data.
//!   The plaintext form is short-lived; the wrapped form is persisted.
//!
//! This module owns the per-tenant DEK lifecycle:
//!
//! * [`DekManager`] — coordinates [`DekStore`] persistence with the
//!   [`crate::kms::KmsKeyProvider`]. `get_or_create` is the primary entry
//!   point; it lazily mints a DEK on first use and reuses the stored
//!   record thereafter. `rotate_tenant` requests a new KEK version from
//!   the KMS and replaces the stored DEK with one wrapped under the new
//!   version.
//! * [`DekStore`] — pluggable persistence for [`StoredDek`] records,
//!   keyed by `TenantId`. The crate ships [`InMemoryDekStore`] for tests
//!   and ephemeral runs, and [`crate::dek_pg::PgDekStore`] for production
//!   deployments backed by Postgres with row-level security.
//! * [`crypto_erase`](crate::shred::crypto_erase_tenant) (in
//!   [`crate::shred`]) — deletes the stored DEK record so the wrapped
//!   form is gone forever. Because the KMS-wrapped DEK was the only path
//!   back to the plaintext, all ciphertext encrypted under it becomes
//!   permanently unrecoverable.
//!
//! ## Rotation policy
//!
//! Rotation is *time-driven*: each [`StoredDek`] stamps its `created_at`
//! when it was minted. [`DekManager::is_due_for_rotation`] returns `true`
//! once `created_at + rotation_interval` is in the past. Callers (a
//! scheduler, a cron job, a policy engine) decide *when* to invoke
//! [`DekManager::rotate_tenant`]; the manager itself never rotates on its
//! own schedule.
//!
//! Rotation is **non-destructive** for existing ciphertext: old DEK
//! versions remain available inside the KMS until explicitly destroyed,
//! so payloads encrypted under the previous wrapped DEK can still be
//! decrypted by passing the stored ciphertext through the KMS. The new
//! DEK is used only for *new* writes after rotation.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, RwLock};
use tracing::{debug, info};
use uuid::Uuid;

use crate::error::SecretsError;
use crate::kms::provider::{Ciphertext, KmsKeyProvider, WrappedDek};

/// Opaque tenant identifier used to scope DEKs.
///
/// Wraps a [`Uuid`] so the same tenant can be addressed across services
/// without leaking domain-specific column names.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TenantId(pub Uuid);

impl TenantId {
    /// Construct a `TenantId` from a raw UUID.
    #[must_use]
    pub const fn new(id: Uuid) -> Self {
        Self(id)
    }

    /// Mint a brand-new random tenant ID. Useful for tests.
    #[must_use]
    pub fn random() -> Self {
        Self(Uuid::new_v4())
    }

    /// Borrow the underlying UUID.
    #[must_use]
    pub const fn as_uuid(&self) -> &Uuid {
        &self.0
    }
}

impl std::fmt::Display for TenantId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
    }
}

/// A wrapped DEK as persisted in a [`DekStore`].
///
/// The plaintext form is **never** persisted: it is dropped immediately
/// after the in-memory crypto operation that minted it. Only the
/// KMS-wrapped form survives, alongside enough metadata to perform
/// rotation and audit.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredDek {
    /// Tenant the DEK belongs to.
    pub tenant_id: TenantId,
    /// KEK identifier that wrapped the DEK (e.g. a Vault Transit key
    /// name).
    pub key_id: String,
    /// KEK version active at the time the DEK was minted.
    pub version: u32,
    /// Wrapped (ciphertext) DEK; opaque to anyone but the KMS.
    pub wrapped: Ciphertext,
    /// Wall-clock timestamp the DEK was minted.
    pub created_at: DateTime<Utc>,
}

impl StoredDek {
    /// Construct a `StoredDek` from a freshly minted [`WrappedDek`].
    #[must_use]
    pub fn from_wrapped(tenant_id: TenantId, dek: &WrappedDek) -> Self {
        Self {
            tenant_id,
            key_id: dek.key_id.clone(),
            version: dek.version,
            wrapped: dek.wrapped.clone(),
            created_at: dek.created_at,
        }
    }
}

/// Pluggable persistence layer for [`StoredDek`] records.
///
/// Implementations must be `Send + Sync` so they can be shared across
/// tasks behind an [`Arc`]. The crate ships [`InMemoryDekStore`] for
/// tests and ephemeral runs, and [`crate::dek_pg::PgDekStore`] for
/// production deployments backed by a `tenant_deks` table guarded by
/// row-level security.
#[async_trait]
pub trait DekStore: Send + Sync {
    /// Look up the DEK for `tenant_id`. Returns `Ok(None)` when no DEK
    /// has been provisioned yet.
    async fn get(&self, tenant_id: TenantId) -> Result<Option<StoredDek>, SecretsError>;

    /// Persist (insert or update) the given DEK record.
    async fn put(&self, dek: StoredDek) -> Result<(), SecretsError>;

    /// Delete the DEK for `tenant_id`. Idempotent: deleting a missing
    /// tenant must succeed quietly.
    async fn delete(&self, tenant_id: TenantId) -> Result<(), SecretsError>;
}

#[async_trait]
impl<T> DekStore for Arc<T>
where
    T: DekStore + ?Sized,
{
    async fn get(&self, tenant_id: TenantId) -> Result<Option<StoredDek>, SecretsError> {
        (**self).get(tenant_id).await
    }

    async fn put(&self, dek: StoredDek) -> Result<(), SecretsError> {
        (**self).put(dek).await
    }

    async fn delete(&self, tenant_id: TenantId) -> Result<(), SecretsError> {
        (**self).delete(tenant_id).await
    }
}

/// In-memory [`DekStore`] backed by a `tokio::sync::RwLock<HashMap>`.
///
/// Process-local: state is lost when the process exits. Cheap to clone
/// because the map is held behind an [`Arc`].
#[derive(Debug, Default, Clone)]
pub struct InMemoryDekStore {
    inner: Arc<RwLock<HashMap<TenantId, StoredDek>>>,
}

impl InMemoryDekStore {
    /// Construct an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of tenants currently stored.
    pub async fn len(&self) -> usize {
        self.inner.read().await.len()
    }

    /// `true` when no DEK has been stored yet.
    pub async fn is_empty(&self) -> bool {
        self.inner.read().await.is_empty()
    }
}

#[async_trait]
impl DekStore for InMemoryDekStore {
    async fn get(&self, tenant_id: TenantId) -> Result<Option<StoredDek>, SecretsError> {
        Ok(self.inner.read().await.get(&tenant_id).cloned())
    }

    async fn put(&self, dek: StoredDek) -> Result<(), SecretsError> {
        self.inner.write().await.insert(dek.tenant_id, dek);
        Ok(())
    }

    async fn delete(&self, tenant_id: TenantId) -> Result<(), SecretsError> {
        self.inner.write().await.remove(&tenant_id);
        Ok(())
    }
}

/// How often a tenant's DEK should be rotated.
///
/// 90 days is the default to match common compliance baselines (PCI DSS
/// "at least annually", FIPS 140-3 cryptographic-period guidance). The
/// manager exposes [`DekManager::is_due_for_rotation`] so policy code
/// can ask "should I rotate this tenant now?" without owning the clock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RotationPolicy {
    /// Maximum age a stored DEK may reach before it is considered due
    /// for rotation.
    pub max_age: Duration,
}

impl RotationPolicy {
    /// Default rotation policy: 90 days.
    #[must_use]
    pub const fn default_90_days() -> Self {
        Self {
            max_age: Duration::days(90),
        }
    }

    /// Construct a custom rotation policy.
    #[must_use]
    pub const fn new(max_age: Duration) -> Self {
        Self { max_age }
    }
}

impl Default for RotationPolicy {
    fn default() -> Self {
        Self::default_90_days()
    }
}

/// Coalescing in-flight creation guard.
///
/// `get_or_create` may be invoked concurrently for the same tenant from
/// many tasks. Without a guard, every concurrent caller would round-trip
/// to the KMS and race to overwrite the store. The mutex below serialises
/// just the *minting* path: readers go straight through the [`DekStore`],
/// and only the slow path (no record yet) takes the lock.
type CoalesceGuard = Arc<Mutex<()>>;

/// Coordinates DEK lifecycle: lookup, lazy creation, rotation.
///
/// Generic over both [`KmsKeyProvider`] and [`DekStore`] so production
/// (Vault + Postgres) and tests (mock KMS + in-memory store) share the
/// same code path.
#[derive(Debug, Clone)]
pub struct DekManager<K, S> {
    kms: Arc<K>,
    store: Arc<S>,
    /// KEK identifier under which all tenants' DEKs are wrapped. In
    /// multi-region or BYOK deployments callers may want to scope this
    /// per tenant; that's a future refactor.
    key_id: String,
    policy: RotationPolicy,
    /// Per-process serialisation of the slow create path.
    creating: Arc<Mutex<HashMap<TenantId, CoalesceGuard>>>,
}

impl<K, S> DekManager<K, S>
where
    K: KmsKeyProvider + 'static,
    S: DekStore + 'static,
{
    /// Construct a manager. `key_id` is the KEK name in the KMS under
    /// which every tenant's DEK is wrapped.
    pub fn new(kms: Arc<K>, store: Arc<S>, key_id: impl Into<String>) -> Self {
        Self {
            kms,
            store,
            key_id: key_id.into(),
            policy: RotationPolicy::default(),
            creating: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Build with a custom rotation policy.
    #[must_use]
    pub const fn with_policy(mut self, policy: RotationPolicy) -> Self {
        self.policy = policy;
        self
    }

    /// The KEK identifier the manager wraps DEKs under.
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// The rotation policy in effect.
    #[must_use]
    pub const fn policy(&self) -> RotationPolicy {
        self.policy
    }

    /// `true` when `dek` has aged past the rotation policy.
    #[must_use]
    pub fn is_due_for_rotation(&self, dek: &StoredDek) -> bool {
        Utc::now().signed_duration_since(dek.created_at) >= self.policy.max_age
    }

    /// Fetch the tenant's DEK, minting and persisting one on first use.
    ///
    /// Concurrent callers for the same tenant are coalesced: at most one
    /// task talks to the KMS, the rest re-read the freshly stored record.
    #[allow(clippy::cognitive_complexity)] // store check + per-tenant guard + KMS mint + persist
    pub async fn get_or_create(&self, tenant_id: TenantId) -> Result<StoredDek, SecretsError> {
        if let Some(existing) = self.store.get(tenant_id).await? {
            return Ok(existing);
        }

        // Slow path: acquire the per-tenant coalesce guard, then re-check
        // the store. A concurrent task may have populated it while we
        // were waiting on the lock.
        let guard = self.tenant_guard(tenant_id).await;
        let _held = guard.lock().await;
        if let Some(existing) = self.store.get(tenant_id).await? {
            return Ok(existing);
        }

        debug!(
            target: "sx_secrets::dek",
            tenant_id = %tenant_id,
            key_id = %self.key_id,
            "minting new DEK"
        );
        let wrapped = self.kms.generate_dek(&self.key_id).await?;
        let stored = StoredDek::from_wrapped(tenant_id, &wrapped);
        self.store.put(stored.clone()).await?;
        info!(
            target: "sx_secrets::dek",
            tenant_id = %tenant_id,
            key_id = %self.key_id,
            version = stored.version,
            "DEK minted"
        );
        Ok(stored)
    }

    /// Force-rotate the tenant's DEK.
    ///
    /// Implementation: ask the KMS to rotate the KEK (so subsequent
    /// `generate_dek` calls use the new version), then mint a fresh DEK
    /// and overwrite the stored record. The returned [`StoredDek`] is
    /// the new active key.
    ///
    /// Rotation is idempotent in the sense that calling it twice in a
    /// row produces two distinct new versions; it never returns an error
    /// because "the key is already at this version".
    pub async fn rotate_tenant(&self, tenant_id: TenantId) -> Result<StoredDek, SecretsError> {
        let previous_version = self
            .store
            .get(tenant_id)
            .await?
            .map(|d| d.version)
            .unwrap_or_default();

        let new_version = self.kms.rotate(&self.key_id).await?;
        debug!(
            target: "sx_secrets::dek",
            tenant_id = %tenant_id,
            key_id = %self.key_id,
            previous_version,
            new_version = new_version.version,
            "rotated KEK"
        );

        let wrapped = self.kms.generate_dek(&self.key_id).await?;
        let stored = StoredDek::from_wrapped(tenant_id, &wrapped);
        self.store.put(stored.clone()).await?;
        info!(
            target: "sx_secrets::dek",
            tenant_id = %tenant_id,
            key_id = %self.key_id,
            previous_version,
            version = stored.version,
            "DEK rotated"
        );
        Ok(stored)
    }

    /// Borrow the underlying KMS provider.
    ///
    /// Exposed so callers (and [`crate::shred`]) can issue raw KMS
    /// operations against the same client without having to thread a
    /// separate `Arc<K>` through their call graph.
    #[must_use]
    pub const fn kms(&self) -> &Arc<K> {
        &self.kms
    }

    /// Borrow the underlying DEK store.
    ///
    /// Used by [`crate::shred::crypto_erase_tenant`] to delete the
    /// wrapped DEK record, and by tests to inspect persisted state.
    #[must_use]
    pub const fn store(&self) -> &Arc<S> {
        &self.store
    }

    async fn tenant_guard(&self, tenant_id: TenantId) -> CoalesceGuard {
        let mut map = self.creating.lock().await;
        map.entry(tenant_id)
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::expect_used,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;
    use crate::kms::provider::KeyVersion;
    use async_trait::async_trait;
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    use secrecy::SecretString;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// Mock KMS that hands out deterministic plaintexts and tracks how
    /// many times each verb was called.
    #[derive(Debug, Default)]
    struct MockKms {
        version: AtomicU32,
        generate_calls: AtomicU32,
        rotate_calls: AtomicU32,
    }

    impl MockKms {
        fn new() -> Self {
            Self {
                version: AtomicU32::new(1),
                generate_calls: AtomicU32::new(0),
                rotate_calls: AtomicU32::new(0),
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
            use secrecy::ExposeSecret;
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
            self.generate_calls.fetch_add(1, Ordering::SeqCst);
            let v = self.version.load(Ordering::SeqCst);
            let pt = SecretString::new(format!("dek-bytes-v{v}").into_boxed_str());
            Ok(WrappedDek::new(
                key_id,
                v,
                pt,
                Ciphertext::new(format!("mock:v{v}:WRAPPED")),
            ))
        }

        async fn rotate(&self, _key_id: &str) -> Result<KeyVersion, SecretsError> {
            self.rotate_calls.fetch_add(1, Ordering::SeqCst);
            let v = self.version.fetch_add(1, Ordering::SeqCst) + 1;
            Ok(KeyVersion::now(v))
        }
    }

    fn manager() -> (DekManager<MockKms, InMemoryDekStore>, Arc<MockKms>) {
        let kms = Arc::new(MockKms::new());
        let store = Arc::new(InMemoryDekStore::new());
        let mgr = DekManager::new(Arc::clone(&kms), store, "tenant-kek");
        (mgr, kms)
    }

    #[tokio::test]
    async fn dek_store_round_trips_record() {
        let store = InMemoryDekStore::new();
        let tenant = TenantId::random();
        assert!(store.is_empty().await);

        let dek = StoredDek {
            tenant_id: tenant,
            key_id: "k".into(),
            version: 4,
            wrapped: Ciphertext::new("mock:v4:WRAPPED"),
            created_at: Utc::now(),
        };
        store.put(dek.clone()).await.unwrap();
        assert_eq!(store.len().await, 1);

        let got = store.get(tenant).await.unwrap().unwrap();
        assert_eq!(got, dek);

        assert!(store.get(TenantId::random()).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn get_or_create_is_stable_across_calls() {
        let (mgr, kms) = manager();
        let tenant = TenantId::random();
        let first = mgr.get_or_create(tenant).await.unwrap();
        let second = mgr.get_or_create(tenant).await.unwrap();
        assert_eq!(first, second);
        // generate_dek must have been called exactly once.
        assert_eq!(kms.generate_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn rotate_tenant_produces_new_version() {
        let (mgr, kms) = manager();
        let tenant = TenantId::random();
        let initial = mgr.get_or_create(tenant).await.unwrap();
        assert_eq!(initial.version, 1);

        let rotated = mgr.rotate_tenant(tenant).await.unwrap();
        assert!(rotated.version > initial.version);
        assert_eq!(kms.rotate_calls.load(Ordering::SeqCst), 1);
        // The stored record should reflect the rotated version.
        let from_store = mgr.store().get(tenant).await.unwrap().unwrap();
        assert_eq!(from_store.version, rotated.version);
    }

    #[tokio::test]
    async fn rotate_is_idempotent_in_the_sense_that_repeats_succeed() {
        // "Idempotent" here means: calling rotate repeatedly never
        // errors and the stored record always reflects the latest
        // version (strictly increasing).
        let (mgr, _kms) = manager();
        let tenant = TenantId::random();
        mgr.get_or_create(tenant).await.unwrap();
        let v1 = mgr.rotate_tenant(tenant).await.unwrap().version;
        let v2 = mgr.rotate_tenant(tenant).await.unwrap().version;
        let v3 = mgr.rotate_tenant(tenant).await.unwrap().version;
        assert!(v1 < v2 && v2 < v3);
    }

    #[tokio::test]
    async fn concurrent_get_or_create_coalesces_to_single_kms_call() {
        let (mgr, kms) = manager();
        let mgr = Arc::new(mgr);
        let tenant = TenantId::random();
        let mut handles = Vec::new();
        for _ in 0..16 {
            let mgr = Arc::clone(&mgr);
            handles.push(tokio::spawn(async move { mgr.get_or_create(tenant).await }));
        }
        let mut versions = Vec::with_capacity(handles.len());
        for h in handles {
            versions.push(h.await.unwrap().unwrap().version);
        }
        // All callers must observe the same minted DEK.
        assert!(versions.windows(2).all(|w| w[0] == w[1]));
        // And the KMS must have been hit exactly once.
        assert_eq!(kms.generate_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn rotation_policy_marks_old_deks_as_due() {
        let (mut mgr, _) = manager();
        mgr = mgr.with_policy(RotationPolicy::new(Duration::seconds(0)));
        let tenant = TenantId::random();
        let dek = mgr.get_or_create(tenant).await.unwrap();
        // A zero-second policy means *any* DEK is due immediately.
        assert!(mgr.is_due_for_rotation(&dek));

        let mgr2 = DekManager::new(
            Arc::new(MockKms::new()),
            Arc::new(InMemoryDekStore::new()),
            "tenant-kek",
        )
        .with_policy(RotationPolicy::new(Duration::days(365)));
        assert!(!mgr2.is_due_for_rotation(&dek));
    }
}
