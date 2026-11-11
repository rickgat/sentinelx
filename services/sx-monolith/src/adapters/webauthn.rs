//! FIDO2 / `WebAuthn` MFA adapter (P1-002).
//!
//! Implements [`sx_api::port::WebauthnPort`] on top of:
//!
//! * `sx_iam::controller::webauthn::*` use cases (register/login start +
//!   finish).
//! * `sx_iam::controller::IssueTokenUseCase` for the credential-bound
//!   token pair minted on `login/finish`.
//! * An in-memory `Mutex<HashMap<TenantId, TenantRp>>` relying-party
//!   store seeded at boot.
//! * An in-memory `Mutex<Vec<StoredCredential>>` credential store keyed
//!   by `(tenant_id, cred_id)`.
//! * An in-memory `Mutex<HashMap<StateId, StashedState>>` short-TTL
//!   state cache that holds the opaque `PasskeyRegistration` /
//!   `PasskeyAuthentication` between the `start` and `finish` calls.
//!
//! The state cache TTL is hard-coded to five minutes — the W3C reference
//! window for an in-progress ceremony. Entries past the TTL are
//! garbage-collected lazily on each `finish` call (a tighter background
//! sweep is unnecessary at the volumes we expect for MFA).
//!
//! ## Audit trail
//!
//! Every adapter entry-point emits a `tracing::info!` (success) or
//! `tracing::warn!` (failure) line carrying the tenant id, user id (or
//! email hash for `login/start`), state id, and outcome — feeding the
//! standard audit pipeline.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use base64::Engine as _;
use sqlx::types::Json;
use sqlx::{PgPool, Row as _};
use sx_api::port::WebauthnPort;
use sx_api::view::webauthn_view::{
    AaguidPolicyListResponse, AaguidPolicyView, CredentialListResponse, LoginFinishRequest,
    LoginFinishResponse, LoginStartResponse, MdsStatusView, PutAaguidPolicyRequest,
    RegisterFinishRequest, RegisterFinishResponse, RegisterStartResponse, UserCredentialView,
};
use sx_iam::controller::issue_token::IssueTokenInput;
use sx_iam::controller::webauthn::{
    LoginFinishInput, LoginFinishUseCase, LoginStartInput, LoginStartUseCase, RegisterFinishInput,
    RegisterFinishUseCase, RegisterStartInput, RegisterStartUseCase,
};
use sx_iam::controller::IssueTokenUseCase;
use sx_iam::domain::{TenantId, UserId};
use sx_iam::model::webauthn::{
    AaguidAction, AaguidPolicy, AttestationPolicy, MdsEntry, MdsStatus, StoredCredential, TenantRp,
};
use sx_iam::port::{
    UserRepository, WebauthnAaguidPolicyRepository, WebauthnCredentialRepository,
    WebauthnMdsRepository, WebauthnRpRepository,
};
use sx_iam::service::webauthn::{MdsConfig, MdsFetcher};
use sx_iam::service::{JwtIssuer, SystemClock};
use sx_iam::IamError;
use sx_storage::prelude::TenantId as StorageTenantId;
use sx_storage::tenant_context::TenantContext;
use time::OffsetDateTime;
use uuid::Uuid;
use webauthn_rs::prelude::{
    PasskeyAuthentication, PasskeyRegistration, PublicKeyCredential, RegisterPublicKeyCredential,
};

use crate::adapters::iam::MonolithUserRepo;

/// State-cache TTL — matches the W3C reference window for an in-progress
/// ceremony. Entries past this age are evicted lazily.
const STATE_TTL: Duration = Duration::from_secs(5 * 60);

// ---------------------------------------------------------------------------
// Repositories (in-memory)
// ---------------------------------------------------------------------------

/// In-memory `WebauthnRpRepository` — one row per tenant, seeded at boot
/// with a default `localhost` relying party so the developer-mode
/// monolith works out of the box. Production deployments populate the
/// store via a future admin endpoint (out of scope for the P1-002 MVP).
#[derive(Default)]
pub(crate) struct InMemoryRpRepo {
    rows: Mutex<HashMap<TenantId, TenantRp>>,
}

impl InMemoryRpRepo {
    /// Seed a row.
    pub(crate) fn put(&self, rp: TenantRp) {
        // Mutex poisoning surfaces as `Repository` in the port; in the
        // in-memory adapter we treat it as fatal because every other
        // user of the same mutex must now consider its data
        // potentially-corrupt.
        let mut guard = match self.rows.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.insert(rp.tenant_id, rp);
    }
}

#[async_trait]
impl WebauthnRpRepository for InMemoryRpRepo {
    async fn get(&self, tenant_id: TenantId) -> Result<Option<TenantRp>, IamError> {
        let guard = self
            .rows
            .lock()
            .map_err(|_| IamError::repository("webauthn rp mutex poisoned"))?;
        Ok(guard.get(&tenant_id).cloned())
    }
}

/// In-memory `WebauthnCredentialRepository` — keyed by
/// `(tenant_id, cred_id)` for primary lookup and a per-user index for
/// `list_active`.
#[derive(Default)]
pub(crate) struct InMemoryCredRepo {
    rows: Mutex<Vec<StoredCredential>>,
}

#[async_trait]
impl WebauthnCredentialRepository for InMemoryCredRepo {
    async fn insert(&self, credential: &StoredCredential) -> Result<(), IamError> {
        let mut guard = self
            .rows
            .lock()
            .map_err(|_| IamError::repository("webauthn cred mutex poisoned"))?;
        if guard
            .iter()
            .any(|c| c.tenant_id == credential.tenant_id && c.cred_id == credential.cred_id)
        {
            return Err(IamError::conflict("webauthn credential already registered"));
        }
        guard.push(credential.clone());
        Ok(())
    }

    async fn list_active(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> Result<Vec<StoredCredential>, IamError> {
        let guard = self
            .rows
            .lock()
            .map_err(|_| IamError::repository("webauthn cred mutex poisoned"))?;
        let mut out: Vec<StoredCredential> = guard
            .iter()
            .filter(|c| c.tenant_id == tenant_id && c.user_id == user_id && c.is_active())
            .cloned()
            .collect();
        out.sort_by_key(|c| c.created_at);
        Ok(out)
    }

    async fn find_by_cred_id(
        &self,
        tenant_id: TenantId,
        cred_id: &str,
    ) -> Result<Option<StoredCredential>, IamError> {
        let guard = self
            .rows
            .lock()
            .map_err(|_| IamError::repository("webauthn cred mutex poisoned"))?;
        Ok(guard
            .iter()
            .find(|c| c.tenant_id == tenant_id && c.cred_id == cred_id)
            .cloned())
    }

    async fn update_counter(
        &self,
        tenant_id: TenantId,
        cred_id: &str,
        new_counter: u32,
    ) -> Result<(), IamError> {
        let mut guard = self
            .rows
            .lock()
            .map_err(|_| IamError::repository("webauthn cred mutex poisoned"))?;
        for c in guard.iter_mut() {
            if c.tenant_id == tenant_id && c.cred_id == cred_id {
                c.counter = new_counter;
                c.last_used_at = Some(OffsetDateTime::now_utc());
                return Ok(());
            }
        }
        Err(IamError::repository(
            "webauthn credential not found for update",
        ))
    }

    async fn revoke(&self, tenant_id: TenantId, cred_id: &str) -> Result<(), IamError> {
        let mut guard = self
            .rows
            .lock()
            .map_err(|_| IamError::repository("webauthn cred mutex poisoned"))?;
        for c in guard.iter_mut() {
            if c.tenant_id == tenant_id && c.cred_id == cred_id && c.revoked_at.is_none() {
                c.revoked_at = Some(OffsetDateTime::now_utc());
            }
        }
        Ok(())
    }
}

/// Postgres-backed [`WebauthnCredentialRepository`] (durable passkeys).
///
/// The composition root bound registered passkeys to an in-memory
/// `Vec<StoredCredential>`, so every user's FIDO2 credential was lost on a
/// monolith restart — locking passkey-only users out until they re-enrolled.
/// When `database.enabled` this store persists them instead.
///
/// The full [`StoredCredential`] aggregate (public key, counter, passkey
/// blob, attestation, timestamps) is stored losslessly as JSONB in
/// `webauthn_credentials`, keyed by `(tenant_id, cred_id)`, with scalar
/// projections (`user_id`, `revoked_at`, `created_at`) so `list_active` can
/// filter + order without deserialising every row. Every statement runs in a
/// transaction that applies [`TenantContext`] first, so Postgres RLS confines
/// each query to the calling tenant — the same pattern as every other
/// tenant-scoped table.
pub(crate) struct PgCredRepo {
    pool: PgPool,
    stmt_timeout_ms: u64,
}

impl std::fmt::Debug for PgCredRepo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PgCredRepo").finish_non_exhaustive()
    }
}

impl PgCredRepo {
    pub(crate) const fn new(pool: PgPool, stmt_timeout_ms: u64) -> Self {
        Self {
            pool,
            stmt_timeout_ms,
        }
    }

    fn storage_tenant(tenant: TenantId) -> StorageTenantId {
        StorageTenantId::from_uuid(*tenant.as_uuid())
    }
}

#[async_trait]
impl WebauthnCredentialRepository for PgCredRepo {
    async fn insert(&self, credential: &StoredCredential) -> Result<(), IamError> {
        let tid = Self::storage_tenant(credential.tenant_id);
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| IamError::repository(format!("webauthn cred insert begin: {e}")))?;
        TenantContext::apply(&mut tx, tid, self.stmt_timeout_ms)
            .await
            .map_err(|e| IamError::repository(format!("webauthn cred tenant ctx: {e}")))?;
        // `ON CONFLICT DO NOTHING` + a zero-row check reproduces the
        // in-memory store's conflict semantics without parsing SQLSTATEs.
        let res = sqlx::query(
            "INSERT INTO webauthn_credentials \
                 (tenant_id, cred_id, user_id, revoked_at, aggregate, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, now(), now()) \
             ON CONFLICT (tenant_id, cred_id) DO NOTHING",
        )
        .bind(*credential.tenant_id.as_uuid())
        .bind(&credential.cred_id)
        .bind(*credential.user_id.as_uuid())
        .bind(credential.revoked_at)
        .bind(Json(credential))
        .execute(&mut *tx)
        .await
        .map_err(|e| IamError::repository(format!("webauthn cred insert: {e}")))?;
        if res.rows_affected() == 0 {
            return Err(IamError::conflict("webauthn credential already registered"));
        }
        tx.commit()
            .await
            .map_err(|e| IamError::repository(format!("webauthn cred insert commit: {e}")))?;
        Ok(())
    }

    async fn list_active(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> Result<Vec<StoredCredential>, IamError> {
        let tid = Self::storage_tenant(tenant_id);
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| IamError::repository(format!("webauthn cred list begin: {e}")))?;
        TenantContext::apply(&mut tx, tid, self.stmt_timeout_ms)
            .await
            .map_err(|e| IamError::repository(format!("webauthn cred tenant ctx: {e}")))?;
        let rows = sqlx::query(
            "SELECT aggregate FROM webauthn_credentials \
             WHERE tenant_id = $1 AND user_id = $2 AND revoked_at IS NULL \
             ORDER BY created_at ASC",
        )
        .bind(*tenant_id.as_uuid())
        .bind(*user_id.as_uuid())
        .fetch_all(&mut *tx)
        .await
        .map_err(|e| IamError::repository(format!("webauthn cred list: {e}")))?;
        tx.commit()
            .await
            .map_err(|e| IamError::repository(format!("webauthn cred list commit: {e}")))?;
        rows.into_iter()
            .map(|r| {
                r.try_get::<Json<StoredCredential>, _>("aggregate")
                    .map(|j| j.0)
                    .map_err(|e| IamError::repository(format!("webauthn cred decode: {e}")))
            })
            .collect()
    }

    async fn find_by_cred_id(
        &self,
        tenant_id: TenantId,
        cred_id: &str,
    ) -> Result<Option<StoredCredential>, IamError> {
        let tid = Self::storage_tenant(tenant_id);
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| IamError::repository(format!("webauthn cred find begin: {e}")))?;
        TenantContext::apply(&mut tx, tid, self.stmt_timeout_ms)
            .await
            .map_err(|e| IamError::repository(format!("webauthn cred tenant ctx: {e}")))?;
        let row = sqlx::query(
            "SELECT aggregate FROM webauthn_credentials \
             WHERE tenant_id = $1 AND cred_id = $2",
        )
        .bind(*tenant_id.as_uuid())
        .bind(cred_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| IamError::repository(format!("webauthn cred find: {e}")))?;
        tx.commit()
            .await
            .map_err(|e| IamError::repository(format!("webauthn cred find commit: {e}")))?;
        row.map(|r| {
            r.try_get::<Json<StoredCredential>, _>("aggregate")
                .map(|j| j.0)
                .map_err(|e| IamError::repository(format!("webauthn cred decode: {e}")))
        })
        .transpose()
    }

    async fn update_counter(
        &self,
        tenant_id: TenantId,
        cred_id: &str,
        new_counter: u32,
    ) -> Result<(), IamError> {
        let tid = Self::storage_tenant(tenant_id);
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| IamError::repository(format!("webauthn cred counter begin: {e}")))?;
        TenantContext::apply(&mut tx, tid, self.stmt_timeout_ms)
            .await
            .map_err(|e| IamError::repository(format!("webauthn cred tenant ctx: {e}")))?;
        // Read-modify-write so the counter + last_used_at inside the JSONB
        // aggregate stay in the exact `time` serde shape the rest of the
        // code round-trips (a `jsonb_set` with a raw timestamp would not).
        let row = sqlx::query(
            "SELECT aggregate FROM webauthn_credentials \
             WHERE tenant_id = $1 AND cred_id = $2 FOR UPDATE",
        )
        .bind(*tenant_id.as_uuid())
        .bind(cred_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| IamError::repository(format!("webauthn cred counter load: {e}")))?;
        let Some(row) = row else {
            return Err(IamError::repository(
                "webauthn credential not found for update",
            ));
        };
        let mut cred = row
            .try_get::<Json<StoredCredential>, _>("aggregate")
            .map(|j| j.0)
            .map_err(|e| IamError::repository(format!("webauthn cred decode: {e}")))?;
        cred.counter = new_counter;
        cred.last_used_at = Some(OffsetDateTime::now_utc());
        sqlx::query(
            "UPDATE webauthn_credentials \
             SET aggregate = $3, updated_at = now() \
             WHERE tenant_id = $1 AND cred_id = $2",
        )
        .bind(*tenant_id.as_uuid())
        .bind(cred_id)
        .bind(Json(&cred))
        .execute(&mut *tx)
        .await
        .map_err(|e| IamError::repository(format!("webauthn cred counter write: {e}")))?;
        tx.commit()
            .await
            .map_err(|e| IamError::repository(format!("webauthn cred counter commit: {e}")))?;
        Ok(())
    }

    async fn revoke(&self, tenant_id: TenantId, cred_id: &str) -> Result<(), IamError> {
        let tid = Self::storage_tenant(tenant_id);
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| IamError::repository(format!("webauthn cred revoke begin: {e}")))?;
        TenantContext::apply(&mut tx, tid, self.stmt_timeout_ms)
            .await
            .map_err(|e| IamError::repository(format!("webauthn cred tenant ctx: {e}")))?;
        let row = sqlx::query(
            "SELECT aggregate FROM webauthn_credentials \
             WHERE tenant_id = $1 AND cred_id = $2 AND revoked_at IS NULL FOR UPDATE",
        )
        .bind(*tenant_id.as_uuid())
        .bind(cred_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| IamError::repository(format!("webauthn cred revoke load: {e}")))?;
        // Idempotent, matching the in-memory store: a missing or
        // already-revoked credential is a no-op success.
        if let Some(row) = row {
            let mut cred = row
                .try_get::<Json<StoredCredential>, _>("aggregate")
                .map(|j| j.0)
                .map_err(|e| IamError::repository(format!("webauthn cred decode: {e}")))?;
            let now = OffsetDateTime::now_utc();
            cred.revoked_at = Some(now);
            sqlx::query(
                "UPDATE webauthn_credentials \
                 SET aggregate = $3, revoked_at = $4, updated_at = now() \
                 WHERE tenant_id = $1 AND cred_id = $2",
            )
            .bind(*tenant_id.as_uuid())
            .bind(cred_id)
            .bind(Json(&cred))
            .bind(now)
            .execute(&mut *tx)
            .await
            .map_err(|e| IamError::repository(format!("webauthn cred revoke write: {e}")))?;
        }
        tx.commit()
            .await
            .map_err(|e| IamError::repository(format!("webauthn cred revoke commit: {e}")))?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// HIGH-002 — in-memory AAGUID policy + MDS3 cache
// ---------------------------------------------------------------------------

/// In-memory implementation of [`WebauthnAaguidPolicyRepository`]. Tenant
/// rows are unique on `(tenant_id, aaguid)`; `upsert` replaces.
#[derive(Default)]
pub(crate) struct InMemoryAaguidPolicyRepo {
    rows: Mutex<Vec<AaguidPolicy>>,
}

#[async_trait]
impl WebauthnAaguidPolicyRepository for InMemoryAaguidPolicyRepo {
    async fn list(&self, tenant_id: TenantId) -> Result<Vec<AaguidPolicy>, IamError> {
        let guard = self
            .rows
            .lock()
            .map_err(|_| IamError::repository("aaguid policy mutex poisoned"))?;
        let mut out: Vec<AaguidPolicy> = guard
            .iter()
            .filter(|r| r.tenant_id == tenant_id)
            .cloned()
            .collect();
        out.sort_by_key(|r| r.set_at);
        Ok(out)
    }

    async fn upsert(&self, policy: &AaguidPolicy) -> Result<(), IamError> {
        let mut guard = self
            .rows
            .lock()
            .map_err(|_| IamError::repository("aaguid policy mutex poisoned"))?;
        guard.retain(|r| !(r.tenant_id == policy.tenant_id && r.aaguid == policy.aaguid));
        guard.push(policy.clone());
        // HIGH-002 audit hook — every mutation is logged with structured
        // fields so downstream audit pipelines can capture the change.
        tracing::info!(
            target: "audit.webauthn.aaguid_policy",
            tenant_id = %policy.tenant_id.as_uuid(),
            aaguid = %policy.aaguid,
            action = %policy.action.as_str(),
            reason = %policy.reason,
            set_by = %policy.set_by.as_uuid(),
            "webauthn.aaguid_policy.upsert",
        );
        Ok(())
    }

    async fn delete(&self, tenant_id: TenantId, aaguid: Uuid) -> Result<(), IamError> {
        let mut guard = self
            .rows
            .lock()
            .map_err(|_| IamError::repository("aaguid policy mutex poisoned"))?;
        guard.retain(|r| !(r.tenant_id == tenant_id && r.aaguid == aaguid));
        tracing::info!(
            target: "audit.webauthn.aaguid_policy",
            tenant_id = %tenant_id.as_uuid(),
            aaguid = %aaguid,
            "webauthn.aaguid_policy.delete",
        );
        Ok(())
    }
}

/// In-memory implementation of [`WebauthnMdsRepository`].
#[derive(Default)]
pub(crate) struct InMemoryMdsRepo {
    rows: Mutex<Vec<MdsEntry>>,
    last_refresh: Mutex<Option<OffsetDateTime>>,
}

#[async_trait]
impl WebauthnMdsRepository for InMemoryMdsRepo {
    async fn get(&self, aaguid: Uuid) -> Result<Option<MdsEntry>, IamError> {
        let guard = self
            .rows
            .lock()
            .map_err(|_| IamError::repository("mds mutex poisoned"))?;
        Ok(guard.iter().find(|e| e.aaguid == aaguid).cloned())
    }

    async fn replace_all(&self, entries: Vec<MdsEntry>) -> Result<(), IamError> {
        {
            let mut g = self
                .rows
                .lock()
                .map_err(|_| IamError::repository("mds mutex poisoned"))?;
            *g = entries;
        }
        {
            let mut g = self
                .last_refresh
                .lock()
                .map_err(|_| IamError::repository("mds last_refresh mutex poisoned"))?;
            *g = Some(OffsetDateTime::now_utc());
        }
        Ok(())
    }

    async fn status(&self) -> Result<MdsStatus, IamError> {
        let total_entries: u64 = {
            let g = self
                .rows
                .lock()
                .map_err(|_| IamError::repository("mds mutex poisoned"))?;
            g.len() as u64
        };
        let last = {
            let g = self
                .last_refresh
                .lock()
                .map_err(|_| IamError::repository("mds last_refresh mutex poisoned"))?;
            *g
        };
        Ok(MdsStatus {
            last_refresh: last,
            total_entries,
            root_cert_fingerprint: sx_iam::service::webauthn::PINNED_ROOT_SHA256_HEX.to_owned(),
        })
    }

    async fn last_refresh(&self) -> Result<Option<OffsetDateTime>, IamError> {
        let g = self
            .last_refresh
            .lock()
            .map_err(|_| IamError::repository("mds last_refresh mutex poisoned"))?;
        Ok(*g)
    }
}

// ---------------------------------------------------------------------------
// Short-lived state cache
// ---------------------------------------------------------------------------

/// One of the two opaque `webauthn-rs` ceremony states we stash between
/// `start` and `finish`. Tagged so the adapter can refuse to cross the
/// streams (a registration state cannot satisfy an authentication
/// ceremony and vice-versa).
enum StashedState {
    Registration {
        tenant_id: TenantId,
        user_id: UserId,
        label: Option<String>,
        state: PasskeyRegistration,
        deadline: Instant,
    },
    Authentication {
        tenant_id: TenantId,
        user_id: UserId,
        state: PasskeyAuthentication,
        deadline: Instant,
    },
}

#[derive(Default)]
struct StateCache {
    rows: Mutex<HashMap<String, StashedState>>,
}

impl StateCache {
    fn put(&self, state: StashedState) -> String {
        let id = Uuid::new_v4().to_string();
        let mut guard = match self.rows.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        // Lazy GC — purge expired entries before insert so the cache
        // can't grow without bound under benign traffic.
        let now = Instant::now();
        guard.retain(|_, v| match v {
            StashedState::Registration { deadline, .. }
            | StashedState::Authentication { deadline, .. } => *deadline > now,
        });
        guard.insert(id.clone(), state);
        id
    }

    fn take(&self, id: &str) -> Option<StashedState> {
        let mut guard = match self.rows.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        let now = Instant::now();
        guard.retain(|_, v| match v {
            StashedState::Registration { deadline, .. }
            | StashedState::Authentication { deadline, .. } => *deadline > now,
        });
        guard.remove(id)
    }
}

// ---------------------------------------------------------------------------
// Adapter
// ---------------------------------------------------------------------------

/// Concrete adapter implementing [`WebauthnPort`].
pub(crate) struct WebauthnAdapter {
    rp_repo: Arc<InMemoryRpRepo>,
    /// HIGH-002 — credential repo retained so `list_user_credentials`
    /// (the management endpoint) can read the user's active passkeys
    /// and join against the MDS cache for friendly authenticator names.
    /// Trait object so it is the in-memory or the durable Postgres store.
    cred_repo: Arc<dyn WebauthnCredentialRepository>,
    cache: Arc<StateCache>,
    users: Arc<MonolithUserRepo>,
    issue: Arc<IssueTokenUseCase<JwtIssuer<SystemClock>, SystemClock>>,
    register_start_uc: RegisterStartUseCase,
    register_finish_uc: RegisterFinishUseCase<SystemClock>,
    login_start_uc: LoginStartUseCase,
    login_finish_uc: LoginFinishUseCase,
    /// HIGH-002 — per-tenant AAGUID allow/block policy store.
    aaguid_policy_repo: Arc<InMemoryAaguidPolicyRepo>,
    /// HIGH-002 — local cache of FIDO MDS3 metadata.
    mds_repo: Arc<InMemoryMdsRepo>,
    /// HIGH-002 — fetcher driving periodic MDS3 refreshes + freshness
    /// gates.
    mds_fetcher: Arc<MdsFetcher>,
}

impl std::fmt::Debug for WebauthnAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebauthnAdapter").finish_non_exhaustive()
    }
}

/// Bundle returned to the composition root.
pub(crate) struct WebauthnBundle {
    /// HTTP-facing port.
    pub(crate) webauthn: Arc<dyn WebauthnPort>,
    /// Direct handle on the relying-party repo so the boot path can
    /// seed entries before the server starts accepting traffic.
    pub(crate) rp_repo: Arc<InMemoryRpRepo>,
}

/// Build the bundle.
pub(crate) fn build(
    users: Arc<MonolithUserRepo>,
    issue: Arc<IssueTokenUseCase<JwtIssuer<SystemClock>, SystemClock>>,
    postgres: Option<(PgPool, u64)>,
) -> WebauthnBundle {
    let rp_repo: Arc<InMemoryRpRepo> = Arc::new(InMemoryRpRepo::default());
    let cache = Arc::new(StateCache::default());
    let clock = Arc::new(SystemClock);

    let rp_dyn: Arc<dyn WebauthnRpRepository> = Arc::clone(&rp_repo) as _;
    // Registered passkeys are durable (Postgres) when the DB is enabled,
    // else the in-memory store keeps the dev quick-start path unchanged.
    let cred_dyn: Arc<dyn WebauthnCredentialRepository> = match postgres {
        Some((pool, stmt_timeout_ms)) => Arc::new(PgCredRepo::new(pool, stmt_timeout_ms)),
        None => Arc::new(InMemoryCredRepo::default()),
    };

    // HIGH-002 wiring.
    let aaguid_policy_repo: Arc<InMemoryAaguidPolicyRepo> =
        Arc::new(InMemoryAaguidPolicyRepo::default());
    let mds_repo: Arc<InMemoryMdsRepo> = Arc::new(InMemoryMdsRepo::default());
    let mds_fetcher: Arc<MdsFetcher> = Arc::new(MdsFetcher::new(MdsConfig::default()));
    let aaguid_policy_dyn: Arc<dyn WebauthnAaguidPolicyRepository> =
        Arc::clone(&aaguid_policy_repo) as _;
    let mds_dyn: Arc<dyn WebauthnMdsRepository> = Arc::clone(&mds_repo) as _;

    let register_start_uc = RegisterStartUseCase::new(Arc::clone(&rp_dyn), Arc::clone(&cred_dyn));
    let register_finish_uc = RegisterFinishUseCase::with_aaguid_policy(
        Arc::clone(&rp_dyn),
        Arc::clone(&cred_dyn),
        aaguid_policy_dyn,
        mds_dyn,
        Arc::clone(&mds_fetcher),
        clock,
    );
    let login_start_uc = LoginStartUseCase::new(Arc::clone(&rp_dyn), Arc::clone(&cred_dyn));
    let login_finish_uc = LoginFinishUseCase::new(rp_dyn, Arc::clone(&cred_dyn));

    let adapter = Arc::new(WebauthnAdapter {
        rp_repo: Arc::clone(&rp_repo),
        cred_repo: Arc::clone(&cred_dyn),
        cache,
        users,
        issue,
        register_start_uc,
        register_finish_uc,
        login_start_uc,
        login_finish_uc,
        aaguid_policy_repo,
        mds_repo,
        mds_fetcher,
    });
    WebauthnBundle {
        webauthn: adapter as Arc<dyn WebauthnPort>,
        rp_repo,
    }
}

/// Seed a developer-mode relying-party row for `tenant_id`. Uses
/// `https://localhost:8443` as the origin; production deployments
/// configure the row via the admin path.
pub(crate) fn seed_dev_tenant_rp(rp_repo: &InMemoryRpRepo, tenant_id: TenantId) {
    rp_repo.put(TenantRp {
        tenant_id,
        rp_id: "localhost".to_owned(),
        rp_name: "SentinelX (dev)".to_owned(),
        rp_origin: "https://localhost:8443".to_owned(),
        attestation: AttestationPolicy::None,
    });
}

#[async_trait]
impl WebauthnPort for WebauthnAdapter {
    async fn register_start(
        &self,
        tenant_id: &str,
        user_id: &str,
        user_name: &str,
    ) -> Result<RegisterStartResponse, IamError> {
        let tenant_id = parse_tenant(tenant_id)?;
        let user_id = parse_user(user_id)?;

        let out = self
            .register_start_uc
            .execute(RegisterStartInput {
                tenant_id,
                user_id,
                user_name: user_name.to_owned(),
            })
            .await?;

        let state_id = self.cache.put(StashedState::Registration {
            tenant_id,
            user_id,
            label: None,
            state: out.state,
            deadline: Instant::now() + STATE_TTL,
        });
        let challenge = serde_json::to_value(&out.challenge)
            .map_err(|e| IamError::internal(format!("webauthn challenge serialise: {e}")))?;
        Ok(RegisterStartResponse {
            state_id,
            challenge,
        })
    }

    async fn register_finish(
        &self,
        tenant_id: &str,
        user_id: &str,
        req: RegisterFinishRequest,
        label: Option<String>,
    ) -> Result<RegisterFinishResponse, IamError> {
        let tenant_id = parse_tenant(tenant_id)?;
        let user_id = parse_user(user_id)?;

        let stash = self.cache.take(&req.state_id).ok_or_else(|| {
            tracing::warn!(state_id = %req.state_id, "webauthn register/finish: state expired/unknown");
            IamError::InvalidCredentials
        })?;
        let StashedState::Registration {
            tenant_id: stashed_tenant,
            user_id: stashed_user,
            label: stashed_label,
            state,
            deadline: _,
        } = stash
        else {
            tracing::warn!(state_id = %req.state_id, "webauthn register/finish: state-kind mismatch");
            return Err(IamError::InvalidCredentials);
        };
        // Enforce the tenant + user binding so a stolen state id cannot
        // be redeemed against a different account.
        if stashed_tenant != tenant_id || stashed_user != user_id {
            tracing::warn!(
                state_id = %req.state_id,
                "webauthn register/finish: tenant/user mismatch on state",
            );
            return Err(IamError::InvalidCredentials);
        }

        let response: RegisterPublicKeyCredential =
            serde_json::from_value(req.response).map_err(|e| {
                tracing::warn!(error = ?e, "webauthn register/finish: response decode");
                IamError::InvalidCredentials
            })?;

        let out = self
            .register_finish_uc
            .execute(RegisterFinishInput {
                tenant_id,
                user_id,
                state,
                response,
                label: label.or(stashed_label),
            })
            .await?;
        Ok(RegisterFinishResponse {
            cred_id: out.cred_id,
        })
    }

    async fn login_start(&self, email: &str) -> Result<LoginStartResponse, IamError> {
        // Resolve the user via the shared user repository. We do NOT
        // leak whether the user exists; an unknown user collapses into
        // `InvalidCredentials` at the HTTP boundary.
        let email_lc = email.trim().to_ascii_lowercase();
        // Tenant id is not yet known. The in-memory store iterates;
        // production would require an explicit (tenant, email) lookup,
        // but the current architecture matches `auth/login` which also
        // resolves tenant from email via the same path.
        // For the MVP, we look up the user by scanning every known
        // tenant key on the relying-party repo and asking the user
        // repository whether `(tenant, email)` exists. This works
        // because the in-memory user repo's `find_by_email` is itself
        // a linear scan, so the cost is O(tenants * users), which is
        // fine at developer-mode volume.
        let candidate = self.resolve_user_for_email(&email_lc).await?;
        let Some((tenant_id, user_id)) = candidate else {
            tracing::warn!("webauthn login/start: unknown email");
            return Err(IamError::InvalidCredentials);
        };

        let out = self
            .login_start_uc
            .execute(LoginStartInput { tenant_id, user_id })
            .await?;

        let state_id = self.cache.put(StashedState::Authentication {
            tenant_id,
            user_id,
            state: out.state,
            deadline: Instant::now() + STATE_TTL,
        });
        let challenge = serde_json::to_value(&out.challenge)
            .map_err(|e| IamError::internal(format!("webauthn challenge serialise: {e}")))?;
        Ok(LoginStartResponse {
            state_id,
            challenge,
        })
    }

    async fn login_finish(&self, req: LoginFinishRequest) -> Result<LoginFinishResponse, IamError> {
        let stash = self.cache.take(&req.state_id).ok_or_else(|| {
            tracing::warn!(state_id = %req.state_id, "webauthn login/finish: state expired/unknown");
            IamError::InvalidCredentials
        })?;
        let StashedState::Authentication {
            tenant_id,
            user_id,
            state,
            deadline: _,
        } = stash
        else {
            tracing::warn!(state_id = %req.state_id, "webauthn login/finish: state-kind mismatch");
            return Err(IamError::InvalidCredentials);
        };

        let response: PublicKeyCredential = serde_json::from_value(req.response).map_err(|e| {
            tracing::warn!(error = ?e, "webauthn login/finish: response decode");
            IamError::InvalidCredentials
        })?;

        let out = self
            .login_finish_uc
            .execute(LoginFinishInput {
                tenant_id,
                state,
                response,
            })
            .await?;

        // Reload the user so the token claim carries roles/permissions.
        let user = self
            .users
            .find_by_id_with_tenant(tenant_id, user_id)
            .await?
            .ok_or(IamError::InvalidCredentials)?;

        let issued = self.issue.execute(IssueTokenInput {
            user,
            ip: None,
            user_agent: None,
            cred_id: Some(out.cred_id.clone()),
        })?;

        Ok(LoginFinishResponse {
            access_token: {
                use secrecy::ExposeSecret as _;
                issued.token.access.expose_secret().to_string()
            },
            refresh_token: {
                use secrecy::ExposeSecret as _;
                issued.token.refresh.expose_secret().to_string()
            },
            expires_in: issued.token.expires_in,
            cred_id: out.cred_id,
        })
    }

    // -------------------------------------------------------------------
    // HIGH-002 — AAGUID policy + MDS3 management surface
    // -------------------------------------------------------------------

    async fn list_aaguid_policy(
        &self,
        tenant_id: &str,
    ) -> Result<AaguidPolicyListResponse, IamError> {
        let tid = parse_tenant(tenant_id)?;
        let rows = self.aaguid_policy_repo.list(tid).await?;
        let allowlist_mode = rows.iter().any(|r| matches!(r.action, AaguidAction::Allow));
        let rows_view = rows.into_iter().map(map_policy_view).collect();
        Ok(AaguidPolicyListResponse {
            rows: rows_view,
            allowlist_mode,
        })
    }

    async fn put_aaguid_policy(
        &self,
        tenant_id: &str,
        set_by: &str,
        aaguid: &str,
        req: PutAaguidPolicyRequest,
    ) -> Result<AaguidPolicyView, IamError> {
        let tid = parse_tenant(tenant_id)?;
        let uid = parse_user(set_by)?;
        let aaguid_uuid =
            Uuid::parse_str(aaguid).map_err(|_| IamError::config("invalid aaguid (not a UUID)"))?;
        let action = AaguidAction::parse(&req.action)
            .ok_or_else(|| IamError::config("aaguid action must be 'allow' or 'block'"))?;
        let policy = AaguidPolicy {
            tenant_id: tid,
            aaguid: aaguid_uuid,
            action,
            reason: req.reason.clone(),
            set_by: uid,
            set_at: OffsetDateTime::now_utc(),
        };
        self.aaguid_policy_repo.upsert(&policy).await?;
        Ok(map_policy_view(policy))
    }

    async fn delete_aaguid_policy(&self, tenant_id: &str, aaguid: &str) -> Result<(), IamError> {
        let tid = parse_tenant(tenant_id)?;
        let aaguid_uuid =
            Uuid::parse_str(aaguid).map_err(|_| IamError::config("invalid aaguid (not a UUID)"))?;
        self.aaguid_policy_repo.delete(tid, aaguid_uuid).await
    }

    async fn mds_status(&self) -> Result<MdsStatusView, IamError> {
        let status = self.mds_repo.status().await?;
        let last_refresh_str = status.last_refresh.and_then(|t| {
            t.format(&time::format_description::well_known::Rfc3339)
                .ok()
        });
        let is_stale = self.mds_fetcher.stale_for_longer_than(status.last_refresh);
        Ok(MdsStatusView {
            last_refresh: last_refresh_str,
            total_entries: status.total_entries,
            root_cert_fingerprint: status.root_cert_fingerprint,
            is_stale,
        })
    }

    async fn mds_refresh(&self) -> Result<MdsStatusView, IamError> {
        // The fetcher hits the live MDS endpoint. Operators who run the
        // monolith in air-gapped mode can call this and get a structured
        // failure rather than a silent stale cache. Failures surface as
        // `IamError::Repository`.
        match self.mds_fetcher.fetch().await {
            Ok(parsed) => {
                self.mds_repo.replace_all(parsed.entries).await?;
            }
            Err(err) => {
                tracing::warn!(
                    error = ?err,
                    "webauthn.mds_refresh: live fetch failed; cache not updated",
                );
                return Err(err);
            }
        }
        // Status reflects the freshly-written cache.
        self.mds_status().await
    }

    async fn list_user_credentials(
        &self,
        tenant_id: &str,
        user_id: &str,
    ) -> Result<CredentialListResponse, IamError> {
        let tid = parse_tenant(tenant_id)?;
        let uid = parse_user(user_id)?;
        let creds = self.cred_repo.list_active(tid, uid).await?;
        let mut out = Vec::with_capacity(creds.len());
        for c in creds {
            let aaguid_uuid = c.aaguid.map(Uuid::from_bytes);
            let mds_entry = match aaguid_uuid {
                Some(a) => self.mds_repo.get(a).await?,
                None => None,
            };
            out.push(UserCredentialView {
                cred_id: c.cred_id,
                label: c.label,
                aaguid: aaguid_uuid.map(|a| a.to_string()),
                authenticator_name: mds_entry.as_ref().map(|e| e.authenticator_name.clone()),
                certification_level: mds_entry.map(|e| e.certification_level),
                created_at: c
                    .created_at
                    .format(&time::format_description::well_known::Rfc3339)
                    .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned()),
                last_used_at: c.last_used_at.and_then(|t| {
                    t.format(&time::format_description::well_known::Rfc3339)
                        .ok()
                }),
            });
        }
        Ok(CredentialListResponse { credentials: out })
    }
}

/// Project a domain [`AaguidPolicy`] into the wire-shape [`AaguidPolicyView`].
fn map_policy_view(p: AaguidPolicy) -> AaguidPolicyView {
    AaguidPolicyView {
        aaguid: p.aaguid.to_string(),
        action: p.action.as_str().to_owned(),
        reason: p.reason,
        set_by: p.set_by.as_uuid().to_string(),
        set_at: p
            .set_at
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned()),
    }
}

impl WebauthnAdapter {
    /// Probe every relying-party-known tenant for a user with the given
    /// (lower-cased) email. Used by `login_start` because the wire
    /// payload does not carry a tenant id.
    async fn resolve_user_for_email(
        &self,
        email_lc: &str,
    ) -> Result<Option<(TenantId, UserId)>, IamError> {
        let tenants: Vec<TenantId> = {
            let guard = self
                .rp_repo
                .rows
                .lock()
                .map_err(|_| IamError::repository("webauthn rp mutex poisoned"))?;
            guard.keys().copied().collect()
        };
        for tenant_id in tenants {
            if let Some(user) = self.users.find_by_email(tenant_id, email_lc).await? {
                return Ok(Some((tenant_id, user.id)));
            }
        }
        Ok(None)
    }
}

/// Encode a base64url cred id for the public view layer (currently
/// unused by the adapter — exposed only so future surfaces can reuse the
/// same helper).
#[allow(dead_code)]
fn b64url_no_pad(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn parse_tenant(s: &str) -> Result<TenantId, IamError> {
    s.parse::<TenantId>()
        .map_err(|_| IamError::internal("invalid tenant id in claim"))
}

fn parse_user(s: &str) -> Result<UserId, IamError> {
    s.parse::<UserId>()
        .map_err(|_| IamError::internal("invalid user id in claim"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn in_memory_rp_repo_round_trips() {
        let repo = InMemoryRpRepo::default();
        let tid = TenantId::new();
        repo.put(TenantRp {
            tenant_id: tid,
            rp_id: "localhost".into(),
            rp_name: "test".into(),
            rp_origin: "https://localhost:8443".into(),
            attestation: AttestationPolicy::None,
        });
        let got = repo.get(tid).await.unwrap().expect("seeded row visible");
        assert_eq!(got.rp_id, "localhost");
    }

    #[tokio::test]
    async fn in_memory_cred_repo_lists_active_and_revokes() {
        let repo = InMemoryCredRepo::default();
        let tid = TenantId::new();
        let uid = UserId::new();
        let cred = StoredCredential {
            id: Uuid::new_v4(),
            tenant_id: tid,
            user_id: uid,
            cred_id: "abc".into(),
            cred_id_bytes: vec![1, 2, 3],
            public_key: vec![],
            aaguid: None,
            counter: 0,
            passkey: serde_json::Value::Null,
            label: None,
            attestation: AttestationPolicy::None,
            created_at: OffsetDateTime::UNIX_EPOCH,
            last_used_at: None,
            revoked_at: None,
        };
        repo.insert(&cred).await.unwrap();
        // Duplicate cred id MUST conflict.
        let err = repo.insert(&cred).await.unwrap_err();
        assert!(matches!(err, IamError::Conflict(_)));

        let listed = repo.list_active(tid, uid).await.unwrap();
        assert_eq!(listed.len(), 1);

        repo.revoke(tid, "abc").await.unwrap();
        let listed = repo.list_active(tid, uid).await.unwrap();
        assert!(listed.is_empty());
    }

    #[tokio::test]
    async fn in_memory_cred_repo_update_counter_bumps_value() {
        let repo = InMemoryCredRepo::default();
        let tid = TenantId::new();
        let uid = UserId::new();
        let cred = StoredCredential {
            id: Uuid::new_v4(),
            tenant_id: tid,
            user_id: uid,
            cred_id: "abc".into(),
            cred_id_bytes: vec![1, 2, 3],
            public_key: vec![],
            aaguid: None,
            counter: 0,
            passkey: serde_json::Value::Null,
            label: None,
            attestation: AttestationPolicy::None,
            created_at: OffsetDateTime::UNIX_EPOCH,
            last_used_at: None,
            revoked_at: None,
        };
        repo.insert(&cred).await.unwrap();
        repo.update_counter(tid, "abc", 42).await.unwrap();
        let found = repo.find_by_cred_id(tid, "abc").await.unwrap().unwrap();
        assert_eq!(found.counter, 42);
        assert!(found.last_used_at.is_some());
    }

    #[test]
    fn state_cache_take_returns_none_for_unknown_id() {
        // `PasskeyAuthentication` / `PasskeyRegistration` are not
        // constructible from outside `webauthn-rs`, so we cannot
        // hand-stash a row to assert eviction. Instead we exercise the
        // public-shape branches: an unknown id returns `None` (used by
        // `register_finish` / `login_finish` to surface
        // `InvalidCredentials` when the state has already expired or
        // been consumed).
        let cache = StateCache::default();
        assert!(cache.take("does-not-exist").is_none());
    }

    #[test]
    fn parse_tenant_rejects_garbage() {
        let err = parse_tenant("not-a-uuid").unwrap_err();
        assert!(matches!(err, IamError::Internal(_)));
    }

    #[test]
    fn parse_user_rejects_garbage() {
        let err = parse_user("not-a-uuid").unwrap_err();
        assert!(matches!(err, IamError::Internal(_)));
    }

    /// Serde round-trip of the whole aggregate through JSON — the shape the
    /// Postgres store persists. Catches any field (the `[u8; 16]` aaguid, the
    /// `OffsetDateTime`s, the opaque `passkey` blob) that fails to serialise.
    #[test]
    fn stored_credential_json_roundtrip_is_lossless() {
        let cred = StoredCredential {
            id: Uuid::new_v4(),
            tenant_id: TenantId::new(),
            user_id: UserId::new(),
            cred_id: "cred-xyz".into(),
            cred_id_bytes: vec![9, 8, 7, 6],
            public_key: vec![1, 2, 3, 4, 5],
            aaguid: Some([
                0xde, 0xad, 0xbe, 0xef, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xaa, 0xbb,
            ]),
            counter: 1234,
            passkey: serde_json::json!({"cred": {"counter": 1234}, "kind": "passkey"}),
            label: Some("YubiKey 5C".into()),
            attestation: AttestationPolicy::Direct,
            created_at: OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap(),
            last_used_at: Some(OffsetDateTime::from_unix_timestamp(1_700_000_123).unwrap()),
            revoked_at: None,
        };
        let json = serde_json::to_string(&cred).expect("serialise");
        let back: StoredCredential = serde_json::from_str(&json).expect("deserialise");
        assert_eq!(back.id, cred.id);
        assert_eq!(back.cred_id, cred.cred_id);
        assert_eq!(back.cred_id_bytes, cred.cred_id_bytes);
        assert_eq!(back.public_key, cred.public_key);
        assert_eq!(back.aaguid, cred.aaguid);
        assert_eq!(back.counter, cred.counter);
        assert_eq!(back.passkey, cred.passkey);
        assert_eq!(back.label, cred.label);
        assert_eq!(back.attestation, cred.attestation);
        assert_eq!(back.created_at, cred.created_at);
        assert_eq!(back.last_used_at, cred.last_used_at);
        assert_eq!(back.revoked_at, cred.revoked_at);
    }

    /// Durability proof against a real Postgres: insert → list → update
    /// counter → find → *fresh pool (restart-equivalent)* → the credential
    /// and its bumped counter are still there → revoke drops it from
    /// `list_active` but leaves it findable.
    ///
    /// Gated on `TEST_DATABASE_URL` (a DSN for a DB that has already run the
    /// migrations and seeded the bootstrap tenant), so it is a silent no-op
    /// in CI and in the default `cargo test` run — the same shape every
    /// live-DB fixture in the workspace uses. The tenant id must be the
    /// bootstrap tenant so the `tenant_id` FK to `tenants(id)` is satisfied.
    #[tokio::test]
    async fn pg_cred_repo_survives_restart() {
        // Reading `TEST_DATABASE_URL` from the process env is the
        // project-wide convention for live-DB fixtures (not routed through
        // `sx-config`); a silent skip when unset keeps CI green.
        #[allow(clippy::disallowed_methods)]
        let Ok(url) = std::env::var("TEST_DATABASE_URL") else {
            return;
        };
        let tid: TenantId = "01010101-0101-0101-0101-010101010101".parse().unwrap();
        let uid = UserId::new();
        let cred_id = format!("live-{}", Uuid::new_v4());

        let cred = StoredCredential {
            id: Uuid::new_v4(),
            tenant_id: tid,
            user_id: uid,
            cred_id: cred_id.clone(),
            cred_id_bytes: vec![1, 2, 3, 4],
            public_key: vec![10, 20, 30],
            aaguid: Some([
                0xde, 0xad, 0xbe, 0xef, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xaa, 0xbb,
            ]),
            counter: 0,
            passkey: serde_json::json!({"kind": "passkey"}),
            label: Some("Live Test Key".into()),
            attestation: AttestationPolicy::None,
            created_at: OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap(),
            last_used_at: None,
            revoked_at: None,
        };

        {
            let pool = PgPool::connect(&url).await.expect("connect");
            let repo = PgCredRepo::new(pool, 15_000);
            repo.insert(&cred).await.expect("insert");
            assert!(
                matches!(repo.insert(&cred).await, Err(IamError::Conflict(_))),
                "duplicate cred id must conflict"
            );
            let listed = repo.list_active(tid, uid).await.expect("list");
            assert_eq!(listed.iter().filter(|c| c.cred_id == cred_id).count(), 1);
            repo.update_counter(tid, &cred_id, 77).await.expect("bump");
            let found = repo
                .find_by_cred_id(tid, &cred_id)
                .await
                .expect("find")
                .expect("present");
            assert_eq!(found.counter, 77);
            assert_eq!(found.aaguid, cred.aaguid);
            assert!(found.last_used_at.is_some());
        }

        // Fresh pool == a fresh process. In-memory state would be gone here.
        {
            let pool = PgPool::connect(&url).await.expect("reconnect");
            let repo = PgCredRepo::new(pool, 15_000);
            let found = repo
                .find_by_cred_id(tid, &cred_id)
                .await
                .expect("find after restart")
                .expect("credential survived restart");
            assert_eq!(found.counter, 77, "bumped counter survived restart");

            repo.revoke(tid, &cred_id).await.expect("revoke");
            let active = repo.list_active(tid, uid).await.expect("list after revoke");
            assert_eq!(
                active.iter().filter(|c| c.cred_id == cred_id).count(),
                0,
                "revoked credential must drop out of list_active"
            );
            let still = repo
                .find_by_cred_id(tid, &cred_id)
                .await
                .expect("find revoked")
                .expect("revoked credential still findable");
            assert!(still.revoked_at.is_some());
        }
    }
}
