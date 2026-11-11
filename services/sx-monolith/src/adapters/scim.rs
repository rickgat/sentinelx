//! SCIM 2.0 adapter — in-memory implementation of
//! [`sx_api::port::ScimProvisionPort`].
//!
//! Bundles four concerns:
//!
//! 1. The actual SCIM provisioner (`sx_scim::service::InMemoryScimProvisioner`)
//!    — owns Users / Groups + filter evaluation.
//! 2. A per-tenant SCIM bearer-token store, with SHA-256 hash storage and
//!    constant-time comparison via [`subtle::ConstantTimeEq`].
//! 3. The MED-005 token-lifecycle state machine: scopes, expiry,
//!    rotation grace window, immediate revoke.
//! 4. An audit log keyed by `(tenant_id, action, scim_user_id)` — every
//!    CREATE / UPDATE / DELETE the controller routes through here lands a
//!    row, plus every mint / rotate / revoke / scope-violation rejection.
//!
//! The Postgres path lands in a later phase. For now the adapter is purely
//! in-memory so dev / test boots without a database.
//!
//! ## Bearer token format
//!
//! Tokens are minted as `scim_<32-bytes-base64url>`. The plaintext is
//! returned exactly once from `mint_token`; only the SHA-256 hash is
//! retained server-side.
//!
//! ## Constant-time compare
//!
//! `authenticate` hashes the incoming bearer with SHA-256 and walks every
//! known hash, calling `ConstantTimeEq::ct_eq` on each. Walking every row
//! (vs. short-circuiting on the first match) preserves the constant-time
//! property over the whole table — no timing side-channel on token id.
//!
//! ## Lifecycle (MED-005)
//!
//! - `Active`   — created, not yet rotated, not expired, not revoked.
//! - `Grace`    — rotated; `retired_at = now + grace_window` was stamped
//!   on the OLD row. Both rows authenticate until then.
//! - `Expired`  — past `expires_at` *or* (after rotation) past
//!   `retired_at`. Returns `ScimError::Expired`.
//! - `Revoked`  — `revoke_token` was called. Returns `ScimError::Unauthorised`
//!   immediately.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::types::Json;
use sqlx::{PgPool, Row as _};
use subtle::ConstantTimeEq;
use sx_api::port::{ScimAuthContext, ScimProvisionPort};
use sx_api::view::scim_view::{ScimTokenStatus, ScimTokenView};
use sx_scim::filter::{parse as parse_scim_filter, Filter};
use sx_scim::schema::group::ScimGroup;
use sx_scim::schema::meta::Meta;
use sx_scim::schema::user::ScimUser;
use sx_scim::scope::{ScimRotationPolicy, ScimScope};
use sx_scim::service::provisioner::{
    InMemoryScimProvisioner, ListGroupsResult, ListUsersQuery, ListUsersResult, ScimProvisioner,
};
use sx_scim::ScimError;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// Raw byte length of a SCIM bearer token (pre-base64).
const TOKEN_BYTES: usize = 32;

/// Plain-text prefix prepended to a freshly minted token so operators
/// can recognise it.
const TOKEN_PREFIX: &str = "scim_";

/// Hash size for SHA-256 (constant for clarity at call sites).
const HASH_BYTES: usize = 32;

/// Trait abstraction over the wall clock so tests can run deterministic
/// rotation / grace-window assertions without `tokio::time::sleep`.
pub(crate) trait Clock: Send + Sync + std::fmt::Debug {
    fn now(&self) -> OffsetDateTime;
}

/// Real wall-clock implementation.
#[derive(Debug, Default)]
pub(crate) struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
}

/// One stored SCIM token row — the SHA-256 hash of the plaintext plus
/// lifecycle metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct TokenRow {
    id: String,
    tenant_id: String,
    name: String,
    hash: [u8; HASH_BYTES],
    scopes: Vec<ScimScope>,
    created_at: OffsetDateTime,
    activated_at: OffsetDateTime,
    expires_at: OffsetDateTime,
    retired_at: Option<OffsetDateTime>,
    revoked_at: Option<OffsetDateTime>,
    last_used_at: Option<OffsetDateTime>,
}

impl TokenRow {
    fn to_view(&self, now: OffsetDateTime) -> ScimTokenView {
        ScimTokenView {
            id: self.id.clone(),
            tenant_id: self.tenant_id.clone(),
            name: self.name.clone(),
            scopes: self.scopes.iter().map(|s| s.as_str().to_owned()).collect(),
            status: self.status_at(now),
            created_at: format_rfc3339(self.created_at),
            activated_at: format_rfc3339(self.activated_at),
            expires_at: format_rfc3339(self.expires_at),
            retired_at: self.retired_at.map(format_rfc3339),
            revoked_at: self.revoked_at.map(format_rfc3339),
            last_used_at: self.last_used_at.map(format_rfc3339),
        }
    }

    fn status_at(&self, now: OffsetDateTime) -> ScimTokenStatus {
        if self.revoked_at.is_some() {
            return ScimTokenStatus::Revoked;
        }
        if let Some(retired) = self.retired_at {
            if now >= retired {
                return ScimTokenStatus::Expired;
            }
            return ScimTokenStatus::Grace;
        }
        if now >= self.expires_at {
            return ScimTokenStatus::Expired;
        }
        ScimTokenStatus::Active
    }
}

fn format_rfc3339(t: OffsetDateTime) -> String {
    t.format(&Rfc3339).unwrap_or_else(|_| String::new())
}

// ---------------------------------------------------------------------------
// Token store seam — in-memory (dev) or durable Postgres.
// ---------------------------------------------------------------------------

/// Storage seam for SCIM bearer-token rows. Abstracts the token table so
/// the lifecycle state machine (mint / rotate / grace / revoke) in
/// [`InMemoryScim`] runs unchanged over either the in-memory map or the
/// durable Postgres table.
///
/// `find_by_hash` is the authentication lookup: it takes the SHA-256 of the
/// presented bearer and returns the matching row (if any). The in-memory
/// implementation walks every row with a constant-time compare to avoid a
/// timing side-channel on token id; the Postgres implementation resolves it
/// with an indexed exact-match on the hash column (the comparison happens in
/// the database, so the adapter's control flow leaks nothing).
#[async_trait]
pub(crate) trait ScimTokenStore: Send + Sync + std::fmt::Debug {
    async fn insert(&self, row: TokenRow) -> Result<(), ScimError>;
    async fn get(&self, id: &str) -> Result<Option<TokenRow>, ScimError>;
    async fn find_by_hash(&self, hash: [u8; HASH_BYTES]) -> Result<Option<TokenRow>, ScimError>;
    /// Upsert by `id` — used to persist lifecycle mutations (retire on
    /// rotate, revoke, last-used stamp).
    async fn update(&self, row: &TokenRow) -> Result<(), ScimError>;
    async fn list_by_tenant(&self, tenant_id: &str) -> Result<Vec<TokenRow>, ScimError>;
}

/// In-memory token store — the dev / quick-start default. Keyed by token id.
#[derive(Debug, Default)]
pub(crate) struct InMemoryScimTokenStore {
    rows: Mutex<HashMap<String, TokenRow>>,
}

#[async_trait]
impl ScimTokenStore for InMemoryScimTokenStore {
    async fn insert(&self, row: TokenRow) -> Result<(), ScimError> {
        let mut guard = self
            .rows
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.insert(row.id.clone(), row);
        Ok(())
    }

    async fn get(&self, id: &str) -> Result<Option<TokenRow>, ScimError> {
        let guard = self
            .rows
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Ok(guard.get(id).cloned())
    }

    async fn find_by_hash(&self, hash: [u8; HASH_BYTES]) -> Result<Option<TokenRow>, ScimError> {
        let guard = self
            .rows
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Walk every row (vs. short-circuit) to preserve the constant-time
        // property over the whole table — no timing side-channel on id.
        let mut matched: Option<TokenRow> = None;
        for row in guard.values() {
            let eq: bool = row.hash.ct_eq(&hash).into();
            if eq {
                matched = Some(row.clone());
            }
        }
        Ok(matched)
    }

    async fn update(&self, row: &TokenRow) -> Result<(), ScimError> {
        let mut guard = self
            .rows
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.insert(row.id.clone(), row.clone());
        Ok(())
    }

    async fn list_by_tenant(&self, tenant_id: &str) -> Result<Vec<TokenRow>, ScimError> {
        let guard = self
            .rows
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Ok(guard
            .values()
            .filter(|r| r.tenant_id == tenant_id)
            .cloned()
            .collect())
    }
}

/// Postgres-backed token store (durable across restart).
///
/// The composition root bound SCIM bearer tokens to an in-memory map, so
/// every tenant's provisioning token — the credential an IdP uses to push
/// users/groups — was lost on a monolith restart, silently breaking the
/// integration until an admin re-minted and re-configured a token. This
/// store persists them.
///
/// The full [`TokenRow`] (hash, scopes, lifecycle timestamps) is stored as
/// JSONB in `scim_tokens`, keyed by the token `id`, with a `token_hash`
/// column carrying a UNIQUE index for the `authenticate` lookup and a
/// `tenant_id` column for per-tenant listing. The token id and hash are
/// globally unique, and `authenticate` runs before any tenant is known, so
/// — like `mfa_enrollments` — this table is intentionally NOT under tenant
/// RLS; isolation is by the explicit `tenant_id` filter the lifecycle
/// methods (list / rotate / revoke) already enforce.
pub(crate) struct PgScimTokenStore {
    pool: PgPool,
    stmt_timeout_ms: u64,
}

impl std::fmt::Debug for PgScimTokenStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PgScimTokenStore").finish_non_exhaustive()
    }
}

impl PgScimTokenStore {
    pub(crate) const fn new(pool: PgPool, stmt_timeout_ms: u64) -> Self {
        Self {
            pool,
            stmt_timeout_ms,
        }
    }

    fn repo_err(e: impl std::fmt::Display) -> ScimError {
        ScimError::internal(format!("scim token store: {e}"))
    }

    /// Apply a per-statement timeout so a slow/locked row cannot hang the
    /// auth path. `SET LOCAL` must run inside a transaction.
    async fn set_timeout(&self, tx: &mut sqlx::PgConnection) -> Result<(), ScimError> {
        let bounded = self.stmt_timeout_ms.clamp(1, 60_000);
        sqlx::query(&format!("SET LOCAL statement_timeout = {bounded}"))
            .execute(&mut *tx)
            .await
            .map(|_| ())
            .map_err(Self::repo_err)
    }

    fn decode(row: &sqlx::postgres::PgRow) -> Result<TokenRow, ScimError> {
        row.try_get::<Json<TokenRow>, _>("aggregate")
            .map(|j| j.0)
            .map_err(Self::repo_err)
    }
}

#[async_trait]
impl ScimTokenStore for PgScimTokenStore {
    async fn insert(&self, row: TokenRow) -> Result<(), ScimError> {
        let mut tx = self.pool.begin().await.map_err(Self::repo_err)?;
        self.set_timeout(&mut tx).await?;
        sqlx::query(
            "INSERT INTO scim_tokens (id, tenant_id, token_hash, aggregate, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, now(), now())",
        )
        .bind(&row.id)
        .bind(&row.tenant_id)
        .bind(row.hash.as_slice())
        .bind(Json(&row))
        .execute(&mut *tx)
        .await
        .map_err(Self::repo_err)?;
        tx.commit().await.map_err(Self::repo_err)
    }

    async fn get(&self, id: &str) -> Result<Option<TokenRow>, ScimError> {
        let mut tx = self.pool.begin().await.map_err(Self::repo_err)?;
        self.set_timeout(&mut tx).await?;
        let row = sqlx::query("SELECT aggregate FROM scim_tokens WHERE id = $1")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(Self::repo_err)?;
        tx.commit().await.map_err(Self::repo_err)?;
        row.as_ref().map(Self::decode).transpose()
    }

    async fn find_by_hash(&self, hash: [u8; HASH_BYTES]) -> Result<Option<TokenRow>, ScimError> {
        let mut tx = self.pool.begin().await.map_err(Self::repo_err)?;
        self.set_timeout(&mut tx).await?;
        let row = sqlx::query("SELECT aggregate FROM scim_tokens WHERE token_hash = $1")
            .bind(hash.as_slice())
            .fetch_optional(&mut *tx)
            .await
            .map_err(Self::repo_err)?;
        tx.commit().await.map_err(Self::repo_err)?;
        row.as_ref().map(Self::decode).transpose()
    }

    async fn update(&self, row: &TokenRow) -> Result<(), ScimError> {
        let mut tx = self.pool.begin().await.map_err(Self::repo_err)?;
        self.set_timeout(&mut tx).await?;
        sqlx::query("UPDATE scim_tokens SET aggregate = $2, updated_at = now() WHERE id = $1")
            .bind(&row.id)
            .bind(Json(row))
            .execute(&mut *tx)
            .await
            .map_err(Self::repo_err)?;
        tx.commit().await.map_err(Self::repo_err)
    }

    async fn list_by_tenant(&self, tenant_id: &str) -> Result<Vec<TokenRow>, ScimError> {
        let mut tx = self.pool.begin().await.map_err(Self::repo_err)?;
        self.set_timeout(&mut tx).await?;
        let rows = sqlx::query("SELECT aggregate FROM scim_tokens WHERE tenant_id = $1")
            .bind(tenant_id)
            .fetch_all(&mut *tx)
            .await
            .map_err(Self::repo_err)?;
        tx.commit().await.map_err(Self::repo_err)?;
        rows.iter().map(Self::decode).collect()
    }
}

// ---------------------------------------------------------------------------
// Durable SCIM provisioner (users + groups) — Postgres.
// ---------------------------------------------------------------------------

/// RFC 7644 §3.4.2 pagination: `startIndex` is 1-based; an out-of-range start
/// clamps to `total + 1` (an empty page). Mirrors `sx_scim`'s own helper.
fn scim_pagination(
    start_index: Option<usize>,
    count: Option<usize>,
    total: usize,
) -> (usize, usize) {
    let start = start_index.unwrap_or(1).max(1);
    let start = if start > total { total + 1 } else { start };
    let count = count.unwrap_or(100).min(1_000);
    (start, count)
}

/// Postgres-backed [`ScimProvisioner`] (durable users + groups).
///
/// The composition root bound the SCIM provisioner to an in-memory map, so
/// every SCIM-provisioned user and group was lost on a monolith restart. When
/// `database.enabled` this adapter persists them. Each resource is stored as
/// JSONB keyed by `(tenant_id, id)`, with a `resource_name` column
/// (`userName` / `displayName`) carrying a case-insensitive UNIQUE index so
/// the RFC 7644 §3.3 duplicate-name 409 is enforced in the database.
///
/// Soft-delete (user `active = false`) keeps the row — matching the in-memory
/// store and SCIM deprovisioning conventions — so a deprovisioned `userName`
/// still reserves its name. `list_*` loads the tenant's rows and applies the
/// same `sx_scim` filter evaluator + pagination as the in-memory path.
///
/// Keyed by a globally-unique resource id and filtered explicitly by
/// `tenant_id`, this table is intentionally NOT under tenant RLS (same
/// rationale as the other IAM stores wired in this program); isolation is by
/// the explicit `tenant_id` predicate every query carries.
pub(crate) struct PgScimProvisioner {
    pool: PgPool,
    stmt_timeout_ms: u64,
}

impl std::fmt::Debug for PgScimProvisioner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PgScimProvisioner").finish_non_exhaustive()
    }
}

impl PgScimProvisioner {
    pub(crate) const fn new(pool: PgPool, stmt_timeout_ms: u64) -> Self {
        Self {
            pool,
            stmt_timeout_ms,
        }
    }

    fn repo_err(e: impl std::fmt::Display) -> ScimError {
        ScimError::internal(format!("scim provisioner: {e}"))
    }

    fn next_id_and_ts() -> (String, String) {
        let id = uuid::Uuid::new_v4().to_string();
        let ts = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned());
        (id, ts)
    }

    async fn set_timeout(&self, tx: &mut sqlx::PgConnection) -> Result<(), ScimError> {
        let bounded = self.stmt_timeout_ms.clamp(1, 60_000);
        sqlx::query(&format!("SET LOCAL statement_timeout = {bounded}"))
            .execute(&mut *tx)
            .await
            .map(|_| ())
            .map_err(Self::repo_err)
    }

    /// `true` when another row in `table` for `tenant_id` already carries
    /// `name` (case-insensitive), excluding `exclude_id` when given.
    async fn name_taken(
        tx: &mut sqlx::PgConnection,
        table: &str,
        tenant_id: &str,
        name: &str,
        exclude_id: Option<&str>,
    ) -> Result<bool, ScimError> {
        // `table` is a compile-time constant ("scim_users"/"scim_groups"),
        // never user input, so the format is injection-safe.
        let sql = format!(
            "SELECT 1 FROM {table} \
             WHERE tenant_id = $1 AND lower(resource_name) = lower($2) \
               AND ($3::text IS NULL OR id <> $3) LIMIT 1"
        );
        let hit = sqlx::query(&sql)
            .bind(tenant_id)
            .bind(name)
            .bind(exclude_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(Self::repo_err)?;
        Ok(hit.is_some())
    }
}

#[async_trait]
impl ScimProvisioner for PgScimProvisioner {
    async fn create_user(
        &self,
        tenant_id: &str,
        mut user: ScimUser,
    ) -> Result<ScimUser, ScimError> {
        user.validate().map_err(ScimError::invalid_request)?;
        let mut tx = self.pool.begin().await.map_err(Self::repo_err)?;
        self.set_timeout(&mut tx).await?;
        if Self::name_taken(&mut tx, "scim_users", tenant_id, &user.user_name, None).await? {
            return Err(ScimError::conflict("userName already exists"));
        }
        let (id, ts) = Self::next_id_and_ts();
        user.id = Some(id.clone());
        user.meta = Some(Meta::new("User", &ts, format!("/scim/v2/Users/{id}")));
        sqlx::query(
            "INSERT INTO scim_users (tenant_id, id, resource_name, aggregate, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, now(), now())",
        )
        .bind(tenant_id)
        .bind(&id)
        .bind(&user.user_name)
        .bind(Json(&user))
        .execute(&mut *tx)
        .await
        .map_err(Self::repo_err)?;
        tx.commit().await.map_err(Self::repo_err)?;
        Ok(user)
    }

    async fn get_user(&self, tenant_id: &str, id: &str) -> Result<ScimUser, ScimError> {
        let mut tx = self.pool.begin().await.map_err(Self::repo_err)?;
        self.set_timeout(&mut tx).await?;
        let row = sqlx::query("SELECT aggregate FROM scim_users WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(Self::repo_err)?;
        tx.commit().await.map_err(Self::repo_err)?;
        let row = row.ok_or(ScimError::NotFound)?;
        row.try_get::<Json<ScimUser>, _>("aggregate")
            .map(|j| j.0)
            .map_err(Self::repo_err)
    }

    async fn replace_user(
        &self,
        tenant_id: &str,
        id: &str,
        mut user: ScimUser,
    ) -> Result<ScimUser, ScimError> {
        user.validate().map_err(ScimError::invalid_request)?;
        let mut tx = self.pool.begin().await.map_err(Self::repo_err)?;
        self.set_timeout(&mut tx).await?;
        let existing = sqlx::query(
            "SELECT aggregate FROM scim_users WHERE tenant_id = $1 AND id = $2 FOR UPDATE",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(Self::repo_err)?
        .ok_or(ScimError::NotFound)?;
        let existing: ScimUser = existing
            .try_get::<Json<ScimUser>, _>("aggregate")
            .map(|j| j.0)
            .map_err(Self::repo_err)?;
        // A `userName` change must not collide with another user.
        if !existing.user_name.eq_ignore_ascii_case(&user.user_name)
            && Self::name_taken(&mut tx, "scim_users", tenant_id, &user.user_name, Some(id)).await?
        {
            return Err(ScimError::conflict("userName already exists"));
        }
        let (_, ts) = Self::next_id_and_ts();
        user.id = Some(id.to_owned());
        let mut meta = existing
            .meta
            .clone()
            .unwrap_or_else(|| Meta::new("User", &ts, format!("/scim/v2/Users/{id}")));
        meta.touch(&ts);
        user.meta = Some(meta);
        sqlx::query(
            "UPDATE scim_users SET resource_name = $3, aggregate = $4, updated_at = now() \
             WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(id)
        .bind(&user.user_name)
        .bind(Json(&user))
        .execute(&mut *tx)
        .await
        .map_err(Self::repo_err)?;
        tx.commit().await.map_err(Self::repo_err)?;
        Ok(user)
    }

    async fn delete_user(&self, tenant_id: &str, id: &str) -> Result<(), ScimError> {
        let mut tx = self.pool.begin().await.map_err(Self::repo_err)?;
        self.set_timeout(&mut tx).await?;
        let row = sqlx::query(
            "SELECT aggregate FROM scim_users WHERE tenant_id = $1 AND id = $2 FOR UPDATE",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(Self::repo_err)?
        .ok_or(ScimError::NotFound)?;
        let mut user: ScimUser = row
            .try_get::<Json<ScimUser>, _>("aggregate")
            .map(|j| j.0)
            .map_err(Self::repo_err)?;
        // SCIM deprovisioning: flip `active = false` rather than hard-delete
        // so the row (and its reserved userName) survives.
        user.active = false;
        let (_, ts) = Self::next_id_and_ts();
        if let Some(meta) = user.meta.as_mut() {
            meta.touch(&ts);
        }
        sqlx::query(
            "UPDATE scim_users SET aggregate = $3, updated_at = now() \
             WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(id)
        .bind(Json(&user))
        .execute(&mut *tx)
        .await
        .map_err(Self::repo_err)?;
        tx.commit().await.map_err(Self::repo_err)?;
        Ok(())
    }

    async fn list_users(
        &self,
        tenant_id: &str,
        query: ListUsersQuery,
    ) -> Result<ListUsersResult, ScimError> {
        let mut tx = self.pool.begin().await.map_err(Self::repo_err)?;
        self.set_timeout(&mut tx).await?;
        let rows = sqlx::query("SELECT aggregate FROM scim_users WHERE tenant_id = $1")
            .bind(tenant_id)
            .fetch_all(&mut *tx)
            .await
            .map_err(Self::repo_err)?;
        tx.commit().await.map_err(Self::repo_err)?;
        let users: Vec<ScimUser> = rows
            .iter()
            .map(|r| {
                r.try_get::<Json<ScimUser>, _>("aggregate")
                    .map(|j| j.0)
                    .map_err(Self::repo_err)
            })
            .collect::<Result<_, _>>()?;
        // Same filter + sort + pagination as the in-memory provisioner.
        let mut filtered: Vec<ScimUser> = match query.filter.as_deref() {
            None => users,
            Some(raw) => {
                let ast: Filter = parse_scim_filter(raw)?;
                users
                    .into_iter()
                    .filter(|u| {
                        let v = serde_json::to_value(u).unwrap_or(serde_json::Value::Null);
                        ast.matches(&v)
                    })
                    .collect()
            }
        };
        filtered.sort_by(|a, b| a.user_name.cmp(&b.user_name));
        let total = filtered.len();
        let (start, count) = scim_pagination(query.start_index, query.count, total);
        let resources: Vec<ScimUser> = filtered.into_iter().skip(start - 1).take(count).collect();
        Ok(ListUsersResult {
            total_results: total,
            start_index: start,
            items_per_page: resources.len(),
            resources,
        })
    }

    async fn create_group(
        &self,
        tenant_id: &str,
        mut group: ScimGroup,
    ) -> Result<ScimGroup, ScimError> {
        group.validate().map_err(ScimError::invalid_request)?;
        let mut tx = self.pool.begin().await.map_err(Self::repo_err)?;
        self.set_timeout(&mut tx).await?;
        if Self::name_taken(&mut tx, "scim_groups", tenant_id, &group.display_name, None).await? {
            return Err(ScimError::conflict("displayName already exists"));
        }
        let (id, ts) = Self::next_id_and_ts();
        group.id = Some(id.clone());
        group.meta = Some(Meta::new("Group", &ts, format!("/scim/v2/Groups/{id}")));
        sqlx::query(
            "INSERT INTO scim_groups (tenant_id, id, resource_name, aggregate, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, now(), now())",
        )
        .bind(tenant_id)
        .bind(&id)
        .bind(&group.display_name)
        .bind(Json(&group))
        .execute(&mut *tx)
        .await
        .map_err(Self::repo_err)?;
        tx.commit().await.map_err(Self::repo_err)?;
        Ok(group)
    }

    async fn get_group(&self, tenant_id: &str, id: &str) -> Result<ScimGroup, ScimError> {
        let mut tx = self.pool.begin().await.map_err(Self::repo_err)?;
        self.set_timeout(&mut tx).await?;
        let row = sqlx::query("SELECT aggregate FROM scim_groups WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(Self::repo_err)?;
        tx.commit().await.map_err(Self::repo_err)?;
        let row = row.ok_or(ScimError::NotFound)?;
        row.try_get::<Json<ScimGroup>, _>("aggregate")
            .map(|j| j.0)
            .map_err(Self::repo_err)
    }

    async fn list_groups(
        &self,
        tenant_id: &str,
        query: ListUsersQuery,
    ) -> Result<ListGroupsResult, ScimError> {
        let mut tx = self.pool.begin().await.map_err(Self::repo_err)?;
        self.set_timeout(&mut tx).await?;
        let rows = sqlx::query("SELECT aggregate FROM scim_groups WHERE tenant_id = $1")
            .bind(tenant_id)
            .fetch_all(&mut *tx)
            .await
            .map_err(Self::repo_err)?;
        tx.commit().await.map_err(Self::repo_err)?;
        let groups: Vec<ScimGroup> = rows
            .iter()
            .map(|r| {
                r.try_get::<Json<ScimGroup>, _>("aggregate")
                    .map(|j| j.0)
                    .map_err(Self::repo_err)
            })
            .collect::<Result<_, _>>()?;
        let mut filtered: Vec<ScimGroup> = match query.filter.as_deref() {
            None => groups,
            Some(raw) => {
                let ast: Filter = parse_scim_filter(raw)?;
                groups
                    .into_iter()
                    .filter(|g| {
                        let v = serde_json::to_value(g).unwrap_or(serde_json::Value::Null);
                        ast.matches(&v)
                    })
                    .collect()
            }
        };
        filtered.sort_by(|a, b| a.display_name.cmp(&b.display_name));
        let total = filtered.len();
        let (start, count) = scim_pagination(query.start_index, query.count, total);
        let resources: Vec<ScimGroup> = filtered.into_iter().skip(start - 1).take(count).collect();
        Ok(ListGroupsResult {
            total_results: total,
            start_index: start,
            items_per_page: resources.len(),
            resources,
        })
    }
}

/// One audit row — every CREATE / UPDATE / DELETE the SCIM port lands one,
/// plus every mint / rotate / revoke and every scope-violation rejection.
///
/// Surfaced via the test helper `audit_rows()`; the Postgres-backed audit
/// flush lands in a later phase.
#[derive(Debug, Clone)]
#[allow(dead_code)] // consumed only by `#[cfg(test)]` helpers today; Postgres flusher lands next phase
pub(crate) struct ScimAuditRow {
    /// Owning tenant id.
    pub tenant_id: String,
    /// `create_user` / `replace_user` / `delete_user` / `create_group`
    /// / `mint_token` / `rotate_token` / `revoke_token` /
    /// `scope_violation`.
    pub action: String,
    /// SCIM user / group / token id when relevant.
    pub scim_user_id: Option<String>,
    /// Serialised payload — masks `password` if ever present. For
    /// token-lifecycle rows carries `{ token_id, scopes, ttl_days }`;
    /// for `scope_violation` carries `{ token_id, required, granted }`.
    pub payload: serde_json::Value,
    /// Wall-clock timestamp.
    pub ts: OffsetDateTime,
}

/// In-memory adapter.
pub(crate) struct InMemoryScim {
    /// Users/groups provisioner — in-memory (dev) or durable Postgres.
    provisioner: Arc<dyn ScimProvisioner>,
    /// SCIM bearer-token store — in-memory (dev) or durable Postgres.
    tokens: Arc<dyn ScimTokenStore>,
    /// Audit log — append-only, oldest-first.
    audit: Mutex<Vec<ScimAuditRow>>,
    /// Rotation policy (cadence + grace window). Defaults to 90 / 7
    /// days; tests override via [`Self::with_clock_and_policy`].
    policy: ScimRotationPolicy,
    /// Wall-clock source. Tests inject a controllable clock.
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for InMemoryScim {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InMemoryScim")
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

impl InMemoryScim {
    /// Build an empty adapter using the standard rotation policy (90-day
    /// cadence, 7-day grace), the real system clock, and an in-memory token
    /// store.
    #[must_use]
    pub(crate) fn new() -> Self {
        Self::with_store_clock_policy(
            Arc::new(InMemoryScimProvisioner::new()),
            Arc::new(InMemoryScimTokenStore::default()),
            Arc::new(SystemClock),
            ScimRotationPolicy::standard(),
        )
    }

    /// Test seam — inject a fake clock + custom policy over in-memory stores.
    #[cfg(test)]
    pub(crate) fn with_clock_and_policy(clock: Arc<dyn Clock>, policy: ScimRotationPolicy) -> Self {
        Self::with_store_clock_policy(
            Arc::new(InMemoryScimProvisioner::new()),
            Arc::new(InMemoryScimTokenStore::default()),
            clock,
            policy,
        )
    }

    /// Full constructor — inject the provisioner, token store, clock, and
    /// policy. The composition root passes the Postgres-backed provisioner +
    /// token store when the DB is enabled.
    pub(crate) fn with_store_clock_policy(
        provisioner: Arc<dyn ScimProvisioner>,
        tokens: Arc<dyn ScimTokenStore>,
        clock: Arc<dyn Clock>,
        policy: ScimRotationPolicy,
    ) -> Self {
        Self {
            provisioner,
            tokens,
            audit: Mutex::new(Vec::new()),
            policy,
            clock,
        }
    }

    /// Test-only — snapshot the in-memory audit log.
    #[cfg(test)]
    pub(crate) fn audit_rows(&self) -> Vec<ScimAuditRow> {
        self.audit
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn mint_plaintext() -> (String, [u8; HASH_BYTES]) {
        let mut buf = [0u8; TOKEN_BYTES];
        OsRng.fill_bytes(&mut buf);
        let encoded = URL_SAFE_NO_PAD.encode(buf);
        let plaintext = format!("{TOKEN_PREFIX}{encoded}");
        let hash = Self::sha256(&plaintext);
        (plaintext, hash)
    }

    fn sha256(input: &str) -> [u8; HASH_BYTES] {
        let mut h = Sha256::new();
        h.update(input.as_bytes());
        let out = h.finalize();
        let mut arr = [0u8; HASH_BYTES];
        arr.copy_from_slice(&out);
        arr
    }

    fn audit_row(
        &self,
        tenant_id: &str,
        action: &str,
        scim_user_id: Option<&str>,
        payload: serde_json::Value,
    ) {
        let mut guard = self
            .audit
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.push(ScimAuditRow {
            tenant_id: tenant_id.to_owned(),
            action: action.to_owned(),
            scim_user_id: scim_user_id.map(str::to_owned),
            payload,
            ts: self.clock.now(),
        });
    }

    /// Build a fresh token row for `tenant_id` with the supplied
    /// scopes + (optional) TTL override. The TTL override is stored as
    /// `expires_at = now + ttl_days` (defaulting to the standard
    /// cadence).
    fn build_row(
        &self,
        tenant_id: &str,
        name: &str,
        scopes: Vec<ScimScope>,
        ttl: Duration,
    ) -> (TokenRow, String) {
        let now = self.clock.now();
        let (plaintext, hash) = Self::mint_plaintext();
        let expires_at = now + time::Duration::seconds_f64(ttl.as_secs_f64());
        let row = TokenRow {
            id: uuid::Uuid::new_v4().to_string(),
            tenant_id: tenant_id.to_owned(),
            name: name.to_owned(),
            hash,
            scopes,
            created_at: now,
            activated_at: now,
            expires_at,
            retired_at: None,
            revoked_at: None,
            last_used_at: None,
        };
        (row, plaintext)
    }

    /// Public scope-violation audit hook — called by the HTTP layer
    /// after a successful auth but before the (denied) handler runs.
    ///
    /// Today the HTTP layer (`crates/sx-api/src/controller/scim.rs`)
    /// short-circuits on the scope check without round-tripping back
    /// into the adapter (the 403 envelope is built locally so the
    /// caller never holds an `Arc<dyn ScimProvisionPort>` cast back to
    /// `InMemoryScim`). The hook stays on the adapter for the Postgres
    /// implementation's audit flusher to call once the cast-free port
    /// method lands. Tests exercise it directly via the in-memory type.
    #[allow(dead_code)] // see doc-comment above
    pub(crate) fn record_scope_violation(
        &self,
        tenant_id: &str,
        token_id: &str,
        required: ScimScope,
        granted: &[ScimScope],
    ) {
        let payload = serde_json::json!({
            "token_id": token_id,
            "required": required.as_str(),
            "granted": granted.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
        });
        self.audit_row(tenant_id, "scope_violation", Some(token_id), payload);
    }
}

impl Default for InMemoryScim {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ScimProvisionPort for InMemoryScim {
    async fn authenticate(&self, bearer: &str) -> Result<ScimAuthContext, ScimError> {
        if bearer.trim().is_empty() {
            return Err(ScimError::Unauthorised);
        }
        let incoming = Self::sha256(bearer);
        let now = self.clock.now();
        // Resolve the row by hash. The store preserves the constant-time
        // property (in-memory walks every row; Postgres resolves it with an
        // indexed exact-match, so the adapter's control flow leaks nothing).
        let mut row = self
            .tokens
            .find_by_hash(incoming)
            .await?
            .ok_or(ScimError::Unauthorised)?;
        // Lifecycle gate — NOT timing-sensitive (only runs on a matched hash).
        if row.revoked_at.is_some() {
            return Err(ScimError::Unauthorised);
        }
        if let Some(retired) = row.retired_at {
            if now >= retired {
                return Err(ScimError::expired("token retired past grace window"));
            }
        } else if now >= row.expires_at {
            return Err(ScimError::expired("token past expires_at"));
        }
        let auth_ctx = ScimAuthContext {
            tenant_id: row.tenant_id.clone(),
            scopes: row.scopes.clone(),
            token_id: row.id.clone(),
        };
        // Stamp last-used after the auth decision. Failure to persist is
        // non-fatal: the decision has already been made.
        row.last_used_at = Some(now);
        let _ = self.tokens.update(&row).await;
        Ok(auth_ctx)
    }

    async fn create_user(&self, tenant_id: &str, user: ScimUser) -> Result<ScimUser, ScimError> {
        let created = self.provisioner.create_user(tenant_id, user).await?;
        let payload = serde_json::to_value(&created).unwrap_or(serde_json::Value::Null);
        self.audit_row(tenant_id, "create_user", created.id.as_deref(), payload);
        Ok(created)
    }

    async fn get_user(&self, tenant_id: &str, id: &str) -> Result<ScimUser, ScimError> {
        self.provisioner.get_user(tenant_id, id).await
    }

    async fn replace_user(
        &self,
        tenant_id: &str,
        id: &str,
        user: ScimUser,
    ) -> Result<ScimUser, ScimError> {
        let updated = self.provisioner.replace_user(tenant_id, id, user).await?;
        let payload = serde_json::to_value(&updated).unwrap_or(serde_json::Value::Null);
        self.audit_row(tenant_id, "replace_user", Some(id), payload);
        Ok(updated)
    }

    async fn delete_user(&self, tenant_id: &str, id: &str) -> Result<(), ScimError> {
        self.provisioner.delete_user(tenant_id, id).await?;
        self.audit_row(tenant_id, "delete_user", Some(id), serde_json::Value::Null);
        Ok(())
    }

    async fn list_users(
        &self,
        tenant_id: &str,
        query: ListUsersQuery,
    ) -> Result<ListUsersResult, ScimError> {
        self.provisioner.list_users(tenant_id, query).await
    }

    async fn create_group(
        &self,
        tenant_id: &str,
        group: ScimGroup,
    ) -> Result<ScimGroup, ScimError> {
        let created = self.provisioner.create_group(tenant_id, group).await?;
        let payload = serde_json::to_value(&created).unwrap_or(serde_json::Value::Null);
        self.audit_row(tenant_id, "create_group", created.id.as_deref(), payload);
        Ok(created)
    }

    async fn get_group(&self, tenant_id: &str, id: &str) -> Result<ScimGroup, ScimError> {
        self.provisioner.get_group(tenant_id, id).await
    }

    async fn list_groups(
        &self,
        tenant_id: &str,
        query: ListUsersQuery,
    ) -> Result<ListGroupsResult, ScimError> {
        self.provisioner.list_groups(tenant_id, query).await
    }

    async fn mint_token(
        &self,
        tenant_id: &str,
        name: &str,
        scopes: Vec<ScimScope>,
        ttl_days: Option<u32>,
    ) -> Result<(ScimTokenView, String), ScimError> {
        if name.trim().is_empty() {
            return Err(ScimError::invalid_request("name must be non-empty"));
        }
        if scopes.is_empty() {
            return Err(ScimError::invalid_request(
                "at least one scope is required (default-deny on missing scope)",
            ));
        }
        let ttl = ttl_days.map_or(self.policy.cadence, |days| {
            Duration::from_secs(u64::from(days) * 60 * 60 * 24)
        });
        let (row, plaintext) = self.build_row(tenant_id, name, scopes.clone(), ttl);
        let view = row.to_view(self.clock.now());
        let payload = serde_json::json!({
            "token_id": row.id,
            "scopes": scopes.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
            "ttl_days": ttl_days,
        });
        self.audit_row(tenant_id, "mint_token", Some(&row.id), payload);
        self.tokens.insert(row).await?;
        Ok((view, plaintext))
    }

    async fn rotate_token(
        &self,
        tenant_id: &str,
        id: &str,
    ) -> Result<(ScimTokenView, String), ScimError> {
        let now = self.clock.now();
        let grace = self.policy.grace_window;
        // Snapshot the old row's scopes + name + ttl so the new one
        // inherits them. Also stamp `retired_at` on the old row to
        // start the grace window.
        let (scopes, name, old_ttl) = {
            let mut old = self.tokens.get(id).await?.ok_or(ScimError::NotFound)?;
            if old.tenant_id != tenant_id {
                return Err(ScimError::NotFound);
            }
            if old.revoked_at.is_some() {
                return Err(ScimError::invalid_request(
                    "cannot rotate a revoked token; mint a new one instead",
                ));
            }
            // If already retired, refuse — caller should issue a fresh
            // token rather than re-rotating a half-dead one.
            if old.retired_at.is_some() {
                return Err(ScimError::invalid_request(
                    "token already rotated; mint a new one instead",
                ));
            }
            let original_ttl = old.expires_at - old.created_at;
            old.retired_at = Some(now + grace);
            let snapshot = (
                old.scopes.clone(),
                old.name.clone(),
                original_ttl.unsigned_abs(),
            );
            self.tokens.update(&old).await?;
            snapshot
        };
        let (row, plaintext) = self.build_row(tenant_id, &name, scopes.clone(), old_ttl);
        let view = row.to_view(now);
        let payload = serde_json::json!({
            "rotated_from": id,
            "new_token_id": row.id,
            "scopes": scopes.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
            "grace_window_secs": grace.as_secs(),
        });
        self.audit_row(tenant_id, "rotate_token", Some(&row.id), payload);
        self.tokens.insert(row).await?;
        Ok((view, plaintext))
    }

    async fn list_tokens(&self, tenant_id: &str) -> Result<Vec<ScimTokenView>, ScimError> {
        let now = self.clock.now();
        let mut rows: Vec<ScimTokenView> = self
            .tokens
            .list_by_tenant(tenant_id)
            .await?
            .iter()
            .map(|r| r.to_view(now))
            .collect();
        rows.sort_by(|a, b| a.created_at.cmp(&b.created_at));
        Ok(rows)
    }

    async fn revoke_token(&self, tenant_id: &str, id: &str) -> Result<(), ScimError> {
        let now = self.clock.now();
        {
            let mut row = self.tokens.get(id).await?.ok_or(ScimError::NotFound)?;
            if row.tenant_id != tenant_id {
                return Err(ScimError::NotFound);
            }
            // Idempotent — second revoke is a no-op rather than a hard
            // 404. The spec says "revoke is immediate" so re-revoking
            // should also be cheap + audit-friendly.
            if row.revoked_at.is_none() {
                row.revoked_at = Some(now);
                self.tokens.update(&row).await?;
            }
        }
        let payload = serde_json::json!({ "token_id": id });
        self.audit_row(tenant_id, "revoke_token", Some(id), payload);
        Ok(())
    }
}

/// Bundle returned to the composition root.
pub(crate) struct ScimBundle {
    /// HTTP-facing SCIM provisioning port.
    pub scim: Arc<dyn ScimProvisionPort>,
}

/// Build the SCIM adapter. The users/groups provisioner and bearer-token
/// store are durable (Postgres) when the DB is enabled, else in-memory (dev
/// quick-start). The audit log remains in-memory for now.
pub(crate) fn build(postgres: Option<(PgPool, u64)>) -> ScimBundle {
    let (provisioner, tokens): (Arc<dyn ScimProvisioner>, Arc<dyn ScimTokenStore>) = match postgres
    {
        Some((pool, stmt_timeout_ms)) => (
            Arc::new(PgScimProvisioner::new(pool.clone(), stmt_timeout_ms)),
            Arc::new(PgScimTokenStore::new(pool, stmt_timeout_ms)),
        ),
        None => (
            Arc::new(InMemoryScimProvisioner::new()),
            Arc::new(InMemoryScimTokenStore::default()),
        ),
    };
    ScimBundle {
        scim: Arc::new(InMemoryScim::with_store_clock_policy(
            provisioner,
            tokens,
            Arc::new(SystemClock),
            ScimRotationPolicy::standard(),
        )),
    }
}

// ---------------------------------------------------------------------------
// Test seam: a manually-advanced clock to drive grace-window assertions.
// ---------------------------------------------------------------------------

#[cfg(test)]
#[derive(Debug)]
pub(crate) struct FakeClock {
    inner: Mutex<OffsetDateTime>,
}

#[cfg(test)]
impl FakeClock {
    pub(crate) fn new(start: OffsetDateTime) -> Self {
        Self {
            inner: Mutex::new(start),
        }
    }

    pub(crate) fn advance(&self, d: time::Duration) {
        let mut g = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *g += d;
    }
}

#[cfg(test)]
impl Clock for FakeClock {
    fn now(&self) -> OffsetDateTime {
        *self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use sx_scim::scope::ScimScope;

    fn default_scopes() -> Vec<ScimScope> {
        vec![ScimScope::UsersRead, ScimScope::UsersWrite]
    }

    fn build_scim() -> (Arc<FakeClock>, InMemoryScim) {
        let clock = Arc::new(FakeClock::new(
            OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap(),
        ));
        let scim =
            InMemoryScim::with_clock_and_policy(clock.clone(), ScimRotationPolicy::standard());
        (clock, scim)
    }

    #[tokio::test]
    async fn mint_then_authenticate_returns_tenant_and_scopes() {
        let (_clock, scim) = build_scim();
        let (_view, plain) = scim
            .mint_token("t1", "okta-prod", default_scopes(), None)
            .await
            .unwrap();
        let ctx = scim.authenticate(&plain).await.unwrap();
        assert_eq!(ctx.tenant_id, "t1");
        assert_eq!(ctx.scopes, default_scopes());
        assert!(!ctx.token_id.is_empty());
    }

    #[tokio::test]
    async fn mint_rejects_empty_scopes() {
        let (_clock, scim) = build_scim();
        let err = scim
            .mint_token("t1", "okta-prod", vec![], None)
            .await
            .unwrap_err();
        assert!(matches!(err, ScimError::InvalidRequest(_)));
    }

    #[tokio::test]
    async fn mint_emits_audit_row_with_scopes() {
        let (_clock, scim) = build_scim();
        let _ = scim
            .mint_token("t1", "okta-prod", default_scopes(), Some(30))
            .await
            .unwrap();
        let audit = scim.audit_rows();
        let row = audit.iter().find(|r| r.action == "mint_token").unwrap();
        assert_eq!(row.tenant_id, "t1");
        assert_eq!(row.payload["scopes"].as_array().unwrap().len(), 2);
        assert_eq!(row.payload["ttl_days"], serde_json::json!(30));
    }

    #[tokio::test]
    async fn authenticate_rejects_wrong_token() {
        let (_clock, scim) = build_scim();
        scim.mint_token("t1", "x", default_scopes(), None)
            .await
            .unwrap();
        let err = scim
            .authenticate("scim_wrong")
            .await
            .expect_err("must reject");
        assert!(matches!(err, ScimError::Unauthorised));
    }

    #[tokio::test]
    async fn authenticate_rejects_empty_token() {
        let (_clock, scim) = build_scim();
        assert!(matches!(
            scim.authenticate("").await.unwrap_err(),
            ScimError::Unauthorised
        ));
    }

    #[tokio::test]
    async fn revoke_is_immediate() {
        let (_clock, scim) = build_scim();
        let (view, plain) = scim
            .mint_token("t1", "x", default_scopes(), None)
            .await
            .unwrap();
        // Works pre-revoke.
        scim.authenticate(&plain).await.unwrap();
        scim.revoke_token("t1", &view.id).await.unwrap();
        // Returns 401 immediately afterwards (no grace).
        assert!(matches!(
            scim.authenticate(&plain).await.unwrap_err(),
            ScimError::Unauthorised
        ));
    }

    #[tokio::test]
    async fn revoke_emits_audit_row() {
        let (_clock, scim) = build_scim();
        let (view, _) = scim
            .mint_token("t1", "x", default_scopes(), None)
            .await
            .unwrap();
        scim.revoke_token("t1", &view.id).await.unwrap();
        let audit = scim.audit_rows();
        assert!(audit
            .iter()
            .any(|r| r.action == "revoke_token" && r.scim_user_id.as_deref() == Some(&view.id)));
    }

    #[tokio::test]
    async fn revoke_token_rejects_foreign_tenant() {
        let (_clock, scim) = build_scim();
        let (view, _) = scim
            .mint_token("t1", "x", default_scopes(), None)
            .await
            .unwrap();
        assert!(matches!(
            scim.revoke_token("t2", &view.id).await.unwrap_err(),
            ScimError::NotFound
        ));
    }

    #[tokio::test]
    async fn revoke_is_idempotent() {
        let (_clock, scim) = build_scim();
        let (view, _) = scim
            .mint_token("t1", "x", default_scopes(), None)
            .await
            .unwrap();
        scim.revoke_token("t1", &view.id).await.unwrap();
        // Second revoke does not error — still NoContent semantics
        // upstream, and stays cheap for the audit log.
        scim.revoke_token("t1", &view.id).await.unwrap();
    }

    #[tokio::test]
    async fn list_tokens_scopes_per_tenant() {
        let (_clock, scim) = build_scim();
        scim.mint_token("t1", "a", default_scopes(), None)
            .await
            .unwrap();
        scim.mint_token("t1", "b", default_scopes(), None)
            .await
            .unwrap();
        scim.mint_token("t2", "c", default_scopes(), None)
            .await
            .unwrap();
        let t1 = scim.list_tokens("t1").await.unwrap();
        let t2 = scim.list_tokens("t2").await.unwrap();
        assert_eq!(t1.len(), 2);
        assert_eq!(t2.len(), 1);
        assert_eq!(t2[0].name, "c");
        // Status surfaces correctly.
        assert!(t1.iter().all(|v| v.status == ScimTokenStatus::Active));
    }

    #[tokio::test]
    async fn rotation_within_grace_accepts_both_tokens() {
        let (clock, scim) = build_scim();
        let (view, old_plain) = scim
            .mint_token("t1", "x", default_scopes(), None)
            .await
            .unwrap();
        // Advance a tiny bit, then rotate.
        clock.advance(time::Duration::hours(1));
        let (_new_view, new_plain) = scim.rotate_token("t1", &view.id).await.unwrap();
        // Within grace: both authenticate.
        let old_ctx = scim.authenticate(&old_plain).await.unwrap();
        let new_ctx = scim.authenticate(&new_plain).await.unwrap();
        assert_eq!(old_ctx.tenant_id, "t1");
        assert_eq!(new_ctx.tenant_id, "t1");
        assert_eq!(old_ctx.scopes, default_scopes());
        assert_eq!(new_ctx.scopes, default_scopes());
    }

    #[tokio::test]
    async fn rotation_past_grace_rejects_old_token() {
        let (clock, scim) = build_scim();
        let (view, old_plain) = scim
            .mint_token("t1", "x", default_scopes(), None)
            .await
            .unwrap();
        let (_new_view, new_plain) = scim.rotate_token("t1", &view.id).await.unwrap();
        // Advance past the 7-day grace.
        clock.advance(time::Duration::days(8));
        let err = scim.authenticate(&old_plain).await.unwrap_err();
        assert!(matches!(err, ScimError::Expired(_)));
        // New token still works (only ~8 days old vs. 90-day cadence).
        scim.authenticate(&new_plain).await.unwrap();
    }

    #[tokio::test]
    async fn rotation_emits_audit_row() {
        let (_clock, scim) = build_scim();
        let (view, _) = scim
            .mint_token("t1", "x", default_scopes(), None)
            .await
            .unwrap();
        scim.rotate_token("t1", &view.id).await.unwrap();
        let audit = scim.audit_rows();
        let row = audit.iter().find(|r| r.action == "rotate_token").unwrap();
        assert_eq!(row.payload["rotated_from"], serde_json::json!(view.id));
        assert!(row.payload["grace_window_secs"].is_number());
    }

    #[tokio::test]
    async fn expired_token_returns_expired_error() {
        let (clock, scim) = build_scim();
        let (_view, plain) = scim
            .mint_token("t1", "x", default_scopes(), Some(1))
            .await
            .unwrap();
        // Authenticate while fresh.
        scim.authenticate(&plain).await.unwrap();
        // Advance past 1-day TTL.
        clock.advance(time::Duration::days(2));
        let err = scim.authenticate(&plain).await.unwrap_err();
        assert!(matches!(err, ScimError::Expired(_)));
    }

    #[tokio::test]
    async fn cannot_rotate_unknown_token() {
        let (_clock, scim) = build_scim();
        let err = scim.rotate_token("t1", "no-such-id").await.unwrap_err();
        assert!(matches!(err, ScimError::NotFound));
    }

    #[tokio::test]
    async fn cannot_rotate_revoked_token() {
        let (_clock, scim) = build_scim();
        let (view, _) = scim
            .mint_token("t1", "x", default_scopes(), None)
            .await
            .unwrap();
        scim.revoke_token("t1", &view.id).await.unwrap();
        let err = scim.rotate_token("t1", &view.id).await.unwrap_err();
        assert!(matches!(err, ScimError::InvalidRequest(_)));
    }

    #[tokio::test]
    async fn cannot_rotate_already_rotated_token() {
        let (_clock, scim) = build_scim();
        let (view, _) = scim
            .mint_token("t1", "x", default_scopes(), None)
            .await
            .unwrap();
        scim.rotate_token("t1", &view.id).await.unwrap();
        let err = scim.rotate_token("t1", &view.id).await.unwrap_err();
        assert!(matches!(err, ScimError::InvalidRequest(_)));
    }

    #[tokio::test]
    async fn cannot_rotate_foreign_tenant_token() {
        let (_clock, scim) = build_scim();
        let (view, _) = scim
            .mint_token("t1", "x", default_scopes(), None)
            .await
            .unwrap();
        let err = scim.rotate_token("t2", &view.id).await.unwrap_err();
        assert!(matches!(err, ScimError::NotFound));
    }

    #[tokio::test]
    async fn list_token_view_reflects_lifecycle_phase() {
        let (clock, scim) = build_scim();
        let (view, _) = scim
            .mint_token("t1", "x", default_scopes(), None)
            .await
            .unwrap();
        scim.rotate_token("t1", &view.id).await.unwrap();
        let listed = scim.list_tokens("t1").await.unwrap();
        let original = listed.iter().find(|v| v.id == view.id).unwrap();
        assert_eq!(original.status, ScimTokenStatus::Grace);
        assert!(original.retired_at.is_some());
        // Advance past grace; status flips to Expired on next list call.
        clock.advance(time::Duration::days(8));
        let listed = scim.list_tokens("t1").await.unwrap();
        let original = listed.iter().find(|v| v.id == view.id).unwrap();
        assert_eq!(original.status, ScimTokenStatus::Expired);
    }

    #[tokio::test]
    async fn create_user_writes_audit_row() {
        let (_clock, scim) = build_scim();
        let u = ScimUser::new("alice");
        let created = scim.create_user("t1", u).await.unwrap();
        let audit = scim.audit_rows();
        assert_eq!(
            audit.iter().filter(|r| r.action == "create_user").count(),
            1
        );
        let row = audit.iter().find(|r| r.action == "create_user").unwrap();
        assert_eq!(row.scim_user_id, created.id);
    }

    #[tokio::test]
    async fn replace_user_writes_audit_row() {
        let (_clock, scim) = build_scim();
        let created = scim
            .create_user("t1", ScimUser::new("alice"))
            .await
            .unwrap();
        let id = created.id.clone().unwrap();
        let mut u = ScimUser::new("alice");
        u.display_name = Some("Alice".into());
        scim.replace_user("t1", &id, u).await.unwrap();
        let audit = scim.audit_rows();
        assert!(audit.iter().any(|r| r.action == "replace_user"));
    }

    #[tokio::test]
    async fn delete_user_writes_audit_row() {
        let (_clock, scim) = build_scim();
        let created = scim
            .create_user("t1", ScimUser::new("alice"))
            .await
            .unwrap();
        let id = created.id.clone().unwrap();
        scim.delete_user("t1", &id).await.unwrap();
        let audit = scim.audit_rows();
        assert!(audit.iter().any(|r| r.action == "delete_user"));
    }

    #[tokio::test]
    async fn mint_token_rejects_empty_name() {
        let (_clock, scim) = build_scim();
        let err = scim
            .mint_token("t1", "  ", default_scopes(), None)
            .await
            .unwrap_err();
        assert!(matches!(err, ScimError::InvalidRequest(_)));
    }

    #[tokio::test]
    async fn constant_time_compare_with_many_tokens() {
        // Smoke-check: mint a bunch of tokens for different tenants
        // and confirm `authenticate` still returns the right tenant.
        let (_clock, scim) = build_scim();
        let mut plaintexts = Vec::new();
        for i in 0..10 {
            let tenant = format!("t{i}");
            let (_, plain) = scim
                .mint_token(&tenant, "x", default_scopes(), None)
                .await
                .unwrap();
            plaintexts.push((tenant, plain));
        }
        for (tenant, plain) in &plaintexts {
            let ctx = scim.authenticate(plain).await.unwrap();
            assert_eq!(&ctx.tenant_id, tenant);
        }
    }

    #[tokio::test]
    async fn scope_violation_audit_row_is_recorded() {
        let (_clock, scim) = build_scim();
        let (view, _) = scim
            .mint_token("t1", "x", vec![ScimScope::UsersRead], None)
            .await
            .unwrap();
        scim.record_scope_violation(
            "t1",
            &view.id,
            ScimScope::UsersWrite,
            &[ScimScope::UsersRead],
        );
        let audit = scim.audit_rows();
        let row = audit
            .iter()
            .find(|r| r.action == "scope_violation")
            .unwrap();
        assert_eq!(
            row.payload["required"],
            serde_json::json!("scim:users:write")
        );
        assert_eq!(
            row.payload["granted"],
            serde_json::json!(["scim:users:read"])
        );
    }

    /// Serde round-trip of a `TokenRow` through JSON — the shape the
    /// Postgres store persists (the `[u8; 32]` hash, the `OffsetDateTime`s,
    /// the `Vec<ScimScope>`).
    #[test]
    fn token_row_json_roundtrip_is_lossless() {
        let now = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let row = TokenRow {
            id: "tok-1".into(),
            tenant_id: "11111111-1111-1111-1111-111111111111".into(),
            name: "CI pipeline".into(),
            hash: [7u8; HASH_BYTES],
            scopes: vec![ScimScope::UsersRead, ScimScope::UsersWrite],
            created_at: now,
            activated_at: now,
            expires_at: now + time::Duration::days(90),
            retired_at: None,
            revoked_at: None,
            last_used_at: Some(now + time::Duration::hours(1)),
        };
        let json = serde_json::to_string(&row).expect("serialise");
        let back: TokenRow = serde_json::from_str(&json).expect("deserialise");
        assert_eq!(back.id, row.id);
        assert_eq!(back.hash, row.hash);
        assert_eq!(back.scopes, row.scopes);
        assert_eq!(back.expires_at, row.expires_at);
        assert_eq!(back.last_used_at, row.last_used_at);
    }

    /// Durability proof for the Postgres provisioner: create user → get →
    /// list (filter) → duplicate-name conflict → replace → soft-delete
    /// (active=false) → create group → *fresh pool (restart-equivalent)* →
    /// the user (still inactive) and group survive.
    ///
    /// Gated on `TEST_DATABASE_URL` (silent no-op in CI; workspace
    /// live-DB fixture convention). `scim_users`/`scim_groups` have no
    /// tenant FK, so no seeded tenant is needed.
    #[tokio::test]
    async fn pg_scim_provisioner_survives_restart() {
        #[allow(clippy::disallowed_methods)]
        let Ok(url) = std::env::var("TEST_DATABASE_URL") else {
            return;
        };
        let tenant = format!("tenant-{}", uuid::Uuid::new_v4());
        let uname = format!("alice-{}", uuid::Uuid::new_v4());
        let gname = format!("eng-{}", uuid::Uuid::new_v4());

        let user_id;
        {
            let pool = PgPool::connect(&url).await.expect("connect");
            let prov = PgScimProvisioner::new(pool, 15_000);
            let created = prov
                .create_user(&tenant, ScimUser::new(uname.clone()))
                .await
                .expect("create_user");
            user_id = created.id.clone().expect("id assigned");
            assert!(created.meta.is_some());

            // Duplicate userName (case-insensitive) is a 409.
            let dup = prov
                .create_user(&tenant, ScimUser::new(uname.to_uppercase()))
                .await;
            assert!(matches!(dup, Err(ScimError::Conflict(_))), "dup must 409");

            let got = prov.get_user(&tenant, &user_id).await.expect("get");
            assert_eq!(got.user_name, uname);

            // Filter list down to this user.
            let listed = prov
                .list_users(
                    &tenant,
                    ListUsersQuery {
                        filter: Some(format!("userName eq \"{uname}\"")),
                        start_index: None,
                        count: None,
                    },
                )
                .await
                .expect("list");
            assert_eq!(listed.total_results, 1);

            // Replace (display name change) keeps the id + bumps meta.
            let mut repl = ScimUser::new(uname.clone());
            repl.display_name = Some("Alice A.".into());
            let replaced = prov
                .replace_user(&tenant, &user_id, repl)
                .await
                .expect("replace");
            assert_eq!(replaced.display_name.as_deref(), Some("Alice A."));

            // Soft-delete flips active=false but keeps the row.
            prov.delete_user(&tenant, &user_id).await.expect("delete");
            assert!(!prov.get_user(&tenant, &user_id).await.unwrap().active);

            prov.create_group(&tenant, ScimGroup::new(gname.clone()))
                .await
                .expect("create_group");
        }

        // Fresh pool == a fresh process. In-memory state would be gone here.
        {
            let pool = PgPool::connect(&url).await.expect("reconnect");
            let prov = PgScimProvisioner::new(pool, 15_000);
            let got = prov
                .get_user(&tenant, &user_id)
                .await
                .expect("user survived restart");
            assert!(!got.active, "soft-delete survived restart");
            // The deprovisioned userName is still reserved.
            let reuse = prov
                .create_user(&tenant, ScimUser::new(uname.clone()))
                .await;
            assert!(
                matches!(reuse, Err(ScimError::Conflict(_))),
                "deprovisioned userName stays reserved across restart"
            );
            let groups = prov
                .list_groups(&tenant, ListUsersQuery::default())
                .await
                .expect("list groups");
            assert!(groups.resources.iter().any(|g| g.display_name == gname));
        }
    }

    /// Durability proof against a real Postgres: mint (insert) → authenticate
    /// lookup by hash → list → stamp last-used (update) → *fresh pool
    /// (restart-equivalent)* → the token and its mutation are still there.
    ///
    /// Gated on `TEST_DATABASE_URL` (a DSN for a DB that has run the
    /// migrations), so it is a silent no-op in CI and the default
    /// `cargo test` run — the workspace live-DB fixture convention. The
    /// `scim_tokens` table has no tenant FK, so no seeded tenant is needed.
    #[tokio::test]
    async fn pg_scim_token_store_survives_restart() {
        // Project-wide live-DB fixture convention (not routed through
        // `sx-config`); silent skip when unset keeps CI green.
        #[allow(clippy::disallowed_methods)]
        let Ok(url) = std::env::var("TEST_DATABASE_URL") else {
            return;
        };
        let now = OffsetDateTime::from_unix_timestamp(1_700_000_500).unwrap();
        let tenant = format!("tenant-{}", uuid::Uuid::new_v4());
        let id = format!("tok-{}", uuid::Uuid::new_v4());
        let hash = InMemoryScim::sha256(&format!("scim_live_{id}"));
        let row = TokenRow {
            id: id.clone(),
            tenant_id: tenant.clone(),
            name: "live".into(),
            hash,
            scopes: vec![ScimScope::UsersRead],
            created_at: now,
            activated_at: now,
            expires_at: now + time::Duration::days(90),
            retired_at: None,
            revoked_at: None,
            last_used_at: None,
        };

        {
            let pool = PgPool::connect(&url).await.expect("connect");
            let store = PgScimTokenStore::new(pool, 15_000);
            store.insert(row.clone()).await.expect("insert");
            let by_hash = store
                .find_by_hash(hash)
                .await
                .expect("find_by_hash")
                .expect("present");
            assert_eq!(by_hash.id, id);
            let listed = store.list_by_tenant(&tenant).await.expect("list");
            assert_eq!(listed.len(), 1);
            let mut mutated = by_hash;
            mutated.last_used_at = Some(now + time::Duration::minutes(5));
            store.update(&mutated).await.expect("update");
        }

        // Fresh pool == a fresh process. In-memory state would be gone here.
        {
            let pool = PgPool::connect(&url).await.expect("reconnect");
            let store = PgScimTokenStore::new(pool, 15_000);
            let got = store
                .get(&id)
                .await
                .expect("get after restart")
                .expect("token survived restart");
            assert_eq!(got.id, id);
            assert_eq!(
                got.last_used_at,
                Some(now + time::Duration::minutes(5)),
                "last-used mutation survived restart"
            );
        }
    }
}
