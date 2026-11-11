//! Inbound and outbound port traits.
//!
//! `UserRepository` mirrors `sx_core::port::user_repository::UserRepository`.
//! Adapter crates (`sx-storage`) implement it; the use cases here depend
//! only on the trait.

use async_trait::async_trait;

use crate::domain::{TenantId, User, UserId};
use crate::model::oidc_client::{ClientId, OidcClient};
use crate::model::webauthn::{AaguidPolicy, MdsEntry, MdsStatus, StoredCredential, TenantRp};
use crate::IamError;
use uuid::Uuid;

/// Read- and write-side access to user records.
///
/// Mirrors `sx_core::port::user_repository::UserRepository`. Once `sx-core`
/// provides the canonical trait, replace this module with a `pub use`.
#[async_trait]
pub trait UserRepository: Send + Sync {
    /// Locate a user by tenant + (lower-cased) email.
    ///
    /// Implementations MUST return `Ok(None)` when the user does not
    /// exist; use cases will fold that into [`IamError::InvalidCredentials`]
    /// at the boundary so existence cannot be probed.
    async fn find_by_email(
        &self,
        tenant_id: TenantId,
        email: &str,
    ) -> Result<Option<User>, IamError>;

    /// Locate a user by id.
    async fn find_by_id(&self, id: UserId) -> Result<Option<User>, IamError>;

    /// Insert a new user.
    ///
    /// Returns `Err(IamError::Conflict(_))` when a user with the same
    /// `(tenant_id, email)` already exists. The email on `user` is
    /// expected to be already lower-cased by the caller (the
    /// [`crate::controller::CreateUserUseCase`] enforces that).
    async fn create(&self, user: &User) -> Result<(), IamError>;

    /// Tenant-aware lookup that satisfies Postgres RLS.
    ///
    /// Postgres adapters MUST override this so the `SELECT` runs inside a
    /// transaction that has applied the `app.current_tenant_id` GUC,
    /// otherwise the FORCE-RLS policy on the `users` table returns zero
    /// rows. In-memory adapters can simply delegate to [`Self::find_by_id`]
    /// after asserting the returned user's `tenant_id` matches.
    ///
    /// The default delegates to [`Self::find_by_id`] (sufficient for the
    /// in-memory implementors that back tests and the developer mode), so
    /// existing implementors stay source-compatible.
    async fn find_by_id_with_tenant(
        &self,
        tenant_id: TenantId,
        id: UserId,
    ) -> Result<Option<User>, IamError> {
        let _ = tenant_id;
        self.find_by_id(id).await
    }

    /// Persist mutations to a `User` aggregate.
    ///
    /// Used by write-side use cases that mutate an existing user — email
    /// verification flipping `is_active`, password-reset rotating
    /// `password_hash`, etc. Postgres adapters MUST override this with an
    /// `UPDATE ... WHERE id = $1 AND tenant_id = $2` that covers every
    /// mutable column, so a single round-trip satisfies RLS regardless of
    /// which field the caller changed.
    ///
    /// The default returns
    /// [`IamError::Internal`] so adapters that legitimately do not support
    /// mutation (read-only test stubs) surface a clear error instead of
    /// silently succeeding.
    async fn update(&self, user: &User) -> Result<(), IamError> {
        let _ = user;
        Err(IamError::internal(
            "UserRepository::update unsupported by this adapter",
        ))
    }
}

/// Per-tenant `WebAuthn` relying-party configuration lookup.
///
/// One row per tenant. Adapters that do not yet support storage MUST
/// return `Ok(None)` for unknown tenants so the FIDO2 endpoints fall back
/// to a configuration error rather than silently leaking a default
/// relying party across tenants.
#[async_trait]
pub trait WebauthnRpRepository: Send + Sync {
    /// Load the relying-party configuration for `tenant_id`.
    async fn get(&self, tenant_id: TenantId) -> Result<Option<TenantRp>, IamError>;
}

/// Per-tenant + per-user `WebAuthn` passkey credential store.
///
/// Implementations live in `sx-storage` (Postgres) and in the monolith's
/// in-memory adapter. The contract:
///
/// * `insert` — append a fresh credential. The caller has already
///   verified the registration ceremony.
/// * `list_active` — every non-revoked credential for `(tenant, user)`.
///   Used by both `start_authentication` (to assemble the allow-list)
///   and the management UI.
/// * `find_by_cred_id` — locate a credential by its base64url id.
/// * `update_counter` — bump the signature counter after a successful
///   assertion. Implementations MUST set `last_used_at = now()` in the
///   same statement.
/// * `revoke` — soft-delete (sets `revoked_at`). Counter regressions
///   trigger this; the operator-facing UI also does.
#[async_trait]
pub trait WebauthnCredentialRepository: Send + Sync {
    /// Persist a fresh credential row.
    async fn insert(&self, credential: &StoredCredential) -> Result<(), IamError>;

    /// Every active credential for a given user, oldest-first.
    async fn list_active(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> Result<Vec<StoredCredential>, IamError>;

    /// Locate a credential by its base64url id (tenant-scoped).
    async fn find_by_cred_id(
        &self,
        tenant_id: TenantId,
        cred_id: &str,
    ) -> Result<Option<StoredCredential>, IamError>;

    /// Update the stored signature counter after a successful assertion.
    async fn update_counter(
        &self,
        tenant_id: TenantId,
        cred_id: &str,
        new_counter: u32,
    ) -> Result<(), IamError>;

    /// Soft-delete a credential (sets `revoked_at = now()`). Idempotent.
    async fn revoke(&self, tenant_id: TenantId, cred_id: &str) -> Result<(), IamError>;
}

/// Per-tenant AAGUID allow/deny policy store (HIGH-002).
///
/// Implementations live in `sx-storage` (Postgres) and the monolith's
/// in-memory adapter. Rows MUST be unique on `(tenant_id, aaguid)`; the
/// `upsert` operation replaces an existing row in place.
#[async_trait]
pub trait WebauthnAaguidPolicyRepository: Send + Sync {
    /// List every policy row for `tenant_id`. Used by the policy
    /// enforcement layer (which derives "is the tenant in allowlist
    /// mode?" from the presence of any `allow` row) and by the admin
    /// management UI.
    async fn list(&self, tenant_id: TenantId) -> Result<Vec<AaguidPolicy>, IamError>;

    /// Insert or update a row.
    async fn upsert(&self, policy: &AaguidPolicy) -> Result<(), IamError>;

    /// Delete `(tenant_id, aaguid)` if present. Idempotent.
    async fn delete(&self, tenant_id: TenantId, aaguid: Uuid) -> Result<(), IamError>;
}

/// Cached FIDO Alliance MDS3 metadata store (HIGH-002).
///
/// Populated by [`crate::service::webauthn::mds::MdsFetcher`] from the
/// signed JWT blob published at <https://mds.fidoalliance.org/>. The
/// registration-finish path reads it to enrich audit logs and (in strict
/// mode) reject authenticators absent from MDS.
#[async_trait]
pub trait WebauthnMdsRepository: Send + Sync {
    /// Look up the metadata entry for a single AAGUID. Returns `Ok(None)`
    /// when the AAGUID is not present in the cache.
    async fn get(&self, aaguid: Uuid) -> Result<Option<MdsEntry>, IamError>;

    /// Wholesale-replace the cached metadata table with the supplied rows
    /// and record `last_refresh = now()`. Implementations SHOULD wrap the
    /// replace in a transaction so concurrent readers either see the old
    /// or new table, never an interleaved view.
    async fn replace_all(&self, entries: Vec<MdsEntry>) -> Result<(), IamError>;

    /// Snapshot for the `GET /v1/iam/webauthn/mds-status` endpoint.
    async fn status(&self) -> Result<MdsStatus, IamError>;

    /// Last successful refresh time. Used by the staleness check that
    /// drives [`crate::service::webauthn::error::WebauthnError::MdsCacheStale`].
    async fn last_refresh(&self) -> Result<Option<time::OffsetDateTime>, IamError>;
}

/// Per-tenant confidential-client registry (MED-004).
///
/// One row per `(tenant_id, client_id)` in `oidc_clients`. The shape
/// mirrors the in-memory [`OidcClient`] aggregate: the live + previous
/// secret are envelope-decrypted by the adapter before they reach this
/// trait, so use cases never see ciphertext.
///
/// Implementations:
/// * `MemoryOidcClientRepo` — in-process map; used by tests and the
///   developer-mode adapter.
/// * `PgOidcClientRepo` (sx-storage) — RLS-scoped Postgres-backed
///   implementation that wraps the secret bytes via the `sx-secrets`
///   [`EnvelopeKeyManager`](sx_secrets::envelope::EnvelopeKeyManager).
#[async_trait]
pub trait OidcClientRepository: Send + Sync {
    /// Locate a client by `(tenant_id, client_id)`.
    ///
    /// Returns `Ok(None)` when no row exists.
    async fn find(
        &self,
        tenant_id: TenantId,
        client_id: &ClientId,
    ) -> Result<Option<OidcClient>, IamError>;

    /// Persist a freshly minted client. Returns
    /// [`IamError::Conflict`] on duplicate `(tenant_id, client_id)`.
    async fn create(&self, client: &OidcClient) -> Result<(), IamError>;

    /// Replace the persisted record (used by rotation). The repository
    /// MUST honour FORCE-RLS — a write through a wrong-tenant session
    /// MUST return zero rows.
    async fn update(&self, client: &OidcClient) -> Result<(), IamError>;
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::domain::{TenantId, UserId};
    use time::OffsetDateTime;

    /// Minimal fixture exercising only the trait defaults.
    ///
    /// `find_by_id` returns the embedded `user` (filtered by id) so the
    /// default implementation of `find_by_id_with_tenant` has something to
    /// delegate to.
    struct DefaultsFixture {
        user: Option<User>,
    }

    #[async_trait]
    impl UserRepository for DefaultsFixture {
        async fn find_by_email(
            &self,
            _tenant_id: TenantId,
            _email: &str,
        ) -> Result<Option<User>, IamError> {
            Ok(None)
        }

        async fn find_by_id(&self, id: UserId) -> Result<Option<User>, IamError> {
            Ok(self.user.clone().filter(|u| u.id == id))
        }

        async fn create(&self, _user: &User) -> Result<(), IamError> {
            Err(IamError::internal("not used in defaults test"))
        }
    }

    fn sample_user() -> User {
        User {
            id: UserId::new(),
            tenant_id: TenantId::new(),
            email: "a@b".into(),
            password_hash: String::new(),
            is_active: true,
            roles: vec![],
            created_at: OffsetDateTime::UNIX_EPOCH,
            updated_at: OffsetDateTime::UNIX_EPOCH,
        }
    }

    #[tokio::test]
    async fn default_update_returns_internal_error() {
        let repo = DefaultsFixture { user: None };
        let u = sample_user();
        let err = repo.update(&u).await.expect_err("default must error");
        match err {
            IamError::Internal(msg) => assert!(msg.contains("update")),
            other => panic!("expected IamError::Internal, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn default_find_by_id_with_tenant_delegates_to_find_by_id() {
        let u = sample_user();
        let repo = DefaultsFixture {
            user: Some(u.clone()),
        };
        // Any tenant id reaches the same delegate — the default ignores it.
        let other_tenant = TenantId::new();
        let got = repo
            .find_by_id_with_tenant(other_tenant, u.id)
            .await
            .expect("delegate must not error");
        assert_eq!(got.map(|x| x.id), Some(u.id));

        // Unknown id still returns None via the delegate.
        let unknown = repo
            .find_by_id_with_tenant(other_tenant, UserId::new())
            .await
            .expect("delegate must not error");
        assert!(unknown.is_none());
    }
}
