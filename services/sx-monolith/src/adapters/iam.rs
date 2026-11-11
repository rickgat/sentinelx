//! IAM adapter: wires `sx-iam`'s real use cases behind the `sx-api` ports.
//!
//! Components:
//! - [`Argon2idHasher`](sx_iam::Argon2idHasher) for password storage.
//! - [`JwtIssuer`](sx_iam::JwtIssuer) + [`JwtValidator`](sx_iam::JwtValidator)
//!   with a static `kid` resolver (key rotation lives in Phase 2).
//! - [`InMemoryUserRepository`] and `InMemoryTracker` used until a real
//!   persistence layer is bolted on; the Postgres-backed
//!   [`PgIamUserRepository`] swaps in when `database.enabled = true`.
//! - [`InMemorySessionRevoker`] backs [`LogoutPort`]: revoked `jti`s are
//!   stored in process memory and checked by an outer validator wrapper.
//!
//! ## Repository abstraction
//!
//! Both the in-memory and Postgres user repositories share the
//! [`MonolithUserRepo`] enum, which implements
//! [`sx_iam::port::UserRepository`] by dispatching to the active variant.
//! This keeps the [`AuthenticateUserUseCase`] / [`RefreshTokenUseCase`]
//! generics monomorphised against a single concrete type while still
//! letting the composition root choose between back-ends at boot.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use async_trait::async_trait;
use jsonwebtoken::DecodingKey;
use secrecy::ExposeSecret;
use sqlx::{PgPool, Postgres, Row, Transaction};
use sx_api::port::{
    AuthenticateUserInput, AuthenticateUserPort, LogoutPort, RbaActionWire, RbaEvaluateInput,
    RbaPort, RefreshTokenPort, ValidateTokenPort,
};
use sx_api::view::auth_view::TokenView;
use sx_iam::config::{IamConfig, JwtAlgorithm};
use sx_iam::controller::authenticate_user::AuthenticateInput;
use sx_iam::controller::issue_token::IssueTokenInput;
use sx_iam::controller::refresh_token::RefreshTokenInput;
use sx_iam::controller::{
    AuthenticateUserUseCase, IssueTokenUseCase, RefreshTokenUseCase, ValidateTokenUseCase,
};
use sx_iam::domain::{Role, TenantId, User, UserId};
use sx_iam::model::Credentials;
use sx_iam::port::UserRepository;
use sx_iam::service::{
    Argon2idHasher, AttemptKey, JwtIssuer, JwtValidator, LoginAttemptTracker, StaticKeyResolver,
    SystemClock,
};
use sx_iam::IamError;

type SharedAuth = AuthenticateUserUseCase<MonolithUserRepo, Argon2idHasher, DynTrackerWrapper>;

/// Trait-object wrapper so the use case (which requires a sized `T`) can hold
/// either the in-process tracker or the Redis-backed one.
#[derive(Clone)]
struct DynTrackerWrapper(Arc<dyn LoginAttemptTracker>);

impl std::fmt::Debug for DynTrackerWrapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DynTrackerWrapper").finish_non_exhaustive()
    }
}

#[async_trait]
impl LoginAttemptTracker for DynTrackerWrapper {
    async fn record_failure(&self, key: &AttemptKey) -> Result<u32, IamError> {
        self.0.record_failure(key).await
    }

    async fn count_failures(&self, key: &AttemptKey) -> Result<u32, IamError> {
        self.0.count_failures(key).await
    }

    async fn clear(&self, key: &AttemptKey) -> Result<(), IamError> {
        self.0.clear(key).await
    }
}
type SharedIssue = IssueTokenUseCase<JwtIssuer<SystemClock>, SystemClock>;
type SharedRefresh = RefreshTokenUseCase<
    MonolithUserRepo,
    JwtValidator<StaticKeyResolver>,
    JwtIssuer<SystemClock>,
    SystemClock,
>;
type SharedValidator = ValidateTokenUseCase<JwtValidator<StaticKeyResolver>>;

/// Bundle of ready-to-plug-in IAM trait objects.
///
/// `users` and `hasher` are also exposed so that downstream adapters
/// (notably the admin user-provisioning adapter) can share the same
/// repository + Argon2id hasher rather than constructing a second pair
/// that would not see the bootstrap admin.
pub(crate) struct IamBundle {
    pub authn: Arc<dyn AuthenticateUserPort>,
    /// Concrete `AuthnAdapter` exposed so the composition root can
    /// inject the RBA hook (`AuthnAdapter::set_rba`) after the RBA
    /// adapter is constructed. Keeps the trait-object `authn` slot in
    /// the `AppState` as the single thing handlers see while still
    /// letting the wiring code reach the inner adapter.
    pub authn_concrete: Arc<AuthnAdapter>,
    pub token_validator: Arc<dyn ValidateTokenPort>,
    pub refresh: Arc<dyn RefreshTokenPort>,
    pub logout: Arc<dyn LogoutPort>,
    /// Shared user repository (in-memory OR Postgres-backed).
    pub users: Arc<MonolithUserRepo>,
    /// Concrete Argon2id hasher shared with the admin adapter.
    pub hasher: Arc<Argon2idHasher>,
    /// Concrete issue-token use case shared with the OIDC exchange
    /// adapter so OIDC-issued sessions are minted by the same code path
    /// `/v1/auth/login` uses.
    pub issue: Arc<SharedIssue>,
}

/// Build the IAM bundle from `cfg`.
///
/// When `external_tracker` is `Some`, it is used as the login-attempt
/// tracker (typically a Redis-backed adapter); otherwise an in-process
/// `InMemoryTracker` is used.
///
/// `users` is the active user repository — either the in-memory store
/// (when `database.enabled = false`) or a Postgres-backed adapter (when
/// `database.enabled = true`). Both variants implement
/// [`sx_iam::port::UserRepository`] under the unified [`MonolithUserRepo`]
/// enum so the use case generics monomorphise to a single concrete type
/// regardless of which back-end is active.
///
/// `bootstrap` seeds a single admin user (with the supplied Argon2id PHC
/// string) into whichever repository was passed in. The seeding path is
/// repository-agnostic — see [`seed_bootstrap_admin`].
pub(crate) fn build(
    cfg: &IamConfig,
    session_ttl: Duration,
    external_tracker: Option<Arc<dyn LoginAttemptTracker>>,
    bootstrap: Option<&sx_config::schema::bootstrap::BootstrapConfig>,
    users: Arc<MonolithUserRepo>,
    revoked: Arc<dyn SessionRevoker>,
) -> anyhow::Result<IamBundle> {
    cfg.validate()
        .map_err(|e| anyhow::anyhow!("iam config invalid: {e}"))?;

    let tracker_inner: Arc<dyn LoginAttemptTracker> =
        external_tracker.unwrap_or_else(|| Arc::new(InMemoryTracker::default()));
    let tracker = Arc::new(DynTrackerWrapper(tracker_inner));

    let hasher = Arc::new(
        Argon2idHasher::from_config(&cfg.password)
            .map_err(|e| anyhow::anyhow!("argon2 init: {e}"))?,
    );
    let clock = Arc::new(SystemClock);

    let issuer = Arc::new(
        JwtIssuer::new(cfg.jwt.clone(), Arc::clone(&clock))
            .map_err(|e| anyhow::anyhow!("jwt issuer init: {e}"))?,
    );

    let decoding_key = decoding_key_for(cfg.jwt.algorithm, &cfg.jwt.verifying_key)?;
    let resolver = StaticKeyResolver::single(cfg.jwt.key_id.clone(), decoding_key);
    let validator = Arc::new(JwtValidator::new(cfg.jwt.clone(), resolver));

    let authn_uc: SharedAuth = AuthenticateUserUseCase::new(
        Arc::clone(&users),
        Arc::clone(&hasher),
        Arc::clone(&tracker),
        cfg.lockout,
        cfg.attempt_email_pepper.clone(),
    );
    let issue_uc: SharedIssue =
        IssueTokenUseCase::new(Arc::clone(&issuer), Arc::clone(&clock), session_ttl);
    let issue_shared: Arc<SharedIssue> = Arc::new(issue_uc);
    let refresh_uc: SharedRefresh = RefreshTokenUseCase::new(
        Arc::clone(&users),
        Arc::clone(&validator),
        Arc::clone(&issuer),
        Arc::clone(&clock),
        session_ttl,
    );
    let validate_uc: SharedValidator = ValidateTokenUseCase::new(Arc::clone(&validator));

    let authn_adapter = Arc::new(AuthnAdapter {
        authn: Arc::new(authn_uc),
        issue: Arc::clone(&issue_shared),
        rba: RwLock::new(None),
    });
    let validator_adapter = Arc::new(ValidatorAdapter {
        validate: Arc::new(validate_uc),
        revoked: Arc::clone(&revoked),
    });
    let refresh_adapter = Arc::new(RefreshAdapter {
        refresh: Arc::new(refresh_uc),
    });
    let logout_adapter = Arc::new(LogoutAdapter {
        revoked: Arc::clone(&revoked),
    });

    if let Some(b) = bootstrap.filter(|b| b.enabled) {
        seed_bootstrap_admin(users.as_ref() as &dyn UserRepository, b)?;
        // Analyst is opt-in: only seeded when BOTH email + PHC are
        // configured. The schema invariant in
        // `sx_config::schema::bootstrap` already rejects half-configs,
        // so a half-populated value here means the loader was bypassed
        // and the safer behaviour is to skip rather than panic.
        if b.analyst_email.is_some() && b.analyst_password_phc.is_some() {
            seed_bootstrap_analyst(users.as_ref() as &dyn UserRepository, b)?;
        }
    }

    Ok(IamBundle {
        authn: Arc::clone(&authn_adapter) as Arc<dyn AuthenticateUserPort>,
        authn_concrete: authn_adapter,
        token_validator: validator_adapter,
        refresh: refresh_adapter,
        logout: logout_adapter,
        users,
        hasher,
        issue: issue_shared,
    })
}

/// Seed the bootstrap admin into the supplied user repository.
///
/// Generates a fresh UUID v7 for the user, sets `is_active = true`, and
/// grants a single wildcard role so every protected route is reachable.
/// Idempotent: ignores `Conflict` on re-run.
///
/// Repository-agnostic — accepts any `&dyn sx_iam::port::UserRepository`,
/// so the same code path seeds both the in-memory repository (Phase-1
/// developer mode) and the Postgres repository (Phase-1.5+ production
/// mode).
pub(crate) fn seed_bootstrap_admin(
    users: &dyn UserRepository,
    cfg: &sx_config::schema::bootstrap::BootstrapConfig,
) -> anyhow::Result<()> {
    use sx_iam::domain::{Permission, Role, RoleId};

    let tenant_id = cfg
        .admin_tenant_id
        .map_or_else(TenantId::new, TenantId::from_uuid);

    let wildcard = Permission::parse("*:*")
        .map_err(|e| anyhow::anyhow!("seed: invalid wildcard permission: {e}"))?;
    let role = Role {
        id: RoleId::new(),
        tenant_id,
        name: "admin".to_string(),
        permissions: vec![wildcard],
    };

    let now = time::OffsetDateTime::now_utc();
    let user = User {
        id: UserId::new(),
        tenant_id,
        email: cfg.admin_email.to_ascii_lowercase(),
        password_hash: cfg.admin_password_phc.expose_secret().to_owned(),
        is_active: true,
        roles: vec![role],
        created_at: now,
        updated_at: now,
    };

    // The repository may be in-memory (sync, no I/O) or Postgres-backed
    // (real I/O). Both contracts return `IamError::Conflict` on duplicate
    // `(tenant_id, email)` which we collapse to `Ok(())` to keep the seed
    // idempotent across restarts.
    futures::executor::block_on(async {
        #[allow(clippy::match_same_arms)]
        match users.create(&user).await {
            Ok(()) => Ok(()),
            Err(sx_iam::IamError::Conflict(_)) => Ok(()),
            Err(e) => Err(anyhow::anyhow!("seed: {e}")),
        }
    })?;

    tracing::info!(
        target: "adapters.iam.bootstrap",
        tenant_id = %tenant_id,
        user_id = %user.id,
        email = %user.email,
        "seeded bootstrap admin into user repository"
    );
    Ok(())
}

/// Seed the bootstrap analyst into the supplied user repository.
///
/// Mirrors [`seed_bootstrap_admin`] in shape — same tenant, same
/// idempotency contract, same repository-agnostic signature — but
/// grants an `analyst` role with the read-only permission set the
/// dashboard exercises in the Playwright e2e suite (L1-FU1).
///
/// Caller MUST verify both `cfg.analyst_email` and
/// `cfg.analyst_password_phc` are `Some` before invoking; the function
/// returns early with `Ok(())` if either is missing so a partially-
/// configured boot does not panic.
pub(crate) fn seed_bootstrap_analyst(
    users: &dyn UserRepository,
    cfg: &sx_config::schema::bootstrap::BootstrapConfig,
) -> anyhow::Result<()> {
    use sx_iam::domain::{Permission, Role, RoleId};

    let (Some(analyst_email), Some(analyst_phc)) = (
        cfg.analyst_email.as_ref(),
        cfg.analyst_password_phc.as_ref(),
    ) else {
        // Half-configured — skip silently. The schema validator should
        // have rejected this upstream; treating it as a no-op here keeps
        // the seed call site simple.
        return Ok(());
    };

    let tenant_id = cfg
        .admin_tenant_id
        .map_or_else(TenantId::new, TenantId::from_uuid);

    // Analyst role: dashboard read-only surface area. The dashboard's
    // admin specs separately exercise the `admin` user, so the analyst
    // doesn't need wildcard permissions — `findings:read` +
    // `engagements:read` cover the navigation / list specs that
    // `analyst@sentinelx.dev` drives in e2e.
    let perms = [
        "findings:read",
        "engagements:read",
        "assets:read",
        "dashboard:read",
    ]
    .into_iter()
    .map(Permission::parse)
    .collect::<Result<Vec<_>, _>>()
    .map_err(|e| anyhow::anyhow!("seed: invalid analyst permission: {e}"))?;
    let role = Role {
        id: RoleId::new(),
        tenant_id,
        name: "analyst".to_string(),
        permissions: perms,
    };

    let now = time::OffsetDateTime::now_utc();
    let user = User {
        id: UserId::new(),
        tenant_id,
        email: analyst_email.to_ascii_lowercase(),
        password_hash: analyst_phc.expose_secret().to_owned(),
        is_active: true,
        roles: vec![role],
        created_at: now,
        updated_at: now,
    };

    futures::executor::block_on(async {
        #[allow(clippy::match_same_arms)]
        match users.create(&user).await {
            Ok(()) => Ok(()),
            Err(sx_iam::IamError::Conflict(_)) => Ok(()),
            Err(e) => Err(anyhow::anyhow!("seed analyst: {e}")),
        }
    })?;

    tracing::info!(
        target: "adapters.iam.bootstrap",
        tenant_id = %tenant_id,
        user_id = %user.id,
        email = %user.email,
        "seeded bootstrap analyst into user repository"
    );
    Ok(())
}

fn decoding_key_for(alg: JwtAlgorithm, key: &secrecy::SecretString) -> anyhow::Result<DecodingKey> {
    match alg {
        JwtAlgorithm::Hs256 => Ok(DecodingKey::from_secret(key.expose_secret().as_bytes())),
        JwtAlgorithm::Rs256 => DecodingKey::from_rsa_pem(key.expose_secret().as_bytes())
            .map_err(|e| anyhow::anyhow!("invalid RS256 PEM: {e}")),
        JwtAlgorithm::EdDsa => DecodingKey::from_ed_pem(key.expose_secret().as_bytes())
            .map_err(|e| anyhow::anyhow!("invalid EdDSA PEM: {e}")),
    }
}

// ----- AuthnAdapter -------------------------------------------------------

pub(crate) struct AuthnAdapter {
    authn: Arc<SharedAuth>,
    issue: Arc<SharedIssue>,
    /// Optional RBA hook — when present the adapter consults the engine
    /// AFTER a successful credential check but BEFORE a JWT is issued.
    /// The hook is installed by `set_rba` once the composition root has
    /// resolved its own RBA adapter; running with `None` skips RBA
    /// entirely (matches the historic behaviour and is the safe default
    /// for unit tests).
    rba: RwLock<Option<Arc<dyn RbaPort>>>,
}

impl AuthnAdapter {
    /// Install the RBA hook. Idempotent — the latest call wins.
    pub(crate) fn set_rba(&self, rba: Arc<dyn RbaPort>) {
        if let Ok(mut g) = self.rba.write() {
            *g = Some(rba);
        }
    }
}

#[async_trait]
impl AuthenticateUserPort for AuthnAdapter {
    async fn authenticate(&self, input: AuthenticateUserInput) -> Result<TokenView, IamError> {
        let tenant = input
            .tenant_id
            .parse::<uuid::Uuid>()
            .map(TenantId::from_uuid)
            .map_err(|_| IamError::InvalidCredentials)?;

        let email_norm = input.email.to_ascii_lowercase();
        let ip = input.ip.clone();
        let ua = input.user_agent.clone();

        let creds = Credentials {
            tenant_id: tenant,
            email: input.email,
            password: input.password,
        };
        let user = self
            .authn
            .execute(AuthenticateInput { credentials: creds })
            .await?;

        // RBA hook: consult the engine after credential success but
        // BEFORE issuing a JWT. The engine always audits, even on
        // `Allow`, so the SOC has a record either way.
        let rba_opt: Option<Arc<dyn RbaPort>> = self.rba.read().ok().and_then(|g| g.clone());
        if let Some(rba) = rba_opt {
            let rba_input = RbaEvaluateInput {
                tenant_id: input.tenant_id.clone(),
                user_id: Some(user.id.to_string()),
                email: email_norm,
                ip: ip.unwrap_or_default(),
                device_fingerprint: ua,
            };
            match rba.evaluate(rba_input).await {
                Ok(out) => match out.action {
                    RbaActionWire::Allow => {}
                    RbaActionWire::StepUpMfa => {
                        tracing::info!(
                            target: "adapters.iam.rba",
                            tenant_id = %input.tenant_id,
                            score = out.score,
                            "rba step-up MFA required"
                        );
                        return Err(IamError::forbidden("rba_step_up_mfa_required"));
                    }
                    RbaActionWire::Block => {
                        tracing::warn!(
                            target: "adapters.iam.rba",
                            tenant_id = %input.tenant_id,
                            score = out.score,
                            "rba blocked login"
                        );
                        return Err(IamError::forbidden("rba_block"));
                    }
                },
                Err(e) => {
                    // Engine failure is fail-open in the MVP: a transient
                    // adapter error must not lock every user out. The
                    // audit row is still written by the engine path
                    // before the error surfaces.
                    tracing::error!(
                        target: "adapters.iam.rba",
                        error = %e,
                        "rba evaluate failed — proceeding without action"
                    );
                }
            }
        }

        let out = self.issue.execute(IssueTokenInput {
            user,
            ip: None,
            user_agent: None,
            cred_id: None,
        })?;
        Ok(token_to_view(&out.token))
    }
}

fn token_to_view(token: &sx_iam::model::Token) -> TokenView {
    let access = token.access.expose_secret().to_owned();
    let refresh = token.refresh.expose_secret().to_owned();
    let expires_in = i64::try_from(token.expires_in).unwrap_or(i64::MAX);
    TokenView::bearer(access, refresh, expires_in)
}

// ----- ValidatorAdapter ---------------------------------------------------

struct ValidatorAdapter {
    validate: Arc<SharedValidator>,
    revoked: Arc<dyn SessionRevoker>,
}

#[async_trait]
impl ValidateTokenPort for ValidatorAdapter {
    async fn validate(&self, token: &str) -> Result<sx_iam::model::claims::AccessClaims, IamError> {
        let claims = self.validate.execute(token)?;
        if self.revoked.is_revoked(&claims.jti).await {
            return Err(IamError::InvalidToken);
        }
        Ok(claims)
    }
}

// ----- RefreshAdapter -----------------------------------------------------

struct RefreshAdapter {
    refresh: Arc<SharedRefresh>,
}

#[async_trait]
impl RefreshTokenPort for RefreshAdapter {
    async fn refresh(&self, refresh_token: &str) -> Result<TokenView, IamError> {
        let token = self
            .refresh
            .execute(RefreshTokenInput {
                refresh_token: refresh_token.to_owned(),
            })
            .await?;
        Ok(token_to_view(&token))
    }
}

// ----- LogoutAdapter ------------------------------------------------------

struct LogoutAdapter {
    revoked: Arc<dyn SessionRevoker>,
}

#[async_trait]
impl LogoutPort for LogoutAdapter {
    async fn revoke(&self, jti: &str) -> Result<(), IamError> {
        self.revoked.revoke(jti).await
    }
}

// ----- In-memory backing stores ------------------------------------------

/// In-memory user repository. Empty by default; user provisioning is a
/// dedicated controller in Phase 1.5.
#[derive(Debug, Default)]
pub(crate) struct InMemoryUserRepository {
    by_id: Mutex<HashMap<UserId, User>>,
    by_email: Mutex<HashMap<(TenantId, String), UserId>>,
}

impl InMemoryUserRepository {
    /// List users for `tenant_id`, capped at `limit` rows after skipping
    /// the first `offset`. Stable order by `id` so paging is
    /// deterministic across calls.
    #[allow(clippy::unused_async)] // async kept for symmetry with the Postgres variant in the parent enum
    pub(crate) async fn list_for_tenant(
        &self,
        tenant_id: TenantId,
        limit: u32,
        offset: u64,
    ) -> Result<Vec<User>, IamError> {
        let guard = self
            .by_id
            .lock()
            .map_err(|_| IamError::internal("user repo poisoned"))?;
        let mut rows: Vec<User> = guard
            .values()
            .filter(|u| u.tenant_id == tenant_id)
            .cloned()
            .collect();
        rows.sort_by_key(|u| u.id);
        Ok(rows
            .into_iter()
            .skip(usize::try_from(offset).unwrap_or(usize::MAX))
            .take(usize::try_from(limit).unwrap_or(usize::MAX))
            .collect())
    }
}

#[async_trait]
impl UserRepository for InMemoryUserRepository {
    async fn find_by_email(
        &self,
        tenant_id: TenantId,
        email: &str,
    ) -> Result<Option<User>, IamError> {
        let id = {
            let guard = self
                .by_email
                .lock()
                .map_err(|_| IamError::internal("user repo poisoned"))?;
            guard.get(&(tenant_id, email.to_ascii_lowercase())).copied()
        };
        let Some(id) = id else { return Ok(None) };
        let guard = self
            .by_id
            .lock()
            .map_err(|_| IamError::internal("user repo poisoned"))?;
        Ok(guard.get(&id).cloned())
    }

    async fn find_by_id(&self, id: UserId) -> Result<Option<User>, IamError> {
        let guard = self
            .by_id
            .lock()
            .map_err(|_| IamError::internal("user repo poisoned"))?;
        Ok(guard.get(&id).cloned())
    }

    async fn create(&self, user: &User) -> Result<(), IamError> {
        let email_key = (user.tenant_id, user.email.to_ascii_lowercase());
        let mut by_email = self
            .by_email
            .lock()
            .map_err(|_| IamError::internal("user repo poisoned"))?;
        if by_email.contains_key(&email_key) {
            return Err(IamError::conflict("user"));
        }
        let mut by_id = self
            .by_id
            .lock()
            .map_err(|_| IamError::internal("user repo poisoned"))?;
        by_email.insert(email_key, user.id);
        by_id.insert(user.id, user.clone());
        Ok(())
    }

    async fn find_by_id_with_tenant(
        &self,
        tenant_id: TenantId,
        id: UserId,
    ) -> Result<Option<User>, IamError> {
        let guard = self
            .by_id
            .lock()
            .map_err(|_| IamError::internal("user repo poisoned"))?;
        Ok(guard.get(&id).filter(|u| u.tenant_id == tenant_id).cloned())
    }

    /// Replace the mutable state of an existing user row and stamp
    /// `updated_at` to the wall clock now. Covers both the
    /// `verify_email` (is_active flip) and `reset_password`
    /// (password_hash rotation) call-sites.
    async fn update(&self, user: &User) -> Result<(), IamError> {
        let mut by_id = self
            .by_id
            .lock()
            .map_err(|_| IamError::internal("user repo poisoned"))?;
        match by_id.get_mut(&user.id) {
            Some(existing) if existing.tenant_id == user.tenant_id => {
                // Replace the aggregate wholesale so any mutable column the
                // caller changed (is_active, password_hash, ...) lands in
                // one shot, matching the Postgres adapter's UPDATE
                // semantics.
                *existing = user.clone();
                existing.updated_at = time::OffsetDateTime::now_utc();
                Ok(())
            }
            Some(_) | None => Err(IamError::repository("user not found")),
        }
    }
}

/// Postgres-backed implementation of [`sx_iam::port::UserRepository`].
///
/// Reads / writes the `users` table under tenant-scoped RLS context. The
/// [`sx_storage::tenant_context::TenantContext`] is applied via a sub-
/// transaction so the row-level security policy passes.
///
/// ## `find_by_id` vs. `find_by_id_with_tenant`
///
/// The [`sx_iam::port::UserRepository::find_by_id`] contract does not
/// carry a tenant id. The `users` table is under FORCE RLS, so a plain
/// `SELECT … WHERE id = $1` returns zero rows when the GUC is unset —
/// this adapter therefore short-circuits `find_by_id` to `Ok(None)` and
/// logs a debug breadcrumb. Callers that have a tenant available (the
/// [`sx_iam::controller::RefreshTokenUseCase`] reads it from the JWT
/// claim) should instead call
/// [`sx_iam::port::UserRepository::find_by_id_with_tenant`], which this
/// adapter overrides to open a tx, `SET LOCAL`s `app.current_tenant_id`,
/// and runs the lookup under RLS.
#[derive(Debug, Clone)]
pub(crate) struct PgIamUserRepository {
    pool: PgPool,
    stmt_timeout_ms: u64,
}

impl PgIamUserRepository {
    /// Construct a Postgres-backed user repository.
    pub(crate) const fn new(pool: PgPool, stmt_timeout_ms: u64) -> Self {
        Self {
            pool,
            stmt_timeout_ms,
        }
    }

    fn bounded_timeout(&self) -> u64 {
        self.stmt_timeout_ms.min(u64::from(u32::MAX))
    }
}

/// Translate a `users` row into the [`sx_iam::domain::User`] shape.
///
/// Roles are not persisted alongside the user in the current schema (a
/// dedicated `user_roles` table joins to `roles`). For the bootstrap-
/// admin path the seeded wildcard role is reconstructed by the caller
/// via the JWT issuer's permissions claim, so returning an empty `roles`
/// list here is correct for Phase-1.5 authentication.
fn pg_row_to_iam_user(row: &sqlx::postgres::PgRow) -> Result<User, IamError> {
    let id: uuid::Uuid = row
        .try_get("id")
        .map_err(|e| IamError::internal(format!("decode users.id: {e}")))?;
    let tenant_id: uuid::Uuid = row
        .try_get("tenant_id")
        .map_err(|e| IamError::internal(format!("decode users.tenant_id: {e}")))?;
    let email: String = row
        .try_get("email")
        .map_err(|e| IamError::internal(format!("decode users.email: {e}")))?;
    let password_hash: String = row
        .try_get("password_hash")
        .map_err(|e| IamError::internal(format!("decode users.password_hash: {e}")))?;
    let is_active: bool = row
        .try_get("is_active")
        .map_err(|e| IamError::internal(format!("decode users.is_active: {e}")))?;
    // The current `users` schema doesn't expose created_at / updated_at via this
    // adapter; populate with `now` as a defensible default. A follow-up will
    // thread the real persisted timestamps through.
    let now = time::OffsetDateTime::now_utc();
    Ok(User {
        id: UserId::from_uuid(id),
        tenant_id: TenantId::from_uuid(tenant_id),
        email,
        password_hash,
        is_active,
        // Roles are loaded separately by `pg_load_user_roles` (joined from
        // `user_roles`/`role_permissions`) and assigned by the caller, which
        // holds the open RLS transaction. Start empty here.
        roles: vec![],
        created_at: now,
        updated_at: now,
    })
}

/// Load a user's roles + their permissions from the RBAC tables, within an
/// already-open, tenant-scoped (RLS GUC applied) transaction.
///
/// Without this join a Postgres-backed user authenticates with an empty
/// permissions claim and every authorised endpoint returns 403 — see the
/// IAM-RBAC fix. A permission string that fails to parse is skipped (never
/// panics); a malformed stored grant must not take down login.
async fn pg_load_user_roles(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: TenantId,
    user_id: UserId,
) -> Result<Vec<Role>, IamError> {
    use std::collections::BTreeMap;

    use sx_iam::domain::{Permission, RoleId};

    let rows = sqlx::query(
        "SELECT r.id AS role_id, r.name AS role_name, p.name AS perm_name \
         FROM user_roles ur \
         JOIN roles r ON r.id = ur.role_id \
         LEFT JOIN role_permissions rp ON rp.role_id = r.id \
         LEFT JOIN permissions p ON p.id = rp.permission_id \
         WHERE ur.tenant_id = $1 AND ur.user_id = $2 \
         ORDER BY r.name",
    )
    .bind(tenant_id.as_uuid())
    .bind(user_id.as_uuid())
    .fetch_all(&mut **tx)
    .await
    .map_err(|e| IamError::internal(format!("pg load user roles: {e}")))?;

    // Group rows (one per role×permission) back into roles.
    let mut by_role: BTreeMap<uuid::Uuid, (String, Vec<Permission>)> = BTreeMap::new();
    for row in &rows {
        let rid: uuid::Uuid = row
            .try_get("role_id")
            .map_err(|e| IamError::internal(format!("decode role_id: {e}")))?;
        let rname: String = row
            .try_get("role_name")
            .map_err(|e| IamError::internal(format!("decode role_name: {e}")))?;
        let perm_name: Option<String> = row
            .try_get("perm_name")
            .map_err(|e| IamError::internal(format!("decode perm_name: {e}")))?;
        let entry = by_role.entry(rid).or_insert_with(|| (rname, Vec::new()));
        if let Some(pn) = perm_name {
            if let Ok(perm) = Permission::parse(&pn) {
                entry.1.push(perm);
            } else {
                tracing::warn!(permission = %pn, "skipping unparseable stored permission");
            }
        }
    }

    Ok(by_role
        .into_iter()
        .map(|(rid, (name, permissions))| Role {
            id: RoleId::from_uuid(rid),
            tenant_id,
            name,
            permissions,
        })
        .collect())
}

/// Persist a user's roles + permissions + links, within an already-open,
/// tenant-scoped (RLS GUC applied) transaction. Idempotent: roles upsert on
/// `(tenant_id, name)`, permissions on `name`, and both link tables use
/// `ON CONFLICT DO NOTHING`. This is what lets the bootstrap admin's `*:*`
/// role (and any seeded role) survive into the Postgres deployment.
async fn pg_persist_user_roles(
    tx: &mut Transaction<'_, Postgres>,
    user: &User,
) -> Result<(), IamError> {
    for role in &user.roles {
        let role_row = sqlx::query(
            "INSERT INTO roles (id, tenant_id, name, description, is_system, created_at) \
             VALUES ($1, $2, $3, '', FALSE, now()) \
             ON CONFLICT (tenant_id, name) DO UPDATE SET name = EXCLUDED.name \
             RETURNING id",
        )
        .bind(role.id.as_uuid())
        .bind(user.tenant_id.as_uuid())
        .bind(&role.name)
        .fetch_one(&mut **tx)
        .await
        .map_err(|e| IamError::internal(format!("pg upsert role: {e}")))?;
        let role_id: uuid::Uuid = role_row
            .try_get("id")
            .map_err(|e| IamError::internal(format!("decode upserted role id: {e}")))?;

        for perm in &role.permissions {
            let perm_row = sqlx::query(
                "INSERT INTO permissions (id, name, description) \
                 VALUES (gen_random_uuid(), $1, '') \
                 ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name \
                 RETURNING id",
            )
            .bind(perm.to_string())
            .fetch_one(&mut **tx)
            .await
            .map_err(|e| IamError::internal(format!("pg upsert permission: {e}")))?;
            let perm_id: uuid::Uuid = perm_row
                .try_get("id")
                .map_err(|e| IamError::internal(format!("decode upserted perm id: {e}")))?;

            sqlx::query(
                "INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2) \
                 ON CONFLICT DO NOTHING",
            )
            .bind(role_id)
            .bind(perm_id)
            .execute(&mut **tx)
            .await
            .map_err(|e| IamError::internal(format!("pg link role_permission: {e}")))?;
        }

        sqlx::query(
            "INSERT INTO user_roles (tenant_id, user_id, role_id, assigned_at) \
             VALUES ($1, $2, $3, now()) ON CONFLICT DO NOTHING",
        )
        .bind(user.tenant_id.as_uuid())
        .bind(user.id.as_uuid())
        .bind(role_id)
        .execute(&mut **tx)
        .await
        .map_err(|e| IamError::internal(format!("pg link user_role: {e}")))?;
    }
    Ok(())
}

#[async_trait]
impl UserRepository for PgIamUserRepository {
    async fn find_by_email(
        &self,
        tenant_id: TenantId,
        email: &str,
    ) -> Result<Option<User>, IamError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| IamError::internal(format!("pg find_by_email begin: {e}")))?;

        // RLS gate: apply the tenant-scoped GUC + statement timeout.
        sqlx::query("SELECT set_config('app.current_tenant_id', $1, true)")
            .bind(tenant_id.as_uuid().to_string())
            .execute(&mut *tx)
            .await
            .map_err(|e| IamError::internal(format!("pg set_config tenant: {e}")))?;
        let stmt = format!("SET LOCAL statement_timeout = {}", self.bounded_timeout());
        sqlx::query(&stmt)
            .execute(&mut *tx)
            .await
            .map_err(|e| IamError::internal(format!("pg statement_timeout: {e}")))?;

        let row = sqlx::query(
            "SELECT id, tenant_id, email::text AS email, password_hash, is_active \
             FROM users WHERE email = $1::citext AND tenant_id = $2 AND is_active = TRUE",
        )
        .bind(email)
        .bind(tenant_id.as_uuid())
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| IamError::internal(format!("pg find_by_email: {e}")))?;

        // Load RBAC grants inside the same RLS tx before committing, so the
        // authenticated user carries its real roles/permissions.
        let user = match row {
            Some(r) => {
                let mut u = pg_row_to_iam_user(&r)?;
                u.roles = pg_load_user_roles(&mut tx, tenant_id, u.id).await?;
                Some(u)
            }
            None => None,
        };

        tx.commit()
            .await
            .map_err(|e| IamError::internal(format!("pg find_by_email commit: {e}")))?;

        Ok(user)
    }

    async fn find_by_id(&self, id: UserId) -> Result<Option<User>, IamError> {
        // `find_by_id` carries no tenant context, but the `users` table
        // is under FORCE RLS. Without a tenant GUC the policy rejects
        // every row, so we short-circuit to `Ok(None)` here. Callers
        // that do have a tenant (e.g. the refresh-token controller, via
        // the JWT `tenant_id` claim) should use
        // [`UserRepository::find_by_id_with_tenant`] instead, which is
        // overridden below to apply the tenant GUC under a tx.
        tracing::debug!(
            user_id = %id,
            "pg user repo: find_by_id without tenant context — returning None; use find_by_id_with_tenant"
        );
        Ok(None)
    }

    async fn find_by_id_with_tenant(
        &self,
        tenant_id: TenantId,
        id: UserId,
    ) -> Result<Option<User>, IamError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| IamError::internal(format!("pg find_by_id_with_tenant begin: {e}")))?;

        // RLS gate: apply the tenant-scoped GUC + statement timeout. The
        // same shape as `find_by_email` above — keep it identical so the
        // two paths share an audit story.
        sqlx::query("SELECT set_config('app.current_tenant_id', $1, true)")
            .bind(tenant_id.as_uuid().to_string())
            .execute(&mut *tx)
            .await
            .map_err(|e| IamError::internal(format!("pg set_config tenant: {e}")))?;
        let stmt = format!("SET LOCAL statement_timeout = {}", self.bounded_timeout());
        sqlx::query(&stmt)
            .execute(&mut *tx)
            .await
            .map_err(|e| IamError::internal(format!("pg statement_timeout: {e}")))?;

        // RLS filters by tenant; we still bind `tenant_id` explicitly so
        // the query plan does not rely solely on the policy and so a
        // misconfigured GUC cannot leak cross-tenant rows.
        let row = sqlx::query(
            "SELECT id, tenant_id, email::text AS email, password_hash, is_active \
             FROM users WHERE id = $1 AND tenant_id = $2",
        )
        .bind(id.as_uuid())
        .bind(tenant_id.as_uuid())
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| IamError::internal(format!("pg find_by_id_with_tenant: {e}")))?;

        let user = match row {
            Some(r) => {
                let mut u = pg_row_to_iam_user(&r)?;
                u.roles = pg_load_user_roles(&mut tx, tenant_id, u.id).await?;
                Some(u)
            }
            None => None,
        };

        tx.commit()
            .await
            .map_err(|e| IamError::internal(format!("pg find_by_id_with_tenant commit: {e}")))?;

        Ok(user)
    }

    async fn create(&self, user: &User) -> Result<(), IamError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| IamError::internal(format!("pg create begin: {e}")))?;

        sqlx::query("SELECT set_config('app.current_tenant_id', $1, true)")
            .bind(user.tenant_id.as_uuid().to_string())
            .execute(&mut *tx)
            .await
            .map_err(|e| IamError::internal(format!("pg set_config tenant: {e}")))?;
        let stmt = format!("SET LOCAL statement_timeout = {}", self.bounded_timeout());
        sqlx::query(&stmt)
            .execute(&mut *tx)
            .await
            .map_err(|e| IamError::internal(format!("pg statement_timeout: {e}")))?;

        // Display name defaults to the email local-part to satisfy the
        // NOT NULL + length constraint on the column.
        let display_name = user
            .email
            .split('@')
            .next()
            .filter(|s| !s.is_empty())
            .unwrap_or(&user.email);

        let result = sqlx::query(
            "INSERT INTO users (id, tenant_id, email, password_hash, display_name, is_active) \
             VALUES ($1, $2, $3::citext, $4, $5, $6) \
             ON CONFLICT (tenant_id, email) DO NOTHING",
        )
        .bind(user.id.as_uuid())
        .bind(user.tenant_id.as_uuid())
        .bind(&user.email)
        .bind(&user.password_hash)
        .bind(display_name)
        .bind(user.is_active)
        .execute(&mut *tx)
        .await
        .map_err(|e| IamError::internal(format!("pg create user: {e}")))?;

        if result.rows_affected() == 0 {
            // ON CONFLICT DO NOTHING — the user already exists. Commit the
            // no-op tx and collapse to the canonical conflict error so the
            // bootstrap seeder treats it as success (roles already persisted
            // on the original insert).
            tx.commit()
                .await
                .map_err(|e| IamError::internal(format!("pg create commit: {e}")))?;
            return Err(IamError::conflict("user"));
        }

        // Persist the user's RBAC grants (roles -> permissions -> links) in
        // the same tenant-scoped tx, so a Postgres-backed user carries its
        // permissions on the next login. Without this the user would load
        // with an empty permissions claim (every authorised endpoint 403).
        pg_persist_user_roles(&mut tx, user).await?;

        tx.commit()
            .await
            .map_err(|e| IamError::internal(format!("pg create commit: {e}")))?;
        Ok(())
    }

    /// Update the mutable columns of a `users` row under the
    /// tenant-scoped RLS context. Covers both `customer_auth::verify_email`
    /// (flipping `is_active`) and `customer_auth::reset_password`
    /// (rotating `password_hash`). `updated_at` is stamped server-side via
    /// `now()` so we don't need to thread a clock through the adapter.
    async fn update(&self, user: &User) -> Result<(), IamError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| IamError::internal(format!("pg update begin: {e}")))?;

        sqlx::query("SELECT set_config('app.current_tenant_id', $1, true)")
            .bind(user.tenant_id.as_uuid().to_string())
            .execute(&mut *tx)
            .await
            .map_err(|e| IamError::internal(format!("pg set_config tenant: {e}")))?;
        let stmt = format!("SET LOCAL statement_timeout = {}", self.bounded_timeout());
        sqlx::query(&stmt)
            .execute(&mut *tx)
            .await
            .map_err(|e| IamError::internal(format!("pg statement_timeout: {e}")))?;

        let result = sqlx::query(
            "UPDATE users \
             SET is_active = $1, password_hash = $2, email = $3::citext, updated_at = now() \
             WHERE id = $4 AND tenant_id = $5",
        )
        .bind(user.is_active)
        .bind(&user.password_hash)
        .bind(&user.email)
        .bind(user.id.as_uuid())
        .bind(user.tenant_id.as_uuid())
        .execute(&mut *tx)
        .await
        .map_err(|e| IamError::internal(format!("pg update user: {e}")))?;

        tx.commit()
            .await
            .map_err(|e| IamError::internal(format!("pg update commit: {e}")))?;

        if result.rows_affected() == 0 {
            return Err(IamError::repository("user not found"));
        }
        Ok(())
    }
}

/// Unified user repository used by the IAM use cases.
///
/// Wraps either the in-memory store (developer mode) or the Postgres-
/// backed adapter (production mode). The active variant is chosen by the
/// composition root at boot — see `crate::adapters::build_app_state`.
#[derive(Debug)]
pub(crate) enum MonolithUserRepo {
    /// In-process store backing the developer / test mode.
    InMemory(InMemoryUserRepository),
    /// Postgres-backed store wired to the live `users` table.
    Postgres(PgIamUserRepository),
}

impl MonolithUserRepo {
    /// Convenience constructor for the in-memory variant.
    pub(crate) fn in_memory() -> Self {
        Self::InMemory(InMemoryUserRepository::default())
    }

    /// Convenience constructor for the Postgres variant.
    pub(crate) const fn postgres(repo: PgIamUserRepository) -> Self {
        Self::Postgres(repo)
    }

    /// List active users for a tenant, capped at `limit` rows after
    /// skipping the first `offset`. Used by the admin-user list HTTP
    /// surface (`GET /v1/admin/users`).
    ///
    /// The in-memory flavour iterates the local map; the Postgres flavour
    /// returns an empty vector for now — wiring a `SELECT … LIMIT $1
    /// OFFSET $2` lands when the production deploy phase adds the
    /// per-tenant index. Callers should treat the response as a
    /// best-effort projection.
    pub(crate) async fn list_for_tenant(
        &self,
        tenant_id: TenantId,
        limit: u32,
        offset: u64,
    ) -> Result<Vec<User>, IamError> {
        match self {
            Self::InMemory(r) => r.list_for_tenant(tenant_id, limit, offset).await,
            Self::Postgres(_) => Ok(Vec::new()),
        }
    }
}

#[async_trait]
impl UserRepository for MonolithUserRepo {
    async fn find_by_email(
        &self,
        tenant_id: TenantId,
        email: &str,
    ) -> Result<Option<User>, IamError> {
        match self {
            Self::InMemory(r) => r.find_by_email(tenant_id, email).await,
            Self::Postgres(r) => r.find_by_email(tenant_id, email).await,
        }
    }

    async fn find_by_id(&self, id: UserId) -> Result<Option<User>, IamError> {
        match self {
            Self::InMemory(r) => r.find_by_id(id).await,
            Self::Postgres(r) => r.find_by_id(id).await,
        }
    }

    async fn find_by_id_with_tenant(
        &self,
        tenant_id: TenantId,
        id: UserId,
    ) -> Result<Option<User>, IamError> {
        match self {
            Self::InMemory(r) => r.find_by_id_with_tenant(tenant_id, id).await,
            Self::Postgres(r) => r.find_by_id_with_tenant(tenant_id, id).await,
        }
    }

    async fn create(&self, user: &User) -> Result<(), IamError> {
        match self {
            Self::InMemory(r) => r.create(user).await,
            Self::Postgres(r) => r.create(user).await,
        }
    }

    async fn update(&self, user: &User) -> Result<(), IamError> {
        match self {
            Self::InMemory(r) => r.update(user).await,
            Self::Postgres(r) => r.update(user).await,
        }
    }
}

/// In-memory failure-count tracker. Mirrors the Redis adapter's contract.
#[derive(Debug, Default)]
pub(crate) struct InMemoryTracker {
    counts: Mutex<HashMap<AttemptKey, u32>>,
}

#[async_trait]
impl LoginAttemptTracker for InMemoryTracker {
    async fn record_failure(&self, key: &AttemptKey) -> Result<u32, IamError> {
        let mut g = self
            .counts
            .lock()
            .map_err(|_| IamError::internal("tracker poisoned"))?;
        let entry = g.entry(key.clone()).or_insert(0);
        *entry = entry.saturating_add(1);
        Ok(*entry)
    }

    async fn count_failures(&self, key: &AttemptKey) -> Result<u32, IamError> {
        let g = self
            .counts
            .lock()
            .map_err(|_| IamError::internal("tracker poisoned"))?;
        Ok(g.get(key).copied().unwrap_or(0))
    }

    async fn clear(&self, key: &AttemptKey) -> Result<(), IamError> {
        let mut g = self
            .counts
            .lock()
            .map_err(|_| IamError::internal("tracker poisoned"))?;
        g.remove(key);
        Ok(())
    }
}

/// In-memory revocation set keyed by JWT `jti`. A Redis impl would back this
/// across instances; here we accept single-process semantics.
/// Session-revocation store: holds the `jti` of every logged-out / revoked
/// access token so [`ValidateTokenPort`] rejects it before its natural
/// expiry. It is a request hot path (checked on every token validation), so
/// the durable backend is Redis (survives a monolith restart, shared across
/// instances); the in-memory impl below is the single-process dev fallback
/// and loses its set on restart.
#[async_trait]
pub(crate) trait SessionRevoker: Send + Sync + std::fmt::Debug {
    /// Mark `jti` revoked.
    async fn revoke(&self, jti: &str) -> Result<(), IamError>;
    /// Whether `jti` has been revoked.
    async fn is_revoked(&self, jti: &str) -> bool;
}

#[derive(Debug, Default)]
pub(crate) struct InMemorySessionRevoker {
    jtis: Mutex<HashSet<String>>,
}

#[async_trait]
impl SessionRevoker for InMemorySessionRevoker {
    async fn revoke(&self, jti: &str) -> Result<(), IamError> {
        if let Ok(mut g) = self.jtis.lock() {
            g.insert(jti.to_owned());
        }
        Ok(())
    }

    async fn is_revoked(&self, jti: &str) -> bool {
        self.jtis.lock().is_ok_and(|g| g.contains(jti))
    }
}

// ---------------------------------------------------------------------------
// Tests — bootstrap-admin seeding repo-agnosticism + Postgres adapter parsing
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use secrecy::SecretString;
    use sx_config::schema::bootstrap::BootstrapConfig;
    use uuid::Uuid;

    /// Mock repository capturing every `create` call. Used to demonstrate
    /// that [`seed_bootstrap_admin`] is repository-agnostic — any type
    /// implementing [`sx_iam::port::UserRepository`] is acceptable.
    #[derive(Debug, Default)]
    struct MockUserRepo {
        created: Mutex<Vec<User>>,
        force_conflict: bool,
    }

    #[async_trait]
    impl UserRepository for MockUserRepo {
        async fn find_by_email(
            &self,
            _tenant: TenantId,
            _email: &str,
        ) -> Result<Option<User>, IamError> {
            Ok(None)
        }

        async fn find_by_id(&self, _id: UserId) -> Result<Option<User>, IamError> {
            Ok(None)
        }

        async fn create(&self, user: &User) -> Result<(), IamError> {
            if self.force_conflict {
                return Err(IamError::conflict("user"));
            }
            self.created.lock().unwrap().push(user.clone());
            Ok(())
        }
    }

    fn sample_bootstrap_cfg() -> BootstrapConfig {
        BootstrapConfig {
            enabled: true,
            admin_tenant_slug: "default".into(),
            admin_tenant_name: "Default Tenant".into(),
            admin_tenant_id: Some(
                Uuid::parse_str("01010101-0101-0101-0101-010101010101").unwrap(),
            ),
            admin_email: "admin@sentinelx.dev".into(),
            admin_password_phc: SecretString::from(
                "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0c2FsdA$abcdefghijklmnopqrstuvwxyz123456"
                    .to_string(),
            ),
            seed_demo_data: false,
            analyst_email: None,
            analyst_password_phc: None,
        }
    }

    fn sample_bootstrap_cfg_with_analyst() -> BootstrapConfig {
        let mut cfg = sample_bootstrap_cfg();
        cfg.analyst_email = Some("analyst@sentinelx.dev".into());
        cfg.analyst_password_phc = Some(SecretString::from(
            "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0c2FsdA$abcdefghijklmnopqrstuvwxyz123456"
                .to_string(),
        ));
        cfg
    }

    #[test]
    fn seed_bootstrap_admin_works_with_inmemory_repo() {
        let repo = InMemoryUserRepository::default();
        let cfg = sample_bootstrap_cfg();
        // Repo-agnostic call signature: any `&dyn UserRepository` works.
        seed_bootstrap_admin(&repo as &dyn UserRepository, &cfg).expect("seed must succeed");
        // The seed wrote one row.
        let stored = futures::executor::block_on(repo.find_by_email(
            TenantId::from_uuid(cfg.admin_tenant_id.unwrap()),
            "admin@sentinelx.dev",
        ))
        .unwrap()
        .expect("seeded user must be present");
        assert_eq!(stored.email, "admin@sentinelx.dev");
        assert!(stored.is_active);
        assert!(stored.password_hash.starts_with("$argon2"));
    }

    #[test]
    fn seed_bootstrap_admin_works_with_mock_repo() {
        let repo = MockUserRepo::default();
        let cfg = sample_bootstrap_cfg();
        // Same function, different concrete impl — the seeder is
        // repository-agnostic.
        seed_bootstrap_admin(&repo as &dyn UserRepository, &cfg).expect("seed must succeed");
        let created = repo.created.lock().unwrap();
        assert_eq!(created.len(), 1);
        let user = created.first().unwrap();
        assert_eq!(user.email, "admin@sentinelx.dev");
        assert_eq!(
            user.tenant_id,
            TenantId::from_uuid(cfg.admin_tenant_id.unwrap())
        );
    }

    #[test]
    fn seed_bootstrap_admin_is_idempotent_on_conflict() {
        let repo = MockUserRepo {
            force_conflict: true,
            ..MockUserRepo::default()
        };
        let cfg = sample_bootstrap_cfg();
        // Conflict from the underlying repo must collapse to `Ok(())`
        // so re-seeding on every boot stays cheap and silent.
        seed_bootstrap_admin(&repo as &dyn UserRepository, &cfg)
            .expect("conflict must collapse to success");
    }

    #[test]
    fn seed_bootstrap_admin_works_with_monolith_repo_wrapper() {
        // The unified `MonolithUserRepo` is the actual production type
        // — verify it routes the seed correctly through the in-memory
        // variant. The Postgres variant cannot be exercised without a
        // live database; see the integration tests for that path.
        let repo = MonolithUserRepo::in_memory();
        let cfg = sample_bootstrap_cfg();
        seed_bootstrap_admin(&repo as &dyn UserRepository, &cfg).expect("seed must succeed");
        let stored = futures::executor::block_on(repo.find_by_email(
            TenantId::from_uuid(cfg.admin_tenant_id.unwrap()),
            "admin@sentinelx.dev",
        ))
        .unwrap()
        .expect("seeded user must be present");
        assert_eq!(stored.email, "admin@sentinelx.dev");
    }

    #[test]
    fn seed_bootstrap_analyst_is_a_noop_when_email_missing() {
        let repo = InMemoryUserRepository::default();
        let mut cfg = sample_bootstrap_cfg();
        // Half-config: only email, no PHC → seeder must early-return Ok(()).
        cfg.analyst_email = Some("analyst@sentinelx.dev".into());
        cfg.analyst_password_phc = None;
        seed_bootstrap_analyst(&repo as &dyn UserRepository, &cfg)
            .expect("half-config must not error");
        let found = futures::executor::block_on(repo.find_by_email(
            TenantId::from_uuid(cfg.admin_tenant_id.unwrap()),
            "analyst@sentinelx.dev",
        ))
        .unwrap();
        assert!(
            found.is_none(),
            "analyst must NOT be seeded when PHC is missing",
        );
    }

    #[test]
    fn seed_bootstrap_analyst_seeds_user_with_analyst_role() {
        let repo = InMemoryUserRepository::default();
        let cfg = sample_bootstrap_cfg_with_analyst();
        seed_bootstrap_analyst(&repo as &dyn UserRepository, &cfg)
            .expect("analyst seed must succeed");
        let stored = futures::executor::block_on(repo.find_by_email(
            TenantId::from_uuid(cfg.admin_tenant_id.unwrap()),
            "analyst@sentinelx.dev",
        ))
        .unwrap()
        .expect("seeded analyst must be present");
        assert_eq!(stored.email, "analyst@sentinelx.dev");
        assert!(stored.is_active);
        assert!(stored.password_hash.starts_with("$argon2"));
        // Role must be `analyst` (NOT wildcard) — that's the whole point
        // of having a non-admin fixture for the e2e suite.
        assert_eq!(stored.roles.len(), 1);
        assert_eq!(stored.roles[0].name, "analyst");
        assert!(
            !stored.roles[0]
                .permissions
                .iter()
                .any(|p| p.to_string() == "*:*"),
            "analyst role must not include wildcard permissions",
        );
    }

    #[test]
    fn seed_bootstrap_analyst_is_idempotent_on_conflict() {
        let repo = MockUserRepo {
            force_conflict: true,
            ..MockUserRepo::default()
        };
        let cfg = sample_bootstrap_cfg_with_analyst();
        seed_bootstrap_analyst(&repo as &dyn UserRepository, &cfg)
            .expect("conflict must collapse to success");
    }

    /// In-memory `find_by_id_with_tenant` defaults to the tenant-agnostic
    /// `find_by_id` — which is fine because the in-memory store has no
    /// RLS. The Postgres variant overrides this; that path is covered by
    /// the live-DB integration test below.
    #[test]
    fn in_memory_find_by_id_with_tenant_defaults_to_find_by_id() {
        let repo = InMemoryUserRepository::default();
        let cfg = sample_bootstrap_cfg();
        seed_bootstrap_admin(&repo as &dyn UserRepository, &cfg).expect("seed must succeed");
        let tenant = TenantId::from_uuid(cfg.admin_tenant_id.unwrap());
        let user = futures::executor::block_on(repo.find_by_email(tenant, "admin@sentinelx.dev"))
            .unwrap()
            .expect("seeded user must be present");

        // The in-memory override DOES filter by tenant (A9 design — RLS
        // parity with Postgres): a non-matching tenant resolves to None.
        let other_tenant = TenantId::new();
        let found = futures::executor::block_on(repo.find_by_id_with_tenant(other_tenant, user.id))
            .unwrap();
        assert!(
            found.is_none(),
            "in-memory tenant filter must reject mismatched tenant",
        );

        // The matching tenant still resolves the id.
        let found_matching =
            futures::executor::block_on(repo.find_by_id_with_tenant(tenant, user.id)).unwrap();
        assert!(found_matching.is_some(), "matching tenant must resolve");
    }

    /// Live integration test against a developer-supplied Postgres on
    /// `TEST_DATABASE_URL`. Requires the `users` table with the
    /// `app.current_tenant_id` RLS policy already migrated in.
    ///
    /// Run with:
    ///
    /// ```text
    /// TEST_DATABASE_URL=postgres://... \
    ///   cargo test -p sx-monolith --lib adapters::iam -- --ignored
    /// ```
    #[tokio::test]
    #[ignore = "Requires live Postgres on TEST_DATABASE_URL"]
    async fn pg_find_by_id_with_tenant_respects_rls() {
        #[allow(clippy::disallowed_methods)] // live-DB test-only env lookup
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("TEST_DATABASE_URL must be set for live PG tests");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(&url)
            .await
            .expect("connect to test postgres");
        let repo = PgIamUserRepository::new(pool, 5_000);

        // Seed a user under tenant A. We mint a tenant id locally; the
        // outer migration is expected to allow `INSERT` once we set the
        // tenant GUC (which `create` does).
        let tenant_a = TenantId::new();
        let tenant_b = TenantId::new();
        let user_id = UserId::new();
        let now = time::OffsetDateTime::now_utc();
        let user = User {
            id: user_id,
            tenant_id: tenant_a,
            email: format!("rls-{}@sentinelx.test", user_id.as_uuid()),
            password_hash: "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0c2FsdA$abcdefghijklmnopqrstuvwxyz123456".into(),
            is_active: true,
            roles: vec![],
            created_at: now,
            updated_at: now,
        };
        repo.create(&user).await.expect("seed user under tenant A");

        // Tenant A — should find the user.
        let found_a = repo
            .find_by_id_with_tenant(tenant_a, user_id)
            .await
            .expect("query under tenant A succeeds");
        assert!(found_a.is_some(), "tenant A must see its own user");

        // Tenant B — RLS must filter the row out.
        let found_b = repo
            .find_by_id_with_tenant(tenant_b, user_id)
            .await
            .expect("query under tenant B succeeds");
        assert!(found_b.is_none(), "tenant B must NOT see tenant A's user");
    }

    // ---- RBA integration: login flow consults RBA after credential check ----

    use sx_api::port::{RbaActionWire, RbaEvaluateInput, RbaEvaluateOutput, RbaPortError};
    use sx_api::view::rba_view::{RbaConfigView, RbaDecisionView};

    /// Mock RBA port the integration tests below install on the
    /// AuthnAdapter. The fixed action is returned for every
    /// `evaluate` call; the input is recorded so the assertions
    /// can verify the login flow forwarded the IP / email.
    struct MockRba {
        action: RbaActionWire,
        last_input: Mutex<Option<RbaEvaluateInput>>,
    }

    impl MockRba {
        fn new(action: RbaActionWire) -> Self {
            Self {
                action,
                last_input: Mutex::new(None),
            }
        }
    }

    #[async_trait]
    impl RbaPort for MockRba {
        async fn evaluate(
            &self,
            input: RbaEvaluateInput,
        ) -> Result<RbaEvaluateOutput, RbaPortError> {
            if let Ok(mut g) = self.last_input.lock() {
                *g = Some(input);
            }
            Ok(RbaEvaluateOutput {
                score: match self.action {
                    RbaActionWire::Allow => 0,
                    RbaActionWire::StepUpMfa => 50,
                    RbaActionWire::Block => 95,
                },
                action: self.action,
                reason: "mock".into(),
            })
        }
        async fn list_decisions(
            &self,
            _tenant_id: &str,
            _limit: u32,
            _include_signals: bool,
        ) -> Result<Vec<RbaDecisionView>, RbaPortError> {
            Ok(Vec::new())
        }
        async fn get_config(&self, _tenant_id: &str) -> Result<RbaConfigView, RbaPortError> {
            Err(RbaPortError::Internal("unused".into()))
        }
        async fn put_config(
            &self,
            _tenant_id: &str,
            _cfg: RbaConfigView,
        ) -> Result<RbaConfigView, RbaPortError> {
            Err(RbaPortError::Internal("unused".into()))
        }
        async fn list_known_devices(
            &self,
            _tenant_id: &str,
            _user_id: &str,
        ) -> Result<sx_api::view::rba_view::KnownDevicesResponse, RbaPortError> {
            Ok(sx_api::view::rba_view::KnownDevicesResponse {
                devices: Vec::new(),
            })
        }
        async fn revoke_known_device(
            &self,
            _tenant_id: &str,
            _user_id: &str,
            _fp_hash: &str,
        ) -> Result<(), RbaPortError> {
            Ok(())
        }
    }

    /// Build a minimal `IamBundle` against an in-memory user + tracker
    /// and pre-seed one user with the password `hunter2`.
    async fn build_test_bundle(tenant: TenantId, email: &str) -> (IamBundle, String) {
        use sx_iam::config::{
            IamConfig as IamCfg, JwtAlgorithm, JwtConfig as JwtCfg, LockoutPolicy,
            PasswordConfig as PwCfg, WebauthnConfig as WebauthnCfg,
        };
        use sx_iam::prelude::PasswordHasher as PasswordHasherTrait;

        let cfg = IamCfg {
            password: PwCfg {
                m_cost_kib: 1024,
                t_cost: 1,
                p_cost: 1,
                output_len: 32,
            },
            lockout: LockoutPolicy {
                max_failures: 5,
                lock_duration: Duration::from_secs(60),
            },
            attempt_email_pepper: SecretString::from("pep".to_owned()),
            jwt: JwtCfg {
                issuer: "sx-test".into(),
                audience: "sx-test".into(),
                signing_key: SecretString::from("0123456789abcdef0123456789abcdef".to_owned()),
                verifying_key: SecretString::from("0123456789abcdef0123456789abcdef".to_owned()),
                key_id: "k1".into(),
                access_ttl: Duration::from_secs(900),
                refresh_ttl: Duration::from_secs(86_400),
                algorithm: JwtAlgorithm::Hs256,
                leeway_seconds: 30,
            },
            webauthn: WebauthnCfg::default(),
        };
        let users = Arc::new(MonolithUserRepo::in_memory());
        let bundle = build(
            &cfg,
            Duration::from_secs(900),
            None,
            None,
            users,
            Arc::new(InMemorySessionRevoker::default()),
        )
        .expect("test bundle build must succeed");

        // Seed a user with `hunter2` under the supplied tenant. The
        // `hash` method lives on the `PasswordHasher` trait imported
        // above; we go through `as_ref` so the `Arc<Argon2idHasher>`
        // dispatches to the trait method.
        let phc = PasswordHasherTrait::hash(
            bundle.hasher.as_ref(),
            &SecretString::from("hunter2".to_owned()),
        )
        .expect("hash test password");
        let now = time::OffsetDateTime::now_utc();
        let user = User {
            id: UserId::new(),
            tenant_id: tenant,
            email: email.to_owned(),
            password_hash: phc.clone(),
            is_active: true,
            roles: vec![],
            created_at: now,
            updated_at: now,
        };
        bundle.users.create(&user).await.expect("seed user");
        (bundle, phc)
    }

    fn auth_input(tenant: TenantId, email: &str) -> AuthenticateUserInput {
        AuthenticateUserInput {
            tenant_id: tenant.as_uuid().to_string(),
            email: email.to_owned(),
            password: SecretString::from("hunter2".to_owned()),
            ip: Some("8.8.8.8".to_owned()),
            user_agent: Some("integration-test/1.0".to_owned()),
        }
    }

    #[tokio::test]
    async fn login_consults_rba_on_credential_success() {
        let tenant = TenantId::new();
        let (bundle, _) = build_test_bundle(tenant, "alice@x.test").await;
        let rba = Arc::new(MockRba::new(RbaActionWire::Allow));
        bundle
            .authn_concrete
            .set_rba(Arc::clone(&rba) as Arc<dyn RbaPort>);

        let token = bundle
            .authn
            .authenticate(auth_input(tenant, "alice@x.test"))
            .await
            .expect("RBA allow → login must succeed");
        assert_eq!(token.token_type, "Bearer");
        let captured = rba
            .last_input
            .lock()
            .unwrap()
            .clone()
            .expect("RBA must be consulted on credential success");
        assert_eq!(captured.tenant_id, tenant.as_uuid().to_string());
        assert_eq!(captured.email, "alice@x.test");
        assert_eq!(captured.ip, "8.8.8.8");
        assert!(
            captured.user_id.is_some(),
            "user id must be populated post-credential-check"
        );
    }

    #[tokio::test]
    async fn high_rba_score_blocks_login_before_jwt_issued() {
        let tenant = TenantId::new();
        let (bundle, _) = build_test_bundle(tenant, "alice@x.test").await;
        let rba = Arc::new(MockRba::new(RbaActionWire::Block));
        bundle
            .authn_concrete
            .set_rba(Arc::clone(&rba) as Arc<dyn RbaPort>);

        let err = bundle
            .authn
            .authenticate(auth_input(tenant, "alice@x.test"))
            .await
            .expect_err("RBA block → login must reject");
        // Block surfaces as `IamError::Forbidden { required: "rba_block" }`.
        match err {
            IamError::Forbidden { required } => {
                assert_eq!(required, "rba_block");
            }
            other => panic!("expected Forbidden, got {other:?}"),
        }
        // Sanity check: RBA was consulted exactly once.
        assert!(rba.last_input.lock().unwrap().is_some());
    }

    #[tokio::test]
    async fn step_up_required_surfaces_forbidden_reason() {
        let tenant = TenantId::new();
        let (bundle, _) = build_test_bundle(tenant, "alice@x.test").await;
        let rba = Arc::new(MockRba::new(RbaActionWire::StepUpMfa));
        bundle
            .authn_concrete
            .set_rba(Arc::clone(&rba) as Arc<dyn RbaPort>);

        let err = bundle
            .authn
            .authenticate(auth_input(tenant, "alice@x.test"))
            .await
            .expect_err("RBA step-up → login must reject");
        match err {
            IamError::Forbidden { required } => {
                assert_eq!(required, "rba_step_up_mfa_required");
            }
            other => panic!("expected Forbidden, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn invalid_password_does_not_call_rba() {
        let tenant = TenantId::new();
        let (bundle, _) = build_test_bundle(tenant, "alice@x.test").await;
        let rba = Arc::new(MockRba::new(RbaActionWire::Allow));
        bundle
            .authn_concrete
            .set_rba(Arc::clone(&rba) as Arc<dyn RbaPort>);

        let bad = AuthenticateUserInput {
            tenant_id: tenant.as_uuid().to_string(),
            email: "alice@x.test".to_owned(),
            password: SecretString::from("wrong-password".to_owned()),
            ip: Some("8.8.8.8".to_owned()),
            user_agent: None,
        };
        let err = bundle
            .authn
            .authenticate(bad)
            .await
            .expect_err("must reject");
        assert!(matches!(err, IamError::InvalidCredentials));
        // RBA must not have been consulted — the engine only sees
        // attempts that already passed the credential check.
        assert!(rba.last_input.lock().unwrap().is_none());
    }
}
