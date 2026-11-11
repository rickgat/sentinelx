//! Customer-facing auth adapter — wires self-service signup, email
//! verification, forgot-password and reset-password behind the
//! [`CustomerAuthPort`] trait declared in `sx-api`.
//!
//! The adapter is deliberately in-memory. Production deployments will
//! swap the two `Mutex<HashMap>` token stores for a Postgres- or
//! Redis-backed implementation that survives restarts.
//!
//! ## Stores
//!
//! - `pending_verify`  : verify-token  → (user id, expires_at)
//! - `pending_reset`   : reset-token   → (user id, expires_at)
//!
//! Both tokens are 128-bit UUID-v4 strings. Lookups are constant-time
//! string equality (no timing-safe comparison is needed because the
//! token is the *only* secret — exposing presence under timing analysis
//! does not help an attacker who already has to guess 122 bits).
//!
//! ## Lifetime policy
//!
//! Tokens live for **24 hours**. Expired rows are *not* eagerly garbage
//! collected — lookups treat them as invalid and the entry is dropped
//! lazily. A trivial periodic sweep is left to a future adapter.
//!
//! ## Tracing
//!
//! - The verify / reset token VALUES are never logged. The adapter logs
//!   only a `token_id` derived from the **first 8 hex chars** of the
//!   token so an operator can correlate without leaking the secret.
//! - Plaintext passwords are wrapped in `SecretString` from the moment
//!   they leave the HTTP layer.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use secrecy::SecretString;
use sx_api::port::{CustomerAuthPort, Phase3PortError};
use sx_api::view::customer_auth_view::{
    ForgotPasswordRequest, OkView, ResetPasswordRequest, SignupRequest, VerifyEmailRequest,
};
use sx_iam::domain::{TenantId, User, UserId};
use sx_iam::port::UserRepository;
use sx_iam::service::{Argon2idHasher, PasswordHasher};
use sx_iam::IamError;
use time::OffsetDateTime;

use crate::adapters::iam::MonolithUserRepo;
#[cfg(test)]
use crate::adapters::iam::PgIamUserRepository;

/// Default token lifetime — 24 hours.
const DEFAULT_TOKEN_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// Abstract clock so tests can inject a fake.
pub(crate) trait CustomerAuthClock: Send + Sync + std::fmt::Debug {
    fn now(&self) -> OffsetDateTime;
}

/// Production clock — `OffsetDateTime::now_utc()`.
#[derive(Debug, Default)]
pub(crate) struct SystemClock;

impl CustomerAuthClock for SystemClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
}

/// Bundle exposed to the composition root.
pub(crate) struct CustomerAuthBundle {
    /// Customer-facing auth port — `Arc<dyn CustomerAuthPort>` for state.
    pub auth: Arc<dyn CustomerAuthPort>,
}

/// Build the customer-auth bundle from the shared user repo + hasher
/// already held by the IAM bundle. The repo is the unified
/// [`MonolithUserRepo`] enum so the same store backs the bootstrap
/// admin, admin-provisioned users, and customer signups.
pub(crate) fn build(
    users: Arc<MonolithUserRepo>,
    hasher: Arc<Argon2idHasher>,
) -> CustomerAuthBundle {
    let adapter = InMemoryCustomerAuth::new(users, hasher);
    CustomerAuthBundle {
        auth: Arc::new(adapter),
    }
}

/// Concrete in-memory adapter.
pub(crate) struct InMemoryCustomerAuth {
    users: Arc<MonolithUserRepo>,
    hasher: Arc<Argon2idHasher>,
    pending_verify: Mutex<HashMap<String, PendingToken>>,
    pending_reset: Mutex<HashMap<String, PendingToken>>,
    ttl: Duration,
    clock: Arc<dyn CustomerAuthClock>,
}

impl std::fmt::Debug for InMemoryCustomerAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InMemoryCustomerAuth")
            .field("ttl_secs", &self.ttl.as_secs())
            .finish_non_exhaustive()
    }
}

/// One pending verification or reset row.
#[derive(Debug, Clone, Copy)]
struct PendingToken {
    user_id: UserId,
    expires_at: OffsetDateTime,
}

impl InMemoryCustomerAuth {
    /// Production constructor with the default 24h TTL + `SystemClock`.
    pub(crate) fn new(users: Arc<MonolithUserRepo>, hasher: Arc<Argon2idHasher>) -> Self {
        Self::with_ttl_and_clock(users, hasher, DEFAULT_TOKEN_TTL, Arc::new(SystemClock))
    }

    /// Test-only constructor.
    pub(crate) fn with_ttl_and_clock(
        users: Arc<MonolithUserRepo>,
        hasher: Arc<Argon2idHasher>,
        ttl: Duration,
        clock: Arc<dyn CustomerAuthClock>,
    ) -> Self {
        Self {
            users,
            hasher,
            pending_verify: Mutex::new(HashMap::new()),
            pending_reset: Mutex::new(HashMap::new()),
            ttl,
            clock,
        }
    }

    /// Short, non-secret correlation id derived from the token for
    /// tracing. Returns the first 8 hex chars (the token is a 32-hex
    /// UUID with hyphens stripped).
    fn token_id(token: &str) -> String {
        token.chars().take(8).collect::<String>()
    }

    /// Mint a fresh opaque token. UUID-v4 hyphens are stripped so the
    /// wire form fits the canonical 32-hex shape.
    fn mint_token() -> String {
        uuid::Uuid::new_v4().simple().to_string()
    }

    /// Compute the absolute expiry from "now" + TTL.
    fn expires_at(&self) -> OffsetDateTime {
        let now = self.clock.now();
        // Saturate on overflow — practical TTLs are far below i64::MAX seconds.
        let secs = i64::try_from(self.ttl.as_secs()).unwrap_or(i64::MAX);
        now.checked_add(time::Duration::seconds(secs))
            .unwrap_or(now)
    }

    /// Look up + consume a pending token from the supplied store.
    /// Returns `None` if the token is absent or expired.
    fn consume_token(
        store: &Mutex<HashMap<String, PendingToken>>,
        token: &str,
        now: OffsetDateTime,
    ) -> Result<Option<UserId>, Phase3PortError> {
        let mut guard = store
            .lock()
            .map_err(|_| Phase3PortError::Internal("token store poisoned".into()))?;
        match guard.remove(token) {
            Some(p) if p.expires_at > now => Ok(Some(p.user_id)),
            Some(_) | None => Ok(None),
        }
    }
}

#[async_trait]
impl CustomerAuthPort for InMemoryCustomerAuth {
    async fn signup(&self, req: SignupRequest) -> Result<OkView, Phase3PortError> {
        let tenant = uuid::Uuid::parse_str(&req.tenant_id)
            .map(TenantId::from_uuid)
            .map_err(|_| Phase3PortError::Invalid("invalid tenant_id".into()))?;

        let email = req.email.to_ascii_lowercase();

        // Conflict if the email already exists.
        let existing = self
            .users
            .find_by_email(tenant, &email)
            .await
            .map_err(map_iam)?;
        if existing.is_some() {
            return Err(Phase3PortError::Invalid("email already exists".into()));
        }

        // Hash the password (Argon2id PHC string).
        let secret = SecretString::from(req.password().to_owned());
        let phc = self.hasher.hash(&secret).map_err(map_iam)?;

        let now = self.clock.now();
        let user = User {
            id: UserId::new(),
            tenant_id: tenant,
            email,
            password_hash: phc,
            is_active: false,
            roles: vec![],
            created_at: now,
            updated_at: now,
        };

        self.users.create(&user).await.map_err(map_iam)?;

        // Mint a verification token + persist.
        let token = Self::mint_token();
        let expires_at = self.expires_at();
        {
            let mut guard = self
                .pending_verify
                .lock()
                .map_err(|_| Phase3PortError::Internal("verify store poisoned".into()))?;
            guard.insert(
                token.clone(),
                PendingToken {
                    user_id: user.id,
                    expires_at,
                },
            );
        }

        // In production the adapter would send `token` via email.
        // Here we log a non-secret correlation id only.
        tracing::info!(
            target: "adapters.customer_auth.signup",
            tenant_id = %tenant,
            user_id = %user.id,
            token_id = %Self::token_id(&token),
            "customer signup minted verify token"
        );

        Ok(OkView::ok())
    }

    async fn verify_email(&self, req: VerifyEmailRequest) -> Result<OkView, Phase3PortError> {
        let now = self.clock.now();
        let Some(user_id) = Self::consume_token(&self.pending_verify, &req.token, now)? else {
            tracing::debug!(
                target: "adapters.customer_auth.verify_email",
                token_id = %Self::token_id(&req.token),
                "verify-email rejected (unknown or expired token)"
            );
            return Err(Phase3PortError::NotFound);
        };

        // Activate the user via the shared `UserRepository::update` row
        // (in-memory mutates its map; Postgres issues a tenant-scoped
        // `UPDATE` under RLS).
        activate_user(&self.users, user_id).await?;

        tracing::info!(
            target: "adapters.customer_auth.verify_email",
            user_id = %user_id,
            token_id = %Self::token_id(&req.token),
            "verify-email succeeded; user activated"
        );

        Ok(OkView::ok())
    }

    async fn forgot_password(&self, req: ForgotPasswordRequest) -> Result<OkView, Phase3PortError> {
        let Ok(tenant_uuid) = uuid::Uuid::parse_str(&req.tenant_id) else {
            // Even invalid tenant ids must NOT reveal failure — but
            // they cannot succeed either. Treat as OK with no work.
            tracing::debug!(
                target: "adapters.customer_auth.forgot_password",
                "forgot-password ignored (invalid tenant)"
            );
            return Ok(OkView::ok());
        };
        let tenant = TenantId::from_uuid(tenant_uuid);
        let email = req.email.to_ascii_lowercase();
        // Don't reveal presence — succeed silently when the user is
        // missing or inactive.
        let user = match self.users.find_by_email(tenant, &email).await {
            Ok(Some(u)) => u,
            Ok(None) => {
                tracing::debug!(
                    target: "adapters.customer_auth.forgot_password",
                    tenant_id = %tenant,
                    "forgot-password no-op (unknown email)"
                );
                return Ok(OkView::ok());
            }
            Err(e) => return Err(map_iam(e)),
        };

        let token = Self::mint_token();
        let expires_at = self.expires_at();
        {
            let mut guard = self
                .pending_reset
                .lock()
                .map_err(|_| Phase3PortError::Internal("reset store poisoned".into()))?;
            guard.insert(
                token.clone(),
                PendingToken {
                    user_id: user.id,
                    expires_at,
                },
            );
        }

        tracing::info!(
            target: "adapters.customer_auth.forgot_password",
            tenant_id = %tenant,
            user_id = %user.id,
            token_id = %Self::token_id(&token),
            "customer reset token minted"
        );

        Ok(OkView::ok())
    }

    async fn reset_password(&self, req: ResetPasswordRequest) -> Result<OkView, Phase3PortError> {
        let now = self.clock.now();
        let Some(user_id) = Self::consume_token(&self.pending_reset, &req.token, now)? else {
            tracing::debug!(
                target: "adapters.customer_auth.reset_password",
                token_id = %Self::token_id(&req.token),
                "reset-password rejected (unknown or expired token)"
            );
            return Err(Phase3PortError::NotFound);
        };

        let secret = SecretString::from(req.new_password().to_owned());
        let new_phc = self.hasher.hash(&secret).map_err(map_iam)?;

        rotate_password(&self.users, user_id, new_phc).await?;

        tracing::info!(
            target: "adapters.customer_auth.reset_password",
            user_id = %user_id,
            token_id = %Self::token_id(&req.token),
            "reset-password succeeded; password rotated"
        );

        Ok(OkView::ok())
    }
}

/// Activate `user_id` in the supplied repository.
///
/// Flips `is_active = true` and stamps `updated_at`.
///
/// Both variants go through the shared `UserRepository::update` row
/// added in Wave 2: the in-memory adapter mutates its map directly, the
/// Postgres adapter issues a tenant-scoped `UPDATE` under RLS.
///
/// ## Tenant-context caveat (Postgres)
///
/// The current [`UserRepository::find_by_id`] contract does not carry a
/// tenant id, so the Postgres lookup returns `None` under FORCE RLS.
/// Until A10's `find_by_id_with_tenant` lands the Postgres branch will
/// surface [`Phase3PortError::NotFound`] in that situation. The `update`
/// call-site below still receives the right `(id, tenant_id)` once a
/// `User` is in hand, so the write path is correct.
async fn activate_user(
    users: &Arc<MonolithUserRepo>,
    user_id: UserId,
) -> Result<(), Phase3PortError> {
    let Some(mut user) = users.find_by_id(user_id).await.map_err(map_iam)? else {
        return Err(Phase3PortError::NotFound);
    };
    user.is_active = true;
    user.updated_at = OffsetDateTime::now_utc();
    users
        .update(&user)
        .await
        .map_err(|e| Phase3PortError::Dependency(e.to_string()))
}

/// Rotate the password hash for `user_id`.
///
/// Mirrors [`activate_user`] — both variants go through the shared
/// `UserRepository::update` row. See that fn for the tenant-context
/// caveat on the Postgres branch.
async fn rotate_password(
    users: &Arc<MonolithUserRepo>,
    user_id: UserId,
    new_phc: String,
) -> Result<(), Phase3PortError> {
    let Some(mut user) = users.find_by_id(user_id).await.map_err(map_iam)? else {
        return Err(Phase3PortError::NotFound);
    };
    user.password_hash = new_phc;
    user.updated_at = OffsetDateTime::now_utc();
    users
        .update(&user)
        .await
        .map_err(|e| Phase3PortError::Dependency(e.to_string()))
}

/// Collapse an [`IamError`] into the shared [`Phase3PortError`] surface
/// the HTTP layer already maps onto a status.
fn map_iam(e: IamError) -> Phase3PortError {
    match e {
        IamError::Conflict(_) => Phase3PortError::Invalid("email already exists".into()),
        IamError::InvalidCredentials => Phase3PortError::Invalid("invalid credentials".into()),
        IamError::Config(m) => Phase3PortError::Invalid(m),
        other => Phase3PortError::Internal(other.to_string()),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::sync::Mutex as StdMutex;
    use sx_iam::config::PasswordConfig;
    use sx_iam::port::UserRepository;
    use time::OffsetDateTime;

    fn fast_hasher() -> Arc<Argon2idHasher> {
        Arc::new(
            Argon2idHasher::from_config(&PasswordConfig {
                m_cost_kib: 1024,
                t_cost: 1,
                p_cost: 1,
                output_len: 32,
            })
            .unwrap(),
        )
    }

    /// Test clock — returns whatever the test most recently set.
    #[derive(Debug)]
    struct FakeClock {
        inner: StdMutex<OffsetDateTime>,
    }

    impl FakeClock {
        fn new(at: OffsetDateTime) -> Self {
            Self {
                inner: StdMutex::new(at),
            }
        }

        fn advance(&self, by: time::Duration) {
            let mut g = self.inner.lock().unwrap();
            *g = g.checked_add(by).unwrap_or(*g);
        }
    }

    impl CustomerAuthClock for FakeClock {
        fn now(&self) -> OffsetDateTime {
            *self.inner.lock().unwrap()
        }
    }

    fn make_adapter() -> (Arc<MonolithUserRepo>, Arc<InMemoryCustomerAuth>) {
        let users = Arc::new(MonolithUserRepo::in_memory());
        let hasher = fast_hasher();
        let adapter = InMemoryCustomerAuth::new(Arc::clone(&users), Arc::clone(&hasher));
        (users, Arc::new(adapter))
    }

    fn make_adapter_with_clock(
        clock: Arc<FakeClock>,
    ) -> (Arc<MonolithUserRepo>, Arc<InMemoryCustomerAuth>) {
        let users = Arc::new(MonolithUserRepo::in_memory());
        let hasher = fast_hasher();
        let adapter = InMemoryCustomerAuth::with_ttl_and_clock(
            Arc::clone(&users),
            Arc::clone(&hasher),
            DEFAULT_TOKEN_TTL,
            clock as Arc<dyn CustomerAuthClock>,
        );
        (users, Arc::new(adapter))
    }

    fn tenant() -> String {
        "22222222-2222-2222-2222-222222222222".to_string()
    }

    fn signup_req(email: &str) -> SignupRequest {
        let json = serde_json::json!({
            "tenant_id": tenant(),
            "email": email,
            "password": "correct-horse-battery",
        });
        serde_json::from_value(json).expect("deserialise signup")
    }

    /// Recover the most recently minted verify token from the adapter's
    /// store. Used by tests to bridge the "out-of-band email" step.
    fn latest_verify_token(adapter: &InMemoryCustomerAuth) -> String {
        let g = adapter.pending_verify.lock().unwrap();
        g.keys().next().expect("at least one pending token").clone()
    }

    fn latest_reset_token(adapter: &InMemoryCustomerAuth) -> String {
        let g = adapter.pending_reset.lock().unwrap();
        g.keys().next().expect("at least one pending token").clone()
    }

    // -------- 1. signup creates an INACTIVE user ------------------------

    #[tokio::test]
    async fn signup_creates_inactive_user() {
        let (users, adapter) = make_adapter();
        adapter
            .signup(signup_req("alice@example.com"))
            .await
            .expect("signup should succeed");
        let tid = TenantId::from_uuid(uuid::Uuid::parse_str(&tenant()).unwrap());
        let u = users
            .find_by_email(tid, "alice@example.com")
            .await
            .unwrap()
            .expect("user should exist");
        assert!(!u.is_active, "newly signed-up users must start inactive");
        assert!(u.password_hash.starts_with("$argon2"));
    }

    // -------- 2. verify_email activates user ----------------------------

    #[tokio::test]
    async fn verify_email_activates_user() {
        let (users, adapter) = make_adapter();
        adapter.signup(signup_req("bob@example.com")).await.unwrap();
        let token = latest_verify_token(&adapter);

        adapter
            .verify_email(VerifyEmailRequest {
                token: token.clone(),
            })
            .await
            .expect("verify should succeed");

        let tid = TenantId::from_uuid(uuid::Uuid::parse_str(&tenant()).unwrap());
        let u = users
            .find_by_email(tid, "bob@example.com")
            .await
            .unwrap()
            .expect("user should exist");
        assert!(u.is_active, "verify should flip is_active to true");
    }

    // -------- 3. verify_email rejects unknown token ---------------------

    #[tokio::test]
    async fn verify_email_rejects_unknown_token() {
        let (_, adapter) = make_adapter();
        let err = adapter
            .verify_email(VerifyEmailRequest {
                token: "no-such-token-xxxxxxxxxxxxxxxxxx".into(),
            })
            .await
            .expect_err("unknown token must be rejected");
        assert!(matches!(err, Phase3PortError::NotFound));
    }

    // -------- 4. forgot_password never reveals presence -----------------

    #[tokio::test]
    async fn forgot_password_does_not_reveal_email_existence() {
        let (_, adapter) = make_adapter();
        // No signup — the email does not exist.
        let resp = adapter
            .forgot_password(ForgotPasswordRequest {
                tenant_id: tenant(),
                email: "ghost@example.com".into(),
            })
            .await
            .expect("forgot-password must always succeed");
        assert!(resp.ok);
        // And it must NOT have minted a reset token.
        let g = adapter.pending_reset.lock().unwrap();
        assert!(
            g.is_empty(),
            "no reset token should be minted for an unknown email"
        );
    }

    // -------- 5. reset_password works with a valid token ----------------

    #[tokio::test]
    async fn reset_password_succeeds_with_valid_token() {
        let (users, adapter) = make_adapter();
        adapter
            .signup(signup_req("carol@example.com"))
            .await
            .unwrap();
        // Activate so forgot-password can find the row.
        adapter
            .verify_email(VerifyEmailRequest {
                token: latest_verify_token(&adapter),
            })
            .await
            .unwrap();
        adapter
            .forgot_password(ForgotPasswordRequest {
                tenant_id: tenant(),
                email: "carol@example.com".into(),
            })
            .await
            .unwrap();
        let token = latest_reset_token(&adapter);

        adapter
            .reset_password(ResetPasswordRequest {
                token,
                new_password: SecretString::from("brand-new-pass-1234".to_owned()),
            })
            .await
            .expect("reset should succeed");

        let tid = TenantId::from_uuid(uuid::Uuid::parse_str(&tenant()).unwrap());
        let u = users
            .find_by_email(tid, "carol@example.com")
            .await
            .unwrap()
            .expect("user should exist");
        // The hash must verify against the NEW password.
        adapter
            .hasher
            .verify(
                &SecretString::from("brand-new-pass-1234".to_owned()),
                &u.password_hash,
            )
            .expect("new password should verify");
    }

    // -------- 6. reset_password rejects a bad token ---------------------

    #[tokio::test]
    async fn reset_password_rejects_bad_token() {
        let (_, adapter) = make_adapter();
        let err = adapter
            .reset_password(ResetPasswordRequest {
                token: "not-a-real-tokennnnnnnnnnnnnnnnn".into(),
                new_password: SecretString::from("brand-new-pass-1234".to_owned()),
            })
            .await
            .expect_err("bad token must be rejected");
        assert!(matches!(err, Phase3PortError::NotFound));
    }

    // -------- 7. token expires after 24h via FakeClock ------------------

    #[tokio::test]
    async fn verify_token_expires_after_24h() {
        let t0 = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let clock = Arc::new(FakeClock::new(t0));
        let (_users, adapter) = make_adapter_with_clock(Arc::clone(&clock));

        adapter
            .signup(signup_req("dave@example.com"))
            .await
            .unwrap();
        let token = latest_verify_token(&adapter);

        // Advance 25h — past the 24h TTL.
        clock.advance(time::Duration::hours(25));
        let err = adapter
            .verify_email(VerifyEmailRequest { token })
            .await
            .expect_err("expired token must be rejected");
        assert!(matches!(err, Phase3PortError::NotFound));
    }

    // -------- 8. concurrent signup + verify stays consistent ------------

    #[tokio::test]
    async fn concurrent_signup_and_verify_is_consistent() {
        let (users, adapter) = make_adapter();
        let n = 8u32;
        let mut handles = Vec::with_capacity(n as usize);
        for i in 0..n {
            let a = Arc::clone(&adapter);
            handles.push(tokio::spawn(async move {
                let email = format!("user{i}@example.com");
                a.signup(signup_req(&email))
                    .await
                    .expect("signup should succeed");
            }));
        }
        for h in handles {
            h.await.expect("join");
        }
        // Now every signup must have produced exactly one pending
        // verify token, and every user must be inactive.
        let pending_count = adapter.pending_verify.lock().unwrap().len();
        assert_eq!(pending_count, n as usize, "one verify token per signup");

        let tid = TenantId::from_uuid(uuid::Uuid::parse_str(&tenant()).unwrap());
        for i in 0..n {
            let email = format!("user{i}@example.com");
            let u = users
                .find_by_email(tid, &email)
                .await
                .unwrap()
                .expect("user must exist");
            assert!(!u.is_active, "user must start inactive");
        }

        // Now drain every pending verify token in parallel; afterwards
        // every user must be active.
        let tokens: Vec<String> = adapter
            .pending_verify
            .lock()
            .unwrap()
            .keys()
            .cloned()
            .collect();
        let mut vh = Vec::with_capacity(tokens.len());
        for tok in tokens {
            let a = Arc::clone(&adapter);
            vh.push(tokio::spawn(async move {
                a.verify_email(VerifyEmailRequest { token: tok })
                    .await
                    .expect("verify should succeed");
            }));
        }
        for h in vh {
            h.await.expect("join");
        }
        for i in 0..n {
            let email = format!("user{i}@example.com");
            let u = users
                .find_by_email(tid, &email)
                .await
                .unwrap()
                .expect("user must exist");
            assert!(u.is_active, "every user must end active");
        }
    }

    // -------- 9. signup conflicts on duplicate email --------------------

    #[tokio::test]
    async fn signup_rejects_duplicate_email() {
        let (_, adapter) = make_adapter();
        adapter
            .signup(signup_req("dup@example.com"))
            .await
            .expect("first signup ok");
        let err = adapter
            .signup(signup_req("dup@example.com"))
            .await
            .expect_err("duplicate must be rejected");
        assert!(matches!(err, Phase3PortError::Invalid(_)));
    }

    // -------- 10. token_id helper never returns full token --------------

    #[test]
    fn token_id_truncates() {
        let tok = InMemoryCustomerAuth::mint_token();
        let id = InMemoryCustomerAuth::token_id(&tok);
        assert_eq!(id.len(), 8);
        assert!(tok.contains(&id));
        // The token must contain MORE than the id — ensures the log
        // marker never doubles as the secret.
        assert!(tok.len() > id.len());
    }

    // -------- 11. activate_user flows through UserRepository::update ----
    //
    // Regression guard for the Wave-2 swap of the in-memory back-door
    // (`set_active`) over to the shared `UserRepository::update` row.
    // Verifies the placeholder `Phase3PortError::Internal` that used to
    // surface on the Postgres branch is gone: the in-memory variant
    // succeeds end-to-end without reaching it.
    #[tokio::test]
    async fn activate_user_via_update_row_succeeds_on_inmemory() {
        let (users, adapter) = make_adapter();
        adapter
            .signup(signup_req("eve@example.com"))
            .await
            .expect("signup ok");
        let tid = TenantId::from_uuid(uuid::Uuid::parse_str(&tenant()).unwrap());
        let inactive = users
            .find_by_email(tid, "eve@example.com")
            .await
            .unwrap()
            .expect("user must exist");
        assert!(!inactive.is_active);

        // Drive the activation path through the verify-email token —
        // exercises `activate_user` -> `users.update`.
        let token = latest_verify_token(&adapter);
        adapter
            .verify_email(VerifyEmailRequest { token })
            .await
            .expect("verify must NOT surface Phase3PortError::Internal");

        let active = users
            .find_by_email(tid, "eve@example.com")
            .await
            .unwrap()
            .expect("user must exist");
        assert!(active.is_active, "update row must have flipped is_active");
        assert!(
            active.updated_at >= inactive.updated_at,
            "update row must have stamped updated_at"
        );
    }

    // -------- 12. live-Postgres smoke test for activate_user ------------
    //
    // Seeds an inactive user against the real Postgres `users` table,
    // runs `activate_user`, and asserts `find_by_email` returns the row
    // with `is_active = true`. Requires `TEST_DATABASE_URL` to be set to
    // a Postgres instance with the migrations applied — hence the
    // `#[ignore]`. Run with:
    //
    //   TEST_DATABASE_URL=postgres://… \
    //     cargo test -p sx-monolith --lib \
    //       adapters::customer_auth::tests::activate_user_postgres -- \
    //       --ignored --nocapture
    #[tokio::test]
    #[ignore = "Requires live Postgres on TEST_DATABASE_URL"]
    async fn activate_user_postgres() {
        #[allow(clippy::disallowed_methods)] // live-DB test-only env lookup
        let url = std::env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL not set");
        let pool = sqlx::PgPool::connect(&url).await.expect("connect pg");
        let pg = PgIamUserRepository::new(pool, 5_000);
        let users = Arc::new(MonolithUserRepo::postgres(pg));
        let hasher = fast_hasher();
        let adapter = InMemoryCustomerAuth::new(Arc::clone(&users), Arc::clone(&hasher));

        // Use a unique tenant + email so reruns don't collide.
        let tenant_uuid = uuid::Uuid::new_v4();
        let tenant = TenantId::from_uuid(tenant_uuid);
        let email = format!("eve+{tenant_uuid}@example.com");

        // Seed an inactive user directly via the repo.
        let now = OffsetDateTime::now_utc();
        let secret = SecretString::from("correct-horse-battery".to_owned());
        let phc = hasher.hash(&secret).expect("hash");
        let user = User {
            id: UserId::new(),
            tenant_id: tenant,
            email: email.clone(),
            password_hash: phc,
            is_active: false,
            roles: vec![],
            created_at: now,
            updated_at: now,
        };
        users.create(&user).await.expect("seed inactive user");

        // Activate via the shared helper — exercises the Postgres
        // `update` path.
        activate_user(&users, user.id)
            .await
            .expect("activate must succeed");

        // `find_by_email` filters `is_active = TRUE`, so a Some(_)
        // result is itself proof the update landed.
        let found = users
            .find_by_email(tenant, &email)
            .await
            .expect("find_by_email")
            .expect("user must be present and active");
        assert!(found.is_active);
        let _ = adapter; // keep the adapter alive — silences unused.
    }
}
