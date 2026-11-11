//! `ExchangeOidcUseCase` — verify an external OIDC `id_token` and issue an
//! SX-internal token pair for the underlying user.
//!
//! Flow:
//!
//! 1. Verify `id_token` via the injected [`OidcVerifier`]. Any failure
//!    collapses to [`IamError::InvalidCredentials`] — the wire never
//!    distinguishes "bad signature" from "wrong audience" from "expired".
//! 2. Resolve the tenant id. The verified claim set is searched for a
//!    string claim with the configured name (`config.tenant_id_claim`,
//!    default `"tenant_id"`); when absent, `config.default_tenant_id`
//!    fills in. Without either, the exchange fails.
//! 3. Look up the user by `(tenant_id, email)`. If absent and JIT
//!    provisioning is enabled, mint a new active user with the configured
//!    `default_roles`. If absent and JIT is disabled, fail.
//! 4. Issue a fresh SX access + refresh token pair via the existing
//!    [`IssueTokenUseCase`].
//!
//! Tracing follows the same hygiene rule the verifier obeys: never log the
//! raw `id_token`, never log the password (there is none here), only log
//! tenant id + user id + outcome.

use std::sync::Arc;

use time::OffsetDateTime;

use crate::controller::issue_token::IssueTokenInput;
use crate::controller::IssueTokenUseCase;
use crate::domain::{Permission, Role, RoleId, TenantId, User, UserId};
use crate::model::Token;
use crate::port::UserRepository;
use crate::service::{Clock, OidcVerifier, TokenIssuer};
use crate::IamError;

/// Output of a successful OIDC exchange.
#[derive(Debug)]
pub struct ExchangeOidcOutput {
    /// The authenticated SX user — either freshly JIT-provisioned or
    /// previously known.
    pub user: User,
    /// The SX-internal access + refresh token pair.
    pub token: Token,
}

/// Runtime configuration the use case consumes. Mirrors the relevant
/// fields of `sx_config::schema::oidc::OidcConfig` so sx-iam can be tested
/// without depending on the loader crate.
#[derive(Debug, Clone)]
pub struct ExchangeOidcConfig {
    /// Whether to provision missing users on the fly.
    pub jit_provision: bool,
    /// Role names granted to a JIT-provisioned user. Unknown role names
    /// fall back to a permission-less role with that name; recognised
    /// names map to a fixed permission grant — see [`Self::role_for_name`].
    pub default_roles: Vec<String>,
    /// Tenant uuid to use when the OIDC claim set does not carry one.
    /// Optional — without it, tokens missing the tenant claim are rejected.
    pub default_tenant_id: Option<TenantId>,
    /// OIDC claim name that carries the SX tenant id. Defaults to
    /// `"tenant_id"`.
    pub tenant_id_claim: String,
}

impl ExchangeOidcConfig {
    /// Map a role name onto a concrete [`Role`] under the supplied tenant.
    ///
    /// Mirrors the admin adapter's mapping; falls back to an empty
    /// permission set for unknown names so JIT-provisioned users still
    /// have a role record (auditable) even if it grants nothing.
    fn role_for_name(name: &str, tenant: TenantId) -> Role {
        let perms: Vec<Permission> = match name {
            "admin" => Permission::parse("*:*").ok().into_iter().collect(),
            "analyst" => [
                "findings:read",
                "findings:update",
                "engagements:read",
                "risk:calculate",
                "reports:render",
                "compliance:read",
            ]
            .iter()
            .filter_map(|p| Permission::parse(p).ok())
            .collect(),
            "ops" => [
                "assets:read",
                "engagements:read",
                "engagements:create",
                "safety:trip",
                "autonomy:run",
                "cloud:inventory",
            ]
            .iter()
            .filter_map(|p| Permission::parse(p).ok())
            .collect(),
            _ => Vec::new(),
        };
        Role {
            id: RoleId::new(),
            tenant_id: tenant,
            name: name.to_string(),
            permissions: perms,
        }
    }
}

/// Use case: exchange an OIDC `id_token` for an SX-internal token pair.
pub struct ExchangeOidcUseCase<V, R, I, C>
where
    V: OidcVerifier,
    R: UserRepository,
    I: TokenIssuer,
    C: Clock,
{
    verifier: Arc<V>,
    users: Arc<R>,
    issue: Arc<IssueTokenUseCase<I, C>>,
    cfg: ExchangeOidcConfig,
}

impl<V, R, I, C> std::fmt::Debug for ExchangeOidcUseCase<V, R, I, C>
where
    V: OidcVerifier,
    R: UserRepository,
    I: TokenIssuer,
    C: Clock,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExchangeOidcUseCase")
            .field("jit_provision", &self.cfg.jit_provision)
            .field("default_roles", &self.cfg.default_roles)
            .field("tenant_id_claim", &self.cfg.tenant_id_claim)
            .finish_non_exhaustive()
    }
}

impl<V, R, I, C> ExchangeOidcUseCase<V, R, I, C>
where
    V: OidcVerifier,
    R: UserRepository,
    I: TokenIssuer,
    C: Clock,
{
    /// Build the use case with its dependencies.
    pub fn new(
        verifier: Arc<V>,
        users: Arc<R>,
        issue: Arc<IssueTokenUseCase<I, C>>,
        cfg: ExchangeOidcConfig,
    ) -> Self {
        Self {
            verifier,
            users,
            issue,
            cfg,
        }
    }

    /// Run the use case.
    #[allow(clippy::cognitive_complexity)] // linear pipeline; each step logs + returns
    pub async fn execute(&self, id_token: &str) -> Result<ExchangeOidcOutput, IamError> {
        // 1. Verify the id_token.
        let claims = self.verifier.verify(id_token).await?;

        // 2. Resolve the tenant id from the configured claim or the
        // configured fallback.
        let tenant_id = self.resolve_tenant_id(&claims)?;

        // 3. Pull the email — without it we can't key the SX user.
        let email = claims.email.clone().ok_or_else(|| {
            tracing::warn!(
                target: "iam.oidc.exchange",
                issuer = %claims.issuer,
                reason = "missing_email",
                "oidc.exchange.reject"
            );
            IamError::InvalidCredentials
        })?;
        let normalised_email = email.trim().to_ascii_lowercase();
        if normalised_email.is_empty() {
            tracing::warn!(
                target: "iam.oidc.exchange",
                issuer = %claims.issuer,
                reason = "empty_email",
                "oidc.exchange.reject"
            );
            return Err(IamError::InvalidCredentials);
        }

        // 4. Look up the user; JIT-provision when configured.
        let user = match self
            .users
            .find_by_email(tenant_id, &normalised_email)
            .await?
        {
            Some(u) if u.is_active => u,
            Some(_) => {
                tracing::warn!(
                    target: "iam.oidc.exchange",
                    tenant_id = %tenant_id,
                    reason = "inactive",
                    "oidc.exchange.reject"
                );
                return Err(IamError::InvalidCredentials);
            }
            None => {
                if !self.cfg.jit_provision {
                    tracing::warn!(
                        target: "iam.oidc.exchange",
                        tenant_id = %tenant_id,
                        reason = "no_user_and_jit_disabled",
                        "oidc.exchange.reject"
                    );
                    return Err(IamError::InvalidCredentials);
                }
                self.provision(tenant_id, &normalised_email).await?
            }
        };

        // 5. Issue an SX-internal token pair.
        let issued = self.issue.execute(IssueTokenInput {
            user: user.clone(),
            ip: None,
            user_agent: None,
            cred_id: None,
        })?;
        tracing::info!(
            target: "iam.oidc.exchange",
            tenant_id = %user.tenant_id,
            user_id = %user.id,
            "oidc.exchange.accept"
        );
        Ok(ExchangeOidcOutput {
            user,
            token: issued.token,
        })
    }

    fn resolve_tenant_id(&self, claims: &crate::service::OidcClaims) -> Result<TenantId, IamError> {
        if let Some(raw) = claims.string_claim(&self.cfg.tenant_id_claim) {
            let uuid = raw.parse::<uuid::Uuid>().map_err(|_| {
                tracing::warn!(
                    target: "iam.oidc.exchange",
                    issuer = %claims.issuer,
                    reason = "tenant_claim_not_uuid",
                    "oidc.exchange.reject"
                );
                IamError::InvalidCredentials
            })?;
            return Ok(TenantId::from_uuid(uuid));
        }
        if let Some(default) = self.cfg.default_tenant_id {
            return Ok(default);
        }
        tracing::warn!(
            target: "iam.oidc.exchange",
            issuer = %claims.issuer,
            reason = "missing_tenant",
            "oidc.exchange.reject"
        );
        Err(IamError::InvalidCredentials)
    }

    async fn provision(&self, tenant_id: TenantId, email: &str) -> Result<User, IamError> {
        let roles: Vec<Role> = self
            .cfg
            .default_roles
            .iter()
            .map(|name| ExchangeOidcConfig::role_for_name(name, tenant_id))
            .collect();
        // The user was authenticated by the IdP — there is no password to
        // hash. We persist an empty password hash. Authentication via
        // `/v1/auth/login` will fail for this user (the hasher rejects an
        // empty PHC), which is the desired behaviour: this is a
        // federated-only account.
        let now = OffsetDateTime::now_utc();
        let user = User {
            id: UserId::new(),
            tenant_id,
            email: email.to_string(),
            password_hash: String::new(),
            is_active: true,
            roles,
            created_at: now,
            updated_at: now,
        };
        match self.users.create(&user).await {
            Ok(()) => {
                tracing::info!(
                    target: "iam.oidc.exchange",
                    tenant_id = %tenant_id,
                    user_id = %user.id,
                    "oidc.exchange.jit_provision"
                );
                Ok(user)
            }
            Err(IamError::Conflict(_)) => {
                // Race with a concurrent provisioner — re-read.
                self.users
                    .find_by_email(tenant_id, email)
                    .await?
                    .ok_or_else(|| {
                        IamError::repository("user vanished after conflict on JIT provision")
                    })
            }
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::config::{JwtAlgorithm, JwtConfig};
    use crate::service::clock::SystemClock;
    use crate::service::token_issuer::JwtIssuer;
    use crate::service::OidcClaims;
    use async_trait::async_trait;
    use secrecy::{ExposeSecret, SecretString};
    use std::collections::HashMap;
    use std::sync::Mutex;
    use std::time::Duration;
    use uuid::Uuid;

    /// In-memory user repository for tests.
    #[derive(Default)]
    struct InMemRepo {
        by_email: Mutex<HashMap<(TenantId, String), User>>,
    }

    #[async_trait]
    impl UserRepository for InMemRepo {
        async fn find_by_email(
            &self,
            tenant: TenantId,
            email: &str,
        ) -> Result<Option<User>, IamError> {
            let g = self.by_email.lock().expect("poisoned");
            Ok(g.get(&(tenant, email.to_ascii_lowercase())).cloned())
        }
        async fn find_by_id(&self, _id: UserId) -> Result<Option<User>, IamError> {
            Ok(None)
        }
        async fn create(&self, user: &User) -> Result<(), IamError> {
            let mut g = self.by_email.lock().expect("poisoned");
            let key = (user.tenant_id, user.email.to_ascii_lowercase());
            if g.contains_key(&key) {
                return Err(IamError::conflict("user"));
            }
            g.insert(key, user.clone());
            Ok(())
        }
    }

    /// Fake verifier returning a fixed claim set.
    struct FakeVerifier {
        claims: OidcClaims,
    }

    #[async_trait]
    impl OidcVerifier for FakeVerifier {
        async fn verify(&self, _id_token: &str) -> Result<OidcClaims, IamError> {
            Ok(self.claims.clone())
        }
    }

    fn jwt_cfg() -> JwtConfig {
        let key = "a".repeat(32);
        JwtConfig {
            issuer: "sx".into(),
            audience: "sx-clients".into(),
            signing_key: SecretString::from(key.clone()),
            verifying_key: SecretString::from(key),
            key_id: "k1".into(),
            access_ttl: Duration::from_secs(900),
            refresh_ttl: Duration::from_secs(3600),
            algorithm: JwtAlgorithm::Hs256,
            leeway_seconds: 5,
        }
    }

    fn build_issuer() -> Arc<IssueTokenUseCase<JwtIssuer<SystemClock>, SystemClock>> {
        let clock = Arc::new(SystemClock);
        let issuer = Arc::new(JwtIssuer::new(jwt_cfg(), Arc::clone(&clock)).expect("jwt issuer"));
        Arc::new(IssueTokenUseCase::new(
            issuer,
            clock,
            Duration::from_secs(900),
        ))
    }

    fn claims_with_tenant(email: &str, tenant: &str) -> OidcClaims {
        let mut extra = serde_json::Map::new();
        extra.insert(
            "tenant_id".to_string(),
            serde_json::Value::String(tenant.to_string()),
        );
        OidcClaims {
            subject: format!("idp|{email}"),
            issuer: "https://idp.example.com/realms/sx".into(),
            audience: "sx-dashboard".into(),
            email: Some(email.to_string()),
            name: Some("Alice".into()),
            extra,
        }
    }

    fn claims_without_tenant(email: &str) -> OidcClaims {
        OidcClaims {
            subject: format!("idp|{email}"),
            issuer: "https://idp.example.com/realms/sx".into(),
            audience: "sx-dashboard".into(),
            email: Some(email.to_string()),
            name: None,
            extra: serde_json::Map::new(),
        }
    }

    fn default_cfg(jit: bool) -> ExchangeOidcConfig {
        ExchangeOidcConfig {
            jit_provision: jit,
            default_roles: vec!["analyst".to_string()],
            default_tenant_id: None,
            tenant_id_claim: "tenant_id".into(),
        }
    }

    #[tokio::test]
    async fn exchange_creates_new_user_when_jit_enabled() {
        let tenant = Uuid::new_v4();
        let claims = claims_with_tenant("alice@example.com", &tenant.to_string());
        let verifier = Arc::new(FakeVerifier { claims });
        let users = Arc::new(InMemRepo::default());
        let issuer = build_issuer();
        let uc = ExchangeOidcUseCase::new(
            Arc::clone(&verifier),
            Arc::clone(&users),
            issuer,
            default_cfg(true),
        );

        let out = uc.execute("dummy").await.expect("jit exchange");
        assert_eq!(out.user.email, "alice@example.com");
        assert_eq!(out.user.tenant_id, TenantId::from_uuid(tenant));
        assert!(out
            .user
            .roles
            .iter()
            .any(|r| r.name == "analyst" && !r.permissions.is_empty()));
        // The user must be persisted.
        let stored = users
            .find_by_email(TenantId::from_uuid(tenant), "alice@example.com")
            .await
            .unwrap()
            .expect("user persisted");
        assert_eq!(stored.email, "alice@example.com");
    }

    #[tokio::test]
    async fn exchange_returns_invalid_credentials_when_jit_disabled_and_user_missing() {
        let tenant = Uuid::new_v4();
        let claims = claims_with_tenant("ghost@example.com", &tenant.to_string());
        let verifier = Arc::new(FakeVerifier { claims });
        let users = Arc::new(InMemRepo::default());
        let issuer = build_issuer();
        let uc = ExchangeOidcUseCase::new(verifier, users, issuer, default_cfg(false));
        let err = uc.execute("dummy").await.expect_err("should reject");
        assert_eq!(err, IamError::InvalidCredentials);
    }

    #[tokio::test]
    async fn exchange_issues_sx_tokens_for_existing_user() {
        let tenant_uuid = Uuid::new_v4();
        let tenant = TenantId::from_uuid(tenant_uuid);
        let users = Arc::new(InMemRepo::default());
        // Seed an existing user.
        let now = OffsetDateTime::now_utc();
        let existing = User {
            id: UserId::new(),
            tenant_id: tenant,
            email: "alice@example.com".into(),
            password_hash: "$argon2id$v=19$m=1024,t=1,p=1$abc$def".into(),
            is_active: true,
            roles: vec![Role {
                id: RoleId::new(),
                tenant_id: tenant,
                name: "analyst".into(),
                permissions: vec![Permission::parse("findings:read").unwrap()],
            }],
            created_at: now,
            updated_at: now,
        };
        users.create(&existing).await.unwrap();

        let claims = claims_with_tenant("alice@example.com", &tenant_uuid.to_string());
        let verifier = Arc::new(FakeVerifier { claims });
        let issuer = build_issuer();
        let uc = ExchangeOidcUseCase::new(verifier, Arc::clone(&users), issuer, default_cfg(false));

        let out = uc.execute("dummy").await.expect("existing user");
        assert_eq!(out.user.id, existing.id);
        assert!(!out.token.access.expose_secret_is_empty());
        assert!(!out.token.refresh.expose_secret_is_empty());
        // Sanity: SX access token is a JWS (three parts).
        assert_eq!(out.token.access.expose_secret().split('.').count(), 3);
    }

    #[tokio::test]
    async fn exchange_uses_default_tenant_when_claim_missing() {
        let default = Uuid::new_v4();
        let claims = claims_without_tenant("solo@example.com");
        let verifier = Arc::new(FakeVerifier { claims });
        let users = Arc::new(InMemRepo::default());
        let issuer = build_issuer();
        let mut cfg = default_cfg(true);
        cfg.default_tenant_id = Some(TenantId::from_uuid(default));
        let uc = ExchangeOidcUseCase::new(verifier, Arc::clone(&users), issuer, cfg);
        let out = uc.execute("dummy").await.expect("default tenant");
        assert_eq!(out.user.tenant_id, TenantId::from_uuid(default));
    }

    #[tokio::test]
    async fn exchange_rejects_when_tenant_claim_not_uuid() {
        let claims = claims_with_tenant("alice@example.com", "not-a-uuid");
        let verifier = Arc::new(FakeVerifier { claims });
        let users = Arc::new(InMemRepo::default());
        let issuer = build_issuer();
        let uc = ExchangeOidcUseCase::new(verifier, users, issuer, default_cfg(true));
        let err = uc.execute("dummy").await.expect_err("bad tenant");
        assert_eq!(err, IamError::InvalidCredentials);
    }

    #[tokio::test]
    async fn exchange_rejects_when_no_tenant_and_no_default() {
        let claims = claims_without_tenant("alice@example.com");
        let verifier = Arc::new(FakeVerifier { claims });
        let users = Arc::new(InMemRepo::default());
        let issuer = build_issuer();
        let uc = ExchangeOidcUseCase::new(verifier, users, issuer, default_cfg(true));
        let err = uc.execute("dummy").await.expect_err("no tenant resolvable");
        assert_eq!(err, IamError::InvalidCredentials);
    }

    #[tokio::test]
    async fn exchange_rejects_when_email_missing() {
        let tenant = Uuid::new_v4();
        let mut claims = claims_with_tenant("doesnt-matter@x.io", &tenant.to_string());
        claims.email = None;
        let verifier = Arc::new(FakeVerifier { claims });
        let users = Arc::new(InMemRepo::default());
        let issuer = build_issuer();
        let uc = ExchangeOidcUseCase::new(verifier, users, issuer, default_cfg(true));
        let err = uc.execute("dummy").await.expect_err("missing email");
        assert_eq!(err, IamError::InvalidCredentials);
    }

    /// Convenience helper used in the test above.
    trait SecretEmpty {
        fn expose_secret_is_empty(&self) -> bool;
    }
    impl SecretEmpty for secrecy::SecretString {
        fn expose_secret_is_empty(&self) -> bool {
            use secrecy::ExposeSecret;
            self.expose_secret().is_empty()
        }
    }
}
