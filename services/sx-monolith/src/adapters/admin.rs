//! Admin port adapter — wraps `sx_iam::CreateUserUseCase`.
//!
//! `sx-iam`'s [`CreateUserUseCase`] is generic over `UserRepository` +
//! `PasswordHasher`. The IAM bundle keeps the concrete in-memory repo +
//! Argon2id hasher; this adapter receives them via constructor injection
//! so admin-provisioned users land in the same store the bootstrap admin
//! does (and can subsequently authenticate against `/v1/auth/login`).
//!
//! ## Role-name mapping
//!
//! The HTTP surface carries plain role names. The adapter maps each name
//! onto a static permission grant:
//!
//! | role name | granted permissions |
//! | --------- | ------------------- |
//! | `admin`   | `*:*` (full wildcard) |
//! | `analyst` | `findings:read`, `findings:update`, `engagements:read`, `risk:calculate`, `reports:render`, `compliance:read` |
//! | `ops`     | `assets:read`, `engagements:read`, `engagements:create`, `safety:trip`, `autonomy:run`, `cloud:inventory`, `admin:users` |
//!
//! Unknown names are silently dropped.

use std::sync::Arc;

use async_trait::async_trait;
use secrecy::SecretString;
use sx_api::port::{AdminUserListPort, CreateUserPort, Phase3PortError};
use sx_api::view::admin_view::{
    AdminUserSummaryView, CreateUserRequestView, CreateUserResponseView,
};
use sx_iam::controller::{CreateUserInput, CreateUserUseCase};
use sx_iam::domain::{Permission, Role, RoleId, TenantId};
use sx_iam::service::Argon2idHasher;
use sx_iam::IamError;

use crate::adapters::iam::MonolithUserRepo;

/// Concrete use case type alias the adapter holds.
type SharedCreateUser = CreateUserUseCase<MonolithUserRepo, Argon2idHasher>;

/// Bundle of admin trait objects ready for [`sx_api::AppState`].
pub(crate) struct AdminBundle {
    /// Admin user-provisioning port.
    pub create_user: Arc<dyn CreateUserPort>,
    /// Admin user-listing port (`GET /v1/admin/users`).
    pub admin_user_list: Arc<dyn AdminUserListPort>,
}

/// Build the admin bundle from the shared user repo + Argon2id hasher
/// held by the IAM bundle. The repo may be in-memory or Postgres-backed
/// — the unified [`MonolithUserRepo`] enum dispatches.
pub(crate) fn build(users: Arc<MonolithUserRepo>, hasher: Arc<Argon2idHasher>) -> AdminBundle {
    let uc: SharedCreateUser = CreateUserUseCase::new(Arc::clone(&users), hasher);
    let list_port: Arc<dyn AdminUserListPort> = Arc::new(AdminUserListAdapter {
        users: Arc::clone(&users),
    });
    AdminBundle {
        create_user: Arc::new(AdminAdapter { uc: Arc::new(uc) }),
        admin_user_list: list_port,
    }
}

/// Read-side list adapter — projects [`sx_iam::domain::User`] rows from
/// the shared user repo onto the narrow
/// [`AdminUserSummaryView`].
struct AdminUserListAdapter {
    users: Arc<MonolithUserRepo>,
}

impl std::fmt::Debug for AdminUserListAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdminUserListAdapter")
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl AdminUserListPort for AdminUserListAdapter {
    async fn list_users(
        &self,
        tenant_id: &str,
        limit: u32,
        offset: u64,
    ) -> Result<Vec<AdminUserSummaryView>, Phase3PortError> {
        let tenant = uuid::Uuid::parse_str(tenant_id)
            .map(TenantId::from_uuid)
            .map_err(|_| Phase3PortError::Invalid("invalid tenant_id".into()))?;
        let rows = self
            .users
            .list_for_tenant(tenant, limit, offset)
            .await
            .map_err(|e| Phase3PortError::Dependency(e.to_string()))?;
        Ok(rows
            .into_iter()
            .map(|u| {
                let created_at = u
                    .created_at
                    .format(&time::format_description::well_known::Rfc3339)
                    .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned());
                let role_count = u32::try_from(u.roles.len()).unwrap_or(u32::MAX);
                AdminUserSummaryView {
                    id: u.id.to_string(),
                    tenant_id: u.tenant_id.to_string(),
                    email: u.email,
                    is_active: u.is_active,
                    role_count,
                    created_at,
                }
            })
            .collect())
    }
}

/// Concrete admin adapter wrapping [`SharedCreateUser`].
struct AdminAdapter {
    uc: Arc<SharedCreateUser>,
}

#[async_trait]
impl CreateUserPort for AdminAdapter {
    async fn create(
        &self,
        req: CreateUserRequestView,
    ) -> Result<CreateUserResponseView, Phase3PortError> {
        let tenant = uuid::Uuid::parse_str(&req.tenant_id)
            .map(TenantId::from_uuid)
            .map_err(|_| Phase3PortError::Invalid("invalid tenant_id".into()))?;

        let roles: Vec<Role> = req
            .roles
            .iter()
            .filter_map(|name| role_for_name(name, tenant))
            .collect();

        let input = CreateUserInput {
            tenant_id: tenant,
            email: req.email.clone(),
            password: SecretString::from(req.password.clone()),
            roles,
        };

        let user = self.uc.execute(input).await.map_err(map_iam_error)?;

        Ok(CreateUserResponseView {
            id: user.id.to_string(),
            tenant_id: user.tenant_id.to_string(),
            email: user.email,
            roles: req.roles,
            created_at: time::OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_else(|_| "1970-01-01T00:00:00Z".into()),
        })
    }
}

/// Map a role name onto a concrete [`Role`] under the given tenant.
///
/// Unknown names return `None` so the caller's `filter_map` drops them.
fn role_for_name(name: &str, tenant: TenantId) -> Option<Role> {
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
            "admin:users",
        ]
        .iter()
        .filter_map(|p| Permission::parse(p).ok())
        .collect(),
        _ => return None,
    };
    Some(Role {
        id: RoleId::new(),
        tenant_id: tenant,
        name: name.to_string(),
        permissions: perms,
    })
}

/// Translate an [`IamError`] into the shared [`Phase3PortError`] surface
/// the HTTP layer already knows how to map onto an HTTP status.
fn map_iam_error(e: IamError) -> Phase3PortError {
    match e {
        IamError::Conflict(_) => Phase3PortError::Invalid("user exists".into()),
        IamError::InvalidCredentials => Phase3PortError::Invalid("invalid input".into()),
        IamError::Config(m) => Phase3PortError::Invalid(m),
        other => Phase3PortError::Internal(other.to_string()),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;
    use sx_iam::config::{LockoutPolicy, PasswordConfig};
    use sx_iam::controller::authenticate_user::AuthenticateInput;
    use sx_iam::controller::AuthenticateUserUseCase;
    use sx_iam::model::Credentials;
    use sx_iam::service::login_attempt_tracker::LoginAttemptTracker;
    use sx_iam::service::{AttemptKey, PasswordHasher};

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

    /// In-memory tracker mirroring the monolith's adapters::iam impl.
    #[derive(Debug, Default)]
    struct InMemTracker {
        counts: Mutex<HashMap<AttemptKey, u32>>,
    }

    #[async_trait]
    impl LoginAttemptTracker for InMemTracker {
        async fn record_failure(&self, key: &AttemptKey) -> Result<u32, IamError> {
            let mut g = self.counts.lock().expect("poisoned");
            let entry = g.entry(key.clone()).or_insert(0);
            *entry = entry.saturating_add(1);
            Ok(*entry)
        }
        async fn count_failures(&self, key: &AttemptKey) -> Result<u32, IamError> {
            Ok(self
                .counts
                .lock()
                .expect("poisoned")
                .get(key)
                .copied()
                .unwrap_or(0))
        }
        async fn clear(&self, key: &AttemptKey) -> Result<(), IamError> {
            self.counts.lock().expect("poisoned").remove(key);
            Ok(())
        }
    }

    fn valid_tenant() -> String {
        TenantId::new().to_string()
    }

    #[tokio::test]
    async fn admin_adapter_creates_user_and_can_login() {
        let users = Arc::new(MonolithUserRepo::in_memory());
        let hasher = fast_hasher();
        let bundle = build(Arc::clone(&users), Arc::clone(&hasher));

        let tenant_id = valid_tenant();
        let resp = bundle
            .create_user
            .create(CreateUserRequestView {
                tenant_id: tenant_id.clone(),
                email: "analyst@example.com".into(),
                password: "correct-horse-battery".into(),
                roles: vec!["analyst".into()],
            })
            .await
            .expect("create should succeed");
        assert_eq!(resp.email, "analyst@example.com");
        assert_eq!(resp.roles, vec!["analyst".to_string()]);

        // Now authenticate via the same in-memory repo + hasher.
        let tracker = Arc::new(InMemTracker::default());
        let lockout = LockoutPolicy {
            max_failures: 5,
            lock_duration: std::time::Duration::from_secs(60),
        };
        let authn = AuthenticateUserUseCase::new(
            Arc::clone(&users),
            Arc::clone(&hasher),
            Arc::clone(&tracker),
            lockout,
            SecretString::from("test-pepper".to_string()),
        );

        let tenant_uuid = uuid::Uuid::parse_str(&tenant_id).expect("uuid");
        let creds = Credentials {
            tenant_id: TenantId::from_uuid(tenant_uuid),
            email: "analyst@example.com".to_string(),
            password: SecretString::from("correct-horse-battery".to_string()),
        };
        let authed = authn
            .execute(AuthenticateInput { credentials: creds })
            .await
            .expect("login should succeed for admin-provisioned user");
        assert_eq!(authed.email, "analyst@example.com");
    }

    #[tokio::test]
    async fn admin_adapter_returns_conflict_on_duplicate_email() {
        let users = Arc::new(MonolithUserRepo::in_memory());
        let hasher = fast_hasher();
        let bundle = build(Arc::clone(&users), Arc::clone(&hasher));

        let tenant_id = valid_tenant();
        bundle
            .create_user
            .create(CreateUserRequestView {
                tenant_id: tenant_id.clone(),
                email: "dup@example.com".into(),
                password: "correct-horse-battery".into(),
                roles: vec!["admin".into()],
            })
            .await
            .expect("first create should succeed");

        let err = bundle
            .create_user
            .create(CreateUserRequestView {
                tenant_id,
                email: "dup@example.com".into(),
                password: "correct-horse-battery".into(),
                roles: vec!["admin".into()],
            })
            .await
            .expect_err("second create should fail");
        assert!(
            matches!(err, Phase3PortError::Invalid(ref msg) if msg.contains("exists")),
            "expected duplicate-email conflict, got {err:?}"
        );
    }

    #[tokio::test]
    async fn admin_adapter_rejects_invalid_tenant_id() {
        let users = Arc::new(MonolithUserRepo::in_memory());
        let hasher = fast_hasher();
        let bundle = build(users, hasher);
        let err = bundle
            .create_user
            .create(CreateUserRequestView {
                tenant_id: "not-a-uuid".into(),
                email: "x@example.com".into(),
                password: "correct-horse-battery".into(),
                roles: vec!["admin".into()],
            })
            .await
            .expect_err("invalid tenant should be rejected");
        assert!(matches!(err, Phase3PortError::Invalid(_)));
    }

    #[test]
    fn role_for_name_admin_grants_wildcard() {
        let tenant = TenantId::new();
        let role = role_for_name("admin", tenant).expect("admin role");
        assert_eq!(role.name, "admin");
        assert!(role
            .permissions
            .iter()
            .any(|p| p.resource() == "*" && p.action() == "*"));
    }

    #[test]
    fn role_for_name_unknown_drops() {
        let tenant = TenantId::new();
        assert!(role_for_name("unknown", tenant).is_none());
    }

    #[test]
    fn role_for_name_analyst_has_six_permissions() {
        let tenant = TenantId::new();
        let role = role_for_name("analyst", tenant).expect("analyst role");
        assert_eq!(role.permissions.len(), 6);
    }

    #[test]
    fn role_for_name_ops_includes_admin_users() {
        let tenant = TenantId::new();
        let role = role_for_name("ops", tenant).expect("ops role");
        assert!(role
            .permissions
            .iter()
            .any(|p| p.resource() == "admin" && p.action() == "users"));
    }

    /// Sanity-check the password hasher path: a freshly provisioned user
    /// must store a verifiable PHC string.
    #[tokio::test]
    async fn admin_adapter_hashes_password() {
        let users = Arc::new(MonolithUserRepo::in_memory());
        let hasher = fast_hasher();
        let bundle = build(Arc::clone(&users), Arc::clone(&hasher));
        let tenant_id = valid_tenant();
        let _ = bundle
            .create_user
            .create(CreateUserRequestView {
                tenant_id: tenant_id.clone(),
                email: "phc@example.com".into(),
                password: "correct-horse-battery".into(),
                roles: vec!["analyst".into()],
            })
            .await
            .expect("create should succeed");

        // The hashed PHC must verify with the original password and not
        // be a plaintext copy.
        let tenant_uuid = uuid::Uuid::parse_str(&tenant_id).unwrap();
        let user = sx_iam::port::UserRepository::find_by_email(
            users.as_ref(),
            TenantId::from_uuid(tenant_uuid),
            "phc@example.com",
        )
        .await
        .unwrap()
        .expect("user should exist");
        assert!(user.password_hash.starts_with("$argon2id$"));
        hasher
            .verify(
                &SecretString::from("correct-horse-battery".to_string()),
                &user.password_hash,
            )
            .expect("password should verify");
    }
}
