//! `CreateUserUseCase` — provision a new user.
//!
//! Two flavours are exposed:
//!
//! * [`CreateUserUseCase`] takes plaintext credentials, normalises the
//!   email, hashes the password with the injected [`PasswordHasher`],
//!   and persists the resulting [`User`] via [`UserRepository::create`].
//! * [`CreateUserWithHashUseCase`] takes an **already-hashed** Argon2id
//!   PHC string. This is the path used by the monolith's bootstrap
//!   seeder, which loads the Phase-1 admin's pre-computed PHC from
//!   configuration so secrets never appear in plaintext at runtime.
//!
//! Both paths surface `Err(IamError::Conflict(_))` when the repository
//! rejects the insert due to a duplicate `(tenant_id, email)`.

use std::sync::Arc;

use secrecy::SecretString;
use time::OffsetDateTime;

use crate::domain::{Role, TenantId, User, UserId};
use crate::port::UserRepository;
use crate::service::PasswordHasher;
use crate::IamError;

/// Inputs to [`CreateUserUseCase::execute`].
#[derive(Debug)]
pub struct CreateUserInput {
    /// Tenant the new user belongs to.
    pub tenant_id: TenantId,
    /// Login email — lower-cased by the use case before persistence.
    pub email: String,
    /// Plaintext password — hashed by the use case before persistence.
    pub password: SecretString,
    /// Roles directly granted to the new user.
    pub roles: Vec<Role>,
}

/// Inputs to [`CreateUserWithHashUseCase::execute`].
///
/// Used by the boot-time seeder to provision the Phase-1 admin user
/// without ever materialising the plaintext password in the process —
/// the PHC string is pre-computed and carried in configuration.
#[derive(Debug)]
pub struct CreateUserWithHashInput {
    /// Tenant the new user belongs to.
    pub tenant_id: TenantId,
    /// Login email — lower-cased by the use case before persistence.
    pub email: String,
    /// Argon2id PHC-formatted password hash — persisted verbatim.
    pub password_hash: String,
    /// Roles directly granted to the new user.
    pub roles: Vec<Role>,
}

/// Use case: provision a user from plaintext credentials.
pub struct CreateUserUseCase<R, H>
where
    R: UserRepository,
    H: PasswordHasher,
{
    users: Arc<R>,
    hasher: Arc<H>,
}

impl<R, H> std::fmt::Debug for CreateUserUseCase<R, H>
where
    R: UserRepository,
    H: PasswordHasher,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CreateUserUseCase").finish()
    }
}

impl<R, H> CreateUserUseCase<R, H>
where
    R: UserRepository,
    H: PasswordHasher,
{
    /// Build the use case with its dependencies.
    pub fn new(users: Arc<R>, hasher: Arc<H>) -> Self {
        Self { users, hasher }
    }

    /// Run the use case.
    ///
    /// Steps:
    /// 1. trim + lower-case the email and validate it isn't empty,
    /// 2. hash the password,
    /// 3. build the [`User`] (with a freshly minted [`UserId`]) and
    ///    persist it.
    ///
    /// Repository [`IamError::Conflict`] errors are propagated verbatim
    /// so callers can distinguish "already provisioned" from genuine
    /// failures.
    pub async fn execute(&self, input: CreateUserInput) -> Result<User, IamError> {
        let email = normalise_email(&input.email)?;
        let password_hash = self.hasher.hash(&input.password)?;
        let now = OffsetDateTime::now_utc();
        let user = User {
            id: UserId::new(),
            tenant_id: input.tenant_id,
            email,
            password_hash,
            is_active: true,
            roles: input.roles,
            created_at: now,
            updated_at: now,
        };
        self.users.create(&user).await?;
        tracing::info!(
            user_id = %user.id,
            tenant_id = %user.tenant_id,
            "iam.user.created",
        );
        Ok(user)
    }
}

/// Use case: provision a user from a pre-computed PHC hash.
///
/// Used by the bootstrap seeder — see the module-level docs.
pub struct CreateUserWithHashUseCase<R>
where
    R: UserRepository,
{
    users: Arc<R>,
}

impl<R> std::fmt::Debug for CreateUserWithHashUseCase<R>
where
    R: UserRepository,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CreateUserWithHashUseCase").finish()
    }
}

impl<R> CreateUserWithHashUseCase<R>
where
    R: UserRepository,
{
    /// Build the use case with its dependency.
    pub fn new(users: Arc<R>) -> Self {
        Self { users }
    }

    /// Run the use case.
    ///
    /// The supplied `password_hash` is persisted verbatim; the caller is
    /// responsible for ensuring it is a valid Argon2id PHC string. The
    /// email is normalised exactly as in [`CreateUserUseCase::execute`].
    pub async fn execute(&self, input: CreateUserWithHashInput) -> Result<User, IamError> {
        let email = normalise_email(&input.email)?;
        if input.password_hash.trim().is_empty() {
            return Err(IamError::config("password_hash must not be empty"));
        }
        let now = OffsetDateTime::now_utc();
        let user = User {
            id: UserId::new(),
            tenant_id: input.tenant_id,
            email,
            password_hash: input.password_hash,
            is_active: true,
            roles: input.roles,
            created_at: now,
            updated_at: now,
        };
        self.users.create(&user).await?;
        tracing::info!(
            user_id = %user.id,
            tenant_id = %user.tenant_id,
            "iam.user.created_with_hash",
        );
        Ok(user)
    }
}

/// Trim, lower-case, and reject empty emails.
fn normalise_email(raw: &str) -> Result<String, IamError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(IamError::config("email must not be empty"));
    }
    Ok(trimmed.to_ascii_lowercase())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::config::PasswordConfig;
    use crate::domain::UserId;
    use crate::service::password_hasher::Argon2idHasher;
    use async_trait::async_trait;
    use std::sync::Mutex;

    /// Stub repo that records every `create` call and optionally fails
    /// with [`IamError::Conflict`] on the next call.
    #[derive(Default)]
    struct StubRepo {
        created: Mutex<Vec<User>>,
        conflict: bool,
    }

    #[async_trait]
    impl UserRepository for StubRepo {
        async fn find_by_email(
            &self,
            _tenant: TenantId,
            _email: &str,
        ) -> Result<Option<User>, IamError> {
            // Not exercised by create_user tests.
            Ok(None)
        }

        async fn find_by_id(&self, _id: UserId) -> Result<Option<User>, IamError> {
            // Not exercised by create_user tests.
            Ok(None)
        }

        async fn create(&self, user: &User) -> Result<(), IamError> {
            if self.conflict {
                return Err(IamError::conflict("user"));
            }
            self.created
                .lock()
                .expect("stub repo poisoned")
                .push(user.clone());
            Ok(())
        }
    }

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

    #[tokio::test]
    async fn create_user_lowercases_email() {
        let repo = Arc::new(StubRepo::default());
        let hasher = fast_hasher();
        let uc = CreateUserUseCase::new(Arc::clone(&repo), hasher);
        let tid = TenantId::new();
        let user = uc
            .execute(CreateUserInput {
                tenant_id: tid,
                email: "  Admin@Example.COM ".into(),
                password: SecretString::from("hunter2".to_string()),
                roles: vec![],
            })
            .await
            .unwrap();
        assert_eq!(user.email, "admin@example.com");
        assert!(user.is_active);
        assert!(user.password_hash.starts_with("$argon2id$"));
        let created = repo.created.lock().unwrap();
        assert_eq!(created.len(), 1);
        assert_eq!(created.first().unwrap().email, "admin@example.com");
    }

    #[tokio::test]
    async fn create_user_returns_conflict_on_duplicate() {
        let repo = Arc::new(StubRepo {
            created: Mutex::new(Vec::new()),
            conflict: true,
        });
        let hasher = fast_hasher();
        let uc = CreateUserUseCase::new(Arc::clone(&repo), hasher);
        let err = uc
            .execute(CreateUserInput {
                tenant_id: TenantId::new(),
                email: "dup@example.com".into(),
                password: SecretString::from("hunter2".to_string()),
                roles: vec![],
            })
            .await
            .unwrap_err();
        assert!(matches!(err, IamError::Conflict(_)));
    }

    #[tokio::test]
    async fn create_user_with_hash_skips_hashing() {
        let repo = Arc::new(StubRepo::default());
        let uc = CreateUserWithHashUseCase::new(Arc::clone(&repo));
        let phc = "$argon2id$v=19$m=1024,t=1,p=1$abc$def".to_string();
        let user = uc
            .execute(CreateUserWithHashInput {
                tenant_id: TenantId::new(),
                email: "Boot@Example.com".into(),
                password_hash: phc.clone(),
                roles: vec![],
            })
            .await
            .unwrap();
        assert_eq!(user.email, "boot@example.com");
        assert_eq!(user.password_hash, phc);
        let created = repo.created.lock().unwrap();
        assert_eq!(created.len(), 1);
        assert_eq!(created.first().unwrap().password_hash, phc);
    }

    #[tokio::test]
    async fn create_user_with_empty_email_errors() {
        let repo = Arc::new(StubRepo::default());
        let hasher = fast_hasher();
        let uc = CreateUserUseCase::new(Arc::clone(&repo), hasher);
        let err = uc
            .execute(CreateUserInput {
                tenant_id: TenantId::new(),
                email: "   ".into(),
                password: SecretString::from("hunter2".to_string()),
                roles: vec![],
            })
            .await
            .unwrap_err();
        assert!(matches!(err, IamError::Config(_)));
        assert!(repo.created.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn create_user_with_hash_empty_hash_errors() {
        let repo = Arc::new(StubRepo::default());
        let uc = CreateUserWithHashUseCase::new(Arc::clone(&repo));
        let err = uc
            .execute(CreateUserWithHashInput {
                tenant_id: TenantId::new(),
                email: "boot@example.com".into(),
                password_hash: "   ".into(),
                roles: vec![],
            })
            .await
            .unwrap_err();
        assert!(matches!(err, IamError::Config(_)));
        assert!(repo.created.lock().unwrap().is_empty());
    }
}
