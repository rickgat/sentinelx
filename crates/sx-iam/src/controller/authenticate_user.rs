//! `AuthenticateUserUseCase` — verify credentials, enforce lockout.
//!
//! Order matters:
//! 1. derive the attempt key from `(tenant, email, pepper)`,
//! 2. check lockout BEFORE hashing — otherwise we burn CPU on a locked
//!    account, which is also a side channel,
//! 3. look up the user,
//! 4. verify the password (constant-time inside `PasswordHasher`),
//! 5. on success → clear failures; on failure → record failure.

use std::sync::Arc;

use secrecy::SecretString;

use crate::config::LockoutPolicy;
use crate::domain::User;
use crate::model::Credentials;
use crate::port::UserRepository;
use crate::service::{AttemptKey, LoginAttemptTracker, PasswordHasher};
use crate::IamError;

/// Inputs to [`AuthenticateUserUseCase::execute`].
#[derive(Debug)]
pub struct AuthenticateInput {
    /// Credentials — tenant + email + plaintext password.
    pub credentials: Credentials,
}

/// Use case: verify a set of credentials.
pub struct AuthenticateUserUseCase<R, H, T>
where
    R: UserRepository,
    H: PasswordHasher,
    T: LoginAttemptTracker,
{
    users: Arc<R>,
    hasher: Arc<H>,
    tracker: Arc<T>,
    lockout: LockoutPolicy,
    pepper: SecretString,
}

impl<R, H, T> std::fmt::Debug for AuthenticateUserUseCase<R, H, T>
where
    R: UserRepository,
    H: PasswordHasher,
    T: LoginAttemptTracker,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthenticateUserUseCase")
            .field("lockout", &self.lockout)
            .finish()
    }
}

impl<R, H, T> AuthenticateUserUseCase<R, H, T>
where
    R: UserRepository,
    H: PasswordHasher,
    T: LoginAttemptTracker,
{
    /// Build a use case with its dependencies.
    pub fn new(
        users: Arc<R>,
        hasher: Arc<H>,
        tracker: Arc<T>,
        lockout: LockoutPolicy,
        pepper: SecretString,
    ) -> Self {
        Self {
            users,
            hasher,
            tracker,
            lockout,
            pepper,
        }
    }

    /// Run the use case. Returns the authenticated [`User`] on success.
    #[allow(clippy::cognitive_complexity)] // sequential gate machine; each step is local + linear
    pub async fn execute(&self, input: AuthenticateInput) -> Result<User, IamError> {
        let key = AttemptKey::derive(
            input.credentials.tenant_id,
            &input.credentials.email,
            &self.pepper,
        )?;

        // Step 1: deny early if the account is locked.
        let failures = self.tracker.count_failures(&key).await?;
        if failures >= self.lockout.max_failures {
            tracing::warn!(
                tenant_id = %input.credentials.tenant_id,
                "iam.auth.locked",
            );
            return Err(IamError::AccountLocked);
        }

        // Step 2: look up the user.
        let user = self
            .users
            .find_by_email(input.credentials.tenant_id, &input.credentials.email)
            .await?;

        // Step 3: verify the password. Generic error on any failure.
        let user = match user {
            Some(u) if u.is_active => u,
            // Either no user, or the account is deactivated. We DO still
            // record a failure here so an attacker probing an unknown
            // email can't flood the tracker without contributing to the
            // tenant's lockout for that email.
            _ => {
                let _ = self.tracker.record_failure(&key).await?;
                tracing::warn!(
                    tenant_id = %input.credentials.tenant_id,
                    "iam.auth.unknown_or_inactive",
                );
                return Err(IamError::InvalidCredentials);
            }
        };

        match self
            .hasher
            .verify(&input.credentials.password, &user.password_hash)
        {
            Ok(()) => {
                self.tracker.clear(&key).await?;
                tracing::info!(
                    user_id = %user.id,
                    tenant_id = %user.tenant_id,
                    "iam.auth.success",
                );
                Ok(user)
            }
            Err(_) => {
                let new_count = self.tracker.record_failure(&key).await?;
                tracing::warn!(
                    user_id = %user.id,
                    tenant_id = %user.tenant_id,
                    failure_count = new_count,
                    "iam.auth.bad_password",
                );
                Err(IamError::InvalidCredentials)
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::config::PasswordConfig;
    use crate::domain::{TenantId, UserId};
    use crate::service::password_hasher::Argon2idHasher;
    use async_trait::async_trait;
    use secrecy::SecretString;
    use std::sync::Mutex;

    /// In-memory test impls.
    struct InMemoryRepo {
        user: Option<User>,
    }

    #[async_trait]
    impl UserRepository for InMemoryRepo {
        async fn find_by_email(
            &self,
            tenant: TenantId,
            email: &str,
        ) -> Result<Option<User>, IamError> {
            Ok(self
                .user
                .clone()
                .filter(|u| u.tenant_id == tenant && u.email == email))
        }

        async fn find_by_id(&self, id: UserId) -> Result<Option<User>, IamError> {
            Ok(self.user.clone().filter(|u| u.id == id))
        }

        // Read-side fixture: write side is not exercised by these tests.
        async fn create(&self, _user: &User) -> Result<(), IamError> {
            Err(IamError::internal("not implemented in this test fixture"))
        }
    }

    #[derive(Default)]
    struct InMemoryTracker {
        store: Mutex<std::collections::HashMap<String, u32>>,
    }

    #[async_trait]
    impl LoginAttemptTracker for InMemoryTracker {
        async fn record_failure(&self, key: &AttemptKey) -> Result<u32, IamError> {
            let mut g = self.store.lock().expect("tracker poisoned");
            let entry = g.entry(key.email_hash.clone()).or_insert(0);
            *entry += 1;
            Ok(*entry)
        }
        async fn count_failures(&self, key: &AttemptKey) -> Result<u32, IamError> {
            let g = self.store.lock().expect("tracker poisoned");
            Ok(g.get(&key.email_hash).copied().unwrap_or(0))
        }
        async fn clear(&self, key: &AttemptKey) -> Result<(), IamError> {
            let mut g = self.store.lock().expect("tracker poisoned");
            g.remove(&key.email_hash);
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

    fn seeded_user(tenant: TenantId, email: &str, hasher: &Argon2idHasher) -> User {
        let phc = hasher
            .hash(&SecretString::from("hunter2".to_string()))
            .unwrap();
        let now = time::OffsetDateTime::UNIX_EPOCH;
        User {
            id: UserId::new(),
            tenant_id: tenant,
            email: email.into(),
            password_hash: phc,
            is_active: true,
            roles: vec![],
            created_at: now,
            updated_at: now,
        }
    }

    fn pepper() -> SecretString {
        SecretString::from("pep".to_string())
    }

    fn lockout() -> LockoutPolicy {
        LockoutPolicy {
            max_failures: 3,
            lock_duration: std::time::Duration::from_secs(60),
        }
    }

    #[tokio::test]
    async fn authenticate_success_clears_failures() {
        let tid = TenantId::new();
        let hasher = fast_hasher();
        let user = seeded_user(tid, "alice@example.com", &hasher);
        let repo = Arc::new(InMemoryRepo {
            user: Some(user.clone()),
        });
        let tracker = Arc::new(InMemoryTracker::default());

        // Pre-record one failure to prove it's cleared on success.
        let key = AttemptKey::derive(tid, &user.email, &pepper()).unwrap();
        tracker.record_failure(&key).await.unwrap();

        let uc = AuthenticateUserUseCase::new(repo, hasher, tracker.clone(), lockout(), pepper());
        let out = uc
            .execute(AuthenticateInput {
                credentials: Credentials::new(
                    tid,
                    user.email.clone(),
                    SecretString::from("hunter2".to_string()),
                ),
            })
            .await
            .unwrap();
        assert_eq!(out.id, user.id);
        assert_eq!(tracker.count_failures(&key).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn authenticate_bad_password_records_and_errors() {
        let tid = TenantId::new();
        let hasher = fast_hasher();
        let user = seeded_user(tid, "alice@example.com", &hasher);
        let repo = Arc::new(InMemoryRepo {
            user: Some(user.clone()),
        });
        let tracker = Arc::new(InMemoryTracker::default());
        let uc = AuthenticateUserUseCase::new(repo, hasher, tracker.clone(), lockout(), pepper());
        let err = uc
            .execute(AuthenticateInput {
                credentials: Credentials::new(
                    tid,
                    user.email.clone(),
                    SecretString::from("wrong".to_string()),
                ),
            })
            .await
            .unwrap_err();
        assert_eq!(err, IamError::InvalidCredentials);
        let key = AttemptKey::derive(tid, &user.email, &pepper()).unwrap();
        assert_eq!(tracker.count_failures(&key).await.unwrap(), 1);
    }

    #[tokio::test]
    async fn authenticate_unknown_user_records_failure_and_returns_generic() {
        let tid = TenantId::new();
        let hasher = fast_hasher();
        let repo = Arc::new(InMemoryRepo { user: None });
        let tracker = Arc::new(InMemoryTracker::default());
        let uc = AuthenticateUserUseCase::new(repo, hasher, tracker.clone(), lockout(), pepper());
        let err = uc
            .execute(AuthenticateInput {
                credentials: Credentials::new(
                    tid,
                    "ghost@example.com",
                    SecretString::from("x".to_string()),
                ),
            })
            .await
            .unwrap_err();
        // CRITICAL: must NOT be a "not found" — must be the generic variant.
        assert_eq!(err, IamError::InvalidCredentials);
        let key = AttemptKey::derive(tid, "ghost@example.com", &pepper()).unwrap();
        assert_eq!(tracker.count_failures(&key).await.unwrap(), 1);
    }

    #[tokio::test]
    async fn authenticate_user_lockout_after_threshold() {
        let tid = TenantId::new();
        let hasher = fast_hasher();
        let user = seeded_user(tid, "alice@example.com", &hasher);
        let repo = Arc::new(InMemoryRepo {
            user: Some(user.clone()),
        });
        let tracker = Arc::new(InMemoryTracker::default());
        let policy = LockoutPolicy {
            max_failures: 2,
            lock_duration: std::time::Duration::from_secs(60),
        };
        let uc = AuthenticateUserUseCase::new(repo, hasher, tracker.clone(), policy, pepper());
        // Two failures — both return InvalidCredentials.
        for _ in 0..2 {
            let err = uc
                .execute(AuthenticateInput {
                    credentials: Credentials::new(
                        tid,
                        user.email.clone(),
                        SecretString::from("wrong".to_string()),
                    ),
                })
                .await
                .unwrap_err();
            assert_eq!(err, IamError::InvalidCredentials);
        }
        // Third attempt — locked, even with the correct password.
        let err = uc
            .execute(AuthenticateInput {
                credentials: Credentials::new(
                    tid,
                    user.email.clone(),
                    SecretString::from("hunter2".to_string()),
                ),
            })
            .await
            .unwrap_err();
        assert_eq!(err, IamError::AccountLocked);
    }

    #[tokio::test]
    async fn authenticate_inactive_account_returns_generic_error() {
        let tid = TenantId::new();
        let hasher = fast_hasher();
        let mut user = seeded_user(tid, "alice@example.com", &hasher);
        user.is_active = false;
        let repo = Arc::new(InMemoryRepo {
            user: Some(user.clone()),
        });
        let tracker = Arc::new(InMemoryTracker::default());
        let uc = AuthenticateUserUseCase::new(repo, hasher, tracker, lockout(), pepper());
        let err = uc
            .execute(AuthenticateInput {
                credentials: Credentials::new(
                    tid,
                    user.email.clone(),
                    SecretString::from("hunter2".to_string()),
                ),
            })
            .await
            .unwrap_err();
        assert_eq!(err, IamError::InvalidCredentials);
    }
}
