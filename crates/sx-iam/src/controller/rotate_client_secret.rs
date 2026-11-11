//! `RotateOidcClientSecretUseCase` — admin rotates an OIDC client's
//! shared secret (MED-004).
//!
//! Behaviour:
//!
//! 1. Load the [`OidcClient`] by `(tenant_id, client_id)`.
//! 2. Generate a fresh 32-byte (base64-encoded) secret from `OsRng`.
//! 3. Move the current secret to `previous_secret` and stamp
//!    `previous_expires_at = now + grace_window`.
//! 4. Set the new secret as `secret` + `rotated_at = now`.
//! 5. Persist via the repository.
//! 6. Return the *plain* new secret to the caller exactly once — the
//!    admin endpoint serialises it back to the operator. After this
//!    call the bytes are unrecoverable (everything else in the system
//!    sees only the [`SecretString`] wrapped form).
//!
//! ## Audit
//!
//! The use case does not emit audit on its own — the boundary adapter
//! that wraps it (the API controller) records a `SecretRotated` entry
//! via `sx-audit` once the use case succeeds. Decoupling the audit
//! from the use case keeps `sx-iam` free of the `sx-audit` dependency
//! (which the workspace deliberately avoids at the IAM layer).

use std::sync::Arc;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use rand::rngs::OsRng;
use rand::RngCore;
use secrecy::SecretString;
use time::OffsetDateTime;

use crate::domain::TenantId;
use crate::model::oidc_client::{ClientId, ClientSecret};
use crate::port::OidcClientRepository;
use crate::service::Clock;
use crate::IamError;

/// Default grace window — 7 days. Matches MED-004 spec.
pub const DEFAULT_GRACE_WINDOW: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// Default rotation cadence — 90 days. Matches MED-004 spec.
pub const DEFAULT_ROTATION_CADENCE: Duration = Duration::from_secs(90 * 24 * 60 * 60);

/// Configuration for the rotation use case.
#[derive(Debug, Clone, Copy)]
pub struct RotationConfig {
    /// Window during which the previous secret remains accepted.
    pub grace_window: Duration,
}

impl RotationConfig {
    /// Build a config with default 7-day grace.
    #[must_use]
    pub const fn standard() -> Self {
        Self {
            grace_window: DEFAULT_GRACE_WINDOW,
        }
    }
}

impl Default for RotationConfig {
    fn default() -> Self {
        Self::standard()
    }
}

/// Output of [`RotateOidcClientSecretUseCase::execute`].
///
/// The plaintext is wrapped in a [`SecretString`] so the use case
/// itself never emits the bytes via `Debug`. The admin controller is
/// expected to deconstruct it explicitly to write the response body.
#[derive(Debug)]
pub struct RotateOidcClientSecretOutput {
    /// New client secret — surfaced to the operator exactly once.
    pub new_secret: SecretString,
    /// Wall-clock the previous secret stops being accepted.
    pub previous_expires_at: OffsetDateTime,
    /// Wall-clock the rotation was applied.
    pub rotated_at: OffsetDateTime,
}

/// Rotate the OIDC client secret behind an admin endpoint.
pub struct RotateOidcClientSecretUseCase<R, C>
where
    R: OidcClientRepository,
    C: Clock,
{
    repo: Arc<R>,
    clock: Arc<C>,
    cfg: RotationConfig,
}

impl<R, C> std::fmt::Debug for RotateOidcClientSecretUseCase<R, C>
where
    R: OidcClientRepository,
    C: Clock,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RotateOidcClientSecretUseCase")
            .field("cfg", &self.cfg)
            .finish_non_exhaustive()
    }
}

impl<R, C> RotateOidcClientSecretUseCase<R, C>
where
    R: OidcClientRepository,
    C: Clock,
{
    /// Build the use case.
    pub fn new(repo: Arc<R>, clock: Arc<C>, cfg: RotationConfig) -> Self {
        Self { repo, clock, cfg }
    }

    /// Execute the rotation.
    ///
    /// # Errors
    ///
    /// Returns [`IamError::Repository`] if the client cannot be found
    /// or the underlying write fails. The use case never returns the
    /// old secret.
    pub async fn execute(
        &self,
        tenant_id: TenantId,
        client_id: &ClientId,
    ) -> Result<RotateOidcClientSecretOutput, IamError> {
        let mut client = self
            .repo
            .find(tenant_id, client_id)
            .await?
            .ok_or_else(|| IamError::repository("oidc client not found"))?;

        let new_plain = generate_fresh_secret();
        let now = self.clock.now();
        let previous_expires_at = now + self.cfg.grace_window;

        // Demote current secret to `previous_secret`; install fresh
        // secret as the new live one.
        client.previous_secret = Some(client.secret.clone());
        client.previous_expires_at = Some(previous_expires_at);
        client.secret = ClientSecret::from_string(new_plain.clone());
        client.rotated_at = now;

        self.repo.update(&client).await?;

        tracing::info!(
            target: "iam.oidc.client.rotate",
            tenant_id = %tenant_id,
            client_id = %client_id,
            "oidc.client.secret.rotated"
        );

        Ok(RotateOidcClientSecretOutput {
            new_secret: SecretString::from(new_plain),
            previous_expires_at,
            rotated_at: now,
        })
    }
}

/// Generate a 32-byte / 256-bit URL-safe secret encoded as base64.
fn generate_fresh_secret() -> String {
    let mut buf = [0_u8; 32];
    OsRng.fill_bytes(&mut buf);
    B64.encode(buf)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;
    use crate::model::oidc_client::{ClientAuthMethod, OidcClient, OidcClientRowId};
    use crate::service::Clock;
    use async_trait::async_trait;
    use secrecy::ExposeSecret;
    use std::sync::Mutex;
    use time::Duration as TimeDuration;

    #[derive(Default)]
    struct InMemRepo {
        rows: Mutex<Vec<OidcClient>>,
    }

    #[async_trait]
    impl OidcClientRepository for InMemRepo {
        async fn find(
            &self,
            tenant_id: TenantId,
            client_id: &ClientId,
        ) -> Result<Option<OidcClient>, IamError> {
            let g = self.rows.lock().unwrap();
            Ok(g.iter()
                .find(|c| c.tenant_id == tenant_id && c.client_id == *client_id)
                .cloned())
        }

        async fn create(&self, client: &OidcClient) -> Result<(), IamError> {
            let mut g = self.rows.lock().unwrap();
            if g.iter()
                .any(|c| c.tenant_id == client.tenant_id && c.client_id == client.client_id)
            {
                return Err(IamError::conflict("oidc client"));
            }
            g.push(client.clone());
            Ok(())
        }

        async fn update(&self, client: &OidcClient) -> Result<(), IamError> {
            let mut g = self.rows.lock().unwrap();
            let idx = g
                .iter()
                .position(|c| c.tenant_id == client.tenant_id && c.client_id == client.client_id)
                .ok_or_else(|| IamError::repository("not found"))?;
            g[idx] = client.clone();
            Ok(())
        }
    }

    struct FixedClock(OffsetDateTime);
    impl Clock for FixedClock {
        fn now(&self) -> OffsetDateTime {
            self.0
        }
    }

    fn sample_client(now: OffsetDateTime) -> OidcClient {
        OidcClient {
            row_id: OidcClientRowId::new(),
            tenant_id: TenantId::new(),
            client_id: ClientId::new("acme-bot"),
            auth_method: ClientAuthMethod::ClientSecretJwt,
            secret: ClientSecret::from_string("original".into()),
            previous_secret: None,
            previous_expires_at: None,
            rotated_at: now,
            created_at: now,
        }
    }

    #[tokio::test]
    async fn rotate_moves_current_to_previous_and_mints_new() {
        let now = OffsetDateTime::now_utc();
        let repo = Arc::new(InMemRepo::default());
        let client = sample_client(now);
        let tenant = client.tenant_id;
        let cid = client.client_id.clone();
        repo.create(&client).await.unwrap();

        let clock = Arc::new(FixedClock(now));
        let uc =
            RotateOidcClientSecretUseCase::new(repo.clone(), clock, RotationConfig::standard());
        let out = uc.execute(tenant, &cid).await.unwrap();

        let stored = repo.find(tenant, &cid).await.unwrap().unwrap();
        assert_eq!(
            stored.previous_secret.as_ref().unwrap().expose(),
            "original"
        );
        assert_ne!(stored.secret.expose(), "original");
        assert_eq!(stored.secret.expose(), out.new_secret.expose_secret());
        let grace = stored.previous_expires_at.unwrap();
        assert!(grace > now + TimeDuration::days(6));
        assert!(grace <= now + TimeDuration::days(7) + TimeDuration::seconds(1));
    }

    #[tokio::test]
    async fn rotate_unknown_client_errors() {
        let now = OffsetDateTime::now_utc();
        let repo = Arc::new(InMemRepo::default());
        let clock = Arc::new(FixedClock(now));
        let uc = RotateOidcClientSecretUseCase::new(repo, clock, RotationConfig::standard());
        let err = uc
            .execute(TenantId::new(), &ClientId::new("ghost"))
            .await
            .expect_err("unknown client");
        assert!(matches!(err, IamError::Repository(_)));
    }
}
