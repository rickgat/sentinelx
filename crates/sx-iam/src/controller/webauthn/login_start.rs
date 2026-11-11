//! Begin a `WebAuthn` authentication ceremony.

use std::sync::Arc;

use webauthn_rs::prelude::{Passkey, PasskeyAuthentication, RequestChallengeResponse};

use crate::controller::webauthn::build_service_for;
use crate::domain::{TenantId, UserId};
use crate::port::{WebauthnCredentialRepository, WebauthnRpRepository};
use crate::IamError;

/// Inputs to [`LoginStartUseCase::execute`].
#[derive(Debug, Clone)]
pub struct LoginStartInput {
    /// Tenant the assertion is scoped to.
    pub tenant_id: TenantId,
    /// User whose passkeys we list in the allow-list.
    pub user_id: UserId,
}

/// Outputs from [`LoginStartUseCase::execute`].
pub struct LoginStartOutput {
    /// JSON-serialisable challenge the browser hands to `navigator.credentials.get`.
    pub challenge: RequestChallengeResponse,
    /// Opaque state the HTTP layer MUST cache (Redis, short TTL) and feed
    /// into `login_finish`.
    pub state: PasskeyAuthentication,
}

impl std::fmt::Debug for LoginStartOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoginStartOutput").finish_non_exhaustive()
    }
}

/// Use case: begin an authentication ceremony.
pub struct LoginStartUseCase {
    rp_repo: Arc<dyn WebauthnRpRepository>,
    cred_repo: Arc<dyn WebauthnCredentialRepository>,
}

impl std::fmt::Debug for LoginStartUseCase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoginStartUseCase").finish_non_exhaustive()
    }
}

impl LoginStartUseCase {
    /// Wire up the use case.
    #[must_use]
    pub fn new(
        rp_repo: Arc<dyn WebauthnRpRepository>,
        cred_repo: Arc<dyn WebauthnCredentialRepository>,
    ) -> Self {
        Self { rp_repo, cred_repo }
    }

    /// Run the use case.
    #[allow(clippy::cognitive_complexity)] // WebAuthn login_start: RP lookup + credential fan-in + challenge mint + state persist
    pub async fn execute(&self, input: LoginStartInput) -> Result<LoginStartOutput, IamError> {
        let rp = self
            .rp_repo
            .get(input.tenant_id)
            .await?
            .ok_or_else(|| IamError::config("no webauthn relying-party for tenant"))?;
        let svc = build_service_for(&rp)?;

        let stored = self
            .cred_repo
            .list_active(input.tenant_id, input.user_id)
            .await?;
        if stored.is_empty() {
            // Map to `InvalidCredentials` so the HTTP boundary returns
            // 401 without disclosing whether the user is enrolled.
            tracing::warn!(
                tenant_id = %input.tenant_id.as_uuid(),
                user_id = %input.user_id.as_uuid(),
                "webauthn.login_start: no active credentials",
            );
            return Err(IamError::InvalidCredentials);
        }

        // Decode each stored Passkey blob into the `webauthn-rs` type the
        // service-layer expects. A row whose `passkey` column is
        // unparseable is skipped with a warn-log; if every row is
        // unparseable the ceremony fails with InvalidCredentials.
        let mut passkeys: Vec<Passkey> = Vec::with_capacity(stored.len());
        for c in &stored {
            match serde_json::from_value::<Passkey>(c.passkey.clone()) {
                Ok(p) => passkeys.push(p),
                Err(e) => {
                    tracing::warn!(
                        error = ?e,
                        cred_id = %c.cred_id,
                        "webauthn.login_start: stored passkey unparseable",
                    );
                }
            }
        }
        if passkeys.is_empty() {
            return Err(IamError::InvalidCredentials);
        }

        let (challenge, state) = svc.start_authentication(&passkeys).map_err(|e| {
            tracing::warn!(error = ?e, "webauthn.login_start failed");
            IamError::internal("webauthn authentication challenge")
        })?;

        tracing::info!(
            tenant_id = %input.tenant_id.as_uuid(),
            user_id = %input.user_id.as_uuid(),
            cred_count = passkeys.len(),
            "webauthn.login_start",
        );

        Ok(LoginStartOutput { challenge, state })
    }
}
