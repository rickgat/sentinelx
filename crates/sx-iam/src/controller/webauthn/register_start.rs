//! Begin a `WebAuthn` registration ceremony.

use std::sync::Arc;

use webauthn_rs::prelude::{CreationChallengeResponse, PasskeyRegistration};

use crate::controller::webauthn::build_service_for;
use crate::domain::{TenantId, UserId};
use crate::port::{WebauthnCredentialRepository, WebauthnRpRepository};
use crate::IamError;

/// Inputs to [`RegisterStartUseCase::execute`].
#[derive(Debug, Clone)]
pub struct RegisterStartInput {
    /// Tenant the registration is scoped to.
    pub tenant_id: TenantId,
    /// User registering the credential (typically `claims.sub`).
    pub user_id: UserId,
    /// User-facing name displayed by the authenticator (typically the
    /// email or login slug).
    pub user_name: String,
}

/// Outputs from [`RegisterStartUseCase::execute`].
pub struct RegisterStartOutput {
    /// JSON-serialisable challenge the browser hands to `navigator.credentials.create`.
    pub challenge: CreationChallengeResponse,
    /// Opaque state the HTTP layer MUST cache (Redis with short TTL) and
    /// feed back into `register_finish`.
    pub state: PasskeyRegistration,
}

impl std::fmt::Debug for RegisterStartOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never dump challenge bytes or PasskeyRegistration internals.
        f.debug_struct("RegisterStartOutput")
            .finish_non_exhaustive()
    }
}

/// Use case: begin a registration ceremony for `user_id`.
pub struct RegisterStartUseCase {
    rp_repo: Arc<dyn WebauthnRpRepository>,
    cred_repo: Arc<dyn WebauthnCredentialRepository>,
}

impl std::fmt::Debug for RegisterStartUseCase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegisterStartUseCase")
            .finish_non_exhaustive()
    }
}

impl RegisterStartUseCase {
    /// Wire up the use case.
    #[must_use]
    pub fn new(
        rp_repo: Arc<dyn WebauthnRpRepository>,
        cred_repo: Arc<dyn WebauthnCredentialRepository>,
    ) -> Self {
        Self { rp_repo, cred_repo }
    }

    /// Run the use case.
    pub async fn execute(
        &self,
        input: RegisterStartInput,
    ) -> Result<RegisterStartOutput, IamError> {
        let rp = self
            .rp_repo
            .get(input.tenant_id)
            .await?
            .ok_or_else(|| IamError::config("no webauthn relying-party for tenant"))?;
        let svc = build_service_for(&rp)?;

        // Build the exclude-credentials list so the authenticator refuses
        // to re-enrol an existing credential.
        let existing = self
            .cred_repo
            .list_active(input.tenant_id, input.user_id)
            .await?;
        let exclude: Vec<Vec<u8>> = existing.iter().map(|c| c.cred_id_bytes.clone()).collect();

        let (challenge, state) = svc
            .start_registration(*input.user_id.as_uuid(), &input.user_name, &exclude)
            .map_err(|e| {
                tracing::warn!(
                    error = ?e,
                    tenant_id = %input.tenant_id.as_uuid(),
                    user_id = %input.user_id.as_uuid(),
                    "webauthn.register_start failed",
                );
                IamError::internal("webauthn registration challenge")
            })?;

        tracing::info!(
            tenant_id = %input.tenant_id.as_uuid(),
            user_id = %input.user_id.as_uuid(),
            "webauthn.register_start",
        );

        Ok(RegisterStartOutput { challenge, state })
    }
}
