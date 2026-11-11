//! Verify a `WebAuthn` authentication response.

use std::sync::Arc;

use base64::Engine as _;
use webauthn_rs::prelude::{PasskeyAuthentication, PublicKeyCredential};

use crate::controller::webauthn::build_service_for;
use crate::domain::TenantId;
use crate::port::{WebauthnCredentialRepository, WebauthnRpRepository};
use crate::service::webauthn::WebauthnError;
use crate::IamError;

/// Inputs to [`LoginFinishUseCase::execute`].
pub struct LoginFinishInput {
    /// Tenant scope.
    pub tenant_id: TenantId,
    /// Opaque state previously returned by `login_start`.
    pub state: PasskeyAuthentication,
    /// Authenticator response from `navigator.credentials.get`.
    pub response: PublicKeyCredential,
}

impl std::fmt::Debug for LoginFinishInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoginFinishInput")
            .field("tenant_id", &self.tenant_id.as_uuid())
            .finish_non_exhaustive()
    }
}

/// Output — the credential id (`cred_id`) the caller should embed in the
/// access-token claim and the new counter we just persisted.
#[derive(Debug, Clone)]
pub struct LoginFinishOutput {
    /// Base64url-encoded credential id of the passkey that satisfied the
    /// assertion. Caller writes this into the `cred_id` JWT claim.
    pub cred_id: String,
    /// New counter value persisted on the credential row.
    pub counter: u32,
}

/// Use case: complete an authentication ceremony.
pub struct LoginFinishUseCase {
    rp_repo: Arc<dyn WebauthnRpRepository>,
    cred_repo: Arc<dyn WebauthnCredentialRepository>,
}

impl std::fmt::Debug for LoginFinishUseCase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoginFinishUseCase").finish_non_exhaustive()
    }
}

impl LoginFinishUseCase {
    /// Wire up the use case.
    #[must_use]
    pub fn new(
        rp_repo: Arc<dyn WebauthnRpRepository>,
        cred_repo: Arc<dyn WebauthnCredentialRepository>,
    ) -> Self {
        Self { rp_repo, cred_repo }
    }

    /// Run the use case.
    #[allow(clippy::cognitive_complexity)] // WebAuthn login_finish: RP lookup + state verify + assertion verify + sign-count check + audit emit
    pub async fn execute(&self, input: LoginFinishInput) -> Result<LoginFinishOutput, IamError> {
        let rp = self
            .rp_repo
            .get(input.tenant_id)
            .await?
            .ok_or_else(|| IamError::config("no webauthn relying-party for tenant"))?;
        let svc = build_service_for(&rp)?;

        // Discover the credential id off the wire response so we can pull
        // the stored counter prior to verification. `PublicKeyCredential`
        // exposes `raw_id` for this purpose.
        let cred_id_bytes: Vec<u8> = (*input.response.raw_id).clone();
        let cred_id_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&cred_id_bytes);

        let stored = self
            .cred_repo
            .find_by_cred_id(input.tenant_id, &cred_id_b64)
            .await?;
        let Some(stored) = stored else {
            tracing::warn!(
                tenant_id = %input.tenant_id.as_uuid(),
                cred_id = %cred_id_b64,
                "webauthn.login_finish: credential not found",
            );
            return Err(IamError::InvalidCredentials);
        };
        if !stored.is_active() {
            tracing::warn!(
                tenant_id = %input.tenant_id.as_uuid(),
                cred_id = %cred_id_b64,
                "webauthn.login_finish: credential revoked",
            );
            return Err(IamError::InvalidCredentials);
        }

        let result = svc
            .finish_authentication(&input.state, &input.response, stored.counter)
            .map_err(|e| {
                // Counter regression: revoke the credential per W3C
                // §7.2 step 21 and surface InvalidCredentials.
                if let WebauthnError::CounterRegression { stored, presented } = &e {
                    tracing::warn!(
                        tenant_id = %input.tenant_id.as_uuid(),
                        cred_id = %cred_id_b64,
                        stored = *stored,
                        presented = *presented,
                        "webauthn.login_finish: counter regression — revoking",
                    );
                } else {
                    tracing::warn!(
                        error = ?e,
                        tenant_id = %input.tenant_id.as_uuid(),
                        cred_id = %cred_id_b64,
                        "webauthn.login_finish: verification failed",
                    );
                }
                e
            });

        let result = match result {
            Ok(r) => r,
            Err(WebauthnError::CounterRegression { .. }) => {
                // Fire-and-forget revoke; ignore the storage error so we
                // still report InvalidCredentials to the caller.
                if let Err(e) = self.cred_repo.revoke(input.tenant_id, &cred_id_b64).await {
                    tracing::warn!(
                        error = ?e,
                        cred_id = %cred_id_b64,
                        "webauthn.login_finish: revoke on counter regression failed",
                    );
                }
                return Err(IamError::InvalidCredentials);
            }
            Err(_) => return Err(IamError::InvalidCredentials),
        };

        // Persist the new counter; failure to update is logged but does
        // not roll back the assertion — the spec only mandates strict
        // monotonicity, which we already enforced in
        // `service::webauthn::check_counter_monotonicity`.
        let new_counter = result.counter();
        if let Err(e) = self
            .cred_repo
            .update_counter(input.tenant_id, &cred_id_b64, new_counter)
            .await
        {
            tracing::warn!(
                error = ?e,
                cred_id = %cred_id_b64,
                new_counter,
                "webauthn.login_finish: counter persist failed",
            );
        }

        tracing::info!(
            tenant_id = %input.tenant_id.as_uuid(),
            cred_id = %cred_id_b64,
            counter = new_counter,
            "webauthn.login_finish",
        );

        Ok(LoginFinishOutput {
            cred_id: cred_id_b64,
            counter: new_counter,
        })
    }
}
