//! FIDO2 / `WebAuthn` MFA use cases (P1-002).
//!
//! Four orchestration entry points the HTTP layer (sx-api) drives:
//!
//! * `register_start` — issue a [`webauthn_rs::prelude::CreationChallengeResponse`].
//! * `register_finish` — verify the authenticator response and persist a
//!   [`crate::model::StoredCredential`].
//! * `login_start` — issue a [`webauthn_rs::prelude::RequestChallengeResponse`]
//!   keyed to the user's active credentials.
//! * `login_finish` — verify the assertion, bump the signature counter,
//!   and emit `cred_id` so the caller can bind it onto the access token.
//!
//! Each use case takes its dependencies by reference / `Arc` and exposes
//! a single `execute(...)` method. They never own HTTP state — the
//! challenge state (`PasskeyRegistration` / `PasskeyAuthentication`) is
//! returned alongside the wire response so the HTTP layer can stash it
//! in its own short-lived cache (Redis with a sub-five-minute TTL is the
//! canonical pattern).

pub mod login_finish;
pub mod login_start;
pub mod register_finish;
pub mod register_start;

pub use login_finish::{LoginFinishInput, LoginFinishOutput, LoginFinishUseCase};
pub use login_start::{LoginStartInput, LoginStartOutput, LoginStartUseCase};
pub use register_finish::{RegisterFinishInput, RegisterFinishOutput, RegisterFinishUseCase};
pub use register_start::{RegisterStartInput, RegisterStartOutput, RegisterStartUseCase};

use crate::model::webauthn::{AttestationPolicy, TenantRp};
use crate::service::webauthn::{
    AttestationConveyancePreference, WebauthnConfig, WebauthnError, WebauthnService,
};
use crate::IamError;

/// Build a [`WebauthnService`] from a freshly-loaded tenant RP row.
///
/// Returns [`IamError::Config`] when the relying-party configuration is
/// malformed (mismatched `rp_id`/`rp_origin`) — surfaced verbatim so the
/// operator can fix it; callers map the error to a 5xx at the HTTP edge.
pub(crate) fn build_service_for(rp: &TenantRp) -> Result<WebauthnService, IamError> {
    let origin = url::Url::parse(&rp.rp_origin)
        .map_err(|e| IamError::config(format!("webauthn rp_origin parse: {e}")))?;
    let cfg = WebauthnConfig {
        rp_id: rp.rp_id.clone(),
        rp_name: rp.rp_name.clone(),
        rp_origin: origin,
        allow_attestation: map_attestation(rp.attestation),
    };
    WebauthnService::new(cfg).map_err(|e| match e {
        WebauthnError::Configuration => {
            IamError::config("webauthn rp_id must be a registrable suffix of rp_origin host")
        }
        other => IamError::config(format!("webauthn build: {other}")),
    })
}

/// Translate the IAM-domain attestation policy into the service-layer
/// preference. The service-layer enum is held by `webauthn-rs` today
/// (passkey API hard-codes `None` internally) but we still surface the
/// caller's intent so future API surfaces can use it.
pub(crate) const fn map_attestation(p: AttestationPolicy) -> AttestationConveyancePreference {
    match p {
        AttestationPolicy::None => AttestationConveyancePreference::None,
        AttestationPolicy::Indirect => AttestationConveyancePreference::Indirect,
        AttestationPolicy::Direct => AttestationConveyancePreference::Direct,
        AttestationPolicy::Enterprise => AttestationConveyancePreference::Enterprise,
    }
}
