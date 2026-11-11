//! OIDC adapter — wires `sx_iam::ExchangeOidcUseCase` behind the API's
//! [`OidcExchangePort`].
//!
//! When `oidc.enabled = false` (the default), the adapter installed here
//! is the [`DisabledOidcAdapter`] which short-circuits to
//! `Phase3PortError::Invalid("OIDC is not enabled on this deployment")`
//! so the dashboard's exchange call returns a deterministic 422 rather
//! than a stack trace.
//!
//! When `oidc.enabled = true`, the [`EnabledOidcAdapter`] builds a
//! [`JwksOidcVerifier`] against the configured JWKS URL and composes it
//! with the IAM bundle's shared user repository + token issuer use case
//! so an exchange lands a fresh user (when JIT is on) and issues SX
//! tokens identical to those minted by `/v1/auth/login`.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use secrecy::ExposeSecret;
use sx_api::port::{OidcExchangePort, Phase3PortError};
use sx_api::view::auth_view::{OidcExchangeRequest, TokenView};
use sx_config::schema::oidc::OidcConfig;
use sx_iam::controller::{ExchangeOidcConfig, ExchangeOidcOutput, ExchangeOidcUseCase};
use sx_iam::domain::TenantId;
use sx_iam::model::Token;
use sx_iam::service::token_issuer::JwtIssuer;
use sx_iam::service::{JwksOidcVerifier, OidcVerifierConfig, SystemClock};
use sx_iam::IamError;

use crate::adapters::iam::MonolithUserRepo;

/// Concrete use case type the enabled adapter holds.
type SharedExchange =
    ExchangeOidcUseCase<JwksOidcVerifier, MonolithUserRepo, JwtIssuer<SystemClock>, SystemClock>;

/// Build the OIDC exchange port from the loader config + IAM bundle's
/// shared dependencies.
///
/// Returns the appropriate adapter for `cfg.enabled`. The disabled adapter
/// is always available and returns a deterministic 422-mapped error.
pub(crate) fn build(
    cfg: &OidcConfig,
    users: Arc<MonolithUserRepo>,
    issue: Arc<sx_iam::controller::IssueTokenUseCase<JwtIssuer<SystemClock>, SystemClock>>,
    http: reqwest::Client,
) -> Arc<dyn OidcExchangePort> {
    if !cfg.enabled {
        tracing::debug!(target: "adapters.oidc", "oidc disabled; installing stub adapter");
        return Arc::new(DisabledOidcAdapter);
    }

    let verifier_cfg = OidcVerifierConfig {
        issuer: cfg.issuer.clone(),
        audience: cfg.audience.clone(),
        jwks_url: cfg.jwks_url.clone(),
        cache_ttl: Duration::from_secs(cfg.jwks_cache_secs),
    };
    let verifier = Arc::new(JwksOidcVerifier::new(verifier_cfg, http));

    let exchange_cfg = ExchangeOidcConfig {
        jit_provision: cfg.jit_provision,
        default_roles: cfg.default_roles.clone(),
        default_tenant_id: cfg.default_tenant_id.map(TenantId::from_uuid),
        tenant_id_claim: cfg.tenant_id_claim.clone(),
    };

    let uc: SharedExchange = ExchangeOidcUseCase::new(verifier, users, issue, exchange_cfg);

    tracing::info!(
        target: "adapters.oidc",
        issuer = %cfg.issuer,
        audience = %cfg.audience,
        jit = cfg.jit_provision,
        "oidc enabled; installed JWKS verifier"
    );

    Arc::new(EnabledOidcAdapter { uc: Arc::new(uc) })
}

/// Stub adapter installed when `oidc.enabled = false`. Every exchange
/// returns a deterministic [`Phase3PortError::Invalid`] so the dashboard
/// receives a 422 instead of a 500.
pub(crate) struct DisabledOidcAdapter;

#[async_trait]
impl OidcExchangePort for DisabledOidcAdapter {
    async fn exchange(&self, _req: OidcExchangeRequest) -> Result<TokenView, Phase3PortError> {
        Err(Phase3PortError::Invalid(
            "OIDC is not enabled on this deployment".into(),
        ))
    }
}

/// Production adapter installed when `oidc.enabled = true`.
struct EnabledOidcAdapter {
    uc: Arc<SharedExchange>,
}

#[async_trait]
impl OidcExchangePort for EnabledOidcAdapter {
    async fn exchange(&self, req: OidcExchangeRequest) -> Result<TokenView, Phase3PortError> {
        match self.uc.execute(&req.id_token).await {
            Ok(out) => Ok(token_to_view(&out)),
            Err(IamError::InvalidCredentials) => {
                Err(Phase3PortError::Forbidden("oidc verify failed".into()))
            }
            Err(IamError::Repository(m)) => Err(Phase3PortError::Dependency(m)),
            Err(IamError::Config(m)) => Err(Phase3PortError::Invalid(m)),
            Err(other) => Err(Phase3PortError::Internal(other.to_string())),
        }
    }
}

fn token_to_view(out: &ExchangeOidcOutput) -> TokenView {
    let access = out.token.access.expose_secret().to_owned();
    let refresh = out.token.refresh.expose_secret().to_owned();
    let expires_in = i64::try_from(out.token.expires_in).unwrap_or(i64::MAX);
    let _ = token_kind_sanity(&out.token);
    TokenView::bearer(access, refresh, expires_in)
}

/// Sanity helper kept private — silences an unused-import lint for `Token`
/// while documenting that we only ever cross the secret boundary once.
const fn token_kind_sanity(_t: &Token) -> bool {
    true
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use sx_config::schema::oidc::OidcConfig;
    use sx_iam::config::{JwtAlgorithm, JwtConfig};
    use sx_iam::controller::IssueTokenUseCase;
    use sx_iam::service::token_issuer::JwtIssuer;
    use sx_iam::service::SystemClock;

    fn jwt_cfg() -> JwtConfig {
        let key = "a".repeat(32);
        JwtConfig {
            issuer: "sx".into(),
            audience: "sx-clients".into(),
            signing_key: secrecy::SecretString::from(key.clone()),
            verifying_key: secrecy::SecretString::from(key),
            key_id: "k1".into(),
            access_ttl: Duration::from_secs(900),
            refresh_ttl: Duration::from_secs(3600),
            algorithm: JwtAlgorithm::Hs256,
            leeway_seconds: 5,
        }
    }

    fn dummy_issuer() -> Arc<IssueTokenUseCase<JwtIssuer<SystemClock>, SystemClock>> {
        let clock = Arc::new(SystemClock);
        let jwt = Arc::new(JwtIssuer::new(jwt_cfg(), Arc::clone(&clock)).unwrap());
        Arc::new(IssueTokenUseCase::new(jwt, clock, Duration::from_secs(900)))
    }

    fn disabled_cfg() -> OidcConfig {
        OidcConfig::default()
    }

    #[tokio::test]
    async fn oidc_disabled_returns_disabled_error() {
        let users = Arc::new(MonolithUserRepo::in_memory());
        let port = build(
            &disabled_cfg(),
            Arc::clone(&users),
            dummy_issuer(),
            reqwest::Client::new(),
        );
        let err = port
            .exchange(OidcExchangeRequest {
                id_token: "anything".into(),
            })
            .await
            .expect_err("disabled config must reject");
        match err {
            Phase3PortError::Invalid(msg) => assert!(msg.contains("not enabled"), "got {msg}"),
            other => panic!("unexpected variant: {other:?}"),
        }
    }
}
