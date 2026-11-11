//! Composition-root wiring for the MED-004 OIDC confidential-client
//! endpoints — `client_secret_jwt` token issuance, secret rotation, and
//! JWKS publication.
//!
//! Three adapters are exported:
//!
//! * [`InMemoryOidcClientTokenAdapter`] — backs `POST /v1/oauth/token`
//!   by delegating to [`sx_iam::controller::ClientCredentialsTokenUseCase`].
//! * [`InMemoryOidcClientRotateAdapter`] — backs the admin
//!   `POST /v1/admin/oidc/clients/{client_id}/rotate-secret` endpoint
//!   via [`sx_iam::controller::RotateOidcClientSecretUseCase`].
//! * [`SigningRegistryJwksAdapter`] — backs `GET /.well-known/jwks.json`
//!   reading from the workspace [`sx_iam::service::SigningKeyRegistry`].
//!
//! The bundle [`build`] wires a shared in-memory
//! [`sx_iam::controller::OidcClientRepository`] across the two
//! confidential-client adapters so the rotation endpoint and the token
//! endpoint observe the same row set. A Postgres-backed swap lands in a
//! follow-up sprint — the [`sx_iam::port::OidcClientRepository`] trait
//! is the swap point.

use std::sync::Arc;

use async_trait::async_trait;
use secrecy::ExposeSecret;
use std::sync::Mutex;
use sx_api::port::{
    JwksPublishPort, OidcClientPortError, OidcClientRotatePort, OidcClientTokenPort,
};
use sx_api::view::oidc_client_view::{
    OAuthTokenRequest, OAuthTokenResponse, RotateClientSecretResponse,
};
use sx_iam::config::JwtConfig;
use sx_iam::controller::{
    ClientCredentialsTokenUseCase, RotateOidcClientSecretUseCase, RotationConfig,
};
use sx_iam::domain::TenantId;
use sx_iam::model::{ClientAuthMethod, ClientId, ClientSecret, OidcClient, OidcClientRowId};
use sx_iam::port::OidcClientRepository;
use sx_iam::service::client_assertion::{
    ClientAssertionConfig, InMemoryJtiCache, CLIENT_ASSERTION_TYPE_JWT_BEARER,
};
use sx_iam::service::{SigningKeyRegistry, SystemClock};
use sx_iam::IamError;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// Shared in-memory implementation of [`OidcClientRepository`].
///
/// Mirrors the pattern used by the runtime overrides + AAGUID stores —
/// a `Mutex<Vec<_>>` is fine for the small row count expected here
/// (low double-digits per tenant at most). Postgres-backed swap is the
/// natural follow-up.
#[derive(Default)]
pub struct InMemoryOidcClientRepo {
    rows: Mutex<Vec<OidcClient>>,
}

impl std::fmt::Debug for InMemoryOidcClientRepo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InMemoryOidcClientRepo")
            .finish_non_exhaustive()
    }
}

impl InMemoryOidcClientRepo {
    /// Fresh empty repo.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Test/bootstrap helper — seed a single confidential client.
    pub fn seed(&self, client: OidcClient) {
        self.rows
            .lock()
            .expect("oidc client repo mutex poisoned")
            .push(client);
    }

    /// Resolve which tenant owns the given `client_id`. Returns `None`
    /// when no row matches. Used by the OAuth2 token endpoint to look
    /// up tenant scope after parsing the assertion's `sub` claim.
    ///
    /// Production Postgres adapter would index `oidc_clients(client_id)`
    /// to satisfy this in O(log n).
    #[must_use]
    pub fn tenant_for_client(&self, client_id: &ClientId) -> Option<TenantId> {
        let g = self.rows.lock().ok()?;
        g.iter()
            .find(|c| c.client_id == *client_id)
            .map(|c| c.tenant_id)
    }
}

#[async_trait]
impl OidcClientRepository for InMemoryOidcClientRepo {
    async fn find(
        &self,
        tenant_id: TenantId,
        client_id: &ClientId,
    ) -> Result<Option<OidcClient>, IamError> {
        let g = self
            .rows
            .lock()
            .map_err(|_| IamError::internal("oidc client repo mutex poisoned"))?;
        Ok(g.iter()
            .find(|c| c.tenant_id == tenant_id && c.client_id == *client_id)
            .cloned())
    }

    async fn create(&self, client: &OidcClient) -> Result<(), IamError> {
        let mut g = self
            .rows
            .lock()
            .map_err(|_| IamError::internal("oidc client repo mutex poisoned"))?;
        if g.iter()
            .any(|c| c.tenant_id == client.tenant_id && c.client_id == client.client_id)
        {
            return Err(IamError::conflict("oidc client"));
        }
        g.push(client.clone());
        Ok(())
    }

    async fn update(&self, client: &OidcClient) -> Result<(), IamError> {
        let mut g = self
            .rows
            .lock()
            .map_err(|_| IamError::internal("oidc client repo mutex poisoned"))?;
        let slot = g
            .iter_mut()
            .find(|c| c.tenant_id == client.tenant_id && c.client_id == client.client_id)
            .ok_or_else(|| IamError::repository("oidc client not found"))?;
        *slot = client.clone();
        Ok(())
    }
}

/// Bundle returned by [`build`].
#[derive(Clone)]
pub(crate) struct OidcClientBundle {
    pub token: Arc<dyn OidcClientTokenPort>,
    pub rotate: Arc<dyn OidcClientRotatePort>,
    pub jwks: Arc<dyn JwksPublishPort>,
    /// Handle to the underlying repo so the bootstrap path can seed a
    /// dev-mode confidential client without re-wrapping.
    pub repo: Arc<InMemoryOidcClientRepo>,
}

impl std::fmt::Debug for OidcClientBundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OidcClientBundle").finish_non_exhaustive()
    }
}

/// Configuration knobs accepted by [`build`].
#[derive(Debug, Clone)]
pub(crate) struct BuildConfig {
    /// `aud` claim expected on `client_assertion` JWTs. Typically the
    /// absolute URL of the token endpoint.
    pub expected_audience: String,
    /// JWT config used to mint the access tokens we issue back.
    pub jwt_cfg: JwtConfig,
    /// Signing-key registry that backs the JWKS endpoint.
    pub registry: SigningKeyRegistry,
}

/// Build the MED-004 bundle.
pub(crate) fn build(cfg: BuildConfig) -> OidcClientBundle {
    let repo = Arc::new(InMemoryOidcClientRepo::new());
    let clock = Arc::new(SystemClock);
    let cache = Arc::new(InMemoryJtiCache::new());

    let assertion_cfg = ClientAssertionConfig::new(cfg.expected_audience);
    let token_uc = Arc::new(ClientCredentialsTokenUseCase::new(
        Arc::clone(&repo),
        Arc::clone(&clock),
        Arc::clone(&cache),
        assertion_cfg,
        cfg.jwt_cfg,
    ));
    let rotate_uc = Arc::new(RotateOidcClientSecretUseCase::new(
        Arc::clone(&repo),
        Arc::clone(&clock),
        RotationConfig::standard(),
    ));

    let token: Arc<dyn OidcClientTokenPort> = Arc::new(InMemoryOidcClientTokenAdapter {
        uc: token_uc,
        repo: Arc::clone(&repo),
    });
    let rotate: Arc<dyn OidcClientRotatePort> =
        Arc::new(InMemoryOidcClientRotateAdapter { uc: rotate_uc });
    let jwks: Arc<dyn JwksPublishPort> = Arc::new(SigningRegistryJwksAdapter {
        registry: cfg.registry,
    });

    OidcClientBundle {
        token,
        rotate,
        jwks,
        repo,
    }
}

/// Seed a dev-mode confidential client in the bundle's repo so the
/// `POST /v1/oauth/token` endpoint is reachable out of the box.
///
/// The plaintext secret is returned so the bootstrap caller can log it
/// for the operator (we *do not* log it here — that decision belongs to
/// the bootstrap module which already gates on
/// `bootstrap.enabled`).
pub(crate) fn seed_dev_client(
    bundle: &OidcClientBundle,
    tenant_id: TenantId,
    client_id_str: &str,
) -> (ClientId, String) {
    let secret = "dev-client-secret-do-not-use-in-prod".to_owned();
    let now = OffsetDateTime::now_utc();
    let client = OidcClient {
        row_id: OidcClientRowId::new(),
        tenant_id,
        client_id: ClientId::new(client_id_str),
        auth_method: ClientAuthMethod::ClientSecretJwt,
        secret: ClientSecret::from_string(secret.clone()),
        previous_secret: None,
        previous_expires_at: None,
        rotated_at: now,
        created_at: now,
    };
    let id = client.client_id.clone();
    bundle.repo.seed(client);
    (id, secret)
}

/// Wraps [`ClientCredentialsTokenUseCase`] behind the
/// [`OidcClientTokenPort`] HTTP shape.
struct InMemoryOidcClientTokenAdapter {
    uc: Arc<ClientCredentialsTokenUseCase<InMemoryOidcClientRepo, SystemClock, InMemoryJtiCache>>,
    /// Held to support the in-memory `client_id → tenant_id` lookup
    /// required by the OAuth2 token endpoint when no tenant prefix is
    /// supplied in the URL. Postgres-backed adapter would index on
    /// `(client_id)` for the same purpose.
    repo: Arc<InMemoryOidcClientRepo>,
}

impl std::fmt::Debug for InMemoryOidcClientTokenAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InMemoryOidcClientTokenAdapter")
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl OidcClientTokenPort for InMemoryOidcClientTokenAdapter {
    async fn issue(
        &self,
        _tenant_hint: Option<&str>,
        req: OAuthTokenRequest,
    ) -> Result<OAuthTokenResponse, OidcClientPortError> {
        // Shape validation first — the use case assumes these have
        // already been checked.
        if req.grant_type != "client_credentials" {
            return Err(OidcClientPortError::UnsupportedGrant(req.grant_type));
        }
        if req.client_assertion_type != CLIENT_ASSERTION_TYPE_JWT_BEARER {
            return Err(OidcClientPortError::InvalidRequest(
                "client_assertion_type must be jwt-bearer URN".into(),
            ));
        }
        if req.client_assertion.is_empty() {
            return Err(OidcClientPortError::InvalidRequest(
                "client_assertion missing".into(),
            ));
        }

        // Sniff the assertion to recover (tenant_id, client_id). Per
        // RFC 7523 the `iss` equals the `sub` equals the client_id.
        // The tenant_id lives in our extension claim or in a URL
        // prefix; in v1 we look it up by scanning the repo since the
        // adapter holds a single in-memory map.
        let client_id =
            sniff_client_id(&req.client_assertion).map_err(OidcClientPortError::InvalidRequest)?;

        // In the in-memory repo the tenant set is small; the find scan
        // is O(rows). A Postgres adapter would index on (client_id) +
        // resolve tenant from the row.
        let tenant_id = self
            .repo
            .tenant_for_client(&client_id)
            .ok_or(OidcClientPortError::InvalidClient)?;

        let out = self
            .uc
            .execute(tenant_id, &client_id, &req.client_assertion)
            .await
            .map_err(map_iam_to_token_port)?;

        Ok(OAuthTokenResponse {
            access_token: out.access_token.expose_secret().to_owned(),
            token_type: out.token_type.to_owned(),
            expires_in: out.expires_in,
            scope: req.scope,
            warning: if out.used_previous_secret {
                Some("rotate-now".to_owned())
            } else {
                None
            },
        })
    }
}

fn map_iam_to_token_port(err: IamError) -> OidcClientPortError {
    match err {
        IamError::InvalidCredentials
        | IamError::InvalidToken
        | IamError::TokenExpired
        | IamError::Forbidden { .. }
        | IamError::AccountLocked => OidcClientPortError::InvalidClient,
        IamError::Repository(m) => OidcClientPortError::Dependency(m),
        IamError::Conflict(m) | IamError::Internal(m) | IamError::Config(m) => {
            OidcClientPortError::Internal(m)
        }
    }
}

/// Parse out the `sub` claim of the assertion without verifying the
/// signature. Used to recover the client_id before lookup.
fn sniff_client_id(assertion: &str) -> Result<ClientId, String> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
    use base64::Engine as _;
    let mut parts = assertion.split('.');
    let _hdr = parts
        .next()
        .ok_or_else(|| "missing JWT header".to_owned())?;
    let claims_b64 = parts
        .next()
        .ok_or_else(|| "missing JWT claims segment".to_owned())?;
    let _sig = parts
        .next()
        .ok_or_else(|| "missing JWT signature segment".to_owned())?;
    if parts.next().is_some() {
        return Err("malformed JWT".to_owned());
    }
    let bytes = B64URL
        .decode(claims_b64)
        .map_err(|_| "JWT claims not base64url".to_owned())?;
    let v: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|_| "JWT claims not JSON".to_owned())?;
    let sub = v
        .get("sub")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "missing sub".to_owned())?;
    Ok(ClientId::new(sub))
}

/// Wraps [`RotateOidcClientSecretUseCase`] behind the
/// [`OidcClientRotatePort`].
struct InMemoryOidcClientRotateAdapter {
    uc: Arc<RotateOidcClientSecretUseCase<InMemoryOidcClientRepo, SystemClock>>,
}

impl std::fmt::Debug for InMemoryOidcClientRotateAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InMemoryOidcClientRotateAdapter")
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl OidcClientRotatePort for InMemoryOidcClientRotateAdapter {
    async fn rotate(
        &self,
        tenant_id: &str,
        client_id: &str,
        actor: &str,
    ) -> Result<RotateClientSecretResponse, OidcClientPortError> {
        let tid = parse_tenant_id(tenant_id)?;
        let cid = ClientId::new(client_id);
        let out = self
            .uc
            .execute(tid, &cid)
            .await
            .map_err(map_iam_to_rotate_port)?;
        tracing::info!(
            target: "adapters.oidc_client.rotate",
            tenant_id = %tenant_id,
            client_id = %client_id,
            actor = %actor,
            "oidc client secret rotated"
        );
        let previous_expires_at = out
            .previous_expires_at
            .format(&Rfc3339)
            .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned());
        let rotated_at = out
            .rotated_at
            .format(&Rfc3339)
            .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned());
        Ok(RotateClientSecretResponse {
            client_id: client_id.to_owned(),
            new_secret: out.new_secret.expose_secret().to_owned(),
            previous_expires_at,
            rotated_at,
        })
    }
}

fn map_iam_to_rotate_port(err: IamError) -> OidcClientPortError {
    match err {
        IamError::Repository(m) if m.contains("not found") => OidcClientPortError::NotFound,
        IamError::Repository(m) => OidcClientPortError::Dependency(m),
        IamError::Forbidden { .. }
        | IamError::InvalidCredentials
        | IamError::InvalidToken
        | IamError::TokenExpired
        | IamError::AccountLocked => OidcClientPortError::InvalidClient,
        IamError::Conflict(m) | IamError::Internal(m) | IamError::Config(m) => {
            OidcClientPortError::Internal(m)
        }
    }
}

fn parse_tenant_id(s: &str) -> Result<TenantId, OidcClientPortError> {
    uuid::Uuid::parse_str(s)
        .map(TenantId::from_uuid)
        .map_err(|e| OidcClientPortError::InvalidRequest(format!("tenant_id: {e}")))
}

/// Reads a snapshot from the [`SigningKeyRegistry`].
struct SigningRegistryJwksAdapter {
    registry: SigningKeyRegistry,
}

impl std::fmt::Debug for SigningRegistryJwksAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningRegistryJwksAdapter")
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl JwksPublishPort for SigningRegistryJwksAdapter {
    async fn jwks(&self) -> Result<serde_json::Value, OidcClientPortError> {
        let doc = self.registry.publish();
        serde_json::to_value(&doc)
            .map_err(|e| OidcClientPortError::Internal(format!("jwks serialise: {e}")))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use secrecy::SecretString;
    use std::time::Duration;
    use sx_iam::config::JwtAlgorithm;
    use sx_iam::service::client_assertion::mint_assertion_for_test;

    fn jwt_cfg() -> JwtConfig {
        let key = "k".repeat(32);
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

    fn build_bundle() -> OidcClientBundle {
        build(BuildConfig {
            expected_audience: "https://sx.example/v1/oauth/token".into(),
            jwt_cfg: jwt_cfg(),
            registry: SigningKeyRegistry::empty(),
        })
    }

    #[tokio::test]
    async fn jwks_endpoint_serves_empty_keys_array_when_only_hs() {
        let bundle = build_bundle();
        let v = bundle.jwks.jwks().await.unwrap();
        assert!(v["keys"].is_array());
        assert_eq!(v["keys"].as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn rotate_returns_a_fresh_secret_and_grace_metadata() {
        let bundle = build_bundle();
        let tenant_id = TenantId::new();
        let _ = seed_dev_client(&bundle, tenant_id, "acme-bot");
        let resp = bundle
            .rotate
            .rotate(
                &tenant_id.to_string(),
                "acme-bot",
                "00000000-0000-0000-0000-000000000001",
            )
            .await
            .unwrap();
        assert_eq!(resp.client_id, "acme-bot");
        assert!(!resp.new_secret.is_empty());
        assert!(resp.previous_expires_at > resp.rotated_at);
    }

    #[tokio::test]
    async fn rotate_unknown_client_returns_not_found() {
        let bundle = build_bundle();
        let err = bundle
            .rotate
            .rotate(
                &TenantId::new().to_string(),
                "ghost",
                "00000000-0000-0000-0000-000000000001",
            )
            .await
            .unwrap_err();
        assert!(matches!(err, OidcClientPortError::NotFound));
    }

    #[tokio::test]
    async fn token_endpoint_happy_path_issues_jwt() {
        let bundle = build_bundle();
        let tenant_id = TenantId::new();
        let (cid, secret) = seed_dev_client(&bundle, tenant_id, "acme-bot");
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let assertion = mint_assertion_for_test(
            cid.as_str(),
            &secret,
            "https://sx.example/v1/oauth/token",
            "jti-token-happy",
            now,
            now + 60,
        );
        let req = OAuthTokenRequest {
            grant_type: "client_credentials".into(),
            client_assertion_type: CLIENT_ASSERTION_TYPE_JWT_BEARER.into(),
            client_assertion: assertion,
            scope: Some("read".into()),
        };
        let resp = bundle.token.issue(None, req).await.unwrap();
        assert_eq!(resp.token_type, "Bearer");
        assert_eq!(resp.expires_in, 900);
        assert!(resp.warning.is_none());
        assert_eq!(resp.access_token.split('.').count(), 3);
    }

    #[tokio::test]
    async fn token_endpoint_wrong_secret_rejects_as_invalid_client() {
        let bundle = build_bundle();
        let tenant_id = TenantId::new();
        let (cid, _secret) = seed_dev_client(&bundle, tenant_id, "acme-bot");
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let assertion = mint_assertion_for_test(
            cid.as_str(),
            "wrong-secret",
            "https://sx.example/v1/oauth/token",
            "jti-token-wrong",
            now,
            now + 60,
        );
        let req = OAuthTokenRequest {
            grant_type: "client_credentials".into(),
            client_assertion_type: CLIENT_ASSERTION_TYPE_JWT_BEARER.into(),
            client_assertion: assertion,
            scope: None,
        };
        let err = bundle.token.issue(None, req).await.unwrap_err();
        assert!(matches!(err, OidcClientPortError::InvalidClient));
    }

    #[tokio::test]
    async fn token_endpoint_wrong_grant_rejects() {
        let bundle = build_bundle();
        let req = OAuthTokenRequest {
            grant_type: "password".into(),
            client_assertion_type: CLIENT_ASSERTION_TYPE_JWT_BEARER.into(),
            client_assertion: "a.b.c".into(),
            scope: None,
        };
        let err = bundle.token.issue(None, req).await.unwrap_err();
        assert!(matches!(err, OidcClientPortError::UnsupportedGrant(_)));
    }

    #[tokio::test]
    async fn token_endpoint_wrong_assertion_type_rejects() {
        let bundle = build_bundle();
        let req = OAuthTokenRequest {
            grant_type: "client_credentials".into(),
            client_assertion_type: "urn:other".into(),
            client_assertion: "a.b.c".into(),
            scope: None,
        };
        let err = bundle.token.issue(None, req).await.unwrap_err();
        assert!(matches!(err, OidcClientPortError::InvalidRequest(_)));
    }
}
