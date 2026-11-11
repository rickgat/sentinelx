//! `ClientCredentialsTokenUseCase` — the `OAuth2` `client_credentials`
//! grant for MED-004 confidential clients authenticating via
//! `client_secret_jwt` (RFC 7523).
//!
//! Flow:
//!
//! 1. Caller posts `grant_type=client_credentials` +
//!    `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer`
//!    + `client_assertion=<JWT>` to the token endpoint.
//! 2. The use case loads the [`OidcClient`] by `(tenant_id, client_id)`.
//!    The tenant id is supplied by the HTTP boundary (URL prefix or
//!    request context); the client id is the JWT's `sub`.
//! 3. [`verify_client_assertion`] validates the JWT signature
//!    (against live + previous-in-grace secrets), `aud`, `exp`, and
//!    `jti` replay.
//! 4. On success, mint an access-only JWT (no refresh, no session — per
//!    `OAuth2` §4.4 `client_credentials` does NOT issue refresh tokens).
//!    The token's `sub` is `"client:" + client_id` so downstream
//!    services can distinguish service-to-service tokens from user
//!    tokens.
//!
//! Audit + tracing live in the HTTP boundary adapter, not in this
//! crate — see the `oidc_client_auth` adapter in `sx-monolith`.

use std::sync::Arc;

use secrecy::{ExposeSecret, SecretString};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::config::{JwtAlgorithm, JwtConfig};
use crate::domain::TenantId;
use crate::model::oidc_client::{ClientAuthMethod, ClientId};
use crate::port::OidcClientRepository;
use crate::service::client_assertion::{
    verify_client_assertion, ClientAssertionConfig, JtiReplayCache, VerifiedAssertion,
};
use crate::service::token_issuer::encoding_key_for;
use crate::service::Clock;
use crate::IamError;

/// Output of [`ClientCredentialsTokenUseCase::execute`].
#[derive(Debug)]
pub struct ClientCredentialsTokenOutput {
    /// The minted access token (no refresh per `OAuth2` §4.4).
    pub access_token: SecretString,
    /// `token_type` literal — always `"Bearer"`.
    pub token_type: &'static str,
    /// Seconds until `exp`.
    pub expires_in: u64,
    /// `true` when the client authenticated with the previous (grace)
    /// secret — surfaced as `Warning: 199 rotate-secret`.
    pub used_previous_secret: bool,
}

/// `client_credentials` token endpoint use case.
pub struct ClientCredentialsTokenUseCase<R, C, J>
where
    R: OidcClientRepository,
    C: Clock,
    J: JtiReplayCache,
{
    clients: Arc<R>,
    clock: Arc<C>,
    cache: Arc<J>,
    assertion_cfg: ClientAssertionConfig,
    jwt_cfg: JwtConfig,
}

impl<R, C, J> std::fmt::Debug for ClientCredentialsTokenUseCase<R, C, J>
where
    R: OidcClientRepository,
    C: Clock,
    J: JtiReplayCache,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientCredentialsTokenUseCase")
            .field("expected_audience", &self.assertion_cfg.expected_audience)
            .field("issuer", &self.jwt_cfg.issuer)
            .field("audience", &self.jwt_cfg.audience)
            .finish_non_exhaustive()
    }
}

impl<R, C, J> ClientCredentialsTokenUseCase<R, C, J>
where
    R: OidcClientRepository,
    C: Clock,
    J: JtiReplayCache,
{
    /// Build the use case.
    pub fn new(
        clients: Arc<R>,
        clock: Arc<C>,
        cache: Arc<J>,
        assertion_cfg: ClientAssertionConfig,
        jwt_cfg: JwtConfig,
    ) -> Self {
        Self {
            clients,
            clock,
            cache,
            assertion_cfg,
            jwt_cfg,
        }
    }

    /// Validate the assertion + mint a fresh access token.
    ///
    /// # Errors
    ///
    /// All validation failures collapse to [`IamError::InvalidToken`] /
    /// [`IamError::TokenExpired`] / [`IamError::InvalidCredentials`]
    /// per the validator. Repository failures are surfaced as
    /// [`IamError::Repository`].
    pub async fn execute(
        &self,
        tenant_id: TenantId,
        client_id: &ClientId,
        assertion: &str,
    ) -> Result<ClientCredentialsTokenOutput, IamError> {
        let now: OffsetDateTime = self.clock.now();
        let client = self
            .clients
            .find(tenant_id, client_id)
            .await?
            .ok_or_else(|| {
                tracing::warn!(
                    target: "iam.client_token",
                    tenant_id = %tenant_id,
                    client_id = %client_id,
                    reason = "client_not_found",
                    "client_token.reject"
                );
                IamError::InvalidCredentials
            })?;

        if client.auth_method != ClientAuthMethod::ClientSecretJwt {
            tracing::warn!(
                target: "iam.client_token",
                tenant_id = %tenant_id,
                client_id = %client_id,
                method = client.auth_method.as_str(),
                reason = "method_not_jwt",
                "client_token.reject"
            );
            return Err(IamError::InvalidCredentials);
        }

        let VerifiedAssertion {
            claims,
            verified_with_previous_secret,
        } = verify_client_assertion(
            &self.assertion_cfg,
            &client,
            assertion,
            self.cache.as_ref(),
            now,
        )
        .await?;

        // Mint a synthetic access token. Subject is "client:<client_id>".
        let access = self.mint_access_token(tenant_id, client_id, &claims.jti, now)?;
        let expires_in = self.jwt_cfg.access_ttl.as_secs();

        tracing::info!(
            target: "iam.client_token",
            tenant_id = %tenant_id,
            client_id = %client_id,
            grace = verified_with_previous_secret,
            "client_token.accept"
        );

        Ok(ClientCredentialsTokenOutput {
            access_token: SecretString::from(access),
            token_type: "Bearer",
            expires_in,
            used_previous_secret: verified_with_previous_secret,
        })
    }

    fn mint_access_token(
        &self,
        tenant_id: TenantId,
        client_id: &ClientId,
        assertion_jti: &str,
        now: OffsetDateTime,
    ) -> Result<String, IamError> {
        use jsonwebtoken::{encode, Header};
        use serde::Serialize;

        #[derive(Serialize)]
        struct ClientClaims<'a> {
            sub: String,
            tenant_id: String,
            client_id: &'a str,
            iss: &'a str,
            aud: &'a str,
            iat: i64,
            nbf: i64,
            exp: i64,
            jti: String,
            #[serde(rename = "assertion_jti")]
            assertion_jti: &'a str,
            token_type: &'static str,
            grant_type: &'static str,
        }

        // We sign with the configured JwtConfig — same encoding key path
        // as the user-token issuer.
        let encoding_key = encoding_key_for(self.jwt_cfg.algorithm, &self.jwt_cfg.signing_key)?;
        let mut header = Header::new(match self.jwt_cfg.algorithm {
            JwtAlgorithm::Hs256 => jsonwebtoken::Algorithm::HS256,
            JwtAlgorithm::Rs256 => jsonwebtoken::Algorithm::RS256,
            JwtAlgorithm::EdDsa => jsonwebtoken::Algorithm::EdDSA,
        });
        header.kid = Some(self.jwt_cfg.key_id.clone());

        let iat = now.unix_timestamp();
        let access_ttl: i64 = i64::try_from(self.jwt_cfg.access_ttl.as_secs())
            .map_err(|_| IamError::config("jwt.access_ttl too large"))?;
        let exp = iat.saturating_add(access_ttl);

        let claims = ClientClaims {
            sub: format!("client:{}", client_id.as_str()),
            tenant_id: tenant_id.to_string(),
            client_id: client_id.as_str(),
            iss: &self.jwt_cfg.issuer,
            aud: &self.jwt_cfg.audience,
            iat,
            nbf: iat,
            exp,
            jti: Uuid::now_v7().to_string(),
            assertion_jti,
            token_type: "access",
            grant_type: "client_credentials",
        };
        encode(&header, &claims, &encoding_key)
            .map_err(|e| IamError::internal(format!("jwt encode: {e}")))
    }
}

/// Sanity helper kept private — silences the unused-import warning
/// `SecretString::expose_secret` would otherwise produce.
#[doc(hidden)]
pub fn _force_expose(s: &SecretString) -> usize {
    s.expose_secret().len()
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
    use crate::model::oidc_client::{ClientSecret, OidcClient, OidcClientRowId};
    use crate::service::client_assertion::{mint_assertion_for_test, InMemoryJtiCache};
    use crate::service::Clock;
    use async_trait::async_trait;
    use std::sync::Mutex;
    use std::time::Duration as StdDuration;
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
            Ok(self
                .rows
                .lock()
                .unwrap()
                .iter()
                .find(|c| c.tenant_id == tenant_id && c.client_id == *client_id)
                .cloned())
        }
        async fn create(&self, client: &OidcClient) -> Result<(), IamError> {
            self.rows.lock().unwrap().push(client.clone());
            Ok(())
        }
        async fn update(&self, client: &OidcClient) -> Result<(), IamError> {
            let mut g = self.rows.lock().unwrap();
            if let Some(slot) = g
                .iter_mut()
                .find(|c| c.tenant_id == client.tenant_id && c.client_id == client.client_id)
            {
                *slot = client.clone();
                Ok(())
            } else {
                Err(IamError::repository("not found"))
            }
        }
    }

    struct FixedClock(OffsetDateTime);
    impl Clock for FixedClock {
        fn now(&self) -> OffsetDateTime {
            self.0
        }
    }

    fn jwt_cfg() -> JwtConfig {
        let key = "k".repeat(32);
        JwtConfig {
            issuer: "sx".into(),
            audience: "sx-clients".into(),
            signing_key: SecretString::from(key.clone()),
            verifying_key: SecretString::from(key),
            key_id: "k1".into(),
            access_ttl: StdDuration::from_secs(900),
            refresh_ttl: StdDuration::from_secs(3600),
            algorithm: JwtAlgorithm::Hs256,
            leeway_seconds: 5,
        }
    }

    fn assertion_cfg() -> ClientAssertionConfig {
        ClientAssertionConfig::new("https://sx.example/v1/oauth/token")
    }

    fn make_client(secret: &str, now: OffsetDateTime) -> OidcClient {
        OidcClient {
            row_id: OidcClientRowId::new(),
            tenant_id: TenantId::new(),
            client_id: ClientId::new("acme-bot"),
            auth_method: ClientAuthMethod::ClientSecretJwt,
            secret: ClientSecret::from_string(secret.into()),
            previous_secret: None,
            previous_expires_at: None,
            rotated_at: now,
            created_at: now,
        }
    }

    #[tokio::test]
    async fn happy_path_issues_access_token() {
        let now = OffsetDateTime::now_utc();
        let repo = Arc::new(InMemRepo::default());
        let client = make_client("live", now);
        let tenant = client.tenant_id;
        let cid = client.client_id.clone();
        repo.create(&client).await.unwrap();

        let uc = ClientCredentialsTokenUseCase::new(
            repo.clone(),
            Arc::new(FixedClock(now)),
            Arc::new(InMemoryJtiCache::new()),
            assertion_cfg(),
            jwt_cfg(),
        );

        let now_unix = now.unix_timestamp();
        let assertion = mint_assertion_for_test(
            "acme-bot",
            "live",
            "https://sx.example/v1/oauth/token",
            "jti-token-1",
            now_unix,
            now_unix + 60,
        );

        let out = uc.execute(tenant, &cid, &assertion).await.unwrap();
        assert_eq!(out.token_type, "Bearer");
        assert_eq!(out.expires_in, 900);
        assert!(!out.used_previous_secret);
        // The minted token is a three-part JWS.
        let token = out.access_token.expose_secret().to_string();
        assert_eq!(token.split('.').count(), 3);
    }

    #[tokio::test]
    async fn grace_window_flagged_in_output() {
        let now = OffsetDateTime::now_utc();
        let repo = Arc::new(InMemRepo::default());
        let mut client = make_client("new", now);
        client.previous_secret = Some(ClientSecret::from_string("old".into()));
        client.previous_expires_at = Some(now + TimeDuration::days(3));
        let tenant = client.tenant_id;
        let cid = client.client_id.clone();
        repo.create(&client).await.unwrap();

        let uc = ClientCredentialsTokenUseCase::new(
            repo.clone(),
            Arc::new(FixedClock(now)),
            Arc::new(InMemoryJtiCache::new()),
            assertion_cfg(),
            jwt_cfg(),
        );

        let now_unix = now.unix_timestamp();
        let assertion = mint_assertion_for_test(
            "acme-bot",
            "old",
            "https://sx.example/v1/oauth/token",
            "jti-grace",
            now_unix,
            now_unix + 60,
        );
        let out = uc.execute(tenant, &cid, &assertion).await.unwrap();
        assert!(out.used_previous_secret);
    }

    #[tokio::test]
    async fn unknown_client_returns_invalid_credentials() {
        let now = OffsetDateTime::now_utc();
        let repo = Arc::new(InMemRepo::default());
        let uc = ClientCredentialsTokenUseCase::new(
            repo.clone(),
            Arc::new(FixedClock(now)),
            Arc::new(InMemoryJtiCache::new()),
            assertion_cfg(),
            jwt_cfg(),
        );
        let err = uc
            .execute(TenantId::new(), &ClientId::new("ghost"), "x.y.z")
            .await
            .expect_err("unknown client");
        assert_eq!(err, IamError::InvalidCredentials);
    }

    #[tokio::test]
    async fn client_with_non_jwt_auth_rejects() {
        let now = OffsetDateTime::now_utc();
        let repo = Arc::new(InMemRepo::default());
        let mut client = make_client("live", now);
        client.auth_method = ClientAuthMethod::ClientSecretBasic;
        let tenant = client.tenant_id;
        let cid = client.client_id.clone();
        repo.create(&client).await.unwrap();
        let uc = ClientCredentialsTokenUseCase::new(
            repo,
            Arc::new(FixedClock(now)),
            Arc::new(InMemoryJtiCache::new()),
            assertion_cfg(),
            jwt_cfg(),
        );
        let err = uc
            .execute(tenant, &cid, "x.y.z")
            .await
            .expect_err("wrong method");
        assert_eq!(err, IamError::InvalidCredentials);
    }
}
