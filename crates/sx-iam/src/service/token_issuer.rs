//! JWT issuance.
//!
//! Algorithm and TTL come from [`JwtConfig`]; `jti` is per-token `UUIDv7`;
//! `iat`/`nbf`/`exp` are computed from the injected [`Clock`].

use std::sync::Arc;

use jsonwebtoken::{EncodingKey, Header};
use secrecy::{ExposeSecret, SecretString};
use uuid::Uuid;

use crate::config::{JwtAlgorithm, JwtConfig};
use crate::domain::Permission;
use crate::model::claims::{AccessClaims, TokenType};
use crate::model::{Session, Token};
use crate::service::Clock;
use crate::IamError;

/// Input passed to [`TokenIssuer::issue`].
#[derive(Debug)]
pub struct IssueInput {
    /// Subject — string-form user id.
    pub user_id: String,
    /// String-form tenant id.
    pub tenant_id: String,
    /// Session linking the access and refresh tokens together.
    pub session: Session,
    /// Role names assigned to the user (denormalised for `roles` claim).
    pub roles: Vec<String>,
    /// Permission grants (flattened from the user's roles).
    pub permissions: Vec<Permission>,
    /// Optional credential binding (P1-002 / `WebAuthn`). When `Some`, the
    /// issued access token carries `cred_id` so downstream services can
    /// require a hardware-backed MFA factor on sensitive operations. The
    /// value is the base64url-encoded credential id of the passkey that
    /// satisfied the assertion.
    #[allow(clippy::struct_field_names)]
    pub cred_id: Option<String>,
}

/// Issues access + refresh JWTs.
pub trait TokenIssuer: Send + Sync {
    /// Sign a fresh `(access, refresh)` pair.
    fn issue(&self, input: &IssueInput) -> Result<Token, IamError>;
}

/// `jsonwebtoken`-backed [`TokenIssuer`].
pub struct JwtIssuer<C: Clock> {
    cfg: JwtConfig,
    clock: Arc<C>,
    encoding_key: EncodingKey,
}

impl<C: Clock> std::fmt::Debug for JwtIssuer<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JwtIssuer")
            .field("issuer", &self.cfg.issuer)
            .field("audience", &self.cfg.audience)
            .field("algorithm", &self.cfg.algorithm)
            .field("key_id", &self.cfg.key_id)
            .finish()
    }
}

impl<C: Clock> JwtIssuer<C> {
    /// Build a [`JwtIssuer`] from configuration.
    ///
    /// For `HS256` the signing key is treated as raw bytes; for `RS256`
    /// and `EdDSA` the signing key MUST be a PEM-encoded private key.
    pub fn new(cfg: JwtConfig, clock: Arc<C>) -> Result<Self, IamError> {
        let encoding_key = encoding_key_for(cfg.algorithm, &cfg.signing_key)?;
        Ok(Self {
            cfg,
            clock,
            encoding_key,
        })
    }

    fn header(&self) -> Header {
        let mut h = Header::new(self.cfg.algorithm.to_jwt());
        h.kid = Some(self.cfg.key_id.clone());
        h
    }

    fn build_claims(
        &self,
        input: &IssueInput,
        token_type: TokenType,
        ttl_secs: i64,
    ) -> AccessClaims {
        let now = self.clock.unix_seconds();
        let jti = Uuid::now_v7().to_string();
        AccessClaims {
            sub: input.user_id.clone(),
            tenant_id: input.tenant_id.clone(),
            iss: self.cfg.issuer.clone(),
            aud: self.cfg.audience.clone(),
            iat: now,
            nbf: now,
            exp: now.saturating_add(ttl_secs),
            jti,
            sid: input.session.id.to_string(),
            token_type,
            roles: input.roles.clone(),
            permissions: input.permissions.clone(),
            cred_id: input.cred_id.clone(),
        }
    }

    fn sign(&self, claims: &AccessClaims) -> Result<String, IamError> {
        let header = self.header();
        jsonwebtoken::encode(&header, claims, &self.encoding_key)
            .map_err(|e| IamError::internal(format!("jwt encode: {e}")))
    }
}

impl<C: Clock> TokenIssuer for JwtIssuer<C> {
    fn issue(&self, input: &IssueInput) -> Result<Token, IamError> {
        let access_ttl: i64 = i64::try_from(self.cfg.access_ttl.as_secs())
            .map_err(|_| IamError::config("jwt.access_ttl too large"))?;
        let refresh_ttl: i64 = i64::try_from(self.cfg.refresh_ttl.as_secs())
            .map_err(|_| IamError::config("jwt.refresh_ttl too large"))?;

        let access_claims = self.build_claims(input, TokenType::Access, access_ttl);
        let refresh_claims = self.build_claims(input, TokenType::Refresh, refresh_ttl);

        let access = self.sign(&access_claims)?;
        let refresh = self.sign(&refresh_claims)?;

        tracing::info!(
            user_id = %input.user_id,
            tenant_id = %input.tenant_id,
            sid = %input.session.id,
            "iam.token.issued",
        );

        Ok(Token {
            access: SecretString::from(access),
            refresh: SecretString::from(refresh),
            expires_in: self.cfg.access_ttl.as_secs(),
        })
    }
}

/// Build an `EncodingKey` for the configured algorithm + key material.
pub(crate) fn encoding_key_for(
    alg: JwtAlgorithm,
    key: &SecretString,
) -> Result<EncodingKey, IamError> {
    match alg {
        JwtAlgorithm::Hs256 => Ok(EncodingKey::from_secret(key.expose_secret().as_bytes())),
        JwtAlgorithm::Rs256 => EncodingKey::from_rsa_pem(key.expose_secret().as_bytes())
            .map_err(|e| IamError::config(format!("invalid RSA private key: {e}"))),
        JwtAlgorithm::EdDsa => EncodingKey::from_ed_pem(key.expose_secret().as_bytes())
            .map_err(|e| IamError::config(format!("invalid Ed25519 private key: {e}"))),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::config::PasswordConfig;
    use crate::domain::{TenantId, UserId};
    use crate::model::{Session, SessionId};
    use crate::service::clock::fake::FixedClock;
    use std::sync::Arc;
    use std::time::Duration;
    use time::macros::datetime;

    fn cfg() -> JwtConfig {
        let key = "a".repeat(32);
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

    fn _touch_password_cfg() {
        let _ = PasswordConfig::default();
    }

    fn input(clock: &FixedClock) -> IssueInput {
        let now = clock.now();
        let tenant = TenantId::new();
        let user = UserId::new();
        let sid = SessionId::new();
        IssueInput {
            user_id: user.to_string(),
            tenant_id: tenant.to_string(),
            session: Session {
                id: sid,
                user_id: user,
                tenant_id: tenant,
                issued_at: now,
                expires_at: now + Duration::from_secs(3600),
                ip: None,
                user_agent: None,
            },
            roles: vec!["admin".into()],
            permissions: vec![],
            cred_id: None,
        }
    }

    #[test]
    fn hs256_issuer_signs_a_three_part_token() {
        let clock = Arc::new(FixedClock::new(datetime!(2025-01-01 00:00 UTC)));
        let issuer = JwtIssuer::new(cfg(), clock.clone()).unwrap();
        let token = issuer.issue(&input(&clock)).unwrap();
        let access = token.access.expose_secret().to_string();
        assert_eq!(access.split('.').count(), 3);
    }
}
