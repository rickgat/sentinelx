//! JWT validation.
//!
//! Validation is strict: algorithm allow-list, `kid` allow-list, `iss`,
//! `aud`, `exp`, `nbf`, `iat`. The `none` algorithm is rejected
//! categorically because it is not in the allow-list.

use std::collections::HashMap;

use jsonwebtoken::{decode, decode_header, DecodingKey, Validation};
use secrecy::{ExposeSecret, SecretString};

use crate::config::{JwtAlgorithm, JwtConfig};
use crate::model::claims::AccessClaims;
use crate::IamError;

/// Resolves a `kid` to the [`DecodingKey`] that should verify it.
///
/// Production wiring will use a JWK-set-backed resolver capable of
/// rotation; the default [`StaticKeyResolver`] holds a single
/// `(kid, key)` pair sourced from config.
pub trait KeyResolver: Send + Sync {
    /// Look up a decoding key by header `kid`.
    ///
    /// Returns `None` when the `kid` is not in the allow-list, which the
    /// validator surfaces as [`IamError::InvalidToken`].
    fn resolve(&self, kid: &str) -> Option<DecodingKey>;
}

/// A single-key resolver — what most deployments need.
pub struct StaticKeyResolver {
    entries: HashMap<String, DecodingKey>,
}

impl std::fmt::Debug for StaticKeyResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StaticKeyResolver")
            .field("known_kids", &self.entries.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl StaticKeyResolver {
    /// Build a resolver from a single `(kid, key)` pair.
    pub fn single(kid: impl Into<String>, key: DecodingKey) -> Self {
        let mut entries = HashMap::new();
        entries.insert(kid.into(), key);
        Self { entries }
    }
}

impl KeyResolver for StaticKeyResolver {
    fn resolve(&self, kid: &str) -> Option<DecodingKey> {
        self.entries.get(kid).cloned()
    }
}

/// Validates JWT tokens and returns the parsed claim set.
pub trait TokenValidator: Send + Sync {
    /// Validate `token` and return its claims on success.
    fn validate(&self, token: &str) -> Result<AccessClaims, IamError>;
}

/// `jsonwebtoken`-backed [`TokenValidator`].
pub struct JwtValidator<R: KeyResolver> {
    cfg: JwtConfig,
    resolver: R,
}

impl<R: KeyResolver> std::fmt::Debug for JwtValidator<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JwtValidator")
            .field("issuer", &self.cfg.issuer)
            .field("audience", &self.cfg.audience)
            .field("algorithm", &self.cfg.algorithm)
            .finish()
    }
}

/// Outcome of unverified header inspection.
///
/// Returned by [`JwtValidator::decode_unverified`]. The header is decoded
/// **without** signature verification — it is unsafe to trust any field of
/// this value for authorization; the type exists for fuzzing the input
/// path and for tooling that needs to read the `kid` / `alg` before
/// resolving a key.
#[derive(Debug, Clone)]
pub struct UnverifiedHeader {
    /// The JOSE `alg` reported by the token, unverified.
    pub alg: jsonwebtoken::Algorithm,
    /// The JOSE `kid` reported by the token, unverified.
    pub kid: Option<String>,
}

impl<R: KeyResolver> JwtValidator<R> {
    /// Build a [`JwtValidator`] from configuration plus a [`KeyResolver`].
    #[must_use]
    pub fn new(cfg: JwtConfig, resolver: R) -> Self {
        Self { cfg, resolver }
    }

    /// Best-effort parse of an arbitrary byte slice as a JWT header,
    /// **without** verifying the signature.
    ///
    /// This is a fuzz-friendly entry point: it MUST NEVER panic for any
    /// input. Garbage input returns [`IamError::InvalidToken`]. Valid
    /// UTF-8 that happens to parse as a JWT header returns the unverified
    /// header — callers must not trust the result for authorization
    /// decisions; use [`TokenValidator::validate`] for that.
    pub fn decode_unverified(data: &[u8]) -> Result<UnverifiedHeader, IamError> {
        // JWTs are ASCII; non-UTF-8 input is rejected up-front so we never
        // hand opaque bytes to the underlying parser.
        let token = std::str::from_utf8(data).map_err(|_| IamError::InvalidToken)?;
        let header = decode_header(token).map_err(|_| IamError::InvalidToken)?;
        Ok(UnverifiedHeader {
            alg: header.alg,
            kid: header.kid,
        })
    }

    fn validation(&self) -> Validation {
        let mut v = Validation::new(self.cfg.algorithm.to_jwt());
        v.set_issuer(&[&self.cfg.issuer]);
        v.set_audience(&[&self.cfg.audience]);
        v.set_required_spec_claims(&["exp", "nbf", "iat", "iss", "aud", "sub"]);
        v.leeway = self.cfg.leeway_seconds;
        v.validate_exp = true;
        v.validate_nbf = true;
        v.validate_aud = true;
        v.algorithms = vec![self.cfg.algorithm.to_jwt()];
        v
    }
}

impl<R: KeyResolver> TokenValidator for JwtValidator<R> {
    fn validate(&self, token: &str) -> Result<AccessClaims, IamError> {
        // Step 1: parse header so we can reject alg=none and resolve kid.
        let header = decode_header(token).map_err(|_| IamError::InvalidToken)?;
        let expected = self.cfg.algorithm.to_jwt();
        if header.alg != expected {
            tracing::warn!(
                got = ?header.alg,
                expected = ?expected,
                "iam.token.alg_mismatch",
            );
            return Err(IamError::InvalidToken);
        }
        // Step 2: enforce a `kid` allow-list.
        let kid = header.kid.ok_or(IamError::InvalidToken)?;
        let key = self.resolver.resolve(&kid).ok_or_else(|| {
            tracing::warn!(kid = %kid, "iam.token.unknown_kid");
            IamError::InvalidToken
        })?;
        // Step 3: full claim validation (signature, iss, aud, exp, nbf).
        let validation = self.validation();
        let data =
            decode::<AccessClaims>(token, &key, &validation).map_err(|e| match e.kind() {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => IamError::TokenExpired,
                _ => IamError::InvalidToken,
            })?;
        Ok(data.claims)
    }
}

/// Build a [`DecodingKey`] for the configured algorithm + key material.
pub fn decoding_key_for(alg: JwtAlgorithm, key: &SecretString) -> Result<DecodingKey, IamError> {
    match alg {
        JwtAlgorithm::Hs256 => Ok(DecodingKey::from_secret(key.expose_secret().as_bytes())),
        JwtAlgorithm::Rs256 => DecodingKey::from_rsa_pem(key.expose_secret().as_bytes())
            .map_err(|e| IamError::config(format!("invalid RSA public key: {e}"))),
        JwtAlgorithm::EdDsa => DecodingKey::from_ed_pem(key.expose_secret().as_bytes())
            .map_err(|e| IamError::config(format!("invalid Ed25519 public key: {e}"))),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::domain::{TenantId, UserId};
    use crate::model::{Session, SessionId};
    use crate::service::clock::fake::FixedClock;
    use crate::service::clock::Clock;
    use crate::service::token_issuer::{IssueInput, JwtIssuer, TokenIssuer};
    use base64::Engine;
    use jsonwebtoken::DecodingKey;
    use std::sync::Arc;
    use std::time::Duration;
    use time::macros::datetime;
    use time::OffsetDateTime;

    fn cfg(audience: &str) -> JwtConfig {
        let key = "a".repeat(32);
        JwtConfig {
            issuer: "sx".into(),
            audience: audience.into(),
            signing_key: SecretString::from(key.clone()),
            verifying_key: SecretString::from(key),
            key_id: "k1".into(),
            access_ttl: Duration::from_secs(900),
            refresh_ttl: Duration::from_secs(3600),
            algorithm: JwtAlgorithm::Hs256,
            leeway_seconds: 5,
        }
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
            roles: vec![],
            permissions: vec![],
            cred_id: None,
        }
    }

    fn resolver(cfg: &JwtConfig) -> StaticKeyResolver {
        let dk = decoding_key_for(cfg.algorithm, &cfg.verifying_key).unwrap();
        StaticKeyResolver::single(cfg.key_id.clone(), dk)
    }

    /// Use the real system clock for happy-path tests so the issued
    /// `exp` claim is in the actual future (jsonwebtoken validates
    /// against wall-clock and ignores any fake clock).
    fn live_clock() -> Arc<crate::service::SystemClock> {
        Arc::new(crate::service::SystemClock)
    }

    fn live_input() -> IssueInput {
        let now = OffsetDateTime::now_utc();
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
            roles: vec![],
            permissions: vec![],
            cred_id: None,
        }
    }

    #[test]
    fn jwt_issue_and_validate_hs256() {
        let issuer = JwtIssuer::new(cfg("sx-clients"), live_clock()).unwrap();
        let token = issuer.issue(&live_input()).unwrap();
        let v = JwtValidator::new(cfg("sx-clients"), resolver(&cfg("sx-clients")));
        let claims = v.validate(token.access.expose_secret()).unwrap();
        assert_eq!(claims.iss, "sx");
        assert_eq!(claims.aud, "sx-clients");
    }

    #[test]
    fn jwt_validation_rejects_alg_none() {
        // Build a minimal "alg=none" token by hand.
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let header = b64.encode(r#"{"alg":"none","typ":"JWT","kid":"k1"}"#);
        let body = b64.encode(
            r#"{"sub":"u","tenant_id":"t","iss":"sx","aud":"sx-clients","iat":0,"nbf":0,"exp":9999999999,"jti":"j","sid":"s","typ":"access","roles":[],"permissions":[]}"#,
        );
        let token = format!("{header}.{body}.");
        let c = cfg("sx-clients");
        let v = JwtValidator::new(c.clone(), resolver(&c));
        let err = v.validate(&token).unwrap_err();
        assert_eq!(err, IamError::InvalidToken);
    }

    #[test]
    fn jwt_validation_rejects_wrong_audience() {
        let issuer = JwtIssuer::new(cfg("sx-clients"), live_clock()).unwrap();
        let token = issuer.issue(&live_input()).unwrap();
        // Validate with a different expected audience.
        let v = JwtValidator::new(cfg("evil-clients"), resolver(&cfg("evil-clients")));
        let err = v.validate(token.access.expose_secret()).unwrap_err();
        assert_eq!(err, IamError::InvalidToken);
    }

    #[test]
    fn jwt_validation_rejects_expired() {
        // Issue with a fake clock pinned far in the past so the resulting
        // token's `exp` claim is already in the actual past at validation
        // time (jsonwebtoken validates `exp` against system wall-clock).
        let clock = Arc::new(FixedClock::new(datetime!(1990-01-01 00:00 UTC)));
        let issuer = JwtIssuer::new(cfg("sx-clients"), clock.clone()).unwrap();
        let token = issuer.issue(&input(&clock)).unwrap();
        let v = JwtValidator::new(cfg("sx-clients"), resolver(&cfg("sx-clients")));
        let err = v.validate(token.access.expose_secret()).unwrap_err();
        assert_eq!(err, IamError::TokenExpired);
    }

    #[test]
    fn jwt_validation_rejects_unknown_kid() {
        let mut c = cfg("sx-clients");
        c.key_id = "rogue".into();
        let issuer = JwtIssuer::new(c, live_clock()).unwrap();
        let token = issuer.issue(&live_input()).unwrap();
        // Resolver only knows "k1".
        let v = JwtValidator::new(cfg("sx-clients"), resolver(&cfg("sx-clients")));
        let err = v.validate(token.access.expose_secret()).unwrap_err();
        assert_eq!(err, IamError::InvalidToken);
    }

    #[test]
    fn jwt_validation_rejects_tampered_signature() {
        let issuer = JwtIssuer::new(cfg("sx-clients"), live_clock()).unwrap();
        let token = issuer.issue(&live_input()).unwrap();
        let mut access = token.access.expose_secret().to_string();
        // Flip the last character — easy way to break the signature.
        let last = access.pop().unwrap_or('a');
        let replacement = if last == 'A' { 'B' } else { 'A' };
        access.push(replacement);
        let v = JwtValidator::new(cfg("sx-clients"), resolver(&cfg("sx-clients")));
        let err = v.validate(&access).unwrap_err();
        assert_eq!(err, IamError::InvalidToken);
    }

    #[test]
    fn decoding_key_for_rejects_invalid_pem() {
        let r = decoding_key_for(
            JwtAlgorithm::Rs256,
            &SecretString::from("garbage".to_string()),
        );
        assert!(r.is_err());
    }

    #[test]
    fn static_resolver_returns_none_for_unknown() {
        let c = cfg("sx-clients");
        let r = resolver(&c);
        assert!(r.resolve("nope").is_none());
        assert!(r.resolve("k1").is_some());
    }

    fn _decoding_key_smoke() {
        let _ = DecodingKey::from_secret(b"x");
    }
}
