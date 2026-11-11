//! OIDC `id_token` verifier with JWKS-fetching + TTL'd cache.
//!
//! Used by the [`ExchangeOidcUseCase`](crate::controller::exchange_oidc)
//! to validate an `id_token` produced by an external `IdP` (Keycloak,
//! Auth0, Okta, etc.) before issuing an SX-internal token pair for the
//! underlying user.
//!
//! ## Design
//!
//! * [`OidcVerifier`] is a small async trait so the use case can be
//!   exercised with a hand-rolled fake in unit tests.
//! * [`JwksOidcVerifier`] is the production implementation. It fetches
//!   the `IdP`'s JWKS over HTTPS with the supplied [`reqwest::Client`],
//!   keeps the parsed `JwkSet` in memory for [`OidcVerifierConfig::cache_ttl`],
//!   and resolves the signing key via the token header's `kid`.
//! * Signatures are verified with `jsonwebtoken`; standard claims
//!   (`iss`, `aud`, `exp`, `nbf`) are enforced inside `Validation`.
//! * The verifier MUST NOT log the raw `id_token` or any public-key body.
//!   Only `iss`, `kid`, and the accept / reject decision (plus a short
//!   reason) end up in the tracing stream.

use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use jsonwebtoken::jwk::{AlgorithmParameters, Jwk, JwkSet};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::IamError;

/// Claims extracted from a successfully verified OIDC `id_token`.
///
/// Only the fields the exchange use case needs are surfaced. Custom `IdP`
/// claims live in `extra` so the use case can pull tenant id (or anything
/// else operators wire in) without the verifier having to know about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidcClaims {
    /// `sub` claim — the `IdP`'s stable user identifier.
    pub subject: String,
    /// `iss` claim — `IdP`'s published issuer.
    pub issuer: String,
    /// `aud` claim — OIDC client id this token was issued for.
    pub audience: String,
    /// `email` claim — login email (lower-cased before lookup at the use-
    /// case level). Optional in the spec, mandatory for SX to function.
    pub email: Option<String>,
    /// `name` claim — display name. Optional.
    pub name: Option<String>,
    /// All remaining claims as a generic JSON object. The exchange use case
    /// inspects this to locate the tenant id under the configured claim
    /// name.
    pub extra: serde_json::Map<String, serde_json::Value>,
}

impl OidcClaims {
    /// Read a string-valued claim from [`Self::extra`]. Used by the
    /// exchange use case to fetch the configured tenant claim.
    #[must_use]
    pub fn string_claim(&self, name: &str) -> Option<String> {
        self.extra.get(name).and_then(|v| match v {
            serde_json::Value::String(s) => Some(s.clone()),
            _ => None,
        })
    }
}

/// Trait surface the exchange use case depends on. A test fake injects a
/// fixed `OidcClaims` value; the production [`JwksOidcVerifier`] fetches
/// the JWKS, resolves the key, and verifies the JWT.
#[async_trait]
pub trait OidcVerifier: Send + Sync {
    /// Verify `id_token`. On failure return [`IamError::InvalidCredentials`].
    async fn verify(&self, id_token: &str) -> Result<OidcClaims, IamError>;
}

/// Configuration the [`JwksOidcVerifier`] consumes.
///
/// This mirrors the relevant fields of `sx_config::schema::oidc::OidcConfig`
/// so sx-iam can be tested without depending on the loader crate's
/// invariants pass.
#[derive(Debug, Clone)]
pub struct OidcVerifierConfig {
    /// Required `iss` claim.
    pub issuer: String,
    /// Required `aud` claim.
    pub audience: String,
    /// JWKS endpoint URL — must be HTTPS in production.
    pub jwks_url: String,
    /// How long fetched JWKS responses are cached.
    pub cache_ttl: Duration,
}

/// JWKS-fetching, cache-backed OIDC verifier.
pub struct JwksOidcVerifier {
    cfg: OidcVerifierConfig,
    http: reqwest::Client,
    cache: Arc<RwLock<JwksCache>>,
}

impl std::fmt::Debug for JwksOidcVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JwksOidcVerifier")
            .field("issuer", &self.cfg.issuer)
            .field("audience", &self.cfg.audience)
            .field("jwks_url", &self.cfg.jwks_url)
            .field("cache_ttl_secs", &self.cfg.cache_ttl.as_secs())
            .finish_non_exhaustive()
    }
}

/// In-memory JWKS cache entry.
#[derive(Default)]
struct JwksCache {
    /// Parsed JWKS — `None` until the first successful fetch.
    set: Option<JwkSet>,
    /// Instant the current cache entry was loaded.
    loaded_at: Option<Instant>,
}

impl JwksOidcVerifier {
    /// Build a [`JwksOidcVerifier`] from configuration + an `http` client.
    ///
    /// The caller owns the HTTP client so connection pooling, timeouts, and
    /// proxy settings stay under the composition root's control.
    #[must_use]
    pub fn new(cfg: OidcVerifierConfig, http: reqwest::Client) -> Self {
        Self {
            cfg,
            http,
            cache: Arc::new(RwLock::new(JwksCache::default())),
        }
    }

    /// Force-refresh the JWKS cache.
    ///
    /// Exposed so an operator could trigger a cache flush from a future
    /// admin endpoint; not invoked anywhere yet.
    pub async fn refresh_jwks(&self) -> Result<(), IamError> {
        let fresh = self.fetch_jwks().await?;
        let mut guard = self.cache.write().await;
        guard.set = Some(fresh);
        guard.loaded_at = Some(Instant::now());
        Ok(())
    }

    async fn fetch_jwks(&self) -> Result<JwkSet, IamError> {
        let resp = self
            .http
            .get(&self.cfg.jwks_url)
            .send()
            .await
            .map_err(|e| {
                tracing::warn!(
                    target: "iam.oidc.jwks",
                    error = %e,
                    "oidc.jwks.fetch_failed"
                );
                IamError::repository(format!("jwks fetch: {e}"))
            })?;
        if !resp.status().is_success() {
            tracing::warn!(
                target: "iam.oidc.jwks",
                status = resp.status().as_u16(),
                "oidc.jwks.non_2xx"
            );
            return Err(IamError::repository(format!(
                "jwks fetch returned {}",
                resp.status()
            )));
        }
        let body = resp.text().await.map_err(|e| {
            tracing::warn!(
                target: "iam.oidc.jwks",
                error = %e,
                "oidc.jwks.read_body_failed"
            );
            IamError::repository(format!("jwks body: {e}"))
        })?;
        let parsed: JwkSet = serde_json::from_str(&body).map_err(|e| {
            tracing::warn!(
                target: "iam.oidc.jwks",
                error = %e,
                "oidc.jwks.parse_failed"
            );
            IamError::repository(format!("jwks parse: {e}"))
        })?;
        Ok(parsed)
    }

    async fn jwks(&self) -> Result<JwkSet, IamError> {
        // Read-fast path: the cache is fresh.
        {
            let guard = self.cache.read().await;
            if let (Some(set), Some(loaded_at)) = (guard.set.as_ref(), guard.loaded_at) {
                if loaded_at.elapsed() < self.cfg.cache_ttl {
                    return Ok(set.clone());
                }
            }
        }
        // Refresh path. Concurrent refreshers will overlap — but the
        // result is identical, and we never serve stale data after a
        // successful refresh.
        let fresh = self.fetch_jwks().await?;
        let mut guard = self.cache.write().await;
        guard.set = Some(fresh.clone());
        guard.loaded_at = Some(Instant::now());
        Ok(fresh)
    }

    fn build_validation(&self, alg: Algorithm) -> Validation {
        let mut v = Validation::new(alg);
        v.set_issuer(&[&self.cfg.issuer]);
        v.set_audience(&[&self.cfg.audience]);
        v.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
        v.validate_exp = true;
        v.validate_nbf = true;
        v.validate_aud = true;
        // Modest clock-skew tolerance — most IdPs publish ≤ 30s in practice.
        // Keep this small so a token whose `exp` is in the past is not
        // accepted because the verifier was being too generous.
        v.leeway = 5;
        v.algorithms = vec![alg];
        v
    }
}

#[async_trait]
impl OidcVerifier for JwksOidcVerifier {
    async fn verify(&self, id_token: &str) -> Result<OidcClaims, IamError> {
        // Parse header to discover `kid` and `alg`. The raw token is never
        // logged.
        let header = decode_header(id_token).map_err(|_| {
            tracing::warn!(
                target: "iam.oidc.verify",
                reason = "bad_header",
                "oidc.verify.reject"
            );
            IamError::InvalidCredentials
        })?;
        let kid = header.kid.ok_or_else(|| {
            tracing::warn!(
                target: "iam.oidc.verify",
                reason = "missing_kid",
                "oidc.verify.reject"
            );
            IamError::InvalidCredentials
        })?;
        if matches!(
            header.alg,
            Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512
        ) {
            tracing::warn!(
                target: "iam.oidc.verify",
                kid = %kid,
                reason = "symmetric_alg_rejected",
                "oidc.verify.reject"
            );
            return Err(IamError::InvalidCredentials);
        }

        // Resolve the JWK for this kid via the cache.
        let set = self.jwks().await?;
        let Some(jwk) = set.find(&kid) else {
            tracing::warn!(
                target: "iam.oidc.verify",
                issuer = %self.cfg.issuer,
                kid = %kid,
                reason = "unknown_kid",
                "oidc.verify.reject"
            );
            return Err(IamError::InvalidCredentials);
        };

        let decoding_key = decoding_key_from_jwk(jwk).map_err(|e| {
            tracing::warn!(
                target: "iam.oidc.verify",
                issuer = %self.cfg.issuer,
                kid = %kid,
                reason = "key_material",
                error = %e,
                "oidc.verify.reject"
            );
            IamError::InvalidCredentials
        })?;

        let validation = self.build_validation(header.alg);
        let data = decode::<RawClaims>(id_token, &decoding_key, &validation).map_err(|e| {
            let reason = match e.kind() {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => "expired",
                jsonwebtoken::errors::ErrorKind::InvalidIssuer => "issuer",
                jsonwebtoken::errors::ErrorKind::InvalidAudience => "audience",
                jsonwebtoken::errors::ErrorKind::InvalidSignature => "signature",
                jsonwebtoken::errors::ErrorKind::ImmatureSignature => "nbf",
                _ => "claims",
            };
            tracing::warn!(
                target: "iam.oidc.verify",
                issuer = %self.cfg.issuer,
                kid = %kid,
                reason = %reason,
                "oidc.verify.reject"
            );
            IamError::InvalidCredentials
        })?;

        let raw = data.claims;
        tracing::info!(
            target: "iam.oidc.verify",
            issuer = %raw.iss,
            kid = %kid,
            sub = %raw.sub,
            "oidc.verify.accept"
        );
        Ok(OidcClaims {
            subject: raw.sub,
            issuer: raw.iss,
            audience: raw.aud,
            email: raw.email,
            name: raw.name,
            extra: raw.extra,
        })
    }
}

/// Build a `DecodingKey` from a JWK. Supports RSA, EC, and OKP keys (the
/// algorithms OIDC `IdPs` typically publish). Symmetric (oct) keys are
/// rejected — see the symmetric-alg guard in [`JwksOidcVerifier::verify`].
fn decoding_key_from_jwk(jwk: &Jwk) -> Result<DecodingKey, IamError> {
    match &jwk.algorithm {
        AlgorithmParameters::RSA(_)
        | AlgorithmParameters::EllipticCurve(_)
        | AlgorithmParameters::OctetKeyPair(_) => DecodingKey::from_jwk(jwk)
            .map_err(|e| IamError::repository(format!("jwk decoding: {e}"))),
        AlgorithmParameters::OctetKey(_) => Err(IamError::repository(
            "symmetric JWKs are not accepted".to_string(),
        )),
    }
}

/// Internal representation of the claim set we deserialise off the JWT.
///
/// `extra` collects every claim not pulled into a typed field via
/// `#[serde(flatten)]` so the exchange use case can read the configured
/// tenant claim out of it.
#[derive(Debug, Deserialize, Serialize)]
struct RawClaims {
    iss: String,
    sub: String,
    aud: String,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(flatten)]
    extra: serde_json::Map<String, serde_json::Value>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use serde_json::json;
    use std::time::{SystemTime, UNIX_EPOCH};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// PKCS#8-encoded RSA key pair generated offline for unit tests. The
    /// private key is in PEM form; the corresponding JWK (n, e) is
    /// pre-computed below.
    ///
    /// NOTE: This is a stable 2048-bit RSA key used SOLELY by these tests.
    /// It must never appear in production binaries or fixtures.
    const TEST_RSA_PRIVATE_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCqmMzkx3mbAlye
aLOygtaQ983yFOVkwDs9DubEt3rdCi/FxQ7kP9QjBBIvsZM2NgEhEOdVxW+pRvJ8
RjDF0J4EO8abSCxo7BBGMppgcyxLxrKhTCaVi+HvjtMNViBsJdSz61+nnatJXVfq
eRxxl3hysSFJCGAuejeK3Z2ZzmGnwGN+YaoVVIRIv4NLPnXBJli1cJzAACFRbJKc
GNAUrW5CDB0f2fLJSMeymC9vsLFiz6gbFGidcQdDSMoWHzZ9DKrqyudIt4nPio9f
5ELefC88rzbszp2Lgqcz5uQ8mJyWHO13TTPEiMjOL+/RvgWTgdRhDMJFhMg8YNCo
m9h1TOSZAgMBAAECggEABID7oiZu3D6qAmUeKbjzpaNjLfsAVOJQgLkgCCLAxRfn
y7il1F+9L85OVXEX2Lsrg7Ysvf++xfkZaFpD30nAYuPPR3TL9lpVcihTxCGE8nxc
utkrXhtHBAebubsJE1iFgW6rVB37omMrBxB65aKo+NyFYKZuf/T0+oRat4TX4MFj
5rStmRyBdaIQA+dfs25DAm340lasbcCj8sSB8ni9SeSxRPGsaDoJnHw+6sHxCJ5u
eyDNUE/Lk6azIdaQTbmicPDa2S3qHyS1UmdHI6pd8/bs7UrulBHAiIacLiFoQJ7M
uV9Apx9MZZTtZST7fO5G6UmLTTSsswnMzyHgD+Cv0QKBgQDl4D4u5r0UxPS8Oorq
Dlq5jeCkOHSrHHejS0P0focaAaxRhslKzoBCEcYa+4uSZKqivaH4EHzJZ+9Nlphb
wEc4tBLBZ70kUp2ZdzLxKHQMMGWmGJbLHhlWmIC8IDnuU3VCOUkO5ti/5TOsHQbN
g7ZcPUZNiPJPNA5wuWj8MS4lKQKBgQC9+/UjKkkOXxnlL6D9/rEMF4eyf7dKxGSS
MGqdtKnQWdnB38LO/nKB/MxfjgP/LcSWEPpndX4bTdKinEnFAApHKj2k9uSD/vhF
sqXureleWVlPARU2ZFyU1J0DSfWJP384Dixim6sJ0l4WW7F8BlXlYrtzYvF9Jmgo
3dqhKxjB8QKBgQDSXQHK3fEOvqbQUiqpwnUX9VQsNFXf+O8rCkenyNpN3FYbTWOM
B6mrzKQkMSoqz+CviSZd4oivr2N492V6IV2L8I5xW0Plp4z90e1Wb5SzSt7avwnP
2z2I14qHnl4lUU6vScknz+1uvoso6G8/R1ds1c4uSjKkdJj6Y1JF56O48QKBgEB+
kDFn4XUng7rx+E1BcQkR09cc1DRlh165YPg4pI0+c1YFiDSM3IKUNy0ZIPI3r0zi
Zp9Im47ZVHAvbjuaT+LozBR8XAcTP2UpyHrGPzrwSgkv7OuSFnvP0Z2UNe5px95X
sWmoPuAOsjIU3qOj4vUEF26MYD6EE0gMSHP+FWGBAoGAc4gvSYJHq1pQw7P/JHPk
rU0/9i8URf0eRPwHQTtBa3AjFIRXRIHKCOmj+3TFeYg2+1nSxFDbFMZuvbcdHZB5
XxubfFDM/zI1lx60G8M0/nCm3D+50moXiTJMfjFth97v7rOzYPv3rkmoOacPJzAY
j5zu3nHyNHrJ7Aoe+QnmfIo=
-----END PRIVATE KEY-----";

    /// JWK n/e pre-computed (base64url, no padding) from `TEST_RSA_PRIVATE_PEM`.
    const TEST_RSA_JWK_N: &str = "qpjM5Md5mwJcnmizsoLWkPfN8hTlZMA7PQ7mxLd63QovxcUO5D_UIwQSL7GTNjYBIRDnVcVvqUbyfEYwxdCeBDvGm0gsaOwQRjKaYHMsS8ayoUwmlYvh747TDVYgbCXUs-tfp52rSV1X6nkccZd4crEhSQhgLno3it2dmc5hp8BjfmGqFVSESL-DSz51wSZYtXCcwAAhUWySnBjQFK1uQgwdH9nyyUjHspgvb7CxYs-oGxRonXEHQ0jKFh82fQyq6srnSLeJz4qPX-RC3nwvPK827M6di4KnM-bkPJiclhztd00zxIjIzi_v0b4Fk4HUYQzCRYTIPGDQqJvYdUzkmQ";
    const TEST_RSA_JWK_E: &str = "AQAB";

    fn unit_jwks_json(kid: &str) -> String {
        json!({
            "keys": [{
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": kid,
                "n": TEST_RSA_JWK_N,
                "e": TEST_RSA_JWK_E,
            }]
        })
        .to_string()
    }

    fn now() -> i64 {
        i64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        )
        .unwrap()
    }

    fn sign_token(kid: &str, claims: serde_json::Value) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(kid.to_string());
        let key = EncodingKey::from_rsa_pem(TEST_RSA_PRIVATE_PEM.as_bytes())
            .expect("test rsa pem must decode");
        encode(&header, &claims, &key).expect("sign test token")
    }

    fn verifier_with_mock(server: &MockServer, audience: &str) -> JwksOidcVerifier {
        let cfg = OidcVerifierConfig {
            issuer: "https://idp.example.com/realms/sx".into(),
            audience: audience.to_string(),
            jwks_url: format!("{}/jwks", server.uri()),
            cache_ttl: Duration::from_secs(60),
        };
        let http = reqwest::Client::new();
        JwksOidcVerifier::new(cfg, http)
    }

    #[tokio::test]
    async fn verifier_accepts_token_signed_with_jwks_key() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(unit_jwks_json("kid-1"), "application/json"),
            )
            .mount(&server)
            .await;

        let v = verifier_with_mock(&server, "sx-dashboard");
        let exp = now() + 600;
        let token = sign_token(
            "kid-1",
            json!({
                "iss": "https://idp.example.com/realms/sx",
                "sub": "user-123",
                "aud": "sx-dashboard",
                "exp": exp,
                "iat": now(),
                "email": "alice@example.com",
                "tenant_id": "11111111-1111-1111-1111-111111111111",
            }),
        );
        let claims = v.verify(&token).await.expect("verify should succeed");
        assert_eq!(claims.subject, "user-123");
        assert_eq!(claims.email.as_deref(), Some("alice@example.com"));
        assert_eq!(
            claims.string_claim("tenant_id").as_deref(),
            Some("11111111-1111-1111-1111-111111111111")
        );
    }

    #[tokio::test]
    async fn verifier_rejects_wrong_issuer() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(unit_jwks_json("kid-1"), "application/json"),
            )
            .mount(&server)
            .await;
        let v = verifier_with_mock(&server, "sx-dashboard");
        let token = sign_token(
            "kid-1",
            json!({
                "iss": "https://attacker.example.com/realms/sx",
                "sub": "u",
                "aud": "sx-dashboard",
                "exp": now() + 600,
                "iat": now(),
            }),
        );
        let err = v.verify(&token).await.expect_err("bad issuer");
        assert_eq!(err, IamError::InvalidCredentials);
    }

    #[tokio::test]
    async fn verifier_rejects_expired_token() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(unit_jwks_json("kid-1"), "application/json"),
            )
            .mount(&server)
            .await;
        let v = verifier_with_mock(&server, "sx-dashboard");
        let token = sign_token(
            "kid-1",
            json!({
                "iss": "https://idp.example.com/realms/sx",
                "sub": "u",
                "aud": "sx-dashboard",
                "exp": now() - 600,
                "iat": now() - 7200,
            }),
        );
        let err = v.verify(&token).await.expect_err("expired");
        assert_eq!(err, IamError::InvalidCredentials);
    }

    #[tokio::test]
    async fn verifier_rejects_invalid_signature() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(unit_jwks_json("kid-1"), "application/json"),
            )
            .mount(&server)
            .await;
        let v = verifier_with_mock(&server, "sx-dashboard");
        let token = sign_token(
            "kid-1",
            json!({
                "iss": "https://idp.example.com/realms/sx",
                "sub": "u",
                "aud": "sx-dashboard",
                "exp": now() + 600,
                "iat": now(),
            }),
        );
        // Tamper with the trailing signature char.
        let mut tampered = token;
        let last = tampered.pop().unwrap_or('a');
        tampered.push(if last == 'A' { 'B' } else { 'A' });
        let err = v.verify(&tampered).await.expect_err("bad signature");
        assert_eq!(err, IamError::InvalidCredentials);
    }

    #[tokio::test]
    async fn verifier_rejects_unknown_kid() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(unit_jwks_json("kid-1"), "application/json"),
            )
            .mount(&server)
            .await;
        let v = verifier_with_mock(&server, "sx-dashboard");
        let token = sign_token(
            "kid-other",
            json!({
                "iss": "https://idp.example.com/realms/sx",
                "sub": "u",
                "aud": "sx-dashboard",
                "exp": now() + 600,
                "iat": now(),
            }),
        );
        let err = v.verify(&token).await.expect_err("unknown kid");
        assert_eq!(err, IamError::InvalidCredentials);
    }
}
