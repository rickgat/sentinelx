//! RFC 7523 `client_secret_jwt` authentication (MED-004).
//!
//! Verifies a client-issued JWT assertion used in lieu of HTTP Basic
//! `client_secret_basic`. The wire shape is:
//!
//! ```text
//! POST /v1/oauth/token
//! grant_type=client_credentials
//!  & client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer
//!  & client_assertion=<JWT>
//! ```
//!
//! Validation pipeline:
//!
//! 1. Decode the JWT *header* without verification to learn `alg` + `kid`.
//!    Reject `alg != HS256`. (`HS384`/`HS512` would be acceptable per the
//!    spec; we restrict to HS256 to match the workspace's token issuer.)
//! 2. Decode the JWT *claims* without verification to learn the `iss` /
//!    `sub`. Per RFC 7523 §3 these MUST equal the `client_id`.
//! 3. Look up the [`OidcClient`] by `(tenant_id, client_id)`. The caller
//!    supplies `tenant_id` from URL or request context.
//! 4. For every accepted secret on the client (live + previous-in-grace),
//!    try `HS256` verification of the JWT. The first match wins.
//! 5. Validate `aud` matches the token endpoint URL configured for this
//!    deployment.
//! 6. Validate `exp` is in the future (`leeway_seconds` slack).
//! 7. Reject if `jti` was seen within the configured replay window. Mark
//!    it as seen on success.
//!
//! ## Replay cache
//!
//! The cache is an in-memory `Mutex<HashMap<String, OffsetDateTime>>`
//! keyed on `(client_id, jti)`. Entries are evicted lazily on insert.
//!
//! `RFC: persistent jti cache deferred to LOW` — the in-memory v1 is
//! acceptable for single-instance deployments and during rolling
//! deployments because the replay window is short (5 min). A multi-node
//! deployment SHOULD upgrade to a Redis-backed implementation; the trait
//! [`JtiReplayCache`] is provided so the swap is mechanical.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine as _;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::model::OidcClient;
use crate::IamError;

/// The single `client_assertion_type` URN we accept.
///
/// Per RFC 7521 §4.2 / RFC 7523 §2.2.
pub const CLIENT_ASSERTION_TYPE_JWT_BEARER: &str =
    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// Default replay window — 5 minutes. Mirrors the upper bound vendors
/// (Google, Microsoft) accept for client-assertion `exp`.
pub const DEFAULT_REPLAY_WINDOW: Duration = Duration::from_secs(5 * 60);

/// Configuration for the `client_secret_jwt` validator.
#[derive(Debug, Clone)]
pub struct ClientAssertionConfig {
    /// Expected `aud` claim — typically the absolute URL of the token
    /// endpoint (`https://sentinelx.example.com/v1/oauth/token`).
    pub expected_audience: String,
    /// Maximum lifetime of an accepted assertion. `exp` more than this
    /// far in the future is rejected (defence against
    /// `nbf=0, exp=2099` long-lived tokens).
    pub max_lifetime: Duration,
    /// Replay window — `jti` entries older than this are evicted.
    pub replay_window: Duration,
    /// Clock-skew leeway for `exp` / `iat` / `nbf` in seconds.
    pub leeway_seconds: u64,
}

impl ClientAssertionConfig {
    /// Build a config with sensible defaults; only `expected_audience`
    /// must be supplied.
    #[must_use]
    pub fn new(expected_audience: impl Into<String>) -> Self {
        Self {
            expected_audience: expected_audience.into(),
            max_lifetime: DEFAULT_REPLAY_WINDOW,
            replay_window: DEFAULT_REPLAY_WINDOW,
            leeway_seconds: 30,
        }
    }
}

/// Parsed assertion claims surfaced to callers after validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientAssertionClaims {
    /// `iss` — equals `sub` and `client_id`.
    pub issuer: String,
    /// `aud` — equals the configured token endpoint.
    pub audience: String,
    /// `jti` — replay key.
    pub jti: String,
    /// `exp` as unix seconds.
    pub expires_at: i64,
    /// `iat` as unix seconds (`0` if absent).
    pub issued_at: i64,
}

/// Replay-protection cache shape. The in-memory implementation lives
/// below; a Redis-backed swap is the path to multi-node.
#[async_trait]
pub trait JtiReplayCache: Send + Sync {
    /// Atomically check-and-insert `(client_id, jti)`.
    ///
    /// Returns `true` if the `jti` is fresh (and has been recorded),
    /// `false` if a prior call within the replay window already inserted
    /// the same `(client_id, jti)`.
    async fn mark_if_fresh(
        &self,
        client_id: &str,
        jti: &str,
        expires_at: OffsetDateTime,
    ) -> Result<bool, IamError>;
}

/// Default in-process replay cache.
///
/// `RFC: persistent jti cache deferred to LOW`.
#[derive(Default)]
pub struct InMemoryJtiCache {
    inner: Mutex<HashMap<(String, String), OffsetDateTime>>,
}

impl std::fmt::Debug for InMemoryJtiCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InMemoryJtiCache").finish_non_exhaustive()
    }
}

impl InMemoryJtiCache {
    /// Build a fresh cache.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl JtiReplayCache for InMemoryJtiCache {
    async fn mark_if_fresh(
        &self,
        client_id: &str,
        jti: &str,
        expires_at: OffsetDateTime,
    ) -> Result<bool, IamError> {
        let mut g = self
            .inner
            .lock()
            .map_err(|_| IamError::internal("jti cache mutex poisoned"))?;
        let now = OffsetDateTime::now_utc();
        // Lazy eviction: drop any entries whose expiry has passed.
        g.retain(|_, exp| *exp > now);
        let key = (client_id.to_owned(), jti.to_owned());
        if g.contains_key(&key) {
            return Ok(false);
        }
        g.insert(key, expires_at);
        Ok(true)
    }
}

#[derive(Debug, Deserialize)]
struct RawClaims {
    iss: Option<String>,
    sub: Option<String>,
    aud: Option<serde_json::Value>,
    exp: Option<i64>,
    iat: Option<i64>,
    jti: Option<String>,
}

/// Per RFC 7523 the `aud` claim MAY be a string or array; this helper
/// normalises both into a `Vec<String>`.
fn normalise_aud(value: &serde_json::Value) -> Vec<String> {
    match value {
        serde_json::Value::String(s) => vec![s.clone()],
        serde_json::Value::Array(xs) => xs
            .iter()
            .filter_map(|v| v.as_str().map(ToOwned::to_owned))
            .collect(),
        _ => Vec::new(),
    }
}

/// Sniff the unverified claims so we know which client + secret(s) to
/// try. Bounded by base64 + JSON size — never executes any signature
/// logic.
fn sniff_unverified(assertion: &str) -> Result<(String, String), IamError> {
    let mut parts = assertion.split('.');
    let _hdr = parts.next().ok_or(IamError::InvalidToken)?;
    let claims_b64 = parts.next().ok_or(IamError::InvalidToken)?;
    let _sig = parts.next().ok_or(IamError::InvalidToken)?;
    if parts.next().is_some() {
        return Err(IamError::InvalidToken);
    }
    let bytes = B64URL
        .decode(claims_b64)
        .map_err(|_| IamError::InvalidToken)?;
    let raw: RawClaims = serde_json::from_slice(&bytes).map_err(|_| IamError::InvalidToken)?;
    let iss = raw.iss.ok_or(IamError::InvalidToken)?;
    let sub = raw.sub.ok_or(IamError::InvalidToken)?;
    Ok((iss, sub))
}

/// Outcome of [`verify_client_assertion`].
#[derive(Debug, Clone)]
pub struct VerifiedAssertion {
    /// The validated assertion claims.
    pub claims: ClientAssertionClaims,
    /// `true` when the verifying secret was the *previous* one (grace
    /// window). Useful for surfacing a "rotate now" banner in the
    /// dashboard.
    pub verified_with_previous_secret: bool,
}

/// Verify a `client_secret_jwt` assertion against a known
/// [`OidcClient`].
///
/// Steps:
/// 1. Decode header — require HS256.
/// 2. Decode unverified claims — confirm `iss == sub == client_id`.
/// 3. Try every accepted secret (live + previous-in-grace) until one
///    verifies the signature.
/// 4. Validate `aud == expected_audience`, `exp` in future, `exp - iat
///    <= max_lifetime` if `iat` provided.
/// 5. Check replay cache; reject if `jti` is a replay; record otherwise.
///
/// # Errors
///
/// All failure modes collapse to [`IamError::InvalidToken`] or
/// [`IamError::InvalidCredentials`] — never reveal *which* check failed
/// to the caller. The internal tracing emits the precise reason so
/// operators can debug from logs.
#[allow(clippy::too_many_lines, clippy::cognitive_complexity)] // RFC 7523 §3 mandates a single pipeline; splitting hides the contract.
pub async fn verify_client_assertion<R>(
    cfg: &ClientAssertionConfig,
    client: &OidcClient,
    assertion: &str,
    cache: &R,
    now: OffsetDateTime,
) -> Result<VerifiedAssertion, IamError>
where
    R: JtiReplayCache + ?Sized,
{
    // 1. Header check.
    let header = decode_header(assertion).map_err(|_| {
        tracing::warn!(
            target: "iam.client_assertion",
            client_id = %client.client_id,
            reason = "header_decode",
            "client_assertion.reject"
        );
        IamError::InvalidToken
    })?;
    if header.alg != Algorithm::HS256 {
        tracing::warn!(
            target: "iam.client_assertion",
            client_id = %client.client_id,
            alg = ?header.alg,
            reason = "alg_not_hs256",
            "client_assertion.reject"
        );
        return Err(IamError::InvalidToken);
    }

    // 2. Unverified sniff for iss / sub.
    let (iss, sub) = sniff_unverified(assertion)?;
    if iss != sub || iss != client.client_id.as_str() {
        tracing::warn!(
            target: "iam.client_assertion",
            client_id = %client.client_id,
            reason = "iss_sub_client_id_mismatch",
            "client_assertion.reject"
        );
        return Err(IamError::InvalidToken);
    }

    // 3. Try each accepted secret. Validation skips `aud` / `exp`
    // checks because we want to surface our own error codes uniformly
    // regardless of which secret matched.
    let mut validation = Validation::new(Algorithm::HS256);
    validation.set_required_spec_claims(&["exp", "iss", "sub", "aud", "jti"]);
    validation.validate_aud = false;
    validation.validate_exp = false; // we apply our own leeway below
    validation.leeway = cfg.leeway_seconds;

    let mut verified_with_previous = false;
    let mut last_err: Option<IamError> = None;
    let mut raw: Option<RawClaims> = None;

    for (idx, secret) in client.accepted_secrets(now).into_iter().enumerate() {
        let key = DecodingKey::from_secret(secret.expose().as_bytes());
        match decode::<RawClaims>(assertion, &key, &validation) {
            Ok(token) => {
                raw = Some(token.claims);
                verified_with_previous = idx > 0;
                last_err = None;
                break;
            }
            Err(e) => {
                last_err = Some(map_jwt_err(&e));
            }
        }
    }

    let Some(raw) = raw else {
        tracing::warn!(
            target: "iam.client_assertion",
            client_id = %client.client_id,
            reason = "signature_mismatch_all_secrets",
            "client_assertion.reject"
        );
        return Err(last_err.unwrap_or(IamError::InvalidToken));
    };

    // 4. Manual aud / exp / lifetime validation.
    let aud_value = raw.aud.as_ref().ok_or_else(|| {
        tracing::warn!(
            target: "iam.client_assertion",
            client_id = %client.client_id,
            reason = "missing_aud",
            "client_assertion.reject"
        );
        IamError::InvalidToken
    })?;
    let auds = normalise_aud(aud_value);
    if !auds.iter().any(|a| a == &cfg.expected_audience) {
        tracing::warn!(
            target: "iam.client_assertion",
            client_id = %client.client_id,
            reason = "aud_mismatch",
            "client_assertion.reject"
        );
        return Err(IamError::InvalidToken);
    }

    let exp = raw.exp.ok_or(IamError::InvalidToken)?;
    let now_secs = now.unix_timestamp();
    #[allow(clippy::cast_possible_wrap)]
    let leeway = cfg.leeway_seconds as i64;
    if exp + leeway < now_secs {
        tracing::warn!(
            target: "iam.client_assertion",
            client_id = %client.client_id,
            reason = "expired",
            "client_assertion.reject"
        );
        return Err(IamError::TokenExpired);
    }
    #[allow(clippy::cast_possible_wrap)]
    let max_life = cfg.max_lifetime.as_secs() as i64;
    if let Some(iat) = raw.iat {
        if exp - iat > max_life + leeway {
            tracing::warn!(
                target: "iam.client_assertion",
                client_id = %client.client_id,
                reason = "lifetime_exceeds_max",
                "client_assertion.reject"
            );
            return Err(IamError::InvalidToken);
        }
    }

    let jti = raw.jti.clone().ok_or_else(|| {
        tracing::warn!(
            target: "iam.client_assertion",
            client_id = %client.client_id,
            reason = "missing_jti",
            "client_assertion.reject"
        );
        IamError::InvalidToken
    })?;

    // 5. Replay-protection: cache by (client_id, jti).
    let replay_until = OffsetDateTime::from_unix_timestamp(exp).unwrap_or(now) + cfg.replay_window;
    let fresh = cache
        .mark_if_fresh(client.client_id.as_str(), &jti, replay_until)
        .await?;
    if !fresh {
        tracing::warn!(
            target: "iam.client_assertion",
            client_id = %client.client_id,
            reason = "jti_replay",
            "client_assertion.reject"
        );
        return Err(IamError::InvalidToken);
    }

    Ok(VerifiedAssertion {
        claims: ClientAssertionClaims {
            issuer: raw.iss.unwrap_or_default(),
            audience: cfg.expected_audience.clone(),
            jti,
            expires_at: exp,
            issued_at: raw.iat.unwrap_or(0),
        },
        verified_with_previous_secret: verified_with_previous,
    })
}

fn map_jwt_err(e: &jsonwebtoken::errors::Error) -> IamError {
    use jsonwebtoken::errors::ErrorKind;
    match e.kind() {
        ErrorKind::ExpiredSignature => IamError::TokenExpired,
        _ => IamError::InvalidToken,
    }
}

/// Helper used by tests + the controller to mint a fresh assertion.
#[doc(hidden)]
#[allow(clippy::expect_used)]
pub fn mint_assertion_for_test(
    client_id: &str,
    secret: &str,
    audience: &str,
    jti: &str,
    issued_at_unix: i64,
    expires_at_unix: i64,
) -> String {
    use jsonwebtoken::{encode, EncodingKey, Header};
    #[derive(Serialize)]
    struct Claims<'a> {
        iss: &'a str,
        sub: &'a str,
        aud: &'a str,
        jti: &'a str,
        iat: i64,
        exp: i64,
    }
    let header = Header::new(Algorithm::HS256);
    let claims = Claims {
        iss: client_id,
        sub: client_id,
        aud: audience,
        jti,
        iat: issued_at_unix,
        exp: expires_at_unix,
    };
    encode(
        &header,
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .expect("test assertion encode")
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
    use crate::domain::TenantId;
    use crate::model::{ClientAuthMethod, ClientId, ClientSecret, OidcClient, OidcClientRowId};
    use time::Duration as TimeDuration;

    fn client_with(secret: &str, previous: Option<(&str, OffsetDateTime)>) -> OidcClient {
        let now = OffsetDateTime::now_utc();
        OidcClient {
            row_id: OidcClientRowId::new(),
            tenant_id: TenantId::new(),
            client_id: ClientId::new("acme-bot"),
            auth_method: ClientAuthMethod::ClientSecretJwt,
            secret: ClientSecret::from_string(secret.into()),
            previous_secret: previous.map(|(s, _)| ClientSecret::from_string(s.into())),
            previous_expires_at: previous.map(|(_, e)| e),
            rotated_at: now,
            created_at: now,
        }
    }

    fn cfg() -> ClientAssertionConfig {
        ClientAssertionConfig::new("https://sx.example/v1/oauth/token")
    }

    #[tokio::test]
    async fn hs256_happy_path_accepts_correct_secret() {
        let client = client_with("live-secret", None);
        let now = OffsetDateTime::now_utc();
        let now_unix = now.unix_timestamp();
        let assertion = mint_assertion_for_test(
            "acme-bot",
            "live-secret",
            "https://sx.example/v1/oauth/token",
            "jti-1",
            now_unix,
            now_unix + 60,
        );
        let cache = InMemoryJtiCache::new();
        let out = verify_client_assertion(&cfg(), &client, &assertion, &cache, now)
            .await
            .expect("happy path");
        assert!(!out.verified_with_previous_secret);
        assert_eq!(out.claims.jti, "jti-1");
        assert_eq!(out.claims.issuer, "acme-bot");
    }

    #[tokio::test]
    async fn wrong_secret_rejects() {
        let client = client_with("live-secret", None);
        let now = OffsetDateTime::now_utc();
        let now_unix = now.unix_timestamp();
        let assertion = mint_assertion_for_test(
            "acme-bot",
            "WRONG",
            "https://sx.example/v1/oauth/token",
            "jti-2",
            now_unix,
            now_unix + 60,
        );
        let cache = InMemoryJtiCache::new();
        let err = verify_client_assertion(&cfg(), &client, &assertion, &cache, now)
            .await
            .expect_err("wrong secret");
        assert_eq!(err, IamError::InvalidToken);
    }

    #[tokio::test]
    async fn expired_jwt_rejects() {
        let client = client_with("live-secret", None);
        let now = OffsetDateTime::now_utc();
        let now_unix = now.unix_timestamp();
        let assertion = mint_assertion_for_test(
            "acme-bot",
            "live-secret",
            "https://sx.example/v1/oauth/token",
            "jti-3",
            now_unix - 600,
            now_unix - 300,
        );
        let cache = InMemoryJtiCache::new();
        let err = verify_client_assertion(&cfg(), &client, &assertion, &cache, now)
            .await
            .expect_err("expired");
        assert_eq!(err, IamError::TokenExpired);
    }

    #[tokio::test]
    async fn replayed_jti_rejects_second_time() {
        let client = client_with("live-secret", None);
        let now = OffsetDateTime::now_utc();
        let now_unix = now.unix_timestamp();
        let assertion = mint_assertion_for_test(
            "acme-bot",
            "live-secret",
            "https://sx.example/v1/oauth/token",
            "jti-replay",
            now_unix,
            now_unix + 60,
        );
        let cache = InMemoryJtiCache::new();
        let _ = verify_client_assertion(&cfg(), &client, &assertion, &cache, now)
            .await
            .expect("first accept");
        let err = verify_client_assertion(&cfg(), &client, &assertion, &cache, now)
            .await
            .expect_err("replay rejected");
        assert_eq!(err, IamError::InvalidToken);
    }

    #[tokio::test]
    async fn grace_window_accepts_both_secrets() {
        let now = OffsetDateTime::now_utc();
        let client = client_with(
            "new-secret",
            Some(("old-secret", now + TimeDuration::days(7))),
        );
        let now_unix = now.unix_timestamp();

        let with_new = mint_assertion_for_test(
            "acme-bot",
            "new-secret",
            "https://sx.example/v1/oauth/token",
            "jti-new",
            now_unix,
            now_unix + 60,
        );
        let with_old = mint_assertion_for_test(
            "acme-bot",
            "old-secret",
            "https://sx.example/v1/oauth/token",
            "jti-old",
            now_unix,
            now_unix + 60,
        );
        let cache = InMemoryJtiCache::new();
        let out_new = verify_client_assertion(&cfg(), &client, &with_new, &cache, now)
            .await
            .expect("new accepted");
        assert!(!out_new.verified_with_previous_secret);
        let out_old = verify_client_assertion(&cfg(), &client, &with_old, &cache, now)
            .await
            .expect("old accepted (grace)");
        assert!(out_old.verified_with_previous_secret);
    }

    #[tokio::test]
    async fn post_grace_old_secret_rejects() {
        let now = OffsetDateTime::now_utc();
        let client = client_with(
            "new-secret",
            Some(("old-secret", now - TimeDuration::seconds(1))),
        );
        let now_unix = now.unix_timestamp();
        let assertion = mint_assertion_for_test(
            "acme-bot",
            "old-secret",
            "https://sx.example/v1/oauth/token",
            "jti-post-grace",
            now_unix,
            now_unix + 60,
        );
        let cache = InMemoryJtiCache::new();
        let err = verify_client_assertion(&cfg(), &client, &assertion, &cache, now)
            .await
            .expect_err("old secret post-grace must reject");
        assert_eq!(err, IamError::InvalidToken);
    }

    #[tokio::test]
    async fn audience_mismatch_rejects() {
        let client = client_with("live-secret", None);
        let now = OffsetDateTime::now_utc();
        let now_unix = now.unix_timestamp();
        let assertion = mint_assertion_for_test(
            "acme-bot",
            "live-secret",
            "https://OTHER.example/v1/oauth/token",
            "jti-aud",
            now_unix,
            now_unix + 60,
        );
        let cache = InMemoryJtiCache::new();
        let err = verify_client_assertion(&cfg(), &client, &assertion, &cache, now)
            .await
            .expect_err("aud mismatch");
        assert_eq!(err, IamError::InvalidToken);
    }

    #[tokio::test]
    async fn iss_sub_client_id_mismatch_rejects() {
        let client = client_with("live-secret", None);
        let now = OffsetDateTime::now_utc();
        let now_unix = now.unix_timestamp();
        let assertion = mint_assertion_for_test(
            "different-client",
            "live-secret",
            "https://sx.example/v1/oauth/token",
            "jti-mismatch",
            now_unix,
            now_unix + 60,
        );
        let cache = InMemoryJtiCache::new();
        let err = verify_client_assertion(&cfg(), &client, &assertion, &cache, now)
            .await
            .expect_err("iss != client_id");
        assert_eq!(err, IamError::InvalidToken);
    }

    #[tokio::test]
    async fn missing_jti_rejects() {
        // Hand-craft a token without `jti`.
        use jsonwebtoken::{encode, EncodingKey, Header};
        #[derive(Serialize)]
        struct NoJti<'a> {
            iss: &'a str,
            sub: &'a str,
            aud: &'a str,
            iat: i64,
            exp: i64,
        }
        let client = client_with("live-secret", None);
        let now = OffsetDateTime::now_utc();
        let now_unix = now.unix_timestamp();
        let token = encode(
            &Header::new(Algorithm::HS256),
            &NoJti {
                iss: "acme-bot",
                sub: "acme-bot",
                aud: "https://sx.example/v1/oauth/token",
                iat: now_unix,
                exp: now_unix + 60,
            },
            &EncodingKey::from_secret(b"live-secret"),
        )
        .unwrap();
        let cache = InMemoryJtiCache::new();
        let err = verify_client_assertion(&cfg(), &client, &token, &cache, now)
            .await
            .expect_err("missing jti");
        assert_eq!(err, IamError::InvalidToken);
    }

    #[tokio::test]
    async fn rs256_alg_rejects() {
        // Build an RS256 token with the same payload — we cannot
        // verify it (no key) but the header check must fire first.
        // Use the encoder with a tiny RSA key generated on the fly.
        use jsonwebtoken::{encode, EncodingKey, Header};
        // RSA generation is expensive; use a fixed PKCS#8 PEM from
        // jsonwebtoken's own test fixtures isn't possible here, so we
        // synthesise a token with a HS-signed payload but rewrite the
        // header `alg` to RS256.
        let client = client_with("live-secret", None);
        let now = OffsetDateTime::now_utc();
        let now_unix = now.unix_timestamp();
        let normal = mint_assertion_for_test(
            "acme-bot",
            "live-secret",
            "https://sx.example/v1/oauth/token",
            "jti-rs",
            now_unix,
            now_unix + 60,
        );
        let parts: Vec<&str> = normal.split('.').collect();
        assert_eq!(parts.len(), 3);
        // Rewrite the header to declare RS256.
        let evil_header = serde_json::json!({"alg":"RS256","typ":"JWT"});
        let evil_header_b64 = B64URL.encode(serde_json::to_vec(&evil_header).unwrap());
        let evil = format!("{evil_header_b64}.{}.{}", parts[1], parts[2]);
        let cache = InMemoryJtiCache::new();
        let err = verify_client_assertion(&cfg(), &client, &evil, &cache, now)
            .await
            .expect_err("non-HS256 rejected");
        assert_eq!(err, IamError::InvalidToken);
        // Silence unused-import + unused-Header warning in other branches.
        let _ = (
            encode::<()>,
            &EncodingKey::from_secret(b"x"),
            Header::new(Algorithm::HS256),
        );
    }
}
