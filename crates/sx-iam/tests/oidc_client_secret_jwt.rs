//! MED-004 — end-to-end integration tests for the OIDC
//! `client_secret_jwt` (RFC 7523) confidential-client authentication.
//!
//! The use case under test is
//! [`sx_iam::controller::ClientCredentialsTokenUseCase`]; the test
//! drives it via the trait-based ports it accepts so the wiring used in
//! `services/sx-monolith` is exercised identically here.
//!
//! Scenarios covered:
//!
//! 1. **Happy path** — a freshly minted, well-formed assertion against
//!    the live secret produces a `Bearer` access token.
//! 2. **Wrong secret** — assertion HS256-signed with the wrong shared
//!    secret is rejected as `InvalidCredentials` / `InvalidToken` (mapped
//!    to `IamError::InvalidToken`).
//! 3. **Expired JWT** — assertion whose `exp` lies in the past is
//!    rejected as `TokenExpired`.
//! 4. **Replayed `jti`** — the same `jti` posted twice within the replay
//!    window is rejected on the second submission.
//! 5. **Rotation grace** — after [`RotateOidcClientSecretUseCase`] runs,
//!    the previous secret remains valid for the configured grace window
//!    and the use case surfaces `used_previous_secret = true` so the
//!    HTTP layer can emit a `Warning: rotate-now` header.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::significant_drop_tightening
)]

use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration as StdDuration;

use async_trait::async_trait;
use secrecy::{ExposeSecret, SecretString};
use sx_iam::config::{JwtAlgorithm, JwtConfig};
use sx_iam::controller::{
    ClientCredentialsTokenUseCase, RotateOidcClientSecretUseCase, RotationConfig,
};
use sx_iam::domain::TenantId;
use sx_iam::model::{ClientAuthMethod, ClientId, ClientSecret, OidcClient, OidcClientRowId};
use sx_iam::port::OidcClientRepository;
use sx_iam::service::client_assertion::{
    mint_assertion_for_test, ClientAssertionConfig, InMemoryJtiCache,
};
use sx_iam::service::Clock;
use sx_iam::IamError;
use time::OffsetDateTime;

// -----------------------------------------------------------------------
// Test scaffolding
// -----------------------------------------------------------------------

const TEST_AUDIENCE: &str = "https://sx.example/v1/oauth/token";
const TEST_CLIENT_ID: &str = "acme-bot";

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
        let g = self.rows.lock().unwrap();
        Ok(g.iter()
            .find(|c| c.tenant_id == tenant_id && c.client_id == *client_id)
            .cloned())
    }

    async fn create(&self, client: &OidcClient) -> Result<(), IamError> {
        self.rows.lock().unwrap().push(client.clone());
        Ok(())
    }

    async fn update(&self, client: &OidcClient) -> Result<(), IamError> {
        let mut g = self.rows.lock().unwrap();
        let idx = g
            .iter()
            .position(|c| c.tenant_id == client.tenant_id && c.client_id == client.client_id)
            .ok_or_else(|| IamError::repository("not found"))?;
        g[idx] = client.clone();
        Ok(())
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
    ClientAssertionConfig::new(TEST_AUDIENCE)
}

fn seed_client(repo: &Arc<InMemRepo>, now: OffsetDateTime, secret: &str) -> (TenantId, ClientId) {
    let tenant_id = TenantId::new();
    let client_id = ClientId::new(TEST_CLIENT_ID);
    let client = OidcClient {
        row_id: OidcClientRowId::new(),
        tenant_id,
        client_id: client_id.clone(),
        auth_method: ClientAuthMethod::ClientSecretJwt,
        secret: ClientSecret::from_string(secret.into()),
        previous_secret: None,
        previous_expires_at: None,
        rotated_at: now,
        created_at: now,
    };
    let mut g = repo.rows.lock().unwrap();
    g.push(client);
    drop(g);
    (tenant_id, client_id)
}

fn build_token_uc(
    repo: Arc<InMemRepo>,
    clock: Arc<FixedClock>,
    cache: Arc<InMemoryJtiCache>,
) -> ClientCredentialsTokenUseCase<InMemRepo, FixedClock, InMemoryJtiCache> {
    ClientCredentialsTokenUseCase::new(repo, clock, cache, assertion_cfg(), jwt_cfg())
}

// -----------------------------------------------------------------------
// MED-004 acceptance scenarios
// -----------------------------------------------------------------------

#[tokio::test]
async fn happy_path_client_secret_jwt_mints_bearer_token() {
    let now = OffsetDateTime::now_utc();
    let repo = Arc::new(InMemRepo::default());
    let (tenant, cid) = seed_client(&repo, now, "live-secret");
    let uc = build_token_uc(
        Arc::clone(&repo),
        Arc::new(FixedClock(now)),
        Arc::new(InMemoryJtiCache::new()),
    );

    let now_unix = now.unix_timestamp();
    let assertion = mint_assertion_for_test(
        cid.as_str(),
        "live-secret",
        TEST_AUDIENCE,
        "jti-happy",
        now_unix,
        now_unix + 60,
    );

    let out = uc.execute(tenant, &cid, &assertion).await.unwrap();
    assert_eq!(out.token_type, "Bearer");
    assert_eq!(out.expires_in, 900);
    assert!(!out.used_previous_secret);
    // 3-part JWS.
    let token = out.access_token.expose_secret().to_owned();
    assert_eq!(token.split('.').count(), 3);
}

#[tokio::test]
async fn wrong_secret_rejects() {
    let now = OffsetDateTime::now_utc();
    let repo = Arc::new(InMemRepo::default());
    let (tenant, cid) = seed_client(&repo, now, "live-secret");
    let uc = build_token_uc(
        Arc::clone(&repo),
        Arc::new(FixedClock(now)),
        Arc::new(InMemoryJtiCache::new()),
    );

    let now_unix = now.unix_timestamp();
    let assertion = mint_assertion_for_test(
        cid.as_str(),
        "WRONG-SECRET",
        TEST_AUDIENCE,
        "jti-wrong",
        now_unix,
        now_unix + 60,
    );

    let err = uc.execute(tenant, &cid, &assertion).await.unwrap_err();
    assert_eq!(err, IamError::InvalidToken);
}

#[tokio::test]
async fn expired_jwt_rejects() {
    let now = OffsetDateTime::now_utc();
    let repo = Arc::new(InMemRepo::default());
    let (tenant, cid) = seed_client(&repo, now, "live-secret");
    let uc = build_token_uc(
        Arc::clone(&repo),
        Arc::new(FixedClock(now)),
        Arc::new(InMemoryJtiCache::new()),
    );

    let now_unix = now.unix_timestamp();
    let assertion = mint_assertion_for_test(
        cid.as_str(),
        "live-secret",
        TEST_AUDIENCE,
        "jti-expired",
        now_unix - 600,
        now_unix - 300,
    );

    let err = uc.execute(tenant, &cid, &assertion).await.unwrap_err();
    assert_eq!(err, IamError::TokenExpired);
}

#[tokio::test]
async fn replayed_jti_rejects_second_time() {
    let now = OffsetDateTime::now_utc();
    let repo = Arc::new(InMemRepo::default());
    let (tenant, cid) = seed_client(&repo, now, "live-secret");
    let cache = Arc::new(InMemoryJtiCache::new());
    let uc = build_token_uc(
        Arc::clone(&repo),
        Arc::new(FixedClock(now)),
        Arc::clone(&cache),
    );

    let now_unix = now.unix_timestamp();
    let assertion = mint_assertion_for_test(
        cid.as_str(),
        "live-secret",
        TEST_AUDIENCE,
        "jti-replay",
        now_unix,
        now_unix + 60,
    );

    let _ = uc.execute(tenant, &cid, &assertion).await.unwrap();
    let err = uc.execute(tenant, &cid, &assertion).await.unwrap_err();
    assert_eq!(err, IamError::InvalidToken);
}

#[tokio::test]
async fn rotation_grace_old_secret_accepted_with_warning_flag() {
    // End-to-end: rotate the secret, then submit an assertion signed
    // with the *previous* secret. The token use case must accept and
    // flag `used_previous_secret = true` so the HTTP layer can warn the
    // caller to rotate now.
    let now = OffsetDateTime::now_utc();
    let repo = Arc::new(InMemRepo::default());
    let (tenant, cid) = seed_client(&repo, now, "old-secret");

    // Rotate.
    let rotate_clock = Arc::new(FixedClock(now));
    let rotate_uc = RotateOidcClientSecretUseCase::new(
        Arc::clone(&repo),
        Arc::clone(&rotate_clock),
        RotationConfig::standard(),
    );
    let out = rotate_uc.execute(tenant, &cid).await.unwrap();
    assert_ne!(out.new_secret.expose_secret(), "old-secret");
    assert!(out.previous_expires_at > now);

    // Submit assertion signed with the *previous* secret — must accept.
    let token_uc = build_token_uc(
        Arc::clone(&repo),
        Arc::clone(&rotate_clock),
        Arc::new(InMemoryJtiCache::new()),
    );
    let now_unix = now.unix_timestamp();
    let assertion_old = mint_assertion_for_test(
        cid.as_str(),
        "old-secret",
        TEST_AUDIENCE,
        "jti-grace",
        now_unix,
        now_unix + 60,
    );
    let out_old = token_uc
        .execute(tenant, &cid, &assertion_old)
        .await
        .unwrap();
    assert!(
        out_old.used_previous_secret,
        "grace window must accept previous secret"
    );

    // Submit assertion signed with the new secret — must also accept,
    // with `used_previous_secret = false`.
    let assertion_new = mint_assertion_for_test(
        cid.as_str(),
        out.new_secret.expose_secret(),
        TEST_AUDIENCE,
        "jti-new",
        now_unix,
        now_unix + 60,
    );
    let out_new = token_uc
        .execute(tenant, &cid, &assertion_new)
        .await
        .unwrap();
    assert!(!out_new.used_previous_secret);
}

#[tokio::test]
async fn rotation_post_grace_old_secret_rejected() {
    // Same setup as above but the grace window has lapsed by the time
    // the old secret is presented. Must reject.
    let now = OffsetDateTime::now_utc();
    let repo = Arc::new(InMemRepo::default());
    let (tenant, cid) = seed_client(&repo, now, "old-secret");

    // Rotate at `now`.
    let rotate_clock = Arc::new(FixedClock(now));
    let rotate_uc = RotateOidcClientSecretUseCase::new(
        Arc::clone(&repo),
        Arc::clone(&rotate_clock),
        RotationConfig::standard(), // 7 days
    );
    let _ = rotate_uc.execute(tenant, &cid).await.unwrap();

    // Fast-forward the token use case's clock by 8 days.
    let later = now + time::Duration::days(8);
    let later_clock = Arc::new(FixedClock(later));
    let token_uc = build_token_uc(
        Arc::clone(&repo),
        Arc::clone(&later_clock),
        Arc::new(InMemoryJtiCache::new()),
    );

    let later_unix = later.unix_timestamp();
    let assertion = mint_assertion_for_test(
        cid.as_str(),
        "old-secret",
        TEST_AUDIENCE,
        "jti-post-grace",
        later_unix,
        later_unix + 60,
    );

    let err = token_uc
        .execute(tenant, &cid, &assertion)
        .await
        .unwrap_err();
    assert_eq!(err, IamError::InvalidToken);
}

#[tokio::test]
async fn audience_mismatch_rejects() {
    // Defence-in-depth: an assertion whose `aud` claim names a
    // different SentinelX deployment MUST be rejected. This is the
    // single defence against token re-injection across tenants.
    let now = OffsetDateTime::now_utc();
    let repo = Arc::new(InMemRepo::default());
    let (tenant, cid) = seed_client(&repo, now, "live-secret");
    let uc = build_token_uc(
        Arc::clone(&repo),
        Arc::new(FixedClock(now)),
        Arc::new(InMemoryJtiCache::new()),
    );

    let now_unix = now.unix_timestamp();
    let assertion = mint_assertion_for_test(
        cid.as_str(),
        "live-secret",
        "https://attacker.example/v1/oauth/token",
        "jti-aud",
        now_unix,
        now_unix + 60,
    );

    let err = uc.execute(tenant, &cid, &assertion).await.unwrap_err();
    assert_eq!(err, IamError::InvalidToken);
}

#[tokio::test]
async fn iss_sub_mismatch_with_client_id_rejects() {
    // Per RFC 7523 §3 the `iss` MUST equal the `sub` and both MUST
    // equal the `client_id`. An assertion claiming to be from a
    // different client must be rejected.
    let now = OffsetDateTime::now_utc();
    let repo = Arc::new(InMemRepo::default());
    let (tenant, cid) = seed_client(&repo, now, "live-secret");
    let uc = build_token_uc(
        Arc::clone(&repo),
        Arc::new(FixedClock(now)),
        Arc::new(InMemoryJtiCache::new()),
    );

    let now_unix = now.unix_timestamp();
    let assertion = mint_assertion_for_test(
        "DIFFERENT-CLIENT",
        "live-secret",
        TEST_AUDIENCE,
        "jti-iss-mismatch",
        now_unix,
        now_unix + 60,
    );

    let err = uc.execute(tenant, &cid, &assertion).await.unwrap_err();
    assert_eq!(err, IamError::InvalidToken);
}

#[tokio::test]
async fn unknown_client_returns_invalid_credentials() {
    let now = OffsetDateTime::now_utc();
    let repo = Arc::new(InMemRepo::default());
    let uc = build_token_uc(
        Arc::clone(&repo),
        Arc::new(FixedClock(now)),
        Arc::new(InMemoryJtiCache::new()),
    );

    let err = uc
        .execute(TenantId::new(), &ClientId::new("ghost"), "x.y.z")
        .await
        .unwrap_err();
    assert_eq!(err, IamError::InvalidCredentials);
}
