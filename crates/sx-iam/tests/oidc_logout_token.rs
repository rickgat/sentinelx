//! CRIT-004 — integration test for the OIDC back-channel
//! `logout_token` verifier.
//!
//! The verifier consumes a JWKS the operator has fetched (usually via
//! the existing `JwksOidcVerifier` cache). For end-to-end coverage we
//! spin up a `wiremock` IdP that publishes a JWKS, sign a fresh
//! `logout_token` with the matching RSA-2048 private key, and feed it
//! to [`sx_iam::service::logout::verify_logout_token`].
//!
//! Three cases are covered (replay protection is exercised in the
//! sibling `saml_logout_request.rs`):
//!
//! * happy path — issuer/audience/events/sid all correct.
//! * expired-style guard — `iat` is far in the past but per spec
//!   `logout_token` has no `exp`; the verifier MUST still accept it
//!   because the IdP-side rate-limit is the only thing the SP can rely
//!   on. We document this with an explicit test.
//! * `nonce_present` — spec MUST NOT carry `nonce` on a logout_token;
//!   the verifier rejects.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::doc_markdown,
    clippy::needless_pass_by_value
)]

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde_json::json;
use sx_iam::service::logout::{
    verify_logout_token, LogoutTokenVerifierConfig, BACKCHANNEL_LOGOUT_EVENT,
};
use sx_iam::IamError;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

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

const TEST_RSA_JWK_N: &str = "qpjM5Md5mwJcnmizsoLWkPfN8hTlZMA7PQ7mxLd63QovxcUO5D_UIwQSL7GTNjYBIRDnVcVvqUbyfEYwxdCeBDvGm0gsaOwQRjKaYHMsS8ayoUwmlYvh747TDVYgbCXUs-tfp52rSV1X6nkccZd4crEhSQhgLno3it2dmc5hp8BjfmGqFVSESL-DSz51wSZYtXCcwAAhUWySnBjQFK1uQgwdH9nyyUjHspgvb7CxYs-oGxRonXEHQ0jKFh82fQyq6srnSLeJz4qPX-RC3nwvPK827M6di4KnM-bkPJiclhztd00zxIjIzi_v0b4Fk4HUYQzCRYTIPGDQqJvYdUzkmQ";
const TEST_RSA_JWK_E: &str = "AQAB";

fn jwks_with(kid: &str) -> JwkSet {
    let value = json!({
        "keys": [{
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": kid,
            "n": TEST_RSA_JWK_N,
            "e": TEST_RSA_JWK_E,
        }]
    });
    serde_json::from_value(value).unwrap()
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

fn sign(kid: &str, claims: serde_json::Value) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(kid.to_string());
    let key = EncodingKey::from_rsa_pem(TEST_RSA_PRIVATE_PEM.as_bytes()).unwrap();
    encode(&header, &claims, &key).unwrap()
}

fn cfg() -> LogoutTokenVerifierConfig {
    LogoutTokenVerifierConfig {
        issuer: "https://idp.example.com/realms/sx".into(),
        audience: "sx-dashboard".into(),
        leeway: Duration::from_secs(5),
    }
}

#[tokio::test]
async fn wiremock_idp_logout_token_round_trips() {
    // Spin up a mock IdP that publishes the JWKS at /jwks. Most
    // production flows have the SP cache this set up-front; the test
    // exercises the full fetch path so a regression in the parser
    // shape (e.g. quoted vs. unquoted base64url) surfaces here.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(
            ResponseTemplate::new(200).set_body_raw(
                serde_json::to_vec(&json!({
                    "keys": [{
                        "kty": "RSA", "use": "sig", "alg": "RS256",
                        "kid": "kid-1", "n": TEST_RSA_JWK_N, "e": TEST_RSA_JWK_E,
                    }]
                }))
                .unwrap(),
                "application/json",
            ),
        )
        .mount(&server)
        .await;

    // Fetch JWKS through reqwest (sanity check on the wire shape).
    let resp = reqwest::get(format!("{}/jwks", server.uri()))
        .await
        .expect("jwks fetch");
    let body: serde_json::Value = resp.json().await.expect("jwks json");
    let jwks: JwkSet = serde_json::from_value(body).expect("parse jwks");

    // Sign + verify a well-formed logout_token.
    let token = sign(
        "kid-1",
        json!({
            "iss": "https://idp.example.com/realms/sx",
            "aud": "sx-dashboard",
            "iat": now(),
            "jti": "logout-int-1",
            "sub": "user-A",
            "sid": "idp-sess-1",
            "events": { BACKCHANNEL_LOGOUT_EVENT: {} },
        }),
    );

    let claims = verify_logout_token(&cfg(), &jwks, &token).expect("valid logout_token");
    assert_eq!(claims.session_id.as_deref(), Some("idp-sess-1"));
    assert_eq!(claims.subject.as_deref(), Some("user-A"));
    assert_eq!(claims.jti.as_deref(), Some("logout-int-1"));
}

#[tokio::test]
async fn nonce_present_is_rejected() {
    let jwks = jwks_with("kid-1");
    let token = sign(
        "kid-1",
        json!({
            "iss": "https://idp.example.com/realms/sx",
            "aud": "sx-dashboard",
            "iat": now(),
            "sub": "user-A",
            "sid": "idp-sess-2",
            "nonce": "MUST-NOT-BE-PRESENT",
            "events": { BACKCHANNEL_LOGOUT_EVENT: {} },
        }),
    );
    let err = verify_logout_token(&cfg(), &jwks, &token).expect_err("nonce forbidden");
    assert_eq!(err, IamError::InvalidCredentials);
}

#[tokio::test]
async fn missing_events_claim_is_rejected() {
    let jwks = jwks_with("kid-1");
    let token = sign(
        "kid-1",
        json!({
            "iss": "https://idp.example.com/realms/sx",
            "aud": "sx-dashboard",
            "iat": now(),
            "sub": "user-A",
            "sid": "idp-sess-3",
        }),
    );
    let err = verify_logout_token(&cfg(), &jwks, &token).expect_err("no events");
    assert_eq!(err, IamError::InvalidCredentials);
}

#[tokio::test]
async fn iat_in_past_is_still_accepted_because_logout_token_has_no_exp() {
    // Per OpenID Connect Back-Channel Logout 1.0 §2.4 the logout_token
    // has no `exp`. We document the intentional spec compliance here:
    // even a token issued an hour ago is accepted as long as
    // iss/aud/events/sid are correct.
    let jwks = jwks_with("kid-1");
    let token = sign(
        "kid-1",
        json!({
            "iss": "https://idp.example.com/realms/sx",
            "aud": "sx-dashboard",
            "iat": now() - 3600,
            "sub": "user-A",
            "sid": "idp-sess-4",
            "events": { BACKCHANNEL_LOGOUT_EVENT: {} },
        }),
    );
    let claims = verify_logout_token(&cfg(), &jwks, &token).expect("no exp on logout_token");
    assert_eq!(claims.session_id.as_deref(), Some("idp-sess-4"));
}
