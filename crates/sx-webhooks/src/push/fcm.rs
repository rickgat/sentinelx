//! Firebase Cloud Messaging (FCM) HTTP v1 client.
//!
//! FCM HTTP v1 requires a Google `OAuth2` bearer token whose audience
//! is the FCM messaging scope
//! (`https://www.googleapis.com/auth/firebase.messaging`). The standard
//! way to obtain that token is the *service-account flow*:
//!
//! 1. Build a JWT with `iss = service_account_email`,
//!    `aud = "https://oauth2.googleapis.com/token"`, and
//!    `scope = "https://www.googleapis.com/auth/firebase.messaging"`.
//! 2. Sign it with RS256 over the service account's RSA private key.
//! 3. POST it to the token endpoint to exchange it for a short-lived
//!    `OAuth2` access token.
//! 4. Use that access token as a `Bearer` for FCM HTTP requests.
//!
//! See:
//! * <https://firebase.google.com/docs/cloud-messaging/migrate-v1>
//! * <https://developers.google.com/identity/protocols/oauth2/service-account>
//!
//! ## Security
//!
//! * Service-account private key is wrapped in
//!   [`secrecy::SecretString`] and only exposed during JWT signing.
//! * Issued `OAuth2` access tokens are wrapped in
//!   [`secrecy::SecretString`] and **never** logged.
//! * Provider device tokens (FCM registration ids) are wrapped in
//!   [`secrecy::SecretString`] at the call site.

use std::time::{SystemTime, UNIX_EPOCH};

use jsonwebtoken::{Algorithm, EncodingKey, Header};
use reqwest::Client;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

use crate::push::credentials::FcmCredentials;
use crate::push::error::PushError;

/// Default Google `OAuth2` token endpoint.
pub const DEFAULT_TOKEN_URI: &str = "https://oauth2.googleapis.com/token";

/// Default FCM HTTP v1 endpoint base.
pub const DEFAULT_FCM_BASE: &str = "https://fcm.googleapis.com";

/// `OAuth2` scope FCM HTTP v1 requires.
pub const FCM_SCOPE: &str = "https://www.googleapis.com/auth/firebase.messaging";

/// TTL of the `OAuth2` assertion JWT (1 hour — Google's upper bound).
pub const ASSERTION_JWT_TTL_SECS: i64 = 60 * 60;

#[derive(Debug, Serialize)]
struct AssertionClaims<'a> {
    iss: &'a str,
    scope: &'a str,
    aud: &'a str,
    iat: i64,
    exp: i64,
}

/// `OAuth2` token-exchange response from Google.
#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    #[allow(dead_code)]
    token_type: Option<String>,
    #[allow(dead_code)]
    expires_in: Option<i64>,
}

/// FCM `notification` payload.
#[derive(Debug, Clone, Serialize)]
pub struct FcmNotification {
    /// Short headline.
    pub title: String,
    /// Body text.
    pub body: String,
}

/// Build the RS256-signed assertion JWT used to obtain an `OAuth2`
/// access token.
///
/// # Errors
///
/// * [`PushError::JwtBuild`] — signing failed or the key is invalid.
pub fn build_assertion_jwt(
    creds: &FcmCredentials,
    now_unix: i64,
) -> Result<SecretString, PushError> {
    let key = EncodingKey::from_rsa_pem(creds.private_key_pem.expose_secret().as_bytes())
        .map_err(|_| PushError::JwtBuild)?;
    let header = Header::new(Algorithm::RS256);
    let token_uri = creds.token_uri.as_deref().unwrap_or(DEFAULT_TOKEN_URI);
    let claims = AssertionClaims {
        iss: &creds.client_email,
        scope: FCM_SCOPE,
        aud: token_uri,
        iat: now_unix,
        exp: now_unix.saturating_add(ASSERTION_JWT_TTL_SECS),
    };
    let token = jsonwebtoken::encode(&header, &claims, &key).map_err(|_| PushError::JwtBuild)?;
    Ok(SecretString::from(token))
}

/// FCM HTTP v1 client.
#[derive(Debug)]
pub struct FcmClient {
    http: Client,
}

impl Default for FcmClient {
    fn default() -> Self {
        Self::new()
    }
}

impl FcmClient {
    /// Build a new FCM client. The FCM endpoint base and token
    /// endpoint are taken per-call from the tenant's
    /// [`FcmCredentials`] so the same client can serve many tenants
    /// while letting tests inject a wiremock host.
    #[must_use]
    pub fn new() -> Self {
        Self {
            http: Client::new(),
        }
    }

    /// Exchange the service-account assertion for an `OAuth2` access
    /// token.
    ///
    /// # Errors
    ///
    /// * [`PushError::Transport`] — network failure.
    /// * [`PushError::ProviderRejected`] — Google rejected the
    ///   exchange.
    /// * [`PushError::JwtBuild`] — assertion JWT could not be signed.
    pub async fn fetch_access_token(
        &self,
        creds: &FcmCredentials,
    ) -> Result<SecretString, PushError> {
        let now = unix_now()?;
        let assertion = build_assertion_jwt(creds, now)?;
        let token_uri = creds.token_uri.as_deref().unwrap_or(DEFAULT_TOKEN_URI);
        let form = [
            ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
            ("assertion", assertion.expose_secret()),
        ];
        let resp = self
            .http
            .post(token_uri)
            .form(&form)
            .send()
            .await
            .map_err(|_| PushError::Transport)?;
        let status = resp.status();
        if !status.is_success() {
            tracing::warn!(
                status = status.as_u16(),
                "fcm oauth2 token exchange rejected"
            );
            return Err(PushError::ProviderRejected {
                status: status.as_u16(),
            });
        }
        let body: TokenResponse = resp.json().await.map_err(|_| PushError::Transport)?;
        Ok(SecretString::from(body.access_token))
    }

    /// Send a notification to a single FCM device token.
    ///
    /// `device_token` is the FCM registration id wrapped in a
    /// [`SecretString`].
    ///
    /// # Errors
    ///
    /// See [`PushError`].
    pub async fn send(
        &self,
        creds: &FcmCredentials,
        device_token: &SecretString,
        notification: &FcmNotification,
    ) -> Result<(), PushError> {
        let bearer = self.fetch_access_token(creds).await?;
        let base = creds
            .fcm_base_url
            .as_deref()
            .unwrap_or(DEFAULT_FCM_BASE)
            .trim_end_matches('/');
        let url = format!("{base}/v1/projects/{}/messages:send", creds.project_id);
        let body = serde_json::json!({
            "message": {
                "token": device_token.expose_secret(),
                "notification": {
                    "title": notification.title,
                    "body": notification.body,
                },
                "android": {
                    "priority": "HIGH",
                },
            }
        });
        let resp = self
            .http
            .post(&url)
            .header(
                "authorization",
                format!("Bearer {}", bearer.expose_secret()),
            )
            .json(&body)
            .send()
            .await
            .map_err(|_| PushError::Transport)?;
        let status = resp.status();
        if status.is_success() {
            tracing::info!(status = status.as_u16(), "fcm delivery accepted");
            Ok(())
        } else {
            tracing::warn!(status = status.as_u16(), "fcm delivery rejected");
            Err(PushError::ProviderRejected {
                status: status.as_u16(),
            })
        }
    }
}

fn unix_now() -> Result<i64, PushError> {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| PushError::JwtBuild)?
        .as_secs();
    i64::try_from(secs).map_err(|_| PushError::JwtBuild)
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::panic
)]
mod tests {
    use super::*;

    // RSA-2048 PKCS#8 test key — generated offline, used only by these
    // unit tests. The same fixture is shared with `sx-iam`'s OIDC verifier
    // tests; safe to embed in source as it never signs production traffic.
    const TEST_RSA_PEM: &str = "-----BEGIN PRIVATE KEY-----
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
-----END PRIVATE KEY-----
";

    fn fixture_creds() -> FcmCredentials {
        FcmCredentials {
            project_id: "demo-proj".into(),
            client_email: "svc@demo-proj.iam.gserviceaccount.com".into(),
            private_key_pem: SecretString::from(TEST_RSA_PEM.to_owned()),
            token_uri: None,
            fcm_base_url: None,
        }
    }

    #[test]
    fn build_assertion_jwt_has_rs256_header_and_claims() {
        let creds = fixture_creds();
        let now: i64 = 1_700_000_000;
        let token = build_assertion_jwt(&creds, now).expect("build");

        let raw = token.expose_secret();
        let parts: Vec<&str> = raw.split('.').collect();
        assert_eq!(parts.len(), 3, "RS256 JWT must be header.payload.signature");

        let header_bytes =
            base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, parts[0])
                .expect("decode header");
        let header_json: serde_json::Value =
            serde_json::from_slice(&header_bytes).expect("header json");
        assert_eq!(header_json["alg"], "RS256");

        let claims_bytes =
            base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, parts[1])
                .expect("decode claims");
        let claims_json: serde_json::Value =
            serde_json::from_slice(&claims_bytes).expect("claims json");
        assert_eq!(claims_json["iss"], "svc@demo-proj.iam.gserviceaccount.com");
        assert_eq!(claims_json["scope"], FCM_SCOPE);
        assert_eq!(claims_json["aud"], DEFAULT_TOKEN_URI);
        assert_eq!(claims_json["iat"].as_i64(), Some(now));
        assert_eq!(
            claims_json["exp"].as_i64(),
            Some(now + ASSERTION_JWT_TTL_SECS)
        );
    }
}
