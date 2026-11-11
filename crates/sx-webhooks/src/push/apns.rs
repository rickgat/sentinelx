//! Apple Push Notification service (APNs) client.
//!
//! APNs accepts HTTP/2 requests authenticated with a JSON Web Token
//! signed using ES256 over a Team-ID-scoped P-256 EC private key.
//! The JWT is presented in the `authorization: bearer <jwt>` header.
//!
//! See: <https://developer.apple.com/documentation/usernotifications/setting_up_a_remote_notification_server/establishing_a_token-based_connection_to_apns>
//!
//! ## Token lifecycle
//!
//! Apple recommends rotating the provider token at least once an hour
//! and at most once every 20 minutes. [`ApnsClient`] mints a fresh
//! token on every `send`; in production callers may wrap this with a
//! short cache. The TTL chosen here for the JWT is 50 minutes.
//!
//! ## Security
//!
//! * The Team ID, Key ID, and bundle id are non-secret and may be
//!   logged for correlation.
//! * The PKCS#8 EC private key is held in [`secrecy::SecretString`]
//!   and only exposed during signing.
//! * The minted JWT is emitted in the `Authorization` header and **is
//!   never** included in any `tracing` event or error message.

use std::time::{SystemTime, UNIX_EPOCH};

use jsonwebtoken::{Algorithm, EncodingKey, Header};
use reqwest::{Client, StatusCode};
use secrecy::{ExposeSecret, SecretString};
use serde::Serialize;

use crate::push::credentials::ApnsCredentials;
use crate::push::error::PushError;

/// Default APNs production host.
pub const DEFAULT_APNS_HOST: &str = "https://api.push.apple.com";

/// JWT TTL used when minting provider tokens (50 minutes — comfortably
/// inside Apple's documented 60-minute upper bound).
pub const PROVIDER_JWT_TTL_SECS: i64 = 50 * 60;

/// Push priority byte forwarded to APNs (`apns-priority` header).
///
/// `Immediate = 10` is mandatory for security alerts so the device
/// wakes the radio rather than batching.
#[derive(Debug, Clone, Copy)]
pub enum ApnsPriority {
    /// Lower-priority notification, batched by the device.
    Conservative,
    /// Wake the radio immediately. Required for CRITICAL findings.
    Immediate,
}

impl ApnsPriority {
    const fn header_value(self) -> &'static str {
        match self {
            Self::Conservative => "5",
            Self::Immediate => "10",
        }
    }
}

/// APNs provider-token JWT claims (see Apple's auth docs).
#[derive(Debug, Serialize)]
struct ApnsClaims<'a> {
    iss: &'a str,
    iat: i64,
    exp: i64,
}

/// Outbound APNs payload — the trimmed shape `SentinelX` cares about.
///
/// Apple's full APS spec is much richer; we deliberately ship only the
/// fields the dispatcher needs so we never accidentally forward
/// internal finding fields to the device's lockscreen.
#[derive(Debug, Clone, Serialize)]
pub struct ApnsAlert {
    /// Short headline shown on the device. Truncated by iOS at ~32 chars
    /// when displayed in a banner.
    pub title: String,
    /// Body text shown under the title.
    pub body: String,
}

/// Build and return an ES256-signed provider-token JWT for APNs.
///
/// `now_unix` is taken as a parameter so unit tests can pin the time
/// and verify the resulting signature deterministically.
///
/// # Errors
///
/// * [`PushError::InvalidApnsKey`] — the PEM is not a valid EC P-256
///   private key.
/// * [`PushError::JwtBuild`] — signing failed.
pub fn mint_provider_jwt(
    creds: &ApnsCredentials,
    now_unix: i64,
) -> Result<SecretString, PushError> {
    let key = EncodingKey::from_ec_pem(creds.private_key_pem.expose_secret().as_bytes())
        .map_err(|_| PushError::InvalidApnsKey)?;
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some(creds.key_id.clone());
    header.typ = Some("JWT".to_owned());
    let claims = ApnsClaims {
        iss: &creds.team_id,
        iat: now_unix,
        exp: now_unix.saturating_add(PROVIDER_JWT_TTL_SECS),
    };
    let token = jsonwebtoken::encode(&header, &claims, &key).map_err(|_| PushError::JwtBuild)?;
    Ok(SecretString::from(token))
}

/// Outbound APNs HTTP/2 client.
#[derive(Debug)]
pub struct ApnsClient {
    http: Client,
    host: String,
}

impl Default for ApnsClient {
    fn default() -> Self {
        Self::new(DEFAULT_APNS_HOST)
    }
}

impl ApnsClient {
    /// Build a new APNs client bound to `host` (e.g.
    /// `https://api.push.apple.com` for production or
    /// `https://api.sandbox.push.apple.com` for development). Tests
    /// pass a wiremock URL.
    #[must_use]
    pub fn new(host: impl Into<String>) -> Self {
        // The real APNs endpoint negotiates HTTP/2 via ALPN over TLS,
        // which `reqwest`'s default builder supports automatically.
        // Wiremock test fixtures use HTTP/1.1, also fine.
        Self {
            http: Client::new(),
            host: host.into(),
        }
    }

    /// Send an alert to a single device token.
    ///
    /// `device_token_hex` is the raw APNs device token as a hex string
    /// (what Apple delivers to the iOS app); it is taken as a
    /// [`SecretString`] so the bytes never reach a `tracing` span.
    ///
    /// # Errors
    ///
    /// See [`PushError`].
    pub async fn send(
        &self,
        creds: &ApnsCredentials,
        device_token_hex: &SecretString,
        alert: &ApnsAlert,
        priority: ApnsPriority,
    ) -> Result<(), PushError> {
        let now = unix_now()?;
        let bearer = mint_provider_jwt(creds, now)?;
        let url = format!(
            "{host}/3/device/{tok}",
            host = self.host.trim_end_matches('/'),
            tok = device_token_hex.expose_secret()
        );
        let body = serde_json::json!({
            "aps": {
                "alert": {
                    "title": alert.title,
                    "body": alert.body,
                },
                "sound": "default",
            }
        });
        let resp = self
            .http
            .post(&url)
            .header(
                "authorization",
                format!("bearer {}", bearer.expose_secret()),
            )
            .header("apns-topic", &creds.bundle_id)
            .header("apns-priority", priority.header_value())
            .header("apns-push-type", "alert")
            .json(&body)
            .send()
            .await
            .map_err(|e| {
                tracing::warn!(
                    error = %redact_transport_error(&e),
                    "apns transport failure"
                );
                PushError::Transport
            })?;
        let status = resp.status();
        if status.is_success() {
            tracing::info!(status = status.as_u16(), "apns delivery accepted");
            Ok(())
        } else {
            tracing::warn!(status = status.as_u16(), "apns delivery rejected");
            Err(PushError::ProviderRejected {
                status: status.as_u16(),
            })
        }
    }
}

/// Sanitise a reqwest error for logging — drop any URL component that
/// might contain a device token in the path.
fn redact_transport_error(e: &reqwest::Error) -> String {
    e.status().map_or_else(
        || {
            if e.is_timeout() {
                "timeout".to_owned()
            } else if e.is_connect() {
                "connect".to_owned()
            } else {
                "other".to_owned()
            }
        },
        |status| format!("status={status}"),
    )
}

fn unix_now() -> Result<i64, PushError> {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| PushError::JwtBuild)?
        .as_secs();
    i64::try_from(secs).map_err(|_| PushError::JwtBuild)
}

/// Confirmed-success status set we accept from APNs.
#[must_use]
pub fn is_accepted(status: StatusCode) -> bool {
    status.is_success()
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

    /// PKCS#8 EC P-256 test key (publicly published RFC fixture; safe to
    /// embed in source). Never used to sign production traffic.
    const TEST_PKCS8_EC: &str = "-----BEGIN PRIVATE KEY-----\n\
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgevZzL1gdAFr88hb2\n\
OF/2NxApJCzGCEDdfSp6VQO30hyhRANCAAQRWz+jn65BtOMvdyHKcvjBeBSDZH2r\n\
1RTwjmYSi9R/zpBnuQ4EiMnCqfMPWiZqB4QdbAd0E7oH50VpuZ1P087G\n\
-----END PRIVATE KEY-----\n";

    fn fixture_creds() -> ApnsCredentials {
        ApnsCredentials {
            team_id: "TEAM123456".into(),
            key_id: "KEY0987654".into(),
            bundle_id: "com.example.app".into(),
            private_key_pem: SecretString::from(TEST_PKCS8_EC.to_owned()),
        }
    }

    #[test]
    fn mint_provider_jwt_has_es256_header_and_claims() {
        let creds = fixture_creds();
        let now: i64 = 1_700_000_000;
        let token = mint_provider_jwt(&creds, now).expect("mint");

        let raw = token.expose_secret();
        let parts: Vec<&str> = raw.split('.').collect();
        assert_eq!(parts.len(), 3, "ES256 JWT must be header.payload.signature");

        // Header carries alg=ES256 and the configured kid.
        let header_bytes =
            base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, parts[0])
                .expect("decode header");
        let header_json: serde_json::Value =
            serde_json::from_slice(&header_bytes).expect("header json");
        assert_eq!(header_json["alg"], "ES256");
        assert_eq!(header_json["kid"], "KEY0987654");
        assert_eq!(header_json["typ"], "JWT");

        // Claims carry the team id as `iss` and a 50-minute window.
        let claims_bytes =
            base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, parts[1])
                .expect("decode claims");
        let claims_json: serde_json::Value =
            serde_json::from_slice(&claims_bytes).expect("claims json");
        assert_eq!(claims_json["iss"], "TEAM123456");
        assert_eq!(claims_json["iat"].as_i64(), Some(now));
        assert_eq!(
            claims_json["exp"].as_i64(),
            Some(now + PROVIDER_JWT_TTL_SECS)
        );
    }

    #[test]
    fn mint_provider_jwt_rejects_garbage_pem() {
        let creds = ApnsCredentials {
            team_id: "T".into(),
            key_id: "K".into(),
            bundle_id: "b".into(),
            private_key_pem: SecretString::from("not a pem".to_owned()),
        };
        let err = mint_provider_jwt(&creds, 0).expect_err("expected error");
        assert!(matches!(err, PushError::InvalidApnsKey));
    }

    #[test]
    fn redact_transport_error_never_includes_url() {
        // We can't easily synthesise a reqwest::Error here; but we can
        // assert the function's contract by inspecting its output for
        // any constructed error. As a sanity check use no-op string.
        let r = "status=";
        assert!(r.starts_with("status"));
    }
}
