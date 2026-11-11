//! OIDC confidential-client domain (MED-004).
//!
//! [`OidcClient`] is the SentinelX-side record of a confidential `OAuth2`
//! client that authenticates via either `client_secret_basic`,
//! `client_secret_post`, or — MED-004 — `client_secret_jwt` (RFC 7523).
//!
//! ## Rotation grace window
//!
//! Every client carries a `secret` (the live credential) and an optional
//! `previous_secret` carried for the rotation handover. During the grace
//! window (`previous_expires_at` in the future) both secrets are accepted;
//! once the grace expires the previous secret is dropped on next access.
//!
//! Secrets are kept in [`secrecy::SecretString`] so they never appear in
//! logs. The [`std::fmt::Debug`] impl redacts them explicitly.

use std::fmt;

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::domain::TenantId;

/// Opaque, customer-facing client identifier.
///
/// The `client_id` is treated as a stable string. We do not enforce a UUID
/// shape so operators can pick human-readable IDs (`sx-cli`, `acme-bot`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ClientId(pub String);

impl ClientId {
    /// Construct a `client_id` from a borrowed string.
    #[must_use]
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    /// Borrow the underlying string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ClientId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Surface identifier — an opaque uuid the storage row is keyed on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct OidcClientRowId(pub Uuid);

impl OidcClientRowId {
    /// Mint a fresh row id.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for OidcClientRowId {
    fn default() -> Self {
        Self::new()
    }
}

/// Permitted client-auth method on the token endpoint.
///
/// Variants match the RFC 7591 / OIDC Core `token_endpoint_auth_method`
/// metadata. MED-004 introduces `ClientSecretJwt`; the other two are
/// reserved for future use cases (currently unused — the token endpoint
/// only accepts the JWT method).
#[allow(clippy::enum_variant_names)] // RFC-mandated names; renaming would break OIDC compatibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientAuthMethod {
    /// HTTP Basic with `client_id:client_secret`.
    ClientSecretBasic,
    /// `client_id` + `client_secret` in form-encoded body.
    ClientSecretPost,
    /// MED-004 — JWT signed with the client's shared secret (RFC 7523).
    ClientSecretJwt,
}

impl ClientAuthMethod {
    /// Stable on-disk name (matches `serde(rename_all="snake_case")`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ClientSecretBasic => "client_secret_basic",
            Self::ClientSecretPost => "client_secret_post",
            Self::ClientSecretJwt => "client_secret_jwt",
        }
    }
}

/// Single-version secret bytes wrapped for log hygiene.
#[derive(Clone)]
pub struct ClientSecret(pub SecretString);

impl ClientSecret {
    /// Wrap a raw string as a [`ClientSecret`].
    #[must_use]
    pub fn from_string(s: String) -> Self {
        Self(SecretString::from(s))
    }

    /// Expose the secret bytes. Caller MUST NOT log.
    #[must_use]
    pub fn expose(&self) -> &str {
        self.0.expose_secret()
    }
}

impl fmt::Debug for ClientSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ClientSecret(<redacted>)")
    }
}

/// Persistent confidential-client record.
///
/// Stored in the `oidc_clients` table (one row per `(tenant_id,
/// client_id)`). Secrets are envelope-encrypted at rest via `sx-secrets`
/// before storage; the in-memory shape carries them already-decrypted as
/// [`ClientSecret`] so use cases can validate without re-decrypting on
/// every request.
#[derive(Clone)]
pub struct OidcClient {
    /// Surrogate uuid primary key (set by the repository).
    pub row_id: OidcClientRowId,
    /// Owning tenant.
    pub tenant_id: TenantId,
    /// Opaque, customer-facing client identifier.
    pub client_id: ClientId,
    /// Permitted token-endpoint auth method.
    pub auth_method: ClientAuthMethod,
    /// Current live secret.
    pub secret: ClientSecret,
    /// Previous secret retained for the rotation grace window.
    /// `None` outside an active rotation.
    pub previous_secret: Option<ClientSecret>,
    /// Wall-clock instant the previous secret stops being accepted.
    /// `None` outside an active rotation.
    pub previous_expires_at: Option<OffsetDateTime>,
    /// Wall-clock of the most recent rotation (never `None` — populated
    /// on initial creation as well so audit can compute age).
    pub rotated_at: OffsetDateTime,
    /// Creation timestamp.
    pub created_at: OffsetDateTime,
}

impl fmt::Debug for OidcClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OidcClient")
            .field("row_id", &self.row_id)
            .field("tenant_id", &self.tenant_id)
            .field("client_id", &self.client_id)
            .field("auth_method", &self.auth_method)
            .field("secret", &"<redacted>")
            .field(
                "previous_secret",
                &self.previous_secret.as_ref().map(|_| "<redacted>"),
            )
            .field("previous_expires_at", &self.previous_expires_at)
            .field("rotated_at", &self.rotated_at)
            .field("created_at", &self.created_at)
            .finish()
    }
}

impl OidcClient {
    /// Iterate over every secret that is currently accepted (live +
    /// previous if grace not expired).
    ///
    /// The caller is expected to pass `now` so grace-window decisions
    /// are testable without injecting a clock everywhere.
    pub fn accepted_secrets(&self, now: OffsetDateTime) -> Vec<&ClientSecret> {
        let mut out = Vec::with_capacity(2);
        out.push(&self.secret);
        if let (Some(prev), Some(exp)) = (self.previous_secret.as_ref(), self.previous_expires_at) {
            if exp > now {
                out.push(prev);
            }
        }
        out
    }

    /// True when the rotation grace window is currently in effect.
    #[must_use]
    pub fn is_in_grace(&self, now: OffsetDateTime) -> bool {
        matches!(self.previous_expires_at, Some(exp) if exp > now)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use time::Duration;

    fn sample(now: OffsetDateTime) -> OidcClient {
        OidcClient {
            row_id: OidcClientRowId::new(),
            tenant_id: TenantId::new(),
            client_id: ClientId::new("acme-bot"),
            auth_method: ClientAuthMethod::ClientSecretJwt,
            secret: ClientSecret::from_string("live".into()),
            previous_secret: Some(ClientSecret::from_string("prev".into())),
            previous_expires_at: Some(now + Duration::days(7)),
            rotated_at: now,
            created_at: now,
        }
    }

    #[test]
    fn debug_redacts_secrets() {
        // Use values that cannot collide with field-name substrings.
        let now = OffsetDateTime::now_utc();
        let c = OidcClient {
            row_id: OidcClientRowId::new(),
            tenant_id: TenantId::new(),
            client_id: ClientId::new("acme-bot"),
            auth_method: ClientAuthMethod::ClientSecretJwt,
            secret: ClientSecret::from_string("LIVESECRETVAL".into()),
            previous_secret: Some(ClientSecret::from_string("OLDSECRETVAL".into())),
            previous_expires_at: Some(now + Duration::days(7)),
            rotated_at: now,
            created_at: now,
        };
        let s = format!("{c:?}");
        assert!(s.contains("<redacted>"));
        assert!(!s.contains("LIVESECRETVAL"));
        assert!(!s.contains("OLDSECRETVAL"));
    }

    #[test]
    fn accepted_secrets_includes_previous_when_in_grace() {
        let now = OffsetDateTime::now_utc();
        let c = sample(now);
        let accepted = c.accepted_secrets(now);
        assert_eq!(accepted.len(), 2);
        assert_eq!(accepted[0].expose(), "live");
        assert_eq!(accepted[1].expose(), "prev");
        assert!(c.is_in_grace(now));
    }

    #[test]
    fn accepted_secrets_drops_previous_after_grace() {
        let now = OffsetDateTime::now_utc();
        let mut c = sample(now);
        c.previous_expires_at = Some(now - Duration::seconds(1));
        let accepted = c.accepted_secrets(now);
        assert_eq!(accepted.len(), 1);
        assert!(!c.is_in_grace(now));
    }

    #[test]
    fn client_secret_debug_does_not_leak() {
        let s = ClientSecret::from_string("super-secret-token".into());
        let rendered = format!("{s:?}");
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains("super-secret-token"));
    }

    #[test]
    fn auth_method_as_str_matches_serde() {
        assert_eq!(
            ClientAuthMethod::ClientSecretJwt.as_str(),
            "client_secret_jwt"
        );
        assert_eq!(
            ClientAuthMethod::ClientSecretBasic.as_str(),
            "client_secret_basic"
        );
        assert_eq!(
            ClientAuthMethod::ClientSecretPost.as_str(),
            "client_secret_post"
        );
    }
}
