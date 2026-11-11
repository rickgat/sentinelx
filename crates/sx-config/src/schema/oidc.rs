//! OIDC (`OpenID` Connect) verifier configuration.
//!
//! The dashboard registers an OIDC provider (Keycloak / Auth0 / Okta) when
//! `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET` are exported. After
//! the redirect dance the dashboard hands the resulting `id_token` to the
//! `SentinelX` API via `POST /v1/auth/oidc/exchange`, and the API verifies the
//! token against the `IdP`'s JWKS, then issues an SX-internal token pair.
//!
//! This module owns the configuration the verifier consumes. Disabled by
//! default — when an operator flips `enabled: true`, the three top-level
//! identifiers (`issuer`, `audience`, `jwks_url`) become mandatory.
//!
//! Credential fields are NOT [`secrecy::SecretString`] — these are
//! externally-published trust-anchors, not secrets.

use serde::Deserialize;
use uuid::Uuid;
use validator::Validate;

/// Default JWKS cache TTL when the `IdP` does not advertise one — 1 hour.
const fn default_jwks_cache_secs() -> u64 {
    3600
}

/// Default tenant claim name inspected on the OIDC `id_token`.
fn default_oidc_tenant_claim() -> String {
    "tenant_id".to_string()
}

/// Default roles granted to a JIT-provisioned OIDC user.
fn default_oidc_default_roles() -> Vec<String> {
    vec!["analyst".to_string()]
}

/// OIDC verifier configuration.
///
/// Disabled by default. When `enabled` is `true`:
///   * `issuer`, `audience`, `jwks_url` MUST be non-empty.
///   * `jwks_url` MUST be `https://...` so the verifier cannot be tricked
///     into trusting a plaintext JWKS feed.
#[derive(Debug, Clone, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
pub struct OidcConfig {
    /// Whether the OIDC verifier + exchange endpoint should be wired in.
    pub enabled: bool,

    /// `iss` claim the verifier requires on every incoming `id_token`. Set
    /// this to the `IdP`'s published issuer (e.g.
    /// `https://login.example.com/realms/sentinelx`).
    #[serde(default)]
    pub issuer: String,

    /// `aud` claim the verifier requires. Normally the OIDC client id (or
    /// one of the audiences if the `IdP` issues multi-audience tokens).
    #[serde(default)]
    pub audience: String,

    /// HTTPS URL of the `IdP`'s JWKS endpoint
    /// (e.g. `https://login.example.com/realms/sentinelx/protocol/openid-connect/certs`).
    #[serde(default)]
    pub jwks_url: String,

    /// TTL of the in-memory JWKS cache, in seconds. Defaults to 1 hour.
    #[serde(default = "default_jwks_cache_secs")]
    pub jwks_cache_secs: u64,

    /// Whether to provision a fresh SX user when the OIDC claim email is not
    /// yet known to the platform. When `false` and the user is missing the
    /// exchange returns `InvalidCredentials`.
    #[serde(default)]
    pub jit_provision: bool,

    /// Role names granted to a JIT-provisioned user. Defaults to
    /// `["analyst"]`.
    #[serde(default = "default_oidc_default_roles")]
    pub default_roles: Vec<String>,

    /// Tenant uuid to assign to a JIT-provisioned user when the OIDC claim
    /// does not carry a tenant id. Optional — without it, exchanges for
    /// users without a tenant claim are rejected.
    #[serde(default)]
    pub default_tenant_id: Option<Uuid>,

    /// Name of the OIDC claim that carries the SX tenant id. Defaults to
    /// `"tenant_id"`. The verifier inspects this claim verbatim; the
    /// exchange use case then parses it as a uuid.
    #[serde(default = "default_oidc_tenant_claim")]
    pub tenant_id_claim: String,
}

impl Default for OidcConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            issuer: String::new(),
            audience: String::new(),
            jwks_url: String::new(),
            jwks_cache_secs: default_jwks_cache_secs(),
            jit_provision: false,
            default_roles: default_oidc_default_roles(),
            default_tenant_id: None,
            tenant_id_claim: default_oidc_tenant_claim(),
        }
    }
}

impl OidcConfig {
    /// Cross-field invariants. Disabled configs always pass.
    pub(crate) fn check_invariants(&self) -> Result<(), crate::ConfigError> {
        if !self.enabled {
            return Ok(());
        }
        if self.issuer.trim().is_empty() {
            return Err(crate::ConfigError::missing("oidc.issuer"));
        }
        if self.audience.trim().is_empty() {
            return Err(crate::ConfigError::missing("oidc.audience"));
        }
        if self.jwks_url.trim().is_empty() {
            return Err(crate::ConfigError::missing("oidc.jwks_url"));
        }
        if !self.jwks_url.starts_with("https://") {
            return Err(crate::ConfigError::invalid(
                "oidc.jwks_url",
                "must be an https:// URL",
            ));
        }
        if self.tenant_id_claim.trim().is_empty() {
            return Err(crate::ConfigError::invalid(
                "oidc.tenant_id_claim",
                "must be a non-empty claim name",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::OidcConfig;

    fn enabled() -> OidcConfig {
        OidcConfig {
            enabled: true,
            issuer: "https://idp.example.com/realms/sx".into(),
            audience: "sentinelx-dashboard".into(),
            jwks_url: "https://idp.example.com/realms/sx/protocol/openid-connect/certs".into(),
            ..OidcConfig::default()
        }
    }

    #[test]
    fn disabled_passes_with_no_fields() {
        OidcConfig::default()
            .check_invariants()
            .expect("disabled config must always pass");
    }

    #[test]
    fn enabled_requires_issuer() {
        let mut cfg = enabled();
        cfg.issuer = String::new();
        let err = cfg.check_invariants().expect_err("missing issuer");
        assert!(
            matches!(err, crate::ConfigError::MissingValue { ref key } if key == "oidc.issuer"),
            "got {err:?}"
        );
    }

    #[test]
    fn enabled_requires_audience() {
        let mut cfg = enabled();
        cfg.audience = String::new();
        let err = cfg.check_invariants().expect_err("missing audience");
        assert!(
            matches!(err, crate::ConfigError::MissingValue { ref key } if key == "oidc.audience"),
            "got {err:?}"
        );
    }

    #[test]
    fn enabled_requires_jwks_url() {
        let mut cfg = enabled();
        cfg.jwks_url = String::new();
        let err = cfg.check_invariants().expect_err("missing jwks_url");
        assert!(
            matches!(err, crate::ConfigError::MissingValue { ref key } if key == "oidc.jwks_url"),
            "got {err:?}"
        );
    }

    #[test]
    fn enabled_requires_https_jwks_url() {
        let mut cfg = enabled();
        cfg.jwks_url = "http://idp.example.com/jwks".into();
        let err = cfg.check_invariants().expect_err("http jwks");
        assert!(
            matches!(err, crate::ConfigError::InvalidValue { ref key, .. } if key == "oidc.jwks_url"),
            "got {err:?}"
        );
    }

    #[test]
    fn default_tenant_claim_is_tenant_id() {
        let cfg = OidcConfig::default();
        assert_eq!(cfg.tenant_id_claim, "tenant_id");
    }

    #[test]
    fn default_roles_includes_analyst() {
        let cfg = OidcConfig::default();
        assert_eq!(cfg.default_roles, vec!["analyst".to_string()]);
    }
}
