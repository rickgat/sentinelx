//! Bootstrap configuration.
//!
//! Seeds an initial admin account at startup so the platform is usable on
//! first boot without a chicken-and-egg between "no users exist" and "you
//! need a user to call `/v1/auth/login`".

use secrecy::SecretString;
use serde::Deserialize;
use uuid::Uuid;
use validator::Validate;

use crate::secret;

/// Optional bootstrap settings.
///
/// When `admin_email` is set, the monolith seeds a tenant + admin user
/// with the supplied Argon2id PHC hash at startup; otherwise the
/// platform boots with no users provisioned.
///
/// When `analyst_email` + `analyst_password_phc` are also set, an
/// additional analyst-role user is seeded into the same bootstrap
/// tenant. This path backs the Playwright e2e fixture (L1-FU1); real
/// deployments should leave the analyst fields unset and provision
/// non-admin users through the SCIM / admin-user APIs instead.
#[derive(Debug, Clone, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
pub struct BootstrapConfig {
    /// Whether to attempt seeding at startup. When `false`, every other
    /// field is ignored.
    pub enabled: bool,

    /// Tenant slug for the bootstrap tenant. Must be a valid lowercase
    /// slug (letters, digits, `-`, `_`).
    #[validate(length(min = 1, max = 64))]
    pub admin_tenant_slug: String,

    /// Display name for the bootstrap tenant.
    #[validate(length(min = 1, max = 200))]
    pub admin_tenant_name: String,

    /// Optional fixed UUID for the bootstrap tenant. When `None`, a new
    /// UUID v7 is generated on first seed (recommended for production).
    pub admin_tenant_id: Option<Uuid>,

    /// Login email for the bootstrap admin. Lower-cased before lookup.
    #[validate(email)]
    pub admin_email: String,

    /// Argon2id PHC-encoded password hash for the bootstrap admin.
    /// **NEVER** ship a default value — operators must generate this
    /// per-deployment via `sx-monolith --generate-password` or an
    /// equivalent CLI.
    pub admin_password_phc: SecretString,

    /// When `true` and `enabled` is also `true`, seeds the in-memory
    /// repositories with deterministic demo data at startup. No-op when the
    /// Postgres adapter is enabled — production deployments should never
    /// turn this on.
    #[serde(default)]
    pub seed_demo_data: bool,

    /// Optional login email for an additional non-admin "analyst" user
    /// seeded into the same bootstrap tenant. Lower-cased before lookup.
    ///
    /// Exists exclusively to back the Playwright e2e suite (L1) which
    /// drives the dashboard as a non-privileged role. Real deployments
    /// should leave this `None` and provision analysts through the SCIM
    /// / admin-user surface. When set, `analyst_password_phc` MUST also
    /// be set or the loader rejects the config.
    #[serde(default)]
    #[validate(email)]
    pub analyst_email: Option<String>,

    /// Argon2id PHC-encoded password hash for the bootstrap analyst.
    /// **NEVER** ship a default value — operators must generate this
    /// per-deployment. Ignored when `analyst_email` is `None`.
    #[serde(default)]
    pub analyst_password_phc: Option<SecretString>,
}

impl BootstrapConfig {
    /// Cross-field invariants checked by the loader.
    pub(crate) fn check_invariants(&self) -> Result<(), crate::ConfigError> {
        if !self.enabled {
            return Ok(());
        }
        if secret::is_empty(&self.admin_password_phc) {
            return Err(crate::ConfigError::missing("bootstrap.admin_password_phc"));
        }
        let phc = secret::expose_str(&self.admin_password_phc);
        if !phc.starts_with("$argon2") {
            return Err(crate::ConfigError::invalid(
                "bootstrap.admin_password_phc",
                "must be an Argon2 PHC string starting with $argon2",
            ));
        }
        // Analyst seed is opt-in: both fields must be set together, or
        // both omitted. Half-configurations almost certainly mean the
        // operator typed only one half and would expect a login to work.
        match (
            self.analyst_email.as_ref(),
            self.analyst_password_phc.as_ref(),
        ) {
            (None, None) => {}
            (Some(_), None) => {
                return Err(crate::ConfigError::missing(
                    "bootstrap.analyst_password_phc",
                ));
            }
            (None, Some(_)) => {
                return Err(crate::ConfigError::missing("bootstrap.analyst_email"));
            }
            (Some(_), Some(phc)) => {
                if secret::is_empty(phc) {
                    return Err(crate::ConfigError::missing(
                        "bootstrap.analyst_password_phc",
                    ));
                }
                let phc_str = secret::expose_str(phc);
                if !phc_str.starts_with("$argon2") {
                    return Err(crate::ConfigError::invalid(
                        "bootstrap.analyst_password_phc",
                        "must be an Argon2 PHC string starting with $argon2",
                    ));
                }
            }
        }
        Ok(())
    }
}
