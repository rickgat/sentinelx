//! Authentication input — `email + password`.
//!
//! The password is wrapped in [`SecretString`] so it cannot accidentally
//! be `Display`ed, logged, or compared with `==` (which would leak via
//! timing). The struct intentionally does not derive `Debug` on the
//! password field; the wrapper's own redacted `Debug` is used.

use secrecy::SecretString;

use crate::domain::TenantId;

/// Inputs to [`crate::controller::AuthenticateUserUseCase`].
#[derive(Debug)]
pub struct Credentials {
    /// Tenant scope. Authentication is always tenant-bound — two
    /// tenants may legitimately register the same email.
    pub tenant_id: TenantId,
    /// Login email. Normalised to lower-case before lookup.
    pub email: String,
    /// Plaintext password — never persisted, never logged.
    pub password: SecretString,
}

impl Credentials {
    /// Build a [`Credentials`] from raw inputs, normalising the email.
    #[must_use]
    pub fn new(tenant_id: TenantId, email: impl Into<String>, password: SecretString) -> Self {
        Self {
            tenant_id,
            email: email.into().trim().to_ascii_lowercase(),
            password,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use secrecy::SecretString;

    #[test]
    fn email_normalised_on_construction() {
        let c = Credentials::new(
            TenantId::new(),
            "  Alice@Example.COM ",
            SecretString::from("pw".to_string()),
        );
        assert_eq!(c.email, "alice@example.com");
    }

    #[test]
    fn password_redacts_in_debug() {
        let c = Credentials::new(
            TenantId::new(),
            "a@b.io",
            SecretString::from("hunter2".to_string()),
        );
        let dbg = format!("{c:?}");
        assert!(!dbg.contains("hunter2"));
    }
}
