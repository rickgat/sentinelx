//! `AuthorizeUseCase` — thin wrapper around [`RbacEngine`].
//!
//! Kept as a use case so HTTP handlers can depend on a single concrete
//! type per layer rather than reaching into the service layer directly.

use crate::model::AccessClaims;
use crate::service::RbacEngine;
use crate::IamError;

/// Inputs to [`AuthorizeUseCase::execute`].
#[derive(Debug)]
pub struct AuthorizeInput<'a> {
    /// Authenticated principal's claims.
    pub claims: &'a AccessClaims,
    /// Required permission, as a `"resource:action"` string.
    pub required: &'a str,
}

/// Use case: authorise a claim set against a required permission.
#[derive(Debug, Default, Clone, Copy)]
pub struct AuthorizeUseCase {
    rbac: RbacEngine,
}

impl AuthorizeUseCase {
    /// Build the use case.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            rbac: RbacEngine::new(),
        }
    }

    /// Returns `Ok(())` if the principal holds `required`, else
    /// [`IamError::Forbidden`].
    pub fn execute(&self, input: AuthorizeInput<'_>) -> Result<(), IamError> {
        self.rbac.require(input.claims, input.required)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::domain::Permission;
    use crate::model::claims::TokenType;

    fn claims_with(perms: &[&str]) -> AccessClaims {
        AccessClaims {
            sub: "u".into(),
            tenant_id: "t".into(),
            iss: "i".into(),
            aud: "a".into(),
            iat: 0,
            nbf: 0,
            exp: 9_999_999_999,
            jti: "j".into(),
            sid: "s".into(),
            token_type: TokenType::Access,
            roles: vec![],
            permissions: perms
                .iter()
                .map(|p| Permission::parse(p).unwrap())
                .collect(),
            cred_id: None,
        }
    }

    #[test]
    fn allows_when_held() {
        let c = claims_with(&["engagement:read"]);
        let uc = AuthorizeUseCase::new();
        uc.execute(AuthorizeInput {
            claims: &c,
            required: "engagement:read",
        })
        .unwrap();
    }

    #[test]
    fn denies_when_missing() {
        let c = claims_with(&["engagement:read"]);
        let uc = AuthorizeUseCase::new();
        let err = uc
            .execute(AuthorizeInput {
                claims: &c,
                required: "engagement:write",
            })
            .unwrap_err();
        assert_eq!(err, IamError::forbidden("engagement:write"));
    }
}
