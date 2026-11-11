//! RBAC permission matching.
//!
//! Permissions are stored on [`crate::model::AccessClaims`] as
//! [`Permission`] values. `check` runs through the held permissions and
//! returns true on the first match. Wildcards (`*`) are honoured on
//! either half of the `resource:action` pair.
//!
//! Match rules:
//! * exact: `"engagement:read"` matches `"engagement:read"`.
//! * resource wildcard: `"*:read"` matches `"engagement:read"`.
//! * action wildcard: `"engagement:*"` matches `"engagement:read"`.
//! * global: `"*:*"` matches anything.
//!
//! Held wildcards are honoured — a holder of `"*:*"` is permitted
//! against any required permission.

use crate::domain::Permission;
use crate::model::AccessClaims;
use crate::IamError;

/// Stateless RBAC matcher.
#[derive(Debug, Default, Clone, Copy)]
pub struct RbacEngine;

impl RbacEngine {
    /// Build a new engine. The engine is stateless — claims are passed in.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Return whether `claims` grants the `required` permission.
    ///
    /// `required` is parsed as `resource:action`; a malformed `required`
    /// always returns `false` (callers will surface that as
    /// [`IamError::Forbidden`] via [`Self::require`]).
    #[must_use]
    pub fn check(&self, claims: &AccessClaims, required: &str) -> bool {
        let Ok(needed) = Permission::parse(required) else {
            return false;
        };
        claims.permissions.iter().any(|held| matches(held, &needed))
    }

    /// Return `Ok(())` if `claims` grants `required`, else
    /// [`IamError::Forbidden`].
    pub fn require(&self, claims: &AccessClaims, required: &str) -> Result<(), IamError> {
        if self.check(claims, required) {
            Ok(())
        } else {
            tracing::warn!(
                sub = %claims.sub,
                required = %required,
                "iam.rbac.denied",
            );
            Err(IamError::forbidden(required))
        }
    }
}

/// Does a *held* permission grant a *needed* permission?
fn matches(held: &Permission, needed: &Permission) -> bool {
    half_matches(held.resource(), needed.resource()) && half_matches(held.action(), needed.action())
}

/// A single half (resource or action) matches under wildcard rules.
fn half_matches(held: &str, needed: &str) -> bool {
    // The held side may be a wildcard.
    if held == "*" {
        return true;
    }
    // The needed side being a wildcard means the caller is asking
    // "do I hold anything in this slot?" — only an exact `*` held grants
    // that, which the branch above already returned.
    if needed == "*" {
        return false;
    }
    held == needed
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
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
    fn rbac_exact_match_allow() {
        let c = claims_with(&["engagement:read"]);
        assert!(RbacEngine::new().check(&c, "engagement:read"));
        RbacEngine::new().require(&c, "engagement:read").unwrap();
    }

    #[test]
    fn rbac_wildcard_match() {
        let c = claims_with(&["*:*"]);
        assert!(RbacEngine::new().check(&c, "anything:goes"));
        let c = claims_with(&["engagement:*"]);
        assert!(RbacEngine::new().check(&c, "engagement:read"));
        assert!(RbacEngine::new().check(&c, "engagement:write"));
        let c = claims_with(&["*:read"]);
        assert!(RbacEngine::new().check(&c, "engagement:read"));
        assert!(RbacEngine::new().check(&c, "tenant:read"));
        assert!(!RbacEngine::new().check(&c, "tenant:write"));
    }

    #[test]
    fn rbac_no_match_denies() {
        let c = claims_with(&["engagement:read"]);
        assert!(!RbacEngine::new().check(&c, "engagement:write"));
        assert!(!RbacEngine::new().check(&c, "tenant:read"));
        let err = RbacEngine::new().require(&c, "tenant:read").unwrap_err();
        assert_eq!(err, IamError::forbidden("tenant:read"));
    }

    #[test]
    fn rbac_malformed_required_denies() {
        let c = claims_with(&["*:*"]);
        assert!(!RbacEngine::new().check(&c, "bogus"));
        assert!(RbacEngine::new().require(&c, "bogus").is_err());
    }

    #[test]
    fn rbac_required_wildcard_never_matches_exact_grant() {
        // "Do I hold *any* engagement permission?" — must NOT be granted
        // by an exact `engagement:read` holder.
        let c = claims_with(&["engagement:read"]);
        assert!(!RbacEngine::new().check(&c, "engagement:*"));
        assert!(!RbacEngine::new().check(&c, "*:read"));
    }
}
