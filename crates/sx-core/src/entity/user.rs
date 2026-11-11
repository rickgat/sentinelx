//! User entity — the canonical authentication identity, scoped to a tenant.
//!
//! This is the **canonical** [`User`] aggregate for the `SentinelX` workspace.
//! Sibling crates (notably `sx-iam`) re-export this type rather than carrying
//! their own copy:
//!
//! ```rust,ignore
//! pub use sx_core::entity::user::User;
//! ```
//!
//! The shape mirrors what `sx-iam` requires at the authentication boundary —
//! `email`, `password_hash`, `roles`, `is_active` — plus the [`OffsetDateTime`]
//! timestamps every persisted entity carries. Permission flattening is handled
//! by [`User::permissions`].

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::entity::permission::Permission;
use crate::entity::role::Role;
use crate::value_object::ids::{TenantId, UserId};

/// A user record sufficient for authentication and authorization.
///
/// All fields are public so adapter and use-case layers may construct
/// instances directly (e.g. when hydrating from a `users` row, or from
/// an OIDC exchange).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct User {
    /// Identifier.
    pub id: UserId,
    /// Tenant scope.
    pub tenant_id: TenantId,
    /// Login email (normalised to lower-case by the adapter).
    pub email: String,
    /// Argon2id PHC-formatted password hash.
    pub password_hash: String,
    /// Roles directly assigned to the user.
    pub roles: Vec<Role>,
    /// Whether the account is allowed to sign in at all.
    pub is_active: bool,
    /// When the user record was created.
    pub created_at: OffsetDateTime,
    /// Last update timestamp.
    pub updated_at: OffsetDateTime,
}

impl User {
    /// Flatten the user's roles into a deduplicated permission list.
    ///
    /// The order follows the iteration order of `roles`, then the iteration
    /// order of each role's `permissions`. Duplicate permissions (by value)
    /// are suppressed.
    #[must_use]
    pub fn permissions(&self) -> Vec<Permission> {
        let mut out: Vec<Permission> = Vec::new();
        for role in &self.roles {
            for p in &role.permissions {
                if !out.contains(p) {
                    out.push(p.clone());
                }
            }
        }
        out
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::value_object::ids::RoleId;

    fn ts() -> OffsetDateTime {
        OffsetDateTime::UNIX_EPOCH
    }

    #[test]
    fn permissions_flatten_and_dedupe() {
        let tenant = TenantId::new();
        let role1 = Role {
            id: RoleId::new(),
            tenant_id: tenant,
            name: "a".into(),
            permissions: vec![Permission::new("x", "y").unwrap()],
        };
        let role2 = Role {
            id: RoleId::new(),
            tenant_id: tenant,
            name: "b".into(),
            permissions: vec![
                Permission::new("x", "y").unwrap(),
                Permission::new("z", "w").unwrap(),
            ],
        };
        let u = User {
            id: UserId::new(),
            tenant_id: tenant,
            email: "a@b.co".into(),
            password_hash: String::new(),
            roles: vec![role1, role2],
            is_active: true,
            created_at: ts(),
            updated_at: ts(),
        };
        let perms = u.permissions();
        assert_eq!(perms.len(), 2);
    }

    #[test]
    fn construct_and_serde_round_trip() {
        let u = User {
            id: UserId::new(),
            tenant_id: TenantId::new(),
            email: "alice@example.com".into(),
            password_hash: "$argon2id$v=19$m=1024,t=1,p=1$abc$def".into(),
            roles: vec![],
            is_active: true,
            created_at: ts(),
            updated_at: ts(),
        };
        let json = serde_json::to_string(&u).unwrap();
        let back: User = serde_json::from_str(&json).unwrap();
        assert_eq!(u, back);
    }
}
