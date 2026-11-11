//! Domain-layer types that this crate depends on.
//!
//! ## Phase-3 sx-core consolidation
//!
//! The identifier newtypes ([`TenantId`], [`UserId`], [`RoleId`]) and the
//! canonical [`User`] / [`Role`] / [`Permission`] aggregates are now
//! **re-exported from `sx-core`** — the canonical domain library. Other
//! crates and downstream Postgres adapters depend on the same shape (same
//! field layout, same `serde(transparent)` envelope, same constructor
//! API), so the swap is a no-op for sx-iam callers.
//!
//! What lives here:
//! - Nothing crate-local at the domain layer any more — this module is a
//!   thin compatibility shim that re-exports the canonical types so the
//!   long-established `sx_iam::domain::{User, Role, Permission}` import
//!   paths continue to work.

// ----- Identifier newtypes -------------------------------------------------
//
// `TenantId`, `UserId`, `RoleId` are sourced from sx-core. The
// re-export keeps the existing call-sites (`TenantId::new()`,
// `TenantId::from_uuid(u)`, `tid.as_uuid()`) working unchanged because
// sx-core's macro-generated newtypes expose the same surface.
pub use sx_core::value_object::ids::{RoleId, TenantId, UserId};

// ----- Canonical aggregates ------------------------------------------------
//
// `User`, `Role`, and `Permission` are sourced from sx-core. The
// re-export keeps existing construction sites (`User { id, tenant_id,
// email, password_hash, roles, is_active, created_at, updated_at }`,
// `Role { id, tenant_id, name, permissions }`, `Permission::parse("x:y")`,
// `permission.resource()`, etc.) working unchanged because the canonical
// types expose a superset of the previous sx-iam surface.
pub use sx_core::entity::permission::Permission;
pub use sx_core::entity::role::Role;
pub use sx_core::entity::user::User;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use time::OffsetDateTime;

    #[test]
    fn permission_parse_round_trip() {
        let p = Permission::parse("engagement:read").unwrap();
        assert_eq!(p.resource(), "engagement");
        assert_eq!(p.action(), "read");
        assert_eq!(p.to_string(), "engagement:read");
    }

    #[test]
    fn permission_parse_invalid_string_errors() {
        assert!(Permission::parse("noseparator").is_err());
        assert!(Permission::parse(":action").is_err());
        assert!(Permission::parse("resource:").is_err());
        assert!(Permission::parse("space :read").is_err());
        assert!(Permission::parse("res:rea d").is_err());
    }

    #[test]
    fn user_permissions_flatten_and_dedupe() {
        let tenant = TenantId::new();
        let role1 = Role {
            id: RoleId::new(),
            tenant_id: tenant,
            name: "a".into(),
            permissions: vec![Permission::parse("x:y").unwrap()],
        };
        let role2 = Role {
            id: RoleId::new(),
            tenant_id: tenant,
            name: "b".into(),
            permissions: vec![
                Permission::parse("x:y").unwrap(),
                Permission::parse("z:w").unwrap(),
            ],
        };
        let u = User {
            id: UserId::new(),
            tenant_id: tenant,
            email: "a@b".into(),
            password_hash: String::new(),
            is_active: true,
            roles: vec![role1, role2],
            created_at: OffsetDateTime::UNIX_EPOCH,
            updated_at: OffsetDateTime::UNIX_EPOCH,
        };
        let perms = u.permissions();
        assert_eq!(perms.len(), 2);
    }
}
