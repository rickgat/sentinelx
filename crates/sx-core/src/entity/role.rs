//! Role entity — a named bundle of permissions, scoped to a tenant.

use serde::{Deserialize, Serialize};

use crate::entity::permission::Permission;
use crate::error::DomainError;
use crate::value_object::ids::{RoleId, TenantId};

/// A named bundle of [`Permission`]s within a tenant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Role {
    /// Identifier.
    pub id: RoleId,
    /// Owning tenant.
    pub tenant_id: TenantId,
    /// Human-readable role name (slug).
    pub name: String,
    /// Permissions granted by membership in this role.
    pub permissions: Vec<Permission>,
}

impl Role {
    /// Construct a new role with validation.
    pub fn new(
        tenant_id: TenantId,
        name: impl Into<String>,
        permissions: Vec<Permission>,
    ) -> Result<Self, DomainError> {
        let name = name.into();
        validate_name(&name)?;
        Ok(Self {
            id: RoleId::new(),
            tenant_id,
            name,
            permissions,
        })
    }

    /// Return `true` if any held permission grants `(resource, action)`,
    /// honoring wildcard (`"*"`) on either field.
    #[must_use]
    pub fn allows(&self, resource: &str, action: &str) -> bool {
        self.permissions.iter().any(|p| {
            (p.resource == "*" || p.resource == resource) && (p.action == "*" || p.action == action)
        })
    }
}

fn validate_name(name: &str) -> Result<(), DomainError> {
    if name.is_empty() {
        return Err(DomainError::invalid("role name cannot be empty"));
    }
    if name.len() > 64 {
        return Err(DomainError::invalid(format!(
            "role name exceeds 64 bytes: {name}",
        )));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
    {
        return Err(DomainError::invalid(format!(
            "role name must be lowercase slug: {name}",
        )));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn perm(r: &str, a: &str) -> Permission {
        Permission::new(r, a).unwrap_or_else(|_| Permission::new("x", "x").unwrap())
    }

    #[test]
    fn allows_exact() {
        let role = Role::new(
            TenantId::new(),
            "admin",
            vec![perm("engagement", "approve")],
        )
        .unwrap();
        assert!(role.allows("engagement", "approve"));
        assert!(!role.allows("engagement", "delete"));
    }

    #[test]
    fn allows_wildcard() {
        let role = Role::new(TenantId::new(), "super", vec![perm("*", "*")]).unwrap();
        assert!(role.allows("anything", "everything"));
    }

    #[test]
    fn allows_action_wildcard() {
        let role = Role::new(
            TenantId::new(),
            "engagement-ops",
            vec![perm("engagement", "*")],
        )
        .unwrap();
        assert!(role.allows("engagement", "delete"));
        assert!(!role.allows("user", "create"));
    }

    #[test]
    fn rejects_bad_name() {
        assert!(Role::new(TenantId::new(), "Bad Name", vec![]).is_err());
    }
}
