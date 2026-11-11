//! Tenant entity — the top-level isolation boundary.

use std::fmt;
use std::sync::OnceLock;

use regex::Regex;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::error::DomainError;
use crate::value_object::ids::TenantId;

/// Service tier for a tenant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TenantTier {
    /// Free / trial tier.
    Free,
    /// Standard paid tier.
    Standard,
    /// Enterprise tier with bespoke SLAs.
    Enterprise,
}

impl fmt::Display for TenantTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Free => "free",
            Self::Standard => "standard",
            Self::Enterprise => "enterprise",
        };
        f.write_str(s)
    }
}

/// A tenant — the root aggregate for multi-tenant isolation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tenant {
    /// Identifier.
    pub id: TenantId,
    /// Globally-unique slug name (`[a-z0-9-]{3,40}`).
    pub name: String,
    /// Service tier.
    pub tier: TenantTier,
    /// Creation timestamp.
    pub created_at: OffsetDateTime,
    /// Soft-deletion timestamp; `None` when active.
    pub deleted_at: Option<OffsetDateTime>,
}

impl Tenant {
    /// Build a tenant, validating the slug.
    pub fn new(
        name: impl Into<String>,
        tier: TenantTier,
        now: OffsetDateTime,
    ) -> Result<Self, DomainError> {
        let name = name.into();
        validate_slug(&name)?;
        Ok(Self {
            id: TenantId::new(),
            name,
            tier,
            created_at: now,
            deleted_at: None,
        })
    }

    /// Whether the tenant is currently active (not soft-deleted).
    #[must_use]
    pub const fn is_active(&self) -> bool {
        self.deleted_at.is_none()
    }

    /// Mark the tenant as soft-deleted at `at`. Idempotent: a second call
    /// with a later timestamp keeps the original deletion timestamp.
    pub const fn soft_delete(&mut self, at: OffsetDateTime) {
        if self.deleted_at.is_none() {
            self.deleted_at = Some(at);
        }
    }
}

fn slug_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        #[allow(clippy::unwrap_used)]
        Regex::new(r"^[a-z0-9][a-z0-9-]{2,39}$").unwrap()
    })
}

fn validate_slug(s: &str) -> Result<(), DomainError> {
    if !slug_regex().is_match(s) {
        return Err(DomainError::invalid(format!(
            "tenant slug must be 3..=40 chars, lowercase alphanumeric / dash: {s}",
        )));
    }
    if s.ends_with('-') {
        return Err(DomainError::invalid("tenant slug cannot end with '-'"));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn now() -> OffsetDateTime {
        OffsetDateTime::UNIX_EPOCH
    }

    #[test]
    fn accepts_valid_slug() {
        let t = Tenant::new("acme-corp", TenantTier::Standard, now()).unwrap();
        assert_eq!(t.name, "acme-corp");
        assert!(t.is_active());
    }

    #[test]
    fn rejects_uppercase() {
        assert!(Tenant::new("Acme", TenantTier::Free, now()).is_err());
    }

    #[test]
    fn rejects_too_short() {
        assert!(Tenant::new("a", TenantTier::Free, now()).is_err());
    }

    #[test]
    fn rejects_trailing_dash() {
        assert!(Tenant::new("acme-", TenantTier::Free, now()).is_err());
    }

    #[test]
    fn soft_delete_is_idempotent() {
        let mut t = Tenant::new("acme", TenantTier::Free, now()).unwrap();
        let later = now() + time::Duration::seconds(10);
        t.soft_delete(now());
        let first = t.deleted_at;
        t.soft_delete(later);
        assert_eq!(t.deleted_at, first);
        assert!(!t.is_active());
    }
}
