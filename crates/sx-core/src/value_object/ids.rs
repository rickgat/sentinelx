//! Strongly-typed identifier newtypes.
//!
//! Every aggregate-root ID in the domain is a distinct newtype over
//! [`uuid::Uuid`] (v7 — time-ordered). This prevents accidentally
//! passing a [`UserId`] where a [`TenantId`] is expected, and gives a
//! stable serialised form for transport.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::DomainError;

/// Generate a `UUIDv7` identifier — time-ordered, lexicographically sortable.
#[inline]
#[must_use]
pub fn new_uuid_v7() -> Uuid {
    Uuid::now_v7()
}

macro_rules! id_newtype {
    ($(#[$meta:meta])* $name:ident, $entity:literal) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(Uuid);

        impl $name {
            /// Generate a new time-ordered (v7) identifier.
            #[must_use]
            pub fn new() -> Self {
                Self(new_uuid_v7())
            }

            /// Wrap an existing [`Uuid`].
            #[must_use]
            pub const fn from_uuid(id: Uuid) -> Self {
                Self(id)
            }

            /// Borrow the underlying [`Uuid`].
            #[must_use]
            pub const fn as_uuid(&self) -> &Uuid {
                &self.0
            }

            /// Consume `self` and return the underlying [`Uuid`].
            #[must_use]
            pub const fn into_uuid(self) -> Uuid {
                self.0
            }

            /// Logical entity name — useful for [`crate::error::DomainError::NotFound`].
            #[must_use]
            pub const fn entity_name() -> &'static str {
                $entity
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(&self.0, f)
            }
        }

        impl FromStr for $name {
            type Err = DomainError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Uuid::parse_str(s)
                    .map(Self)
                    .map_err(|e| DomainError::invalid(format!(
                        "invalid {} uuid: {}",
                        $entity, e,
                    )))
            }
        }

        impl From<Uuid> for $name {
            fn from(u: Uuid) -> Self {
                Self(u)
            }
        }

        impl From<$name> for Uuid {
            fn from(id: $name) -> Self {
                id.0
            }
        }
    };
}

id_newtype!(
    /// Identifier for a [`crate::entity::Tenant`].
    TenantId, "Tenant"
);
id_newtype!(
    /// Identifier for a [`crate::entity::User`].
    UserId, "User"
);
id_newtype!(
    /// Identifier for a [`crate::entity::Role`].
    RoleId, "Role"
);
id_newtype!(
    /// Identifier for a [`crate::entity::Engagement`].
    EngagementId, "Engagement"
);
id_newtype!(
    /// Identifier for a [`crate::entity::Asset`].
    AssetId, "Asset"
);
id_newtype!(
    /// Identifier for a [`crate::entity::Finding`].
    FindingId, "Finding"
);

/// CVE identifier (e.g. `CVE-2024-12345`).
///
/// Validated against the canonical pattern `CVE-YYYY-NNNN+`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct CveId(String);

impl CveId {
    /// Build and validate a CVE id.
    pub fn new(value: impl Into<String>) -> Result<Self, DomainError> {
        let raw = value.into();
        let upper = raw.to_ascii_uppercase();
        if !is_valid_cve(&upper) {
            return Err(DomainError::invalid(format!("invalid CVE id: {raw}")));
        }
        Ok(Self(upper))
    }

    /// Borrow the canonical string form.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CveId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for CveId {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl TryFrom<String> for CveId {
    type Error = DomainError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<CveId> for String {
    fn from(id: CveId) -> Self {
        id.0
    }
}

fn is_valid_cve(s: &str) -> bool {
    // CVE-YYYY-Nnnnn (sequence part >= 4 digits)
    let mut parts = s.split('-');
    let Some(prefix) = parts.next() else {
        return false;
    };
    let Some(year) = parts.next() else {
        return false;
    };
    let Some(seq) = parts.next() else {
        return false;
    };
    if parts.next().is_some() {
        return false;
    }
    if prefix != "CVE" {
        return false;
    }
    if year.len() != 4 || !year.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    if seq.len() < 4 || !seq.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    true
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[test]
    fn tenant_id_round_trip() {
        let id = TenantId::new();
        let s = id.to_string();
        let parsed: TenantId = s.parse().unwrap();
        assert_eq!(id, parsed);
    }

    #[test]
    fn tenant_id_default_is_unique() {
        let a = TenantId::default();
        let b = TenantId::default();
        assert_ne!(a, b);
    }

    #[test]
    fn entity_name_is_set() {
        assert_eq!(TenantId::entity_name(), "Tenant");
        assert_eq!(UserId::entity_name(), "User");
        assert_eq!(FindingId::entity_name(), "Finding");
    }

    #[test]
    fn invalid_uuid_rejected() {
        let r: Result<TenantId, _> = "not-a-uuid".parse();
        assert!(r.is_err());
    }

    #[rstest]
    #[case("CVE-2024-12345")]
    #[case("cve-1999-0001")]
    #[case("CVE-2024-1234567890")]
    fn cve_id_accepts_valid(#[case] s: &str) {
        assert!(CveId::new(s).is_ok(), "should accept {s}");
    }

    #[rstest]
    #[case("CVE-24-12345")]
    #[case("CVE-2024-123")]
    #[case("CVE--12345")]
    #[case("XVE-2024-12345")]
    #[case("CVE-2024-12345-1")]
    #[case("CVE-2024-ABCDE")]
    fn cve_id_rejects_invalid(#[case] s: &str) {
        assert!(CveId::new(s).is_err(), "should reject {s}");
    }

    #[test]
    fn cve_id_uppercases() {
        let id = CveId::new("cve-2024-12345").unwrap();
        assert_eq!(id.as_str(), "CVE-2024-12345");
    }

    #[test]
    fn uuid_conversion() {
        let u = Uuid::now_v7();
        let id = UserId::from(u);
        assert_eq!(Uuid::from(id), u);
    }
}
