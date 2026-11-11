//! Local mirror of `sx_core::value_object`.
//!
//! Only the identifiers and pagination types needed by the storage
//! layer's port signatures are mirrored here. Other value objects
//! (severity, exposure, criticality, etc.) are represented at the
//! storage boundary as `String` and converted on the way out by the
//! domain layer.

use std::fmt;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::error::DomainError;

/// Mint a new time-ordered UUID (v7).
#[inline]
#[must_use]
pub fn new_uuid_v7() -> Uuid {
    Uuid::now_v7()
}

macro_rules! id_newtype {
    ($(#[$meta:meta])* $name:ident, $entity:literal) => {
        $(#[$meta])*
        #[derive(
            Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize,
        )]
        #[serde(transparent)]
        pub struct $name(Uuid);

        impl $name {
            /// Mint a new identifier.
            #[must_use]
            pub fn new() -> Self {
                Self(new_uuid_v7())
            }

            /// Wrap an existing UUID.
            #[must_use]
            pub const fn from_uuid(id: Uuid) -> Self {
                Self(id)
            }

            /// Borrow the inner UUID.
            #[must_use]
            pub const fn as_uuid(&self) -> &Uuid {
                &self.0
            }

            /// Take the inner UUID.
            #[must_use]
            pub const fn into_uuid(self) -> Uuid {
                self.0
            }

            /// Logical entity name — used in [`DomainError::NotFound`].
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
    /// Tenant aggregate identifier.
    TenantId, "Tenant"
);
id_newtype!(
    /// User aggregate identifier.
    UserId, "User"
);
id_newtype!(
    /// Engagement aggregate identifier.
    EngagementId, "Engagement"
);
id_newtype!(
    /// Asset aggregate identifier.
    AssetId, "Asset"
);
id_newtype!(
    /// Finding aggregate identifier.
    FindingId, "Finding"
);

/// CVE identifier (`CVE-YYYY-Nnnnn`, sequence >= 4 digits).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct CveId(String);

impl CveId {
    /// Construct and validate.
    pub fn new(value: impl Into<String>) -> Result<Self, DomainError> {
        let upper = value.into().to_ascii_uppercase();
        if !is_valid_cve(&upper) {
            return Err(DomainError::invalid(format!("invalid CVE id: {upper}")));
        }
        Ok(Self(upper))
    }

    /// Borrow as `&str`.
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

/// Mirror of `sx_core::value_object::page::Page`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Page {
    /// Number of items to skip.
    pub offset: u64,
    /// Maximum items returned.
    pub limit: u32,
}

impl Page {
    /// Maximum permitted `limit`.
    pub const MAX_LIMIT: u32 = 10_000;

    /// Construct a validated page.
    pub fn new(offset: u64, limit: u32) -> Result<Self, DomainError> {
        if limit == 0 {
            return Err(DomainError::invalid("page limit must be >= 1"));
        }
        if limit > Self::MAX_LIMIT {
            return Err(DomainError::invalid(format!(
                "page limit must be <= {}",
                Self::MAX_LIMIT,
            )));
        }
        Ok(Self { offset, limit })
    }

    /// Default page (`offset = 0`, `limit = 50`).
    #[must_use]
    pub const fn first() -> Self {
        Self {
            offset: 0,
            limit: 50,
        }
    }
}

/// A page of results plus the total count for the underlying query.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PagedResult<T> {
    /// Page payload.
    pub items: Vec<T>,
    /// Total matching items, across all pages.
    pub total: u64,
    /// Originating request.
    pub page: Page,
}

impl<T> PagedResult<T> {
    /// Build from parts.
    #[must_use]
    pub const fn new(items: Vec<T>, total: u64, page: Page) -> Self {
        Self { items, total, page }
    }
}
