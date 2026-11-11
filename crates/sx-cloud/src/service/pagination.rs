//! Normalized pagination token shared across GCP and Azure connectors.
//!
//! AWS-style pagination differs per service (`Marker`, `NextToken`, etc.) and
//! is handled inline in [`crate::service::aws`].

use serde::{Deserialize, Serialize};

/// An opaque continuation cursor.
///
/// The token's contents are entirely provider-defined; this type is just a
/// type-safe wrapper around a `String` to keep the call sites legible.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaginationToken(String);

impl PaginationToken {
    /// Wrap a raw cursor returned by the upstream API.
    #[must_use]
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    /// Borrow the underlying cursor string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns `true` when the wrapped cursor is empty (meaning "no more
    /// pages" per GCP and Azure conventions).
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<String> for PaginationToken {
    fn from(s: String) -> Self {
        Self(s)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::PaginationToken;

    #[test]
    fn round_trip_value() {
        let t = PaginationToken::new("abc");
        assert_eq!(t.as_str(), "abc");
        assert!(!t.is_empty());
        assert!(PaginationToken::new("").is_empty());
    }
}
