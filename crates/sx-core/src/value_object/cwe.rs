//! Common Weakness Enumeration (CWE) identifier.
//!
//! Newtype around the numeric CWE id with a serde representation that
//! round-trips through the canonical `CWE-<n>` string form. CWE ids are
//! published by MITRE at <https://cwe.mitre.org/>.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::DomainError;

/// A CWE identifier (e.g. `CWE-79` cross-site scripting).
///
/// The wire form is the canonical `CWE-<n>` string used by NVD, CVE.org,
/// SARIF, GitHub Code Scanning, and most downstream consumers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CweId(u32);

impl CweId {
    /// Construct a CWE id. The argument is the numeric portion (e.g. `79`
    /// for `CWE-79`). `0` is rejected because CWE ids are 1-based.
    pub fn new(id: u32) -> Result<Self, DomainError> {
        if id == 0 {
            return Err(DomainError::invalid("CWE id must be > 0"));
        }
        Ok(Self(id))
    }

    /// Numeric form (e.g. `79`).
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self.0
    }
}

impl fmt::Display for CweId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CWE-{}", self.0)
    }
}

impl FromStr for CweId {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let stripped = s
            .strip_prefix("CWE-")
            .or_else(|| s.strip_prefix("cwe-"))
            .ok_or_else(|| {
                DomainError::invalid(format!("CWE id must start with 'CWE-', got {s:?}"))
            })?;
        let n: u32 = stripped
            .parse()
            .map_err(|e| DomainError::invalid(format!("CWE id suffix not a u32: {e}")))?;
        Self::new(n)
    }
}

impl Serialize for CweId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for CweId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::from_str(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn display_format() {
        assert_eq!(CweId::new(79).unwrap().to_string(), "CWE-79");
    }

    #[test]
    fn from_str_canonical() {
        assert_eq!(CweId::from_str("CWE-89").unwrap(), CweId::new(89).unwrap());
    }

    #[test]
    fn from_str_lowercase_prefix() {
        assert_eq!(CweId::from_str("cwe-22").unwrap(), CweId::new(22).unwrap());
    }

    #[test]
    fn rejects_zero() {
        assert!(matches!(CweId::new(0), Err(DomainError::InvalidValue(_))));
    }

    #[test]
    fn rejects_missing_prefix() {
        assert!(matches!(
            CweId::from_str("79"),
            Err(DomainError::InvalidValue(_)),
        ));
    }

    #[test]
    fn serde_round_trip() {
        let c = CweId::new(319).unwrap();
        let s = serde_json::to_string(&c).unwrap();
        assert_eq!(s, "\"CWE-319\"");
        let back: CweId = serde_json::from_str(&s).unwrap();
        assert_eq!(back, c);
    }
}
