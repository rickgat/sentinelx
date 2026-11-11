//! Authorization permission value (`resource:action`).

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::DomainError;

/// A single permission — a `(resource, action)` pair.
///
/// Resources and actions are lowercase snake-case tokens. The on-wire
/// form is `"resource:action"`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Permission {
    /// The resource the permission applies to (e.g. `"engagement"`).
    pub resource: String,
    /// The action permitted on the resource (e.g. `"approve"`).
    pub action: String,
}

impl Permission {
    /// Construct and validate.
    pub fn new(
        resource: impl Into<String>,
        action: impl Into<String>,
    ) -> Result<Self, DomainError> {
        let resource = resource.into();
        let action = action.into();
        validate_token("resource", &resource)?;
        validate_token("action", &action)?;
        Ok(Self { resource, action })
    }

    /// Parse a `resource:action` string into a [`Permission`].
    ///
    /// Provided for source-compatibility with the legacy `sx-iam` API
    /// (`Permission::parse(s)`). Both halves must be non-empty.
    pub fn parse(s: &str) -> Result<Self, DomainError> {
        s.parse()
    }

    /// Borrow the resource half (left of the colon).
    ///
    /// Method form provided for source-compatibility with the legacy
    /// `sx-iam` API. The field [`Permission::resource`] is also `pub` and
    /// may be accessed directly.
    #[must_use]
    pub fn resource(&self) -> &str {
        &self.resource
    }

    /// Borrow the action half (right of the colon).
    ///
    /// Method form provided for source-compatibility with the legacy
    /// `sx-iam` API. The field [`Permission::action`] is also `pub` and
    /// may be accessed directly.
    #[must_use]
    pub fn action(&self) -> &str {
        &self.action
    }
}

fn validate_token(label: &str, t: &str) -> Result<(), DomainError> {
    if t.is_empty() {
        return Err(DomainError::invalid(format!("{label} cannot be empty")));
    }
    if t.len() > 64 {
        return Err(DomainError::invalid(format!(
            "{label} exceeds 64 bytes: {t}",
        )));
    }
    if !t
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '*')
    {
        return Err(DomainError::invalid(format!(
            "{label} must be lowercase ascii / digits / underscore / '*': {t}",
        )));
    }
    Ok(())
}

impl fmt::Display for Permission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.resource, self.action)
    }
}

impl FromStr for Permission {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.splitn(2, ':');
        let resource = parts
            .next()
            .ok_or_else(|| DomainError::invalid("permission missing resource"))?;
        let action = parts.next().ok_or_else(|| {
            DomainError::invalid("permission missing action — expected 'resource:action'")
        })?;
        Self::new(resource, action)
    }
}

impl TryFrom<String> for Permission {
    type Error = DomainError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl From<Permission> for String {
    fn from(p: Permission) -> Self {
        p.to_string()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn parse_round_trip() {
        let p = Permission::from_str("engagement:approve").unwrap();
        assert_eq!(p.resource, "engagement");
        assert_eq!(p.action, "approve");
        assert_eq!(p.to_string(), "engagement:approve");
    }

    #[test]
    fn wildcard_allowed() {
        assert!(Permission::new("engagement", "*").is_ok());
        assert!(Permission::new("*", "*").is_ok());
    }

    #[test]
    fn rejects_missing_action() {
        assert!(Permission::from_str("engagement").is_err());
    }

    #[test]
    fn rejects_uppercase() {
        assert!(Permission::new("Engagement", "approve").is_err());
    }

    #[test]
    fn rejects_empty() {
        assert!(Permission::new("", "approve").is_err());
        assert!(Permission::new("engagement", "").is_err());
    }
}
