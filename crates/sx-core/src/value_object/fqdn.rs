//! Fully-qualified domain name newtype, validated against RFC 1035.

use std::fmt;
use std::str::FromStr;
use std::sync::OnceLock;

use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::error::DomainError;

const MAX_FQDN_LENGTH: usize = 253;
const MAX_LABEL_LENGTH: usize = 63;

/// A normalized fully-qualified domain name.
///
/// Storage is always lowercase and never carries a trailing dot.
///
/// Validation rules (RFC 1035 + RFC 1123):
/// - total length `<= 253`
/// - each label length `1..=63`
/// - labels are `[a-z0-9-]+` (case-insensitive on input)
/// - labels do not start or end with `-`
/// - at least two labels
/// - the rightmost label (TLD) must contain at least one non-digit
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Fqdn(String);

impl Fqdn {
    /// Build and validate an [`Fqdn`].
    pub fn new(input: impl AsRef<str>) -> Result<Self, DomainError> {
        let raw = input.as_ref();
        // Strip a single trailing dot — the root indicator is valid FQDN form.
        let trimmed = raw.strip_suffix('.').unwrap_or(raw);
        let lower = trimmed.to_ascii_lowercase();

        if lower.is_empty() {
            return Err(DomainError::invalid("fqdn is empty"));
        }
        if lower.len() > MAX_FQDN_LENGTH {
            return Err(DomainError::invalid(format!(
                "fqdn exceeds {MAX_FQDN_LENGTH} bytes",
            )));
        }

        let labels: Vec<&str> = lower.split('.').collect();
        if labels.len() < 2 {
            return Err(DomainError::invalid("fqdn must have at least two labels"));
        }

        let label_re = label_regex();
        for label in &labels {
            if label.is_empty() {
                return Err(DomainError::invalid("fqdn contains empty label"));
            }
            if label.len() > MAX_LABEL_LENGTH {
                return Err(DomainError::invalid(format!(
                    "label exceeds {MAX_LABEL_LENGTH} bytes: {label}",
                )));
            }
            if label.starts_with('-') || label.ends_with('-') {
                return Err(DomainError::invalid(format!(
                    "label cannot start or end with '-': {label}",
                )));
            }
            if !label_re.is_match(label) {
                return Err(DomainError::invalid(format!(
                    "label has illegal characters: {label}",
                )));
            }
        }

        // Reject all-numeric TLD (last label) — disallows e.g. "host.123".
        let Some(tld) = labels.last() else {
            return Err(DomainError::invalid("fqdn missing tld"));
        };
        if tld.chars().all(|c| c.is_ascii_digit()) {
            return Err(DomainError::invalid(format!(
                "tld cannot be all-numeric: {tld}",
            )));
        }

        Ok(Self(lower))
    }

    /// Borrow the canonical (lowercase, no trailing dot) form.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Build a wildcard-prefixed [`Fqdn`] of the form `*.example.com`.
    ///
    /// The leading `*.` is the only deviation from the strict RFC 1035 form
    /// permitted here; it is intended for use as a [`crate::value_object::scope::ScopeTarget::Domain`]
    /// scope pattern. The suffix (everything after `*.`) is validated using
    /// the same rules as [`Fqdn::new`].
    ///
    /// # Errors
    /// Returns [`DomainError::InvalidValue`] if the input is not of the form
    /// `*.<valid-fqdn>`.
    pub fn new_wildcard(input: impl AsRef<str>) -> Result<Self, DomainError> {
        let raw = input
            .as_ref()
            .trim()
            .trim_end_matches('.')
            .to_ascii_lowercase();
        let Some(suffix) = raw.strip_prefix("*.") else {
            return Err(DomainError::invalid(format!(
                "wildcard fqdn must start with '*.': {raw}",
            )));
        };
        // Reject `*.*.example.com` etc — only a single leading wildcard.
        if suffix.starts_with("*.") || suffix.contains(".*.") || suffix.ends_with(".*") {
            return Err(DomainError::invalid(format!(
                "wildcard fqdn supports only one leading '*': {raw}",
            )));
        }
        // Validate the suffix using the canonical FQDN rules; discard the result.
        let _ = Self::new(suffix)?;
        Ok(Self(raw))
    }

    /// `true` when this is a leading-wildcard pattern (e.g. `*.example.com`).
    #[must_use]
    pub fn is_wildcard(&self) -> bool {
        self.0.starts_with("*.")
    }
}

fn label_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // Safe: literal pattern, validated by tests.
        #[allow(clippy::unwrap_used)]
        Regex::new(r"^[a-z0-9-]+$").unwrap()
    })
}

impl fmt::Display for Fqdn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for Fqdn {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl TryFrom<String> for Fqdn {
    type Error = DomainError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<Fqdn> for String {
    fn from(f: Fqdn) -> Self {
        f.0
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use rstest::rstest;

    #[rstest]
    #[case("example.com")]
    #[case("EXAMPLE.com")]
    #[case("a.b.c.example.com")]
    #[case("host-1.example.com")]
    #[case("example.com.")]
    #[case("xn--fiqs8s.cn")]
    fn accepts_valid(#[case] s: &str) {
        assert!(Fqdn::new(s).is_ok(), "should accept {s}");
    }

    #[rstest]
    #[case("")]
    #[case("nodot")]
    #[case("-leading.com")]
    #[case("trailing-.com")]
    #[case("under_score.com")]
    #[case(".leading-dot.com")]
    #[case("double..dot.com")]
    #[case("host.123")]
    fn rejects_invalid(#[case] s: &str) {
        assert!(Fqdn::new(s).is_err(), "should reject {s}");
    }

    #[test]
    fn rejects_oversize_total() {
        let s = format!("{}.com", "a".repeat(MAX_FQDN_LENGTH));
        assert!(Fqdn::new(s).is_err());
    }

    #[test]
    fn rejects_oversize_label() {
        let s = format!("{}.com", "a".repeat(MAX_LABEL_LENGTH + 1));
        assert!(Fqdn::new(s).is_err());
    }

    #[test]
    fn lowercases_canonical_form() {
        let f = Fqdn::new("EXAMPLE.com").unwrap();
        assert_eq!(f.as_str(), "example.com");
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn random_lowercase_labels_roundtrip(
            label1 in "[a-z][a-z0-9-]{0,10}[a-z0-9]",
            label2 in "[a-z][a-z0-9-]{0,10}[a-z0-9]",
            tld in "[a-z]{2,6}",
        ) {
            let s = format!("{label1}.{label2}.{tld}");
            let f = Fqdn::new(&s).unwrap();
            prop_assert_eq!(f.as_str(), s.as_str());
        }
    }
}
