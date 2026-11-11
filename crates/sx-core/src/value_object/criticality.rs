//! Asset criticality classification.

use std::fmt;

use serde::{Deserialize, Serialize};

/// How important an asset is to the business.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
#[serde(rename_all = "snake_case")]
pub enum AssetCriticality {
    /// Criticality has not been classified.
    #[default]
    Unknown,
    /// Development / sandbox.
    Dev,
    /// Pre-production / staging.
    Staging,
    /// Production workload.
    Production,
    /// Crown-jewel: outage or breach is existential.
    CrownJewel,
}

impl fmt::Display for AssetCriticality {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Unknown => "unknown",
            Self::Dev => "dev",
            Self::Staging => "staging",
            Self::Production => "production",
            Self::CrownJewel => "crown_jewel",
        };
        f.write_str(s)
    }
}

/// Tolerant parse for a criticality string into [`AssetCriticality`].
///
/// Returns `None` when the input is empty or does not match any known
/// alias. The match is case-insensitive and accepts:
///
/// * `"unknown"`
/// * `"dev"`, `"development"`
/// * `"staging"`, `"stage"`, `"pre-prod"`, `"preprod"`
/// * `"production"`, `"prod"`
/// * `"crown_jewel"`, `"crownjewel"`, `"crown-jewel"`, `"crown jewel"`
///
/// Whitespace around the input is trimmed before matching. Callers that
/// want the loud-default behaviour can do
/// `parse_criticality(s).unwrap_or(AssetCriticality::Unknown)`.
#[must_use]
pub fn parse_criticality(value: &str) -> Option<AssetCriticality> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    let lower = trimmed.to_ascii_lowercase();
    match lower.as_str() {
        "unknown" => Some(AssetCriticality::Unknown),
        "dev" | "development" => Some(AssetCriticality::Dev),
        "staging" | "stage" | "pre-prod" | "preprod" => Some(AssetCriticality::Staging),
        "production" | "prod" => Some(AssetCriticality::Production),
        "crown_jewel" | "crownjewel" | "crown-jewel" | "crown jewel" => {
            Some(AssetCriticality::CrownJewel)
        }
        _ => None,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn ordering() {
        assert!(AssetCriticality::Unknown < AssetCriticality::Dev);
        assert!(AssetCriticality::Dev < AssetCriticality::Staging);
        assert!(AssetCriticality::Staging < AssetCriticality::Production);
        assert!(AssetCriticality::Production < AssetCriticality::CrownJewel);
    }

    #[test]
    fn display() {
        assert_eq!(AssetCriticality::CrownJewel.to_string(), "crown_jewel");
    }

    #[test]
    fn parse_known_canonical_values() {
        assert_eq!(
            parse_criticality("unknown"),
            Some(AssetCriticality::Unknown)
        );
        assert_eq!(parse_criticality("dev"), Some(AssetCriticality::Dev));
        assert_eq!(
            parse_criticality("staging"),
            Some(AssetCriticality::Staging)
        );
        assert_eq!(
            parse_criticality("production"),
            Some(AssetCriticality::Production),
        );
        assert_eq!(
            parse_criticality("crown_jewel"),
            Some(AssetCriticality::CrownJewel),
        );
    }

    #[test]
    fn parse_is_case_insensitive() {
        assert_eq!(
            parse_criticality("Production"),
            Some(AssetCriticality::Production),
        );
        assert_eq!(
            parse_criticality("CROWN_JEWEL"),
            Some(AssetCriticality::CrownJewel),
        );
    }

    #[test]
    fn parse_accepts_crown_jewel_aliases() {
        for s in ["crown_jewel", "crownjewel", "crown-jewel", "crown jewel"] {
            assert_eq!(
                parse_criticality(s),
                Some(AssetCriticality::CrownJewel),
                "alias {s} should map to CrownJewel",
            );
        }
    }

    #[test]
    fn parse_accepts_prod_alias() {
        assert_eq!(
            parse_criticality("prod"),
            Some(AssetCriticality::Production)
        );
        assert_eq!(
            parse_criticality("  PROD  "),
            Some(AssetCriticality::Production)
        );
    }

    #[test]
    fn parse_rejects_empty_and_garbage() {
        assert_eq!(parse_criticality(""), None);
        assert_eq!(parse_criticality("   "), None);
        assert_eq!(parse_criticality("low"), None);
        assert_eq!(parse_criticality("ultra"), None);
    }

    #[test]
    fn display_then_parse_roundtrips_all_variants() {
        for v in [
            AssetCriticality::Unknown,
            AssetCriticality::Dev,
            AssetCriticality::Staging,
            AssetCriticality::Production,
            AssetCriticality::CrownJewel,
        ] {
            assert_eq!(parse_criticality(&v.to_string()), Some(v));
        }
    }
}
