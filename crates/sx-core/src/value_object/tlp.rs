//! Traffic Light Protocol (FIRST.org TLP 2.0) sharing markings.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::DomainError;

/// TLP 2.0 sharing classifications.
///
/// Ordered from most restrictive ([`Tlp::Red`]) to least ([`Tlp::Clear`]).
/// [`Tlp::White`] is the legacy alias for [`Tlp::Clear`] and is accepted
/// on input but normalized for display via the explicit `as_str` method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Tlp {
    /// Not for disclosure, restricted to participants only.
    Red,
    /// Limited disclosure, restricted to participants' organizations.
    Amber,
    /// Limited disclosure, restricted to the community.
    Green,
    /// Legacy alias for [`Tlp::Clear`].
    White,
    /// Disclosure is not limited.
    Clear,
}

impl Tlp {
    /// Canonical lowercase tag.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Red => "red",
            Self::Amber => "amber",
            Self::Green => "green",
            Self::White => "white",
            Self::Clear => "clear",
        }
    }
}

impl fmt::Display for Tlp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Tlp {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "red" => Ok(Self::Red),
            "amber" => Ok(Self::Amber),
            "green" => Ok(Self::Green),
            "white" => Ok(Self::White),
            "clear" => Ok(Self::Clear),
            other => Err(DomainError::invalid(format!("unknown TLP: {other}"))),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case("red", Tlp::Red)]
    #[case("AMBER", Tlp::Amber)]
    #[case("Green", Tlp::Green)]
    #[case("white", Tlp::White)]
    #[case("CLEAR", Tlp::Clear)]
    fn parse_ok(#[case] s: &str, #[case] expected: Tlp) {
        assert_eq!(Tlp::from_str(s).unwrap(), expected);
    }

    #[test]
    fn parse_err() {
        assert!(Tlp::from_str("orange").is_err());
    }

    #[test]
    fn display_round_trips() {
        for tlp in [Tlp::Red, Tlp::Amber, Tlp::Green, Tlp::White, Tlp::Clear] {
            assert_eq!(Tlp::from_str(&tlp.to_string()).unwrap(), tlp);
        }
    }

    #[test]
    fn ordering() {
        assert!(Tlp::Red < Tlp::Amber);
        assert!(Tlp::Amber < Tlp::Green);
    }
}
