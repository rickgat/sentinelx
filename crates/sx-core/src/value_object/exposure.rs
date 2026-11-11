//! Asset exposure level.

use std::fmt;

use serde::{Deserialize, Serialize};

/// Where an asset sits relative to untrusted networks.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
#[serde(rename_all = "snake_case")]
pub enum ExposureLevel {
    /// Network position is not known.
    #[default]
    Unknown,
    /// Air-gapped or otherwise isolated from production traffic.
    Isolated,
    /// Reachable only from internal networks.
    Internal,
    /// Reachable from the public internet.
    Internet,
}

impl fmt::Display for ExposureLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Unknown => "unknown",
            Self::Isolated => "isolated",
            Self::Internal => "internal",
            Self::Internet => "internet",
        };
        f.write_str(s)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn ordering() {
        assert!(ExposureLevel::Unknown < ExposureLevel::Isolated);
        assert!(ExposureLevel::Isolated < ExposureLevel::Internal);
        assert!(ExposureLevel::Internal < ExposureLevel::Internet);
    }

    #[test]
    fn display() {
        assert_eq!(ExposureLevel::Internet.to_string(), "internet");
    }

    #[test]
    fn default_is_unknown() {
        assert_eq!(ExposureLevel::default(), ExposureLevel::Unknown);
    }
}
