//! The three cloud providers `sx-cloud` knows how to talk to.

use serde::{Deserialize, Serialize};

/// Identifies one of the supported hyperscalers.
///
/// Used both as a discriminator on [`crate::model::CloudResource`] and as the
/// return value of [`crate::service::CloudConnector::provider`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CloudProvider {
    /// Amazon Web Services.
    Aws,
    /// Google Cloud Platform.
    Gcp,
    /// Microsoft Azure.
    Azure,
}

impl CloudProvider {
    /// Short lowercase identifier (`"aws"`, `"gcp"`, `"azure"`). Stable for
    /// log lines and metric labels.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Aws => "aws",
            Self::Gcp => "gcp",
            Self::Azure => "azure",
        }
    }
}

impl std::fmt::Display for CloudProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::CloudProvider;

    #[test]
    fn cloud_provider_round_trip_serde() {
        for p in [CloudProvider::Aws, CloudProvider::Gcp, CloudProvider::Azure] {
            let j = serde_json::to_string(&p).unwrap();
            let back: CloudProvider = serde_json::from_str(&j).unwrap();
            assert_eq!(p, back);
        }
        assert_eq!(CloudProvider::Aws.as_str(), "aws");
        assert_eq!(CloudProvider::Gcp.to_string(), "gcp");
    }
}
