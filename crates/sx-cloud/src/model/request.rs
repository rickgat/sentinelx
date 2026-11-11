//! Driver input for [`crate::service::CloudConnector::list_resources`].

use serde::{Deserialize, Serialize};

use super::provider::CloudProvider;

/// What the caller wants enumerated.
///
/// Defaults are deliberately permissive: an empty request asks every
/// connector to list every supported resource kind in its default scope.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ListResourcesRequest {
    /// Optional provider filter; if `Some`, only the matching connector
    /// should respond.
    #[serde(default)]
    pub provider: Option<CloudProvider>,
    /// Optional service filter (`"iam"`, `"compute"`, ...). Each connector
    /// interprets this in its own namespace.
    #[serde(default)]
    pub service: Option<String>,
    /// Maximum number of pages to consume. `None` means "exhaust pagination".
    #[serde(default)]
    pub max_pages: Option<u32>,
}

impl ListResourcesRequest {
    /// Returns `true` when this connector should respond to `req`.
    #[must_use]
    pub fn applies_to(&self, provider: CloudProvider) -> bool {
        self.provider.is_none_or(|p| p == provider)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::{CloudProvider, ListResourcesRequest};

    #[test]
    fn applies_to_all_when_unset() {
        let r = ListResourcesRequest::default();
        assert!(r.applies_to(CloudProvider::Aws));
        assert!(r.applies_to(CloudProvider::Gcp));
        assert!(r.applies_to(CloudProvider::Azure));
    }

    #[test]
    fn applies_to_filters_provider() {
        let r = ListResourcesRequest {
            provider: Some(CloudProvider::Gcp),
            ..Default::default()
        };
        assert!(!r.applies_to(CloudProvider::Aws));
        assert!(r.applies_to(CloudProvider::Gcp));
    }
}
