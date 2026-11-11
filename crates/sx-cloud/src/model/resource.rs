//! The unified [`CloudResource`] record, returned by every connector.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::provider::CloudProvider;

/// A single piece of cloud inventory, normalized across providers.
///
/// `id` is the canonical upstream identifier:
/// - **AWS**: the resource ARN.
/// - **GCP**: the fully-qualified resource name
///   (e.g. `//compute.googleapis.com/projects/foo/zones/.../instances/i`).
/// - **Azure**: the resource id path
///   (e.g. `/subscriptions/.../resourceGroups/.../providers/...`).
///
/// `raw` preserves the upstream JSON payload as-is for downstream analyzers
/// that need fields outside the unified schema.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CloudResource {
    /// Canonical upstream identifier.
    pub id: String,
    /// Originating provider.
    pub provider: CloudProvider,
    /// Region / location the resource lives in, when applicable.
    pub region: Option<String>,
    /// Short service identifier (`"iam"`, `"compute"`, `"storage"`, ...).
    pub service: String,
    /// Kind within that service (`"user"`, `"instance"`, `"bucket"`, ...).
    pub kind: String,
    /// Display name (often the last path segment of `id`).
    pub name: String,
    /// Tag set, normalized to `BTreeMap` for stable serialization.
    pub tags: BTreeMap<String, String>,
    /// The raw upstream payload, for triage and downstream analyzers.
    #[serde(default)]
    pub raw: serde_json::Value,
}

impl CloudResource {
    /// Construct a [`CloudResource`] with no tags and no raw payload.
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        provider: CloudProvider,
        service: impl Into<String>,
        kind: impl Into<String>,
        name: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            provider,
            region: None,
            service: service.into(),
            kind: kind.into(),
            name: name.into(),
            tags: BTreeMap::new(),
            raw: serde_json::Value::Null,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::{CloudProvider, CloudResource};

    #[test]
    fn cloud_resource_serializes() {
        let r = CloudResource::new(
            "arn:aws:iam::123:user/alice",
            CloudProvider::Aws,
            "iam",
            "user",
            "alice",
        );
        let j = serde_json::to_string(&r).unwrap();
        assert!(j.contains("\"provider\":\"aws\""));
        let back: CloudResource = serde_json::from_str(&j).unwrap();
        assert_eq!(back, r);
    }
}
