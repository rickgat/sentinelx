//! `Meta` — common resource metadata (RFC 7643 §3.1).

use serde::{Deserialize, Serialize};

/// SCIM resource metadata shared by every resource type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Meta {
    /// Resource type name (`User`, `Group`).
    pub resource_type: String,
    /// RFC 3339 creation timestamp.
    pub created: String,
    /// RFC 3339 last-modified timestamp.
    pub last_modified: String,
    /// Opaque ETag-like version string.
    pub version: String,
    /// Canonical URI of this resource.
    pub location: String,
}

impl Meta {
    /// Build a meta block with `created == last_modified` and a synthetic
    /// version derived from the modification timestamp.
    #[must_use]
    pub fn new(resource_type: &str, ts: &str, location: String) -> Self {
        Self {
            resource_type: resource_type.to_owned(),
            created: ts.to_owned(),
            last_modified: ts.to_owned(),
            version: format!("W/\"{ts}\""),
            location,
        }
    }

    /// Update `last_modified` to `ts` and bump `version` to match.
    pub fn touch(&mut self, ts: &str) {
        self.last_modified = ts.to_owned();
        self.version = format!("W/\"{ts}\"");
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
#[allow(clippy::expect_used)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::Meta;

    #[test]
    fn meta_round_trips_camel_case() {
        let m = Meta::new("User", "2026-06-12T00:00:00Z", "/scim/v2/Users/x".into());
        let j = serde_json::to_value(&m).expect("serialise");
        assert_eq!(j["resourceType"], "User");
        assert_eq!(j["lastModified"], "2026-06-12T00:00:00Z");
        let parsed: Meta = serde_json::from_value(j).expect("deserialise");
        assert_eq!(parsed, m);
    }

    #[test]
    fn touch_updates_last_modified_and_version() {
        let mut m = Meta::new("User", "2026-06-12T00:00:00Z", "/x".into());
        m.touch("2026-06-13T00:00:00Z");
        assert_eq!(m.last_modified, "2026-06-13T00:00:00Z");
        assert_eq!(m.version, "W/\"2026-06-13T00:00:00Z\"");
    }
}
