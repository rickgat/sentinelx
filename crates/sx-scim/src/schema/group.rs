//! `ScimGroup` — RFC 7643 §4.2 Group resource.

use serde::{Deserialize, Serialize};

use crate::schema::meta::Meta;
use crate::schema::GROUP_SCHEMA;

/// SCIM Group resource.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimGroup {
    /// `schemas` envelope. MUST contain `GROUP_SCHEMA`.
    pub schemas: Vec<String>,
    /// Server-assigned UUID.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub id: Option<String>,
    /// Caller-supplied external identifier.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub external_id: Option<String>,
    /// Display name — REQUIRED per spec.
    pub display_name: String,
    /// Members (user ids).
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub members: Vec<GroupMember>,
    /// Server-managed metadata.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub meta: Option<Meta>,
}

impl ScimGroup {
    /// Build a minimal Group with `displayName` and the schemas array.
    #[must_use]
    pub fn new(display_name: impl Into<String>) -> Self {
        Self {
            schemas: vec![GROUP_SCHEMA.to_owned()],
            id: None,
            external_id: None,
            display_name: display_name.into(),
            members: Vec::new(),
            meta: None,
        }
    }

    /// Reject inputs that are clearly malformed (empty `displayName`).
    pub fn validate(&self) -> Result<(), String> {
        if self.display_name.trim().is_empty() {
            return Err("displayName is required".to_owned());
        }
        for m in &self.members {
            if m.value.trim().is_empty() {
                return Err("group member value must be non-empty".to_owned());
            }
        }
        Ok(())
    }
}

/// Group member sub-attribute.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupMember {
    /// User id.
    pub value: String,
    /// Optional reference to the user's resource location.
    #[serde(rename = "$ref", skip_serializing_if = "Option::is_none", default)]
    pub ref_: Option<String>,
    /// Display name (optional).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub display: Option<String>,
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
#[allow(clippy::expect_used)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn new_sets_schemas_and_display_name() {
        let g = ScimGroup::new("engineers");
        assert_eq!(g.schemas, vec![GROUP_SCHEMA.to_owned()]);
        assert_eq!(g.display_name, "engineers");
    }

    #[test]
    fn round_trip_minimal_group() {
        let g = ScimGroup::new("engineers");
        let j = serde_json::to_value(&g).expect("ser");
        assert_eq!(j["displayName"], "engineers");
        assert!(j.get("members").is_none());
        let parsed: ScimGroup = serde_json::from_value(j).expect("de");
        assert_eq!(parsed, g);
    }

    #[test]
    fn round_trip_group_with_members() {
        let mut g = ScimGroup::new("ops");
        g.id = Some("gid".into());
        g.members = vec![
            GroupMember {
                value: "u1".into(),
                ref_: Some("/Users/u1".into()),
                display: Some("alice".into()),
            },
            GroupMember {
                value: "u2".into(),
                ref_: None,
                display: None,
            },
        ];
        let j = serde_json::to_value(&g).expect("ser");
        assert_eq!(j["members"][0]["value"], "u1");
        assert_eq!(j["members"][0]["$ref"], "/Users/u1");
        let parsed: ScimGroup = serde_json::from_value(j).expect("de");
        assert_eq!(parsed, g);
    }

    #[test]
    fn validate_rejects_empty_display_name() {
        let g = ScimGroup::new("   ");
        assert!(g.validate().is_err());
    }

    #[test]
    fn validate_accepts_well_formed_group() {
        let mut g = ScimGroup::new("ops");
        g.members.push(GroupMember {
            value: "u1".into(),
            ref_: None,
            display: None,
        });
        assert!(g.validate().is_ok());
    }
}
