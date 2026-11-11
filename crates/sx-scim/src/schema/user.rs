//! `ScimUser` — RFC 7643 §4.1 User resource.
//!
//! Only the attributes SentinelX actually consumes are exposed. Optional
//! attributes are `Option`-wrapped and skipped from serialisation when
//! absent so the wire output stays close to what Okta / AAD send.

use serde::{Deserialize, Serialize};

use crate::schema::meta::Meta;
use crate::schema::USER_SCHEMA;

/// SCIM User resource.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimUser {
    /// `schemas` envelope. MUST contain `USER_SCHEMA`.
    pub schemas: Vec<String>,
    /// Server-assigned UUID.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub id: Option<String>,
    /// Caller-supplied external identifier (Okta `externalId`).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub external_id: Option<String>,
    /// Login identifier — REQUIRED per spec.
    pub user_name: String,
    /// Structured name.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub name: Option<Name>,
    /// Display name (often a duplicate of `name.formatted`).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub display_name: Option<String>,
    /// Multi-valued email list.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub emails: Vec<Email>,
    /// Whether the account is currently provisioned (active). SCIM
    /// deactivation flips this to `false`.
    #[serde(default = "default_active")]
    pub active: bool,
    /// Server-managed metadata.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub meta: Option<Meta>,
}

const fn default_active() -> bool {
    true
}

impl ScimUser {
    /// Build a minimal valid User with only `userName` and the schemas array.
    #[must_use]
    pub fn new(user_name: impl Into<String>) -> Self {
        Self {
            schemas: vec![USER_SCHEMA.to_owned()],
            id: None,
            external_id: None,
            user_name: user_name.into(),
            name: None,
            display_name: None,
            emails: Vec::new(),
            active: true,
            meta: None,
        }
    }

    /// Reject inputs that are clearly malformed.
    ///
    /// MVP rules:
    /// * `userName` must be non-empty and ≤ 254 chars,
    /// * any supplied email `value` must be non-empty.
    ///
    /// This is intentionally lighter than full email-RFC compliance; the
    /// adapter layer normalises further.
    pub fn validate(&self) -> Result<(), String> {
        let uname = self.user_name.trim();
        if uname.is_empty() {
            return Err("userName is required".to_owned());
        }
        if uname.chars().count() > 254 {
            return Err("userName exceeds 254 chars".to_owned());
        }
        for e in &self.emails {
            if e.value.trim().is_empty() {
                return Err("email value must be non-empty".to_owned());
            }
        }
        Ok(())
    }
}

/// Sub-attribute: structured name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Name {
    /// Full name, formatted for display.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub formatted: Option<String>,
    /// Family name (surname).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub family_name: Option<String>,
    /// Given name (first name).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub given_name: Option<String>,
}

/// Sub-attribute: multi-valued email.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Email {
    /// Email address.
    pub value: String,
    /// Optional type ("work", "home", ...).
    #[serde(skip_serializing_if = "Option::is_none", default, rename = "type")]
    pub type_: Option<String>,
    /// Primary flag.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub primary: Option<bool>,
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
#[allow(clippy::expect_used)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn new_sets_schemas_and_user_name() {
        let u = ScimUser::new("alice");
        assert_eq!(u.schemas, vec![USER_SCHEMA.to_owned()]);
        assert_eq!(u.user_name, "alice");
        assert!(u.active);
    }

    #[test]
    fn round_trip_minimal_user() {
        let u = ScimUser::new("alice@example.com");
        let j = serde_json::to_value(&u).expect("ser");
        assert_eq!(j["schemas"][0], USER_SCHEMA);
        assert_eq!(j["userName"], "alice@example.com");
        assert_eq!(j["active"], true);
        // Absent optional fields are omitted.
        assert!(j.get("displayName").is_none());
        assert!(j.get("emails").is_none());
        let parsed: ScimUser = serde_json::from_value(j).expect("de");
        assert_eq!(parsed, u);
    }

    #[test]
    fn round_trip_full_user_camel_case() {
        let mut u = ScimUser::new("bob@example.com");
        u.id = Some("xx".into());
        u.external_id = Some("ext-1".into());
        u.display_name = Some("Bob Builder".into());
        u.name = Some(Name {
            formatted: Some("Bob Builder".into()),
            family_name: Some("Builder".into()),
            given_name: Some("Bob".into()),
        });
        u.emails = vec![Email {
            value: "bob@example.com".into(),
            type_: Some("work".into()),
            primary: Some(true),
        }];
        u.meta = Some(Meta::new(
            "User",
            "2026-06-12T00:00:00Z",
            "/Users/xx".into(),
        ));
        let j = serde_json::to_value(&u).expect("ser");
        assert_eq!(j["externalId"], "ext-1");
        assert_eq!(j["displayName"], "Bob Builder");
        assert_eq!(j["name"]["familyName"], "Builder");
        assert_eq!(j["name"]["givenName"], "Bob");
        assert_eq!(j["emails"][0]["value"], "bob@example.com");
        assert_eq!(j["emails"][0]["type"], "work");
        assert_eq!(j["emails"][0]["primary"], true);
        assert_eq!(j["meta"]["resourceType"], "User");
        let parsed: ScimUser = serde_json::from_value(j).expect("de");
        assert_eq!(parsed, u);
    }

    #[test]
    fn validate_rejects_empty_user_name() {
        let u = ScimUser::new("");
        assert!(u.validate().is_err());
    }

    #[test]
    fn validate_rejects_empty_email_value() {
        let mut u = ScimUser::new("alice");
        u.emails.push(Email {
            value: "  ".into(),
            type_: None,
            primary: None,
        });
        assert!(u.validate().is_err());
    }

    #[test]
    fn validate_accepts_minimal_user() {
        let u = ScimUser::new("alice");
        assert!(u.validate().is_ok());
    }

    #[test]
    fn deserialise_accepts_okta_active_default() {
        // SCIM clients may omit `active`; default is `true`.
        let j = serde_json::json!({
            "schemas": [USER_SCHEMA],
            "userName": "alice",
        });
        let u: ScimUser = serde_json::from_value(j).expect("de");
        assert!(u.active);
    }
}
