//! SCIM resource schemas (RFC 7643).
//!
//! Each submodule defines one resource type. Serde renames are aligned
//! with the SCIM wire format (camelCase, with the `schemas` array on top).

pub mod group;
pub mod meta;
pub mod user;

/// SCIM 2.0 schema URN for the `User` resource (RFC 7643 §4.1).
pub const USER_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:User";

/// SCIM 2.0 schema URN for the `Group` resource (RFC 7643 §4.2).
pub const GROUP_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";

/// SCIM 2.0 schema URN for the `ListResponse` envelope (RFC 7644 §3.4.2).
pub const LIST_RESPONSE_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:ListResponse";

/// SCIM 2.0 schema URN for the `Error` envelope (RFC 7644 §3.12).
pub const ERROR_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:Error";
