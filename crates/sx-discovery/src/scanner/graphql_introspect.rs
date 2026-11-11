//! GraphQL introspection probe.
//!
//! Sends the canonical `{__schema{...}}` introspection query to a GraphQL
//! endpoint, parses the response with `serde_json`, and surfaces a
//! [`GraphqlSchemaSummary`] containing the schema's types, fields, the
//! detected dangerous-flag findings, and a small `info` finding when the
//! endpoint exposed introspection on a production-looking URL.
//!
//! This module is intentionally narrow: it does NOT implement the full
//! [`crate::service::scanner::Scanner`] trait. Instead it offers a focused,
//! standalone `probe()` API meant to be composed by orchestrators (the
//! `ApiScanner` and the discovery pipeline). It is also useful as a
//! library entry point for one-shot reconnaissance.
//!
//! Dangerous-flag rules emitted by this probe:
//!
//! | Rule id                         | Severity | Trigger                                               |
//! |---------------------------------|----------|-------------------------------------------------------|
//! | `gql-admin-mutation`            | high     | Mutation name contains `delete|drop|admin|reset|migrate` |
//! | `gql-sensitive-scalar-field`    | high     | Field of type `String` named `password|token|secret|api_key` |
//! | `gql-deprecated-field`          | medium   | Field marked deprecated still queryable               |
//! | `gql-introspection-enabled`     | info     | Introspection enabled on a production-looking URL     |

use std::time::Duration;

use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use url::Url;

use crate::error::DiscoveryError;

/// Canonical introspection query covering schema types, fields, args,
/// deprecation markers, and root operation types.
const INTROSPECTION_QUERY: &str = "\
query IntrospectionQuery {\
  __schema {\
    queryType { name }\
    mutationType { name }\
    subscriptionType { name }\
    types {\
      kind\
      name\
      description\
      fields(includeDeprecated: true) {\
        name\
        description\
        type { kind name ofType { kind name ofType { kind name } } }\
        isDeprecated\
        deprecationReason\
      }\
    }\
  }\
}";

/// Substrings that flag a mutation name as administrative / dangerous.
const ADMIN_MUTATION_MARKERS: &[&str] = &["delete", "drop", "admin", "reset", "migrate"];

/// Names that flag a `String`-typed field as a sensitive scalar.
const SENSITIVE_SCALAR_NAMES: &[&str] = &["password", "token", "secret", "api_key"];

/// Host-substring markers used to classify an endpoint as production-looking.
const PROD_HOST_MARKERS: &[&str] = &["prod", "production", "live", "api"];

/// Severity tag for a [`GraphqlFinding`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GraphqlSeverity {
    /// Highest-severity classification.
    High,
    /// Mid-severity classification.
    Medium,
    /// Low-severity classification.
    Low,
    /// Informational finding (no immediate action).
    Info,
}

impl GraphqlSeverity {
    /// Stable string tag.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
            Self::Info => "info",
        }
    }
}

/// A single dangerous-flag observation produced by [`GraphqlIntrospect::probe`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphqlFinding {
    /// Stable rule identifier (e.g. `gql-admin-mutation`).
    pub rule_id: String,
    /// Severity classification.
    pub severity: GraphqlSeverity,
    /// Qualified element that triggered the rule, e.g.
    /// `Mutation.adminResetPassword` or `User.password`.
    pub element: String,
    /// Short human-readable description of why the rule fired.
    pub message: String,
}

/// One field on a GraphQL type, normalised to a flat record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphqlField {
    /// Field name.
    pub name: String,
    /// Type name of the field's return type (unwrapped through `ofType`).
    pub type_name: String,
    /// Whether this field is marked deprecated by the server.
    pub is_deprecated: bool,
}

/// One named type from the introspected schema.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphqlType {
    /// `OBJECT`, `INTERFACE`, `UNION`, `SCALAR`, `ENUM`, `INPUT_OBJECT`.
    pub kind: String,
    /// Type name.
    pub name: String,
    /// Declared fields (object / interface / input types).
    pub fields: Vec<GraphqlField>,
}

/// Summary of a successful (or empty) GraphQL introspection probe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphqlSchemaSummary {
    /// Root query type name, if the server advertises one.
    pub query_type: Option<String>,
    /// Root mutation type name, if the server advertises one.
    pub mutation_type: Option<String>,
    /// Root subscription type name, if the server advertises one.
    pub subscription_type: Option<String>,
    /// Types listed under `__schema.types`.
    pub types: Vec<GraphqlType>,
    /// Dangerous-flag observations classified by this probe.
    pub findings: Vec<GraphqlFinding>,
    /// Whether the server returned a `__schema` object (introspection
    /// enabled) or not.
    pub introspection_enabled: bool,
}

impl GraphqlSchemaSummary {
    /// Empty summary used when the server disabled introspection.
    #[must_use]
    pub fn introspection_disabled(endpoint: &Url) -> Self {
        let finding = GraphqlFinding {
            rule_id: "gql-introspection-disabled".to_owned(),
            severity: GraphqlSeverity::Info,
            element: endpoint.to_string(),
            message: "GraphQL introspection appears to be disabled (no __schema in response)."
                .to_owned(),
        };
        Self {
            query_type: None,
            mutation_type: None,
            subscription_type: None,
            types: Vec::new(),
            findings: vec![finding],
            introspection_enabled: false,
        }
    }
}

/// GraphQL introspection probe.
#[derive(Debug, Clone)]
pub struct GraphqlIntrospect {
    /// HTTP client used to issue the POST. Caller controls TLS / proxies.
    pub http: Client,
    /// Full URL of the GraphQL endpoint (e.g. `https://api.example.com/graphql`).
    pub endpoint: Url,
    /// Per-request timeout. Must be `> 0`.
    pub timeout: Duration,
}

impl GraphqlIntrospect {
    /// Issue the introspection POST against `endpoint` and parse the
    /// response.
    ///
    /// # Errors
    /// - [`DiscoveryError::Config`] if `timeout` is zero.
    /// - [`DiscoveryError::Io`] for network errors.
    /// - [`DiscoveryError::Timeout`] on per-request timeout.
    /// - [`DiscoveryError::Internal`] (treated by callers as a parse failure)
    ///   when the body is unintelligible JSON.
    pub async fn probe(&self) -> Result<GraphqlSchemaSummary, DiscoveryError> {
        if self.timeout.is_zero() {
            return Err(DiscoveryError::config(
                "graphql introspect timeout must be > 0",
            ));
        }
        let body = json!({ "query": INTROSPECTION_QUERY });
        let req = self
            .http
            .post(self.endpoint.clone())
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header(reqwest::header::ACCEPT, "application/json")
            .json(&body);

        let response = match tokio::time::timeout(self.timeout, req.send()).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) if e.is_timeout() => return Err(DiscoveryError::Timeout),
            Ok(Err(e)) => return Err(DiscoveryError::io(e.to_string())),
            Err(_elapsed) => return Err(DiscoveryError::Timeout),
        };

        let bytes = match tokio::time::timeout(self.timeout, response.bytes()).await {
            Ok(Ok(b)) => b,
            Ok(Err(e)) => return Err(DiscoveryError::io(e.to_string())),
            Err(_elapsed) => return Err(DiscoveryError::Timeout),
        };

        parse_introspection_response(&bytes, &self.endpoint)
    }
}

/// Parse the raw HTTP body of an introspection response into a
/// [`GraphqlSchemaSummary`]. Pulled out of [`GraphqlIntrospect::probe`] so
/// it can be unit-tested without any I/O.
pub fn parse_introspection_response(
    body: &[u8],
    endpoint: &Url,
) -> Result<GraphqlSchemaSummary, DiscoveryError> {
    if body.is_empty() {
        // Empty bodies are unintelligible JSON.
        return Err(DiscoveryError::internal(
            "graphql introspection: empty body",
        ));
    }
    let envelope: Value = serde_json::from_slice(body).map_err(|e| {
        DiscoveryError::internal(format!("graphql introspection: parse error: {e}"))
    })?;
    let schema = envelope.get("data").and_then(|d| d.get("__schema"));
    let Some(schema) = schema else {
        // Server returned no schema; treat as introspection disabled.
        return Ok(GraphqlSchemaSummary::introspection_disabled(endpoint));
    };
    // `__schema` must be an object for the response to be considered valid.
    if !schema.is_object() {
        return Err(DiscoveryError::internal(
            "graphql introspection: __schema is not an object",
        ));
    }

    let query_type = root_name(schema.get("queryType"));
    let mutation_type = root_name(schema.get("mutationType"));
    let subscription_type = root_name(schema.get("subscriptionType"));

    let types = parse_types(schema.get("types"));
    let mut findings = classify(&types, mutation_type.as_deref());
    if is_production_looking(endpoint) {
        findings.push(GraphqlFinding {
            rule_id: "gql-introspection-enabled".to_owned(),
            severity: GraphqlSeverity::Info,
            element: endpoint.to_string(),
            message: "GraphQL introspection is enabled on a production-looking URL.".to_owned(),
        });
    }

    Ok(GraphqlSchemaSummary {
        query_type,
        mutation_type,
        subscription_type,
        types,
        findings,
        introspection_enabled: true,
    })
}

fn root_name(v: Option<&Value>) -> Option<String> {
    v.and_then(|x| x.get("name"))
        .and_then(Value::as_str)
        .map(str::to_owned)
}

fn parse_types(v: Option<&Value>) -> Vec<GraphqlType> {
    let Some(arr) = v.and_then(Value::as_array) else {
        return Vec::new();
    };
    arr.iter().filter_map(parse_one_type).collect()
}

fn parse_one_type(v: &Value) -> Option<GraphqlType> {
    let name = v.get("name").and_then(Value::as_str)?.to_owned();
    if name.starts_with("__") {
        // Skip introspection meta-types so consumer iteration is cleaner.
        return None;
    }
    let kind = v
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or("OBJECT")
        .to_owned();
    let fields = v
        .get("fields")
        .and_then(Value::as_array)
        .map(|arr| arr.iter().filter_map(parse_one_field).collect())
        .unwrap_or_default();
    Some(GraphqlType { kind, name, fields })
}

fn parse_one_field(v: &Value) -> Option<GraphqlField> {
    let name = v.get("name").and_then(Value::as_str)?.to_owned();
    let type_name = unwrap_type_name(v.get("type")).unwrap_or_else(|| "Unknown".to_owned());
    let is_deprecated = v
        .get("isDeprecated")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    Some(GraphqlField {
        name,
        type_name,
        is_deprecated,
    })
}

/// Walk the GraphQL type ref tree, unwrapping `NON_NULL` / `LIST` wrappers
/// to return the underlying type name.
fn unwrap_type_name(v: Option<&Value>) -> Option<String> {
    let mut cur = v?;
    for _ in 0..8 {
        if let Some(name) = cur.get("name").and_then(Value::as_str) {
            if !name.is_empty() {
                return Some(name.to_owned());
            }
        }
        match cur.get("ofType") {
            Some(next) if !next.is_null() => cur = next,
            _ => break,
        }
    }
    None
}

fn classify(types: &[GraphqlType], mutation_type: Option<&str>) -> Vec<GraphqlFinding> {
    let mut out = Vec::new();
    for t in types {
        let is_mutation_root = mutation_type.is_some_and(|m| m == t.name);
        for f in &t.fields {
            if is_mutation_root && is_admin_mutation(&f.name) {
                out.push(GraphqlFinding {
                    rule_id: "gql-admin-mutation".to_owned(),
                    severity: GraphqlSeverity::High,
                    element: format!("{}.{}", t.name, f.name),
                    message: format!(
                        "Mutation '{}' matches admin/destructive name pattern.",
                        f.name
                    ),
                });
            }
            if is_sensitive_scalar(f) {
                out.push(GraphqlFinding {
                    rule_id: "gql-sensitive-scalar-field".to_owned(),
                    severity: GraphqlSeverity::High,
                    element: format!("{}.{}", t.name, f.name),
                    message: format!(
                        "Field '{}.{}' exposes a sensitive-named String scalar.",
                        t.name, f.name
                    ),
                });
            }
            if f.is_deprecated {
                out.push(GraphqlFinding {
                    rule_id: "gql-deprecated-field".to_owned(),
                    severity: GraphqlSeverity::Medium,
                    element: format!("{}.{}", t.name, f.name),
                    message: format!(
                        "Field '{}.{}' is marked deprecated but still queryable.",
                        t.name, f.name
                    ),
                });
            }
        }
    }
    out
}

fn is_admin_mutation(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    ADMIN_MUTATION_MARKERS.iter().any(|m| lower.contains(m))
}

fn is_sensitive_scalar(f: &GraphqlField) -> bool {
    if !f.type_name.eq_ignore_ascii_case("String") {
        return false;
    }
    let lower = f.name.to_ascii_lowercase();
    SENSITIVE_SCALAR_NAMES.iter().any(|n| lower.contains(n))
}

fn is_production_looking(endpoint: &Url) -> bool {
    let Some(host) = endpoint.host_str() else {
        return false;
    };
    let lower = host.to_ascii_lowercase();
    if lower.contains("localhost") || lower == "127.0.0.1" || lower == "::1" {
        return false;
    }
    PROD_HOST_MARKERS.iter().any(|m| lower.contains(m))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;

    fn endpoint() -> Url {
        Url::parse("https://api.example.com/graphql").expect("static url")
    }

    fn minimal_schema_body() -> &'static [u8] {
        br#"{
            "data": {
                "__schema": {
                    "queryType": {"name": "Query"},
                    "mutationType": {"name": "Mutation"},
                    "subscriptionType": null,
                    "types": [
                        {
                            "kind": "OBJECT",
                            "name": "Query",
                            "fields": [
                                {
                                    "name": "me",
                                    "type": {"kind":"OBJECT","name":"User","ofType":null},
                                    "isDeprecated": false,
                                    "deprecationReason": null
                                }
                            ]
                        },
                        {
                            "kind": "OBJECT",
                            "name": "User",
                            "fields": [
                                {
                                    "name": "id",
                                    "type": {"kind":"NON_NULL","name":null,"ofType":{"kind":"SCALAR","name":"ID","ofType":null}},
                                    "isDeprecated": false,
                                    "deprecationReason": null
                                }
                            ]
                        }
                    ]
                }
            }
        }"#
    }

    // 1
    #[test]
    fn parses_minimal_schema_response_correctly() {
        let s = parse_introspection_response(minimal_schema_body(), &endpoint()).unwrap();
        assert!(s.introspection_enabled);
        assert_eq!(s.query_type.as_deref(), Some("Query"));
        assert_eq!(s.mutation_type.as_deref(), Some("Mutation"));
        assert!(s.subscription_type.is_none());
        assert_eq!(s.types.len(), 2);
        assert_eq!(s.types[0].name, "Query");
        assert_eq!(s.types[1].name, "User");
        assert_eq!(s.types[1].fields[0].type_name, "ID");
    }

    // 2
    #[test]
    fn classifies_admin_reset_password_mutation_as_high() {
        let body = br#"{
            "data": {
                "__schema": {
                    "queryType": {"name": "Query"},
                    "mutationType": {"name": "Mutation"},
                    "subscriptionType": null,
                    "types": [
                        {
                            "kind": "OBJECT",
                            "name": "Mutation",
                            "fields": [
                                {
                                    "name": "admin_reset_password",
                                    "type": {"kind":"SCALAR","name":"Boolean","ofType":null},
                                    "isDeprecated": false,
                                    "deprecationReason": null
                                }
                            ]
                        }
                    ]
                }
            }
        }"#;
        let s = parse_introspection_response(body, &endpoint()).unwrap();
        let f = s
            .findings
            .iter()
            .find(|f| f.rule_id == "gql-admin-mutation")
            .expect("expected admin mutation finding");
        assert_eq!(f.severity, GraphqlSeverity::High);
        assert!(f.element.ends_with(".admin_reset_password"));
    }

    // 3
    #[test]
    fn classifies_password_typed_field_as_high() {
        let body = br#"{
            "data": {
                "__schema": {
                    "queryType": {"name": "Query"},
                    "types": [
                        {
                            "kind": "OBJECT",
                            "name": "User",
                            "fields": [
                                {
                                    "name": "password",
                                    "type": {"kind":"SCALAR","name":"String","ofType":null},
                                    "isDeprecated": false,
                                    "deprecationReason": null
                                }
                            ]
                        }
                    ]
                }
            }
        }"#;
        let s = parse_introspection_response(body, &endpoint()).unwrap();
        let f = s
            .findings
            .iter()
            .find(|f| f.rule_id == "gql-sensitive-scalar-field")
            .expect("expected sensitive scalar finding");
        assert_eq!(f.severity, GraphqlSeverity::High);
        assert_eq!(f.element, "User.password");
    }

    // 4
    #[test]
    fn classifies_deprecated_field_as_medium() {
        let body = br#"{
            "data": {
                "__schema": {
                    "queryType": {"name": "Query"},
                    "types": [
                        {
                            "kind": "OBJECT",
                            "name": "User",
                            "fields": [
                                {
                                    "name": "oldName",
                                    "type": {"kind":"SCALAR","name":"String","ofType":null},
                                    "isDeprecated": true,
                                    "deprecationReason": "use displayName"
                                }
                            ]
                        }
                    ]
                }
            }
        }"#;
        let s = parse_introspection_response(body, &endpoint()).unwrap();
        let f = s
            .findings
            .iter()
            .find(|f| f.rule_id == "gql-deprecated-field")
            .expect("expected deprecated-field finding");
        assert_eq!(f.severity, GraphqlSeverity::Medium);
        assert_eq!(f.element, "User.oldName");
    }

    // 5
    #[test]
    fn introspection_disabled_response_surfaces_info_finding() {
        let body = br#"{"errors":[{"message":"GraphQL introspection is not allowed"}]}"#;
        let s = parse_introspection_response(body, &endpoint()).unwrap();
        assert!(!s.introspection_enabled);
        assert_eq!(s.findings.len(), 1);
        assert_eq!(s.findings[0].rule_id, "gql-introspection-disabled");
        assert_eq!(s.findings[0].severity, GraphqlSeverity::Info);
    }

    // 6
    #[test]
    fn malformed_schema_json_returns_parse_error() {
        let body = b"not-json-at-all";
        let err = parse_introspection_response(body, &endpoint()).unwrap_err();
        assert!(matches!(err, DiscoveryError::Internal(_)));
    }

    // 7
    #[test]
    fn empty_body_is_a_parse_error() {
        let err = parse_introspection_response(b"", &endpoint()).unwrap_err();
        assert!(matches!(err, DiscoveryError::Internal(_)));
    }

    // 8
    #[test]
    fn meta_types_are_filtered_out() {
        let body = br#"{
            "data": {
                "__schema": {
                    "queryType": {"name": "Query"},
                    "types": [
                        {"kind":"OBJECT","name":"__Schema","fields":[]},
                        {"kind":"OBJECT","name":"Query","fields":[]}
                    ]
                }
            }
        }"#;
        let s = parse_introspection_response(body, &endpoint()).unwrap();
        assert_eq!(s.types.len(), 1);
        assert_eq!(s.types[0].name, "Query");
    }

    // 9
    #[test]
    fn production_looking_url_adds_introspection_enabled_info() {
        let body = minimal_schema_body();
        let s = parse_introspection_response(body, &endpoint()).unwrap();
        assert!(s
            .findings
            .iter()
            .any(|f| f.rule_id == "gql-introspection-enabled"));
    }

    // 10
    #[test]
    fn localhost_url_skips_introspection_enabled_info() {
        let body = minimal_schema_body();
        let local = Url::parse("http://localhost:8080/graphql").unwrap();
        let s = parse_introspection_response(body, &local).unwrap();
        assert!(!s
            .findings
            .iter()
            .any(|f| f.rule_id == "gql-introspection-enabled"));
    }

    // 11
    #[test]
    fn admin_mutation_marker_is_case_insensitive() {
        let body = br#"{
            "data": {
                "__schema": {
                    "queryType": {"name": "Query"},
                    "mutationType": {"name": "Mutation"},
                    "types": [
                        {
                            "kind": "OBJECT",
                            "name": "Mutation",
                            "fields": [
                                {
                                    "name": "DropTenant",
                                    "type": {"kind":"SCALAR","name":"Boolean","ofType":null},
                                    "isDeprecated": false,
                                    "deprecationReason": null
                                }
                            ]
                        }
                    ]
                }
            }
        }"#;
        let s = parse_introspection_response(body, &endpoint()).unwrap();
        assert!(s.findings.iter().any(|f| f.rule_id == "gql-admin-mutation"));
    }

    // 12
    #[test]
    fn admin_marker_only_applies_to_mutation_root() {
        // Same name appearing on a non-mutation type must not trigger the
        // gql-admin-mutation rule.
        let body = br#"{
            "data": {
                "__schema": {
                    "queryType": {"name": "Query"},
                    "mutationType": {"name": "Mutation"},
                    "types": [
                        {
                            "kind": "OBJECT",
                            "name": "User",
                            "fields": [
                                {
                                    "name": "admin_reset_password",
                                    "type": {"kind":"SCALAR","name":"Boolean","ofType":null},
                                    "isDeprecated": false,
                                    "deprecationReason": null
                                }
                            ]
                        }
                    ]
                }
            }
        }"#;
        let s = parse_introspection_response(body, &endpoint()).unwrap();
        assert!(!s.findings.iter().any(|f| f.rule_id == "gql-admin-mutation"));
    }

    // 13
    #[test]
    fn schema_not_object_yields_parse_error() {
        let body = br#"{"data":{"__schema": 42}}"#;
        let err = parse_introspection_response(body, &endpoint()).unwrap_err();
        assert!(matches!(err, DiscoveryError::Internal(_)));
    }

    // 14
    #[tokio::test]
    async fn probe_rejects_zero_timeout() {
        let p = GraphqlIntrospect {
            http: Client::builder().build().unwrap(),
            endpoint: endpoint(),
            timeout: Duration::from_secs(0),
        };
        let err = p.probe().await.unwrap_err();
        assert!(matches!(err, DiscoveryError::Config(_)));
    }
}
