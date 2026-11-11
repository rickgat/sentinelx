//! `terraform show -json` parser.
//!
//! Terraform's JSON state has the shape:
//!
//! ```json
//! {
//!   "values": {
//!     "root_module": {
//!       "resources": [
//!         { "type": "aws_s3_bucket",
//!           "name": "evidence",
//!           "values": { "arn": "arn:aws:s3:::evidence", "acl": "private", ... }
//!         },
//!         ...
//!       ],
//!       "child_modules": [
//!         { "resources": [...], "child_modules": [...] }
//!       ]
//!     }
//!   }
//! }
//! ```
//!
//! We walk the module tree, ignore unsupported resource types, and
//! flatten the `values` map into the [`BaselineResource::attributes`]
//! bag. The canonical identifier is the resource's `arn` when present,
//! falling back to the Terraform address (`type.name`).
//!
//! No HCL parser is involved — the input is already JSON, which is
//! both stable (versioned by `terraform_version`) and dependency-free
//! to read.

use std::collections::BTreeMap;

use serde_json::Value;

use super::{BaselineDoc, BaselineParseError, BaselineResource, ResourceType};

/// Parse a `terraform show -json` payload into a [`BaselineDoc`].
///
/// # Errors
///
/// Returns [`BaselineParseError::Malformed`] when the payload is not
/// valid JSON, and [`BaselineParseError::Empty`] when it contains no
/// supported resource types.
pub fn parse(payload: &[u8]) -> Result<BaselineDoc, BaselineParseError> {
    let root: Value =
        serde_json::from_slice(payload).map_err(|e| BaselineParseError::Malformed {
            format: "terraform_json",
            reason: e.to_string(),
        })?;

    let mut resources: Vec<BaselineResource> = Vec::new();
    if let Some(root_module) = root.get("values").and_then(|v| v.get("root_module")) {
        walk_module(root_module, &mut resources);
    }

    if resources.is_empty() {
        return Err(BaselineParseError::Empty);
    }

    Ok(BaselineDoc { resources })
}

/// Recursively walk a Terraform module node, collecting resources.
fn walk_module(node: &Value, out: &mut Vec<BaselineResource>) {
    if let Some(arr) = node.get("resources").and_then(Value::as_array) {
        for r in arr {
            if let Some(parsed) = parse_resource(r) {
                out.push(parsed);
            }
        }
    }
    if let Some(children) = node.get("child_modules").and_then(Value::as_array) {
        for c in children {
            walk_module(c, out);
        }
    }
}

/// Parse one `resources[]` entry. Returns `None` for unsupported types.
fn parse_resource(r: &Value) -> Option<BaselineResource> {
    let kind = r.get("type").and_then(Value::as_str)?;
    let resource_type = ResourceType::from_terraform(kind)?;
    let name = r.get("name").and_then(Value::as_str).unwrap_or("");
    let address = r
        .get("address")
        .and_then(Value::as_str)
        .map_or_else(|| format!("{kind}.{name}"), str::to_owned);
    let values = r.get("values").cloned().unwrap_or(Value::Null);

    let identifier = extract_identifier(&values, &address);
    let attributes = flatten_values(&values);

    Some(BaselineResource {
        identifier,
        resource_type,
        attributes,
    })
}

/// Choose a stable identifier for a resource. Preference order:
///
/// 1. `arn` (canonical AWS identifier).
/// 2. `id` (Terraform's primary key, often an ARN for AWS).
/// 3. The Terraform address (`type.name`).
fn extract_identifier(values: &Value, fallback: &str) -> String {
    for key in ["arn", "id"] {
        if let Some(v) = values.get(key).and_then(Value::as_str) {
            if !v.is_empty() {
                return v.to_owned();
            }
        }
    }
    fallback.to_owned()
}

/// Flatten a JSON `values` object into a `BTreeMap` keyed by attribute
/// name. Nested objects / arrays are preserved as-is so the diff engine
/// can compare structured values verbatim. Keys mirror the Terraform
/// schema (`acl`, `ingress`, `assume_role_policy`, ...).
fn flatten_values(values: &Value) -> BTreeMap<String, Value> {
    let mut out = BTreeMap::new();
    if let Value::Object(map) = values {
        for (k, v) in map {
            out.insert(k.clone(), v.clone());
        }
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    /// A minimal fixture covering all three whitelisted resource types
    /// across a root + nested module. Crafted by hand to mirror the
    /// real `terraform show -json` shape without dragging in a full
    /// state dump.
    const FIXTURE: &[u8] = br#"{
        "format_version": "1.0",
        "terraform_version": "1.5.0",
        "values": {
            "root_module": {
                "resources": [
                    {
                        "address": "aws_s3_bucket.evidence",
                        "type": "aws_s3_bucket",
                        "name": "evidence",
                        "values": {
                            "arn": "arn:aws:s3:::evidence-prod",
                            "bucket": "evidence-prod",
                            "acl": "private",
                            "versioning": [{ "enabled": true }]
                        }
                    },
                    {
                        "address": "aws_iam_role.app",
                        "type": "aws_iam_role",
                        "name": "app",
                        "values": {
                            "arn": "arn:aws:iam::123:role/app",
                            "assume_role_policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"ec2.amazonaws.com\"},\"Action\":\"sts:AssumeRole\"}]}"
                        }
                    }
                ],
                "child_modules": [
                    {
                        "resources": [
                            {
                                "address": "module.net.aws_security_group.web",
                                "type": "aws_security_group",
                                "name": "web",
                                "values": {
                                    "arn": "arn:aws:ec2:us-east-1:123:security-group/sg-1",
                                    "ingress": [
                                        { "from_port": 443, "to_port": 443, "protocol": "tcp", "cidr_blocks": ["10.0.0.0/8"] }
                                    ]
                                }
                            },
                            {
                                "address": "module.net.aws_kms_key.app",
                                "type": "aws_kms_key",
                                "name": "app",
                                "values": { "arn": "arn:aws:kms:us-east-1:123:key/abc" }
                            }
                        ]
                    }
                ]
            }
        }
    }"#;

    #[test]
    fn parser_extracts_whitelisted_resources_from_fixture() {
        let doc = parse(FIXTURE).unwrap();
        assert_eq!(doc.resources.len(), 3, "kms key must be filtered out");
        let kinds: Vec<_> = doc.resources.iter().map(|r| r.resource_type).collect();
        assert!(kinds.contains(&ResourceType::AwsS3Bucket));
        assert!(kinds.contains(&ResourceType::AwsIamRole));
        assert!(kinds.contains(&ResourceType::AwsSecurityGroup));
    }

    #[test]
    fn parser_prefers_arn_as_identifier() {
        let doc = parse(FIXTURE).unwrap();
        let bucket = doc
            .resources
            .iter()
            .find(|r| r.resource_type == ResourceType::AwsS3Bucket)
            .unwrap();
        assert_eq!(bucket.identifier, "arn:aws:s3:::evidence-prod");
        assert_eq!(bucket.attributes.get("acl").unwrap(), "private");
    }

    #[test]
    fn parser_recurses_into_child_modules() {
        let doc = parse(FIXTURE).unwrap();
        let sg = doc
            .resources
            .iter()
            .find(|r| r.resource_type == ResourceType::AwsSecurityGroup)
            .unwrap();
        assert_eq!(
            sg.identifier,
            "arn:aws:ec2:us-east-1:123:security-group/sg-1"
        );
        assert!(sg.attributes.contains_key("ingress"));
    }

    #[test]
    fn parser_rejects_malformed_json() {
        let err = parse(b"{not json").unwrap_err();
        assert!(matches!(err, BaselineParseError::Malformed { .. }));
    }

    #[test]
    fn parser_rejects_empty_doc() {
        let empty = br#"{ "values": { "root_module": { "resources": [] } } }"#;
        let err = parse(empty).unwrap_err();
        assert!(matches!(err, BaselineParseError::Empty));
    }

    #[test]
    fn fallback_identifier_is_terraform_address() {
        let payload = br#"{
            "values": { "root_module": { "resources": [
                { "address": "aws_s3_bucket.no_arn", "type": "aws_s3_bucket", "name": "no_arn",
                  "values": { "acl": "private" } }
            ] } }
        }"#;
        let doc = parse(payload).unwrap();
        assert_eq!(doc.resources[0].identifier, "aws_s3_bucket.no_arn");
    }
}
