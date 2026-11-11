//! CloudFormation YAML template parser.
//!
//! CloudFormation templates have the shape:
//!
//! ```yaml
//! AWSTemplateFormatVersion: "2010-09-09"
//! Resources:
//!   EvidenceBucket:
//!     Type: AWS::S3::Bucket
//!     Properties:
//!       BucketName: evidence-prod
//!       AccessControl: Private
//!   AppRole:
//!     Type: AWS::IAM::Role
//!     Properties:
//!       AssumeRolePolicyDocument: { ... }
//! ```
//!
//! We walk the `Resources` map, ignore unsupported `Type` values, and
//! flatten `Properties` into the [`BaselineResource::attributes`] bag.
//! Because CloudFormation does not surface ARNs at template-parse time
//! (they're assigned on stack create), we use the logical name as the
//! identifier. Production deployments should round-trip through a
//! stack-output mapping; the MVP keeps the matching scheme simple.

use std::collections::BTreeMap;

use serde_yaml::Value as YamlValue;

use super::{BaselineDoc, BaselineParseError, BaselineResource, ResourceType};

/// Parse a CloudFormation YAML template into a [`BaselineDoc`].
///
/// # Errors
///
/// Returns [`BaselineParseError::Malformed`] when the payload is not
/// valid YAML, and [`BaselineParseError::Empty`] when no supported
/// resource types are present.
pub fn parse(payload: &[u8]) -> Result<BaselineDoc, BaselineParseError> {
    let root: YamlValue =
        serde_yaml::from_slice(payload).map_err(|e| BaselineParseError::Malformed {
            format: "cloudformation_yaml",
            reason: e.to_string(),
        })?;

    let mut resources: Vec<BaselineResource> = Vec::new();
    if let Some(map) = root.get("Resources").and_then(YamlValue::as_mapping) {
        for (logical_name, body) in map {
            let Some(logical_name) = logical_name.as_str() else {
                continue;
            };
            let Some(parsed) = parse_resource(logical_name, body) else {
                continue;
            };
            resources.push(parsed);
        }
    }

    if resources.is_empty() {
        return Err(BaselineParseError::Empty);
    }

    Ok(BaselineDoc { resources })
}

/// Parse one resource entry. Returns `None` for unsupported types.
fn parse_resource(logical_name: &str, body: &YamlValue) -> Option<BaselineResource> {
    let type_str = body.get("Type")?.as_str()?;
    let resource_type = ResourceType::from_cloudformation(type_str)?;
    let props = body.get("Properties").cloned().unwrap_or(YamlValue::Null);

    let attributes = flatten_props(&props);

    Some(BaselineResource {
        identifier: logical_name.to_owned(),
        resource_type,
        attributes,
    })
}

/// Convert a YAML `Properties` block into a `BTreeMap<String, serde_json::Value>`
/// so the diff engine can compare it against the live JSON inventory.
fn flatten_props(props: &YamlValue) -> BTreeMap<String, serde_json::Value> {
    let mut out = BTreeMap::new();
    let YamlValue::Mapping(map) = props else {
        return out;
    };
    for (k, v) in map {
        let Some(k) = k.as_str() else {
            continue;
        };
        // Convert YAML keys to lowercase_snake_case so the matcher in
        // `severity.rs` can use a single attribute name regardless of
        // baseline format. (`AccessControl` -> `access_control`,
        // `AssumeRolePolicyDocument` -> `assume_role_policy_document`.)
        let normalised = camel_to_snake(k);
        out.insert(normalised, yaml_to_json(v));
    }
    out
}

/// Best-effort lossless mapping from YAML to JSON. Anything that does
/// not round-trip (e.g. YAML-specific tag types) collapses to JSON
/// `null` so the diff engine stays in one universe.
fn yaml_to_json(v: &YamlValue) -> serde_json::Value {
    match v {
        YamlValue::Null => serde_json::Value::Null,
        YamlValue::Bool(b) => serde_json::Value::Bool(*b),
        YamlValue::Number(n) => n.as_i64().map_or_else(
            || {
                n.as_f64()
                    .and_then(serde_json::Number::from_f64)
                    .map_or(serde_json::Value::Null, serde_json::Value::Number)
            },
            |i| serde_json::Value::Number(i.into()),
        ),
        YamlValue::String(s) => serde_json::Value::String(s.clone()),
        YamlValue::Sequence(seq) => {
            serde_json::Value::Array(seq.iter().map(yaml_to_json).collect())
        }
        YamlValue::Mapping(map) => {
            let mut obj = serde_json::Map::new();
            for (k, v) in map {
                if let Some(k) = k.as_str() {
                    obj.insert(k.to_owned(), yaml_to_json(v));
                }
            }
            serde_json::Value::Object(obj)
        }
        YamlValue::Tagged(t) => yaml_to_json(&t.value),
    }
}

/// Convert `CamelCase` → `snake_case`. Pure ASCII; the CFN schema uses
/// no non-ASCII identifiers, so this is sufficient.
fn camel_to_snake(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 4);
    for (i, ch) in s.chars().enumerate() {
        if ch.is_ascii_uppercase() && i > 0 {
            out.push('_');
        }
        out.push(ch.to_ascii_lowercase());
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    const FIXTURE: &[u8] = br#"
AWSTemplateFormatVersion: "2010-09-09"
Resources:
  EvidenceBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: evidence-prod
      AccessControl: Private
  AppRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: app
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal:
              Service: ec2.amazonaws.com
            Action: sts:AssumeRole
  WebSecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: web
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 443
          ToPort: 443
          CidrIp: 10.0.0.0/8
  AppKey:
    Type: AWS::KMS::Key
    Properties: {}
"#;

    #[test]
    fn parser_extracts_whitelisted_resources_from_fixture() {
        let doc = parse(FIXTURE).unwrap();
        assert_eq!(doc.resources.len(), 3, "KMS key must be filtered out");
    }

    #[test]
    fn parser_normalises_property_names_to_snake_case() {
        let doc = parse(FIXTURE).unwrap();
        let bucket = doc
            .resources
            .iter()
            .find(|r| r.identifier == "EvidenceBucket")
            .unwrap();
        // `AccessControl` -> `access_control`
        assert_eq!(bucket.attributes.get("access_control").unwrap(), "Private");
        assert_eq!(
            bucket.attributes.get("bucket_name").unwrap(),
            "evidence-prod"
        );
    }

    #[test]
    fn parser_preserves_nested_yaml_structures_as_json() {
        let doc = parse(FIXTURE).unwrap();
        let role = doc
            .resources
            .iter()
            .find(|r| r.identifier == "AppRole")
            .unwrap();
        let policy = role.attributes.get("assume_role_policy_document").unwrap();
        assert!(policy.is_object(), "nested mapping must become JSON object");
        assert_eq!(policy["Version"], "2012-10-17");
    }

    #[test]
    fn parser_rejects_malformed_yaml() {
        // Mismatched flow brackets — guaranteed to fail YAML parsing.
        let err = parse(b"{a: 1, b: [unterminated").unwrap_err();
        assert!(matches!(err, BaselineParseError::Malformed { .. }));
    }

    #[test]
    fn parser_rejects_empty_resources() {
        let err = parse(b"Resources: {}").unwrap_err();
        assert!(matches!(err, BaselineParseError::Empty));
    }

    #[test]
    fn camel_to_snake_basic_cases() {
        assert_eq!(camel_to_snake("AccessControl"), "access_control");
        assert_eq!(camel_to_snake("BucketName"), "bucket_name");
        assert_eq!(camel_to_snake("ARN"), "a_r_n");
        assert_eq!(camel_to_snake("lower"), "lower");
    }
}
