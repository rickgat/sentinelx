//! IaC baseline parsers.
//!
//! Both supported formats (`terraform show -json` and `CloudFormation`
//! YAML) normalise into the same [`BaselineDoc`] container. The diff
//! engine only ever sees the normalised form so adding a third format
//! later is a new parser, not a new diff path.

pub mod cloudformation;
pub mod terraform;

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Supported baseline formats. Stable lowercase strings the HTTP layer
/// echoes back verbatim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BaselineFormat {
    /// `terraform show -json` JSON output (the JSON form, not raw HCL).
    TerraformJson,
    /// CloudFormation YAML template.
    CloudformationYaml,
}

impl BaselineFormat {
    /// Stable string identifier round-tripped on the wire.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TerraformJson => "terraform_json",
            Self::CloudformationYaml => "cloudformation_yaml",
        }
    }

    /// Inverse of [`Self::as_str`].
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "terraform_json" => Some(Self::TerraformJson),
            "cloudformation_yaml" => Some(Self::CloudformationYaml),
            _ => None,
        }
    }
}

/// Subset of resource types the drift engine currently understands.
///
/// Anything outside this whitelist is dropped at parse time so the
/// diff core only deals with shapes whose attribute keys it recognises.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceType {
    /// AWS S3 bucket (`aws_s3_bucket` / `AWS::S3::Bucket`).
    AwsS3Bucket,
    /// AWS IAM role (`aws_iam_role` / `AWS::IAM::Role`).
    AwsIamRole,
    /// AWS security group (`aws_security_group` / `AWS::EC2::SecurityGroup`).
    AwsSecurityGroup,
}

impl ResourceType {
    /// Canonical Terraform-style identifier (matches HCL `resource "..."`).
    #[must_use]
    pub const fn as_terraform(self) -> &'static str {
        match self {
            Self::AwsS3Bucket => "aws_s3_bucket",
            Self::AwsIamRole => "aws_iam_role",
            Self::AwsSecurityGroup => "aws_security_group",
        }
    }

    /// Parse a Terraform-style identifier.
    #[must_use]
    pub fn from_terraform(s: &str) -> Option<Self> {
        match s {
            "aws_s3_bucket" => Some(Self::AwsS3Bucket),
            "aws_iam_role" => Some(Self::AwsIamRole),
            "aws_security_group" => Some(Self::AwsSecurityGroup),
            _ => None,
        }
    }

    /// Parse a CloudFormation-style identifier
    /// (`AWS::S3::Bucket`, `AWS::IAM::Role`, `AWS::EC2::SecurityGroup`).
    #[must_use]
    pub fn from_cloudformation(s: &str) -> Option<Self> {
        match s {
            "AWS::S3::Bucket" => Some(Self::AwsS3Bucket),
            "AWS::IAM::Role" => Some(Self::AwsIamRole),
            "AWS::EC2::SecurityGroup" => Some(Self::AwsSecurityGroup),
            _ => None,
        }
    }
}

/// A single normalised baseline resource.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaselineResource {
    /// Canonical identifier used to match against the live inventory.
    /// For AWS this is the ARN when the IaC document carries it; for
    /// CloudFormation templates (which don't yet know the ARN) we fall
    /// back to the logical name.
    pub identifier: String,
    /// Resource type, normalised.
    pub resource_type: ResourceType,
    /// Flat attribute map. Keys are dotted paths.
    pub attributes: BTreeMap<String, serde_json::Value>,
}

/// Normalised baseline document, ready to feed the diff engine.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaselineDoc {
    /// Resources keyed by canonical identifier.
    pub resources: Vec<BaselineResource>,
}

impl BaselineDoc {
    /// Build an empty baseline.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            resources: Vec::new(),
        }
    }
}

/// Errors returned by either baseline parser.
#[derive(Debug, Error)]
pub enum BaselineParseError {
    /// The payload was not valid JSON / YAML.
    #[error("malformed {format}: {reason}")]
    Malformed {
        /// Format identifier (`terraform_json` / `cloudformation_yaml`).
        format: &'static str,
        /// Lower-level parser message.
        reason: String,
    },
    /// The payload was structurally valid but contained no resources of
    /// the supported types.
    #[error("baseline has no supported resource types")]
    Empty,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn baseline_format_round_trips() {
        for v in [
            BaselineFormat::TerraformJson,
            BaselineFormat::CloudformationYaml,
        ] {
            assert_eq!(BaselineFormat::parse(v.as_str()), Some(v));
        }
        assert!(BaselineFormat::parse("xml_dump").is_none());
    }

    #[test]
    fn resource_type_round_trips_terraform() {
        for v in [
            ResourceType::AwsS3Bucket,
            ResourceType::AwsIamRole,
            ResourceType::AwsSecurityGroup,
        ] {
            assert_eq!(ResourceType::from_terraform(v.as_terraform()), Some(v));
        }
        assert!(ResourceType::from_terraform("aws_kms_key").is_none());
    }

    #[test]
    fn resource_type_from_cloudformation_maps_supported_types() {
        assert_eq!(
            ResourceType::from_cloudformation("AWS::S3::Bucket"),
            Some(ResourceType::AwsS3Bucket)
        );
        assert_eq!(
            ResourceType::from_cloudformation("AWS::IAM::Role"),
            Some(ResourceType::AwsIamRole)
        );
        assert_eq!(
            ResourceType::from_cloudformation("AWS::EC2::SecurityGroup"),
            Some(ResourceType::AwsSecurityGroup)
        );
        assert!(ResourceType::from_cloudformation("AWS::Lambda::Function").is_none());
    }
}
