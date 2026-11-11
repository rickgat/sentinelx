//! Cloud-drift detection — compare a live cloud inventory snapshot
//! against an Infrastructure-as-Code (IaC) baseline and report any
//! resource-by-resource attribute deltas as drift entries.
//!
//! ## Scope (P2-004 MVP)
//!
//! - Baseline formats: `terraform show -json` output and CloudFormation
//!   YAML templates. Both are normalised into the in-memory
//!   [`BaselineDoc`] shape before diffing.
//! - Live state: any iterator of [`crate::model::CloudResource`] —
//!   typically produced by the existing AWS CSPM / inventory scanner.
//! - Resource-type whitelist: `aws_s3_bucket`, `aws_iam_role`,
//!   `aws_security_group`. Everything else is ignored. New entries can
//!   be added without changing the diff core by extending the matcher
//!   in [`severity::classify`].
//!
//! ## Outputs
//!
//! Every detected delta is materialised as a [`DriftEntry`] (one row per
//! `(resource_id, attribute)` pair). The matcher in
//! [`severity::classify`] assigns a [`DriftSeverity`] hint that the
//! storage / HTTP layers persist verbatim.

pub mod baseline;
pub mod service;
pub mod severity;

pub use baseline::{
    BaselineDoc, BaselineFormat, BaselineParseError, BaselineResource, ResourceType,
};
pub use service::{CloudDriftService, DetectDriftError, DriftDetector, InMemoryCloudDriftService};
pub use severity::{classify, DriftSeverity};

use serde::{Deserialize, Serialize};

/// A single drift observation.
///
/// Each entry represents one attribute that differs between the IaC
/// baseline and the live cloud inventory. Multiple attributes on the
/// same resource produce multiple entries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DriftEntry {
    /// Canonical upstream resource identifier (ARN for AWS).
    pub resource_id: String,
    /// IaC-style resource type (`aws_s3_bucket`, `aws_iam_role`, ...).
    pub resource_type: String,
    /// Dotted attribute path that differs (`acl`, `ingress`, ...).
    pub attribute: String,
    /// Value from the baseline document.
    pub baseline_value: serde_json::Value,
    /// Value observed on the live cloud surface.
    pub live_value: serde_json::Value,
    /// Severity hint for downstream triage.
    pub severity_hint: DriftSeverity,
}
