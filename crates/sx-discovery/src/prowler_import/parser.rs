//! Streaming parser for Prowler v4 native JSON output.
//!
//! Prowler v4 emits an array of records when invoked with
//! `--output-formats json`. Each record has a stable header
//! (`CheckID` / Severity / Status / …) and a provider-specific `Resource`
//! sub-object that varies by cloud. We accept a few common spellings of
//! each field (Prowler has shipped both `camelCase` and `PascalCase` keys
//! across point releases).
//!
//! ## Lenient parsing
//!
//! The parser is intentionally permissive: rows that fail field-level
//! validation are dropped (with a trace), not propagated as errors. The
//! only hard failure modes are top-level JSON syntax errors and the
//! "the root is not an array" case — those abort the whole import so
//! the caller can ask the user to re-upload.
//!
//! ## Provider scope
//!
//! Only `gcp` and `azure` records are emitted. AWS records are silently
//! skipped because the OCSF scanner already covers AWS — double ingestion
//! would duplicate findings.

use serde_json::Value;

use super::error::ProwlerImportError;
use super::model::{CloudProvider, ProwlerFinding, ProwlerStatus, Severity};

/// Parse a Prowler v4 native JSON document.
///
/// Returns one [`ProwlerFinding`] per `FAIL` row whose provider is GCP or
/// Azure. Rows that are not failures or that target unsupported providers
/// are silently filtered out.
///
/// # Errors
///
/// - [`ProwlerImportError::Malformed`] if `bytes` is not valid JSON or the
///   root value is not an array.
pub fn parse_prowler_v4_json(bytes: &[u8]) -> Result<Vec<ProwlerFinding>, ProwlerImportError> {
    let root: Value = serde_json::from_slice(bytes)
        .map_err(|e| ProwlerImportError::malformed(format!("json: {e}")))?;
    let arr = root.as_array().ok_or_else(|| {
        ProwlerImportError::malformed("root value must be a JSON array of findings")
    })?;
    Ok(arr.iter().filter_map(parse_entry).collect())
}

/// Parse a single Prowler row. Returns `None` for skip-conditions:
/// non-FAIL status, unsupported provider, missing required fields.
fn parse_entry(entry: &Value) -> Option<ProwlerFinding> {
    let status_raw = first_string(entry, &["Status", "status"]).unwrap_or_else(|| "PASS".into());
    let status = ProwlerStatus::parse(&status_raw);
    if !matches!(status, ProwlerStatus::Fail) {
        return None;
    }

    let provider_raw = first_string(entry, &["Provider", "provider"])?;
    let provider = CloudProvider::from_prowler(&provider_raw)?;

    let prowler_check_id = first_string(entry, &["CheckID", "check_id", "CheckId"])?;
    if prowler_check_id.is_empty() {
        return None;
    }

    let severity_raw = first_string(entry, &["Severity", "severity"]).unwrap_or_default();
    let severity = Severity::from_prowler(&severity_raw);

    let (account_id, region, resource_uid, resource_name, resource_type) =
        extract_resource(entry, provider)?;

    let status_extended = first_string(entry, &["StatusExtended", "status_extended"]);
    let description = first_string(entry, &["Description", "description", "Risk", "risk"]);
    let remediation = extract_remediation(entry);
    let compliance_refs = extract_compliance(entry);

    Some(ProwlerFinding {
        prowler_check_id,
        provider,
        account_id,
        region,
        resource_uid,
        resource_name,
        resource_type,
        severity,
        status,
        status_extended,
        description,
        remediation,
        compliance_refs,
    })
}

/// Tuple shape returned by [`extract_resource`].
///
/// Fields, in order: `account_id`, `region`, `resource_uid`, `resource_name`,
/// `resource_type`. The required fields (`account_id` and `resource_uid`) are
/// owned `String`s; the optional metadata is `Option<String>` so callers can
/// retain `None` when Prowler omitted them rather than collapsing to an empty
/// string.
type ResourceFields = (
    String,
    Option<String>,
    String,
    Option<String>,
    Option<String>,
);

/// Extract resource-related fields from the entry. Handles both the flat
/// top-level shape (older Prowler) and the nested `Resource: {...}` shape.
///
/// Returns `(account_id, region, resource_uid, resource_name, resource_type)`
/// or `None` if `(account_id, resource_uid)` cannot be resolved.
fn extract_resource(entry: &Value, provider: CloudProvider) -> Option<ResourceFields> {
    // Provider-specific account id keys.
    let account_keys: &[&str] = match provider {
        CloudProvider::Gcp => &[
            "ProjectId",
            "project_id",
            "AccountId",
            "account_id",
            "AccountUID",
            "account_uid",
        ],
        CloudProvider::Azure => &[
            "SubscriptionId",
            "subscription_id",
            "Subscription",
            "AccountId",
            "account_id",
            "AccountUID",
            "account_uid",
        ],
    };
    let mut account_id = first_string(entry, account_keys);
    if account_id.is_none() {
        // Try nested `Resource.AccountId` etc.
        if let Some(resource) = entry.get("Resource").or_else(|| entry.get("resource")) {
            account_id = first_string(resource, account_keys);
        }
    }
    let account_id = account_id?;
    if account_id.trim().is_empty() {
        return None;
    }

    let region = first_string(entry, &["Region", "region", "Location", "location"])
        .filter(|s| !s.trim().is_empty());

    // Resource uid + name keys.
    let uid_keys = &[
        "ResourceUID",
        "ResourceUid",
        "resource_uid",
        "ResourceId",
        "resource_id",
        "ResourceArn",
        "resource_arn",
    ];
    let mut resource_uid = first_string(entry, uid_keys);
    let mut resource_name = first_string(entry, &["ResourceName", "resource_name"]);
    let mut resource_type = first_string(entry, &["ResourceType", "resource_type"]);

    if let Some(resource) = entry.get("Resource").or_else(|| entry.get("resource")) {
        if resource_uid.is_none() {
            resource_uid = first_string(resource, uid_keys);
        }
        if resource_name.is_none() {
            resource_name =
                first_string(resource, &["ResourceName", "resource_name", "Name", "name"]);
        }
        if resource_type.is_none() {
            resource_type =
                first_string(resource, &["ResourceType", "resource_type", "Type", "type"]);
        }
    }

    let resource_uid = resource_uid?;
    if resource_uid.trim().is_empty() {
        return None;
    }

    Some((
        account_id,
        region,
        resource_uid,
        resource_name,
        resource_type,
    ))
}

/// Remediation text can live under `Remediation.Recommendation.Text` or
/// the flat `Remediation` string. We accept either.
fn extract_remediation(entry: &Value) -> Option<String> {
    if let Some(text) = first_string(entry, &["Remediation", "remediation"]) {
        if !text.trim().is_empty() {
            return Some(text);
        }
    }
    let r = entry
        .get("Remediation")
        .or_else(|| entry.get("remediation"))?;
    let rec = r
        .get("Recommendation")
        .or_else(|| r.get("recommendation"))?;
    first_string(rec, &["Text", "text", "Url", "url"])
}

/// Pull compliance frame references. Prowler emits a `Compliance` map keyed
/// by framework name (e.g. `CIS-2.0`) pointing at an array of control ids.
/// We flatten to `["CIS-2.0: 1.1", "CIS-2.0: 1.2"]`.
fn extract_compliance(entry: &Value) -> Vec<String> {
    let Some(comp) = entry.get("Compliance").or_else(|| entry.get("compliance")) else {
        return Vec::new();
    };
    let Some(obj) = comp.as_object() else {
        return Vec::new();
    };
    let mut out: Vec<String> = Vec::new();
    for (framework, controls) in obj {
        match controls {
            Value::Array(arr) => {
                for c in arr {
                    if let Some(s) = c.as_str() {
                        out.push(format!("{framework}: {s}"));
                    }
                }
            }
            Value::String(s) => out.push(format!("{framework}: {s}")),
            _ => {}
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Look up the first matching string key in `entry` from a list of
/// alternates. Returns `None` if no key resolves to a non-null string.
fn first_string(entry: &Value, keys: &[&str]) -> Option<String> {
    for k in keys {
        if let Some(v) = entry.get(*k).and_then(Value::as_str) {
            return Some(v.to_owned());
        }
    }
    None
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn empty_array_yields_no_findings() {
        let findings = parse_prowler_v4_json(b"[]").unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn non_array_root_is_rejected() {
        let err = parse_prowler_v4_json(b"{}").unwrap_err();
        assert!(matches!(err, ProwlerImportError::Malformed(_)));
    }

    #[test]
    fn invalid_json_is_rejected() {
        let err = parse_prowler_v4_json(b"not json").unwrap_err();
        assert!(matches!(err, ProwlerImportError::Malformed(_)));
    }

    #[test]
    fn aws_records_are_skipped() {
        let body = br#"[
            {
                "Status": "FAIL",
                "Provider": "aws",
                "CheckID": "s3_bucket_public",
                "Severity": "high",
                "AccountId": "123456789012",
                "ResourceUID": "arn:aws:s3:::demo"
            }
        ]"#;
        let findings = parse_prowler_v4_json(body).unwrap();
        assert!(findings.is_empty(), "aws should be silently skipped");
    }

    #[test]
    fn pass_records_are_skipped() {
        let body = br#"[
            {
                "Status": "PASS",
                "Provider": "gcp",
                "CheckID": "iam_no_user_keys",
                "ProjectId": "my-project",
                "ResourceUID": "//cloudresourcemanager.googleapis.com/projects/my-project"
            }
        ]"#;
        assert!(parse_prowler_v4_json(body).unwrap().is_empty());
    }

    #[test]
    fn gcp_finding_parses() {
        let body = br#"[
            {
                "Status": "FAIL",
                "Provider": "gcp",
                "CheckID": "iam_sa_user_managed_keys",
                "Severity": "high",
                "ProjectId": "demo-project",
                "Region": "us-central1",
                "ResourceUID": "//iam.googleapis.com/projects/demo-project/serviceAccounts/sa@demo-project.iam.gserviceaccount.com",
                "ResourceName": "sa",
                "ResourceType": "ServiceAccount",
                "StatusExtended": "Service account has user-managed keys",
                "Description": "Service accounts should not have user-managed keys",
                "Remediation": "Rotate to workload identity",
                "Compliance": {
                    "CIS-2.0": ["1.4", "1.5"]
                }
            }
        ]"#;
        let findings = parse_prowler_v4_json(body).unwrap();
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert_eq!(f.provider, CloudProvider::Gcp);
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.account_id, "demo-project");
        assert_eq!(f.region.as_deref(), Some("us-central1"));
        assert!(f.resource_uid.contains("serviceAccounts/sa@"));
        assert_eq!(f.resource_name.as_deref(), Some("sa"));
        assert_eq!(f.resource_type.as_deref(), Some("ServiceAccount"));
        assert_eq!(f.compliance_refs.len(), 2);
        assert!(f.compliance_refs.contains(&"CIS-2.0: 1.4".to_string()));
    }

    #[test]
    fn azure_finding_parses() {
        let body = br#"[
            {
                "Status": "FAIL",
                "Provider": "azure",
                "CheckID": "storage_blob_public_access_level_is_disabled",
                "Severity": "critical",
                "SubscriptionId": "11111111-1111-1111-1111-111111111111",
                "Location": "eastus",
                "ResourceId": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/sa1",
                "ResourceName": "sa1",
                "ResourceType": "Microsoft.Storage/storageAccounts"
            }
        ]"#;
        let findings = parse_prowler_v4_json(body).unwrap();
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert_eq!(f.provider, CloudProvider::Azure);
        assert_eq!(f.severity, Severity::Critical);
        assert_eq!(f.account_id, "11111111-1111-1111-1111-111111111111");
        assert_eq!(f.region.as_deref(), Some("eastus"));
        assert!(f.resource_uid.contains("storageAccounts/sa1"));
    }

    #[test]
    fn nested_resource_shape_is_supported() {
        // Newer Prowler builds nest fields under `Resource`.
        let body = br#"[
            {
                "Status": "FAIL",
                "Provider": "gcp",
                "CheckID": "compute_instance_public_ip",
                "Severity": "medium",
                "Resource": {
                    "ProjectId": "p1",
                    "ResourceUID": "//compute.googleapis.com/projects/p1/zones/us-east1-a/instances/vm1",
                    "Name": "vm1",
                    "Type": "Instance"
                }
            }
        ]"#;
        let findings = parse_prowler_v4_json(body).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].account_id, "p1");
        assert_eq!(findings[0].resource_name.as_deref(), Some("vm1"));
    }

    #[test]
    fn missing_resource_uid_is_dropped() {
        let body = br#"[
            {
                "Status": "FAIL",
                "Provider": "gcp",
                "CheckID": "iam_sa_user_managed_keys",
                "ProjectId": "demo-project"
            }
        ]"#;
        // No ResourceUID anywhere — row is dropped, not an error.
        let findings = parse_prowler_v4_json(body).unwrap();
        assert!(findings.is_empty());
    }
}
