//! ARN-equivalent stable resource identification for GCP and Azure.
//!
//! AWS ARNs encode `(partition, service, region, account, resource)` into a
//! single colon-separated string that is globally unique and used as the
//! primary key in the AWS CSPM path. GCP and Azure each have their own
//! conventions that this module normalises into a single stable string we
//! use as `asset_id` on the multicloud findings table.
//!
//! ## GCP
//!
//! GCP's "ARN equivalent" is the **full resource path** the Cloud Asset API
//! uses, e.g.
//!
//! ```text
//! //iam.googleapis.com/projects/<project>/serviceAccounts/<sa-email>
//! //compute.googleapis.com/projects/<project>/zones/<zone>/instances/<vm>
//! ```
//!
//! Prowler emits this verbatim in `ResourceUID`. We canonicalise:
//!
//! - Ensure the `//` prefix is present.
//! - Lowercase the host (`iam.googleapis.com`) but preserve the path case
//!   (resource names are case-sensitive on GCP).
//! - Strip trailing slashes.
//! - If `ResourceUID` is empty but `(project, resource_name, resource_type)`
//!   are present, synthesise
//!   `//<inferred-host>/projects/<project>/<type>/<name>`.
//!
//! ## Azure
//!
//! Azure's "ARN equivalent" is the **resource ID** of the form
//!
//! ```text
//! /subscriptions/<sub>/resourceGroups/<rg>/providers/<ns>/<type>/<name>
//! ```
//!
//! Prowler emits this in `ResourceId`. We canonicalise:
//!
//! - Ensure leading slash.
//! - Trim trailing slash.
//! - Lowercase the *path keywords* (`subscriptions`, `resourceGroups`,
//!   `providers`) so two reports with mixed casing dedupe consistently.
//!   Resource names themselves are preserved verbatim (Azure storage account
//!   names are lowercase by spec, but resource group names are
//!   case-preserving).

use super::model::{CloudProvider, ProwlerFinding};

/// Decomposed view of a resource identifier — kept for documentation and
/// possible future inspection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceIdParts {
    /// Cloud provider.
    pub provider: CloudProvider,
    /// Account: GCP project id / Azure subscription id.
    pub account: String,
    /// Canonical full resource id.
    pub canonical: String,
}

/// Build a canonical, ARN-equivalent resource id from a parsed finding.
///
/// Returns `None` if the source data is too sparse to identify the
/// resource. The caller should drop the finding in that case.
#[must_use]
pub fn build_resource_id(f: &ProwlerFinding) -> Option<ResourceIdParts> {
    match f.provider {
        CloudProvider::Gcp => build_gcp(f),
        CloudProvider::Azure => build_azure(f),
    }
}

fn build_gcp(f: &ProwlerFinding) -> Option<ResourceIdParts> {
    let raw = f.resource_uid.trim();
    let canonical = if raw.is_empty() {
        // Synthesise from project + name + type when possible.
        let (name, ty) = (f.resource_name.as_deref()?, f.resource_type.as_deref()?);
        let host = infer_gcp_host_from_type(ty);
        format!(
            "//{host}/projects/{project}/{ty_lc}/{name}",
            host = host,
            project = f.account_id,
            ty_lc = ty.to_ascii_lowercase(),
            name = name,
        )
    } else {
        canonicalise_gcp(raw)
    };
    Some(ResourceIdParts {
        provider: CloudProvider::Gcp,
        account: f.account_id.clone(),
        canonical,
    })
}

fn canonicalise_gcp(raw: &str) -> String {
    // Ensure `//host/path` shape, lowercase host, strip trailing slash.
    let body = raw.strip_prefix("//").unwrap_or(raw);
    let body = body.trim_end_matches('/');
    if let Some((host, path)) = body.split_once('/') {
        format!("//{host_lc}/{path}", host_lc = host.to_ascii_lowercase())
    } else {
        format!("//{}", body.to_ascii_lowercase())
    }
}

fn infer_gcp_host_from_type(ty: &str) -> &'static str {
    match ty.to_ascii_lowercase().as_str() {
        "serviceaccount" | "iam" => "iam.googleapis.com",
        "instance" | "vminstance" | "compute" | "firewall" | "network" => "compute.googleapis.com",
        "bucket" | "storage" => "storage.googleapis.com",
        "cryptokey" | "kms" => "cloudkms.googleapis.com",
        "logbucket" | "logsink" => "logging.googleapis.com",
        _ => "cloudresourcemanager.googleapis.com",
    }
}

fn build_azure(f: &ProwlerFinding) -> Option<ResourceIdParts> {
    let raw = f.resource_uid.trim();
    if raw.is_empty() {
        return None;
    }
    let canonical = canonicalise_azure(raw);
    Some(ResourceIdParts {
        provider: CloudProvider::Azure,
        account: f.account_id.clone(),
        canonical,
    })
}

fn canonicalise_azure(raw: &str) -> String {
    let body = raw.trim_end_matches('/');
    let with_lead = if body.starts_with('/') {
        body.to_owned()
    } else {
        format!("/{body}")
    };
    // Normalise path keywords; preserve resource values.
    // Pattern: /subscriptions/<sub>/resourceGroups/<rg>/providers/<ns>/<type>/<name>
    let mut out = String::with_capacity(with_lead.len());
    let mut first = true;
    for seg in with_lead.split('/') {
        if !first {
            out.push('/');
        }
        first = false;
        match seg.to_ascii_lowercase().as_str() {
            "subscriptions" => out.push_str("subscriptions"),
            "resourcegroups" => out.push_str("resourceGroups"),
            "providers" => out.push_str("providers"),
            _ => out.push_str(seg),
        }
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::prowler_import::model::{ProwlerStatus, Severity};

    fn gcp_finding(uid: &str) -> ProwlerFinding {
        ProwlerFinding {
            prowler_check_id: "x".into(),
            provider: CloudProvider::Gcp,
            account_id: "demo".into(),
            region: None,
            resource_uid: uid.into(),
            resource_name: None,
            resource_type: None,
            severity: Severity::Low,
            status: ProwlerStatus::Fail,
            status_extended: None,
            description: None,
            remediation: None,
            compliance_refs: vec![],
        }
    }

    fn azure_finding(uid: &str) -> ProwlerFinding {
        ProwlerFinding {
            prowler_check_id: "x".into(),
            provider: CloudProvider::Azure,
            account_id: "11111111-1111-1111-1111-111111111111".into(),
            region: None,
            resource_uid: uid.into(),
            resource_name: None,
            resource_type: None,
            severity: Severity::Low,
            status: ProwlerStatus::Fail,
            status_extended: None,
            description: None,
            remediation: None,
            compliance_refs: vec![],
        }
    }

    #[test]
    fn gcp_canonical_lowercases_host_keeps_path() {
        let parts = build_resource_id(&gcp_finding(
            "//IAM.googleapis.com/projects/demo/serviceAccounts/Foo@demo.iam.gserviceaccount.com",
        ))
        .unwrap();
        assert_eq!(
            parts.canonical,
            "//iam.googleapis.com/projects/demo/serviceAccounts/Foo@demo.iam.gserviceaccount.com",
        );
    }

    #[test]
    fn gcp_strips_trailing_slash() {
        let parts = build_resource_id(&gcp_finding(
            "//storage.googleapis.com/projects/p/buckets/b/",
        ))
        .unwrap();
        assert!(!parts.canonical.ends_with('/'));
    }

    #[test]
    fn gcp_synthesises_when_uid_missing() {
        let mut f = gcp_finding("");
        f.resource_name = Some("vm1".into());
        f.resource_type = Some("Instance".into());
        let parts = build_resource_id(&f).unwrap();
        assert!(parts.canonical.contains("compute.googleapis.com"));
        assert!(parts.canonical.ends_with("/instance/vm1"));
    }

    #[test]
    fn gcp_empty_uid_without_name_is_none() {
        let f = gcp_finding("");
        assert!(build_resource_id(&f).is_none());
    }

    #[test]
    fn azure_keyword_casing_is_normalised() {
        let parts = build_resource_id(&azure_finding(
            "/Subscriptions/sub/Resourcegroups/RG1/Providers/Microsoft.Storage/storageAccounts/sa1",
        ))
        .unwrap();
        assert_eq!(
            parts.canonical,
            "/subscriptions/sub/resourceGroups/RG1/providers/Microsoft.Storage/storageAccounts/sa1",
        );
    }

    #[test]
    fn azure_prepends_leading_slash() {
        let parts = build_resource_id(&azure_finding("subscriptions/s/resourceGroups/r")).unwrap();
        assert!(parts.canonical.starts_with('/'));
    }

    #[test]
    fn azure_empty_uid_is_none() {
        let f = azure_finding("");
        assert!(build_resource_id(&f).is_none());
    }
}
