//! Drift-severity heuristics.
//!
//! A single matcher function ([`classify`]) is responsible for assigning
//! a [`DriftSeverity`] to a `(resource_type, attribute, baseline, live)`
//! tuple. Centralising the logic here keeps the diff engine free of
//! domain knowledge and makes it cheap to extend the rule set without
//! touching the comparison plumbing.
//!
//! ## Rules shipped at MVP
//!
//! - **Critical** — an S3 bucket that was private in the baseline
//!   appears as public-read / public-read-write on the live surface.
//! - **High**    — an IAM role's trust policy was widened (any new
//!   principal added to `assume_role_policy_document` / equivalent).
//! - **Medium**  — a security group has new ingress rules on the live
//!   surface that the baseline did not authorise.
//! - **Low**     — every other observed delta (config drift on tagging,
//!   metadata, etc).

use serde::{Deserialize, Serialize};

use super::baseline::ResourceType;

/// Ordered severity hint surfaced for every drift entry.
///
/// Variants intentionally mirror the canonical SentinelX severity ladder
/// (`low`, `medium`, `high`, `critical`) so downstream finding-aggregators
/// can map them onto an existing scale without translation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DriftSeverity {
    /// Cosmetic / metadata-only delta.
    Low,
    /// Notable but not directly exploitable (e.g. tag drift,
    /// description change, security group ingress added).
    Medium,
    /// Likely to widen the blast radius (e.g. IAM trust widened).
    High,
    /// Immediately exploitable / data-exposing (e.g. bucket made public).
    Critical,
}

impl DriftSeverity {
    /// Stable lowercase string used for storage + wire serialisation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

/// Classify one drift observation into a severity hint.
///
/// The function only ever returns a value — invalid inputs simply
/// degrade to [`DriftSeverity::Low`] so the diff engine never has to
/// reason about failure. Keep the matcher exhaustive by appending new
/// rules at the top so the most specific clauses fire first.
#[must_use]
pub fn classify(
    resource_type: ResourceType,
    attribute: &str,
    baseline: &serde_json::Value,
    live: &serde_json::Value,
) -> DriftSeverity {
    match resource_type {
        ResourceType::AwsS3Bucket => classify_s3(attribute, baseline, live),
        ResourceType::AwsIamRole => classify_iam_role(attribute, baseline, live),
        ResourceType::AwsSecurityGroup => classify_security_group(attribute, baseline, live),
    }
}

/// S3 bucket rules. `acl` / `access_control` ∈ {`public-read`,
/// `public-read-write`} on the live side is *critical*.
fn classify_s3(
    attribute: &str,
    baseline: &serde_json::Value,
    live: &serde_json::Value,
) -> DriftSeverity {
    if attribute == "acl" || attribute == "access_control" {
        let baseline_public = is_public_acl(baseline);
        let live_public = is_public_acl(live);
        if !baseline_public && live_public {
            return DriftSeverity::Critical;
        }
        return DriftSeverity::Medium;
    }
    if (attribute == "policy" || attribute == "bucket_policy")
        && json_contains_principal_wildcard(live)
        && !json_contains_principal_wildcard(baseline)
    {
        return DriftSeverity::Critical;
    }
    DriftSeverity::Low
}

/// IAM role rules. Any *added* principal in the trust policy upgrades
/// the severity to *high*.
fn classify_iam_role(
    attribute: &str,
    baseline: &serde_json::Value,
    live: &serde_json::Value,
) -> DriftSeverity {
    if attribute == "assume_role_policy" || attribute == "assume_role_policy_document" {
        if trust_widened(baseline, live) {
            return DriftSeverity::High;
        }
        return DriftSeverity::Medium;
    }
    DriftSeverity::Low
}

/// Security-group rules. Live ingress that does not appear in the
/// baseline is *medium*. Live ingress that opens 0.0.0.0/0 on a port
/// the baseline restricted bumps to *high*.
fn classify_security_group(
    attribute: &str,
    baseline: &serde_json::Value,
    live: &serde_json::Value,
) -> DriftSeverity {
    if attribute == "ingress" || attribute == "security_group_ingress" {
        if ingress_widens_to_world(baseline, live) {
            return DriftSeverity::High;
        }
        if ingress_added(baseline, live) {
            return DriftSeverity::Medium;
        }
        return DriftSeverity::Low;
    }
    DriftSeverity::Low
}

/// Whether `v` represents a public ACL ("public-read", "PublicRead", ...).
fn is_public_acl(v: &serde_json::Value) -> bool {
    let s = match v {
        serde_json::Value::String(s) => s.as_str(),
        _ => return false,
    };
    let lower = s.to_ascii_lowercase().replace('_', "-");
    matches!(
        lower.as_str(),
        "public-read" | "public-read-write" | "publicread" | "publicreadwrite"
    )
}

/// Whether `v` recursively contains an IAM `Principal: "*"` field.
fn json_contains_principal_wildcard(v: &serde_json::Value) -> bool {
    match v {
        serde_json::Value::Object(map) => {
            for (k, child) in map {
                if k == "Principal" {
                    if child == &serde_json::Value::String("*".to_owned()) {
                        return true;
                    }
                    if let Some(obj) = child.as_object() {
                        for inner in obj.values() {
                            if inner == &serde_json::Value::String("*".to_owned()) {
                                return true;
                            }
                            if let Some(arr) = inner.as_array() {
                                if arr
                                    .iter()
                                    .any(|x| x == &serde_json::Value::String("*".to_owned()))
                                {
                                    return true;
                                }
                            }
                        }
                    }
                }
                if json_contains_principal_wildcard(child) {
                    return true;
                }
            }
            false
        }
        serde_json::Value::Array(arr) => arr.iter().any(json_contains_principal_wildcard),
        _ => false,
    }
}

/// Whether the live trust policy contains principals not present in the
/// baseline trust policy. Compares by stringified value so JSON-vs-JSON
/// and JSON-vs-stringified-JSON inputs both work.
fn trust_widened(baseline: &serde_json::Value, live: &serde_json::Value) -> bool {
    let baseline_principals = collect_principals(baseline);
    let live_principals = collect_principals(live);
    if json_contains_principal_wildcard(live) && !json_contains_principal_wildcard(baseline) {
        return true;
    }
    live_principals
        .iter()
        .any(|p| !baseline_principals.contains(p))
}

/// Recursively collect every leaf string under any `Principal` key into
/// a vec. Used by [`trust_widened`].
fn collect_principals(v: &serde_json::Value) -> Vec<String> {
    let parsed = normalise_policy_for_diff(v);
    let mut out = Vec::new();
    walk_principals(&parsed, &mut out);
    out
}

/// Recursively flatten a JSON document into all string leaves found
/// under a `Principal` key.
fn walk_principals(v: &serde_json::Value, out: &mut Vec<String>) {
    match v {
        serde_json::Value::Object(map) => {
            for (k, child) in map {
                if k == "Principal" {
                    flatten_strings(child, out);
                }
                walk_principals(child, out);
            }
        }
        serde_json::Value::Array(arr) => {
            for child in arr {
                walk_principals(child, out);
            }
        }
        _ => {}
    }
}

/// Push every JSON string leaf under `v` into `out`.
fn flatten_strings(v: &serde_json::Value, out: &mut Vec<String>) {
    match v {
        serde_json::Value::String(s) => out.push(s.clone()),
        serde_json::Value::Array(arr) => {
            for child in arr {
                flatten_strings(child, out);
            }
        }
        serde_json::Value::Object(map) => {
            for child in map.values() {
                flatten_strings(child, out);
            }
        }
        _ => {}
    }
}

/// Parse a Terraform-style stringified policy back into JSON so the
/// principal walker has a homogeneous tree to traverse.
fn normalise_policy_for_diff(v: &serde_json::Value) -> serde_json::Value {
    if let Some(s) = v.as_str() {
        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(s) {
            return parsed;
        }
    }
    v.clone()
}

/// Whether `live` has any ingress entry not present in `baseline`.
fn ingress_added(baseline: &serde_json::Value, live: &serde_json::Value) -> bool {
    let baseline_set = ingress_entries(baseline);
    let live_set = ingress_entries(live);
    live_set.iter().any(|e| !baseline_set.contains(e))
}

/// Whether any live ingress entry exposes `0.0.0.0/0` or `::/0` that
/// the baseline did not already exposes.
fn ingress_widens_to_world(baseline: &serde_json::Value, live: &serde_json::Value) -> bool {
    let baseline_world = ingress_entries(baseline)
        .into_iter()
        .any(|e| entry_is_world_open(&e));
    let live_world = ingress_entries(live)
        .into_iter()
        .any(|e| entry_is_world_open(&e));
    live_world && !baseline_world
}

/// Flatten an ingress array into a vec of canonicalised JSON strings
/// (sorted-key form) so set operations are order-independent.
fn ingress_entries(v: &serde_json::Value) -> Vec<String> {
    let Some(arr) = v.as_array() else {
        return Vec::new();
    };
    arr.iter().map(stable_json).collect()
}

/// Whether an ingress entry contains a world-open CIDR.
fn entry_is_world_open(entry: &str) -> bool {
    entry.contains("0.0.0.0/0") || entry.contains("::/0")
}

/// Canonical JSON encoding (sorted keys) — used to compare two ingress
/// entries by value, independent of authoring order.
fn stable_json(v: &serde_json::Value) -> String {
    // serde_json's BTreeMap-backed Value preserves insertion order, so
    // we round-trip through a serde_json::Map<String, Value>::clone
    // pipeline that explicitly sorts keys to keep set operations stable.
    fn sort(v: &serde_json::Value) -> serde_json::Value {
        match v {
            serde_json::Value::Object(map) => {
                let mut sorted: Vec<(String, serde_json::Value)> =
                    map.iter().map(|(k, v)| (k.clone(), sort(v))).collect();
                sorted.sort_by(|a, b| a.0.cmp(&b.0));
                let mut out = serde_json::Map::new();
                for (k, v) in sorted {
                    out.insert(k, v);
                }
                serde_json::Value::Object(out)
            }
            serde_json::Value::Array(arr) => {
                serde_json::Value::Array(arr.iter().map(sort).collect())
            }
            other => other.clone(),
        }
    }
    serde_json::to_string(&sort(v)).unwrap_or_default()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn s3_bucket_made_public_is_critical() {
        let s = classify(
            ResourceType::AwsS3Bucket,
            "acl",
            &json!("private"),
            &json!("public-read"),
        );
        assert_eq!(s, DriftSeverity::Critical);
    }

    #[test]
    fn s3_bucket_still_private_drift_is_medium() {
        let s = classify(
            ResourceType::AwsS3Bucket,
            "acl",
            &json!("private"),
            &json!("authenticated-read"),
        );
        assert_eq!(s, DriftSeverity::Medium);
    }

    #[test]
    fn s3_unknown_attribute_is_low() {
        let s = classify(
            ResourceType::AwsS3Bucket,
            "tags",
            &json!({"env": "dev"}),
            &json!({"env": "prod"}),
        );
        assert_eq!(s, DriftSeverity::Low);
    }

    #[test]
    fn iam_trust_widened_with_new_principal_is_high() {
        let baseline = json!({
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "ec2.amazonaws.com"},
                "Action": "sts:AssumeRole"
            }]
        });
        let live = json!({
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "ec2.amazonaws.com"},
                "Action": "sts:AssumeRole"
            },{
                "Effect": "Allow",
                "Principal": {"AWS": "*"},
                "Action": "sts:AssumeRole"
            }]
        });
        let s = classify(
            ResourceType::AwsIamRole,
            "assume_role_policy",
            &baseline,
            &live,
        );
        assert_eq!(s, DriftSeverity::High);
    }

    #[test]
    fn iam_trust_unchanged_principals_is_medium() {
        let baseline = json!({
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "ec2.amazonaws.com"},
                "Action": "sts:AssumeRole"
            }]
        });
        let live = json!({
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "ec2.amazonaws.com"},
                "Action": "sts:AssumeRoleWithWebIdentity"
            }]
        });
        let s = classify(
            ResourceType::AwsIamRole,
            "assume_role_policy",
            &baseline,
            &live,
        );
        assert_eq!(s, DriftSeverity::Medium);
    }

    #[test]
    fn security_group_ingress_added_is_medium() {
        let baseline = json!([{"from_port": 443, "to_port": 443, "cidr_blocks": ["10.0.0.0/8"]}]);
        let live = json!([
            {"from_port": 443, "to_port": 443, "cidr_blocks": ["10.0.0.0/8"]},
            {"from_port": 22,  "to_port": 22,  "cidr_blocks": ["10.0.0.0/8"]}
        ]);
        let s = classify(ResourceType::AwsSecurityGroup, "ingress", &baseline, &live);
        assert_eq!(s, DriftSeverity::Medium);
    }

    #[test]
    fn security_group_widened_to_world_is_high() {
        let baseline = json!([{"from_port": 22, "to_port": 22, "cidr_blocks": ["10.0.0.0/8"]}]);
        let live = json!([{"from_port": 22, "to_port": 22, "cidr_blocks": ["0.0.0.0/0"]}]);
        let s = classify(ResourceType::AwsSecurityGroup, "ingress", &baseline, &live);
        assert_eq!(s, DriftSeverity::High);
    }

    #[test]
    fn drift_severity_round_trip_strings() {
        for v in [
            DriftSeverity::Low,
            DriftSeverity::Medium,
            DriftSeverity::High,
            DriftSeverity::Critical,
        ] {
            let s = serde_json::to_string(&v).unwrap();
            let back: DriftSeverity = serde_json::from_str(&s).unwrap();
            assert_eq!(v, back);
        }
        assert_eq!(DriftSeverity::Critical.as_str(), "critical");
    }

    #[test]
    fn stable_json_sorts_keys() {
        let a = stable_json(&json!({"b": 2, "a": 1}));
        let b = stable_json(&json!({"a": 1, "b": 2}));
        assert_eq!(a, b);
    }
}
