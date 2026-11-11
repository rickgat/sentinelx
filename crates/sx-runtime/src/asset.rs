//! Best-effort Kubernetes `asset_id` resolution.
//!
//! Falco alerts carry `container.image.repository` and `k8s.pod.name`
//! (sometimes `k8s.ns.name`) in their output fields. We build a stable
//! synthetic `asset_id` from those tuples so the SOC pipeline can correlate
//! the finding against an asset-graph node populated by `sx-cloud` /
//! `sx-discovery` without requiring an online DB lookup here.
//!
//! The asset id format is:
//!
//! ```text
//! k8s://{namespace}/{pod}/{image}
//! ```
//!
//! with `default` substituted for a missing namespace. When both pod and
//! image are missing we return `None`.

use crate::alert::FalcoAlert;

/// Subset of fields used to derive the asset id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssetHint<'a> {
    /// Container image repository (e.g. `"nginx"`).
    pub image: Option<&'a str>,
    /// K8s pod name (e.g. `"web-7c4d6f-abc"`).
    pub pod: Option<&'a str>,
    /// K8s namespace (e.g. `"prod"`). Defaults to `"default"` when absent.
    pub namespace: Option<&'a str>,
}

impl<'a> AssetHint<'a> {
    /// Pull a hint out of a Falco alert's `output_fields`.
    #[must_use]
    pub fn from_alert(alert: &'a FalcoAlert) -> Self {
        let image = alert
            .field_str("container.image.repository")
            .or_else(|| alert.field_str("container.image"));
        let pod = alert
            .field_str("k8s.pod.name")
            .or_else(|| alert.field_str("k8s.pod"));
        let namespace = alert
            .field_str("k8s.ns.name")
            .or_else(|| alert.field_str("k8s.namespace.name"))
            .or_else(|| alert.field_str("k8s.ns"));
        Self {
            image,
            pod,
            namespace,
        }
    }
}

/// Derive a synthetic, deterministic `asset_id` from the hint.
///
/// Returns `None` when neither pod nor image is present — without either,
/// any synthesised id would alias every alert into a single bucket.
#[must_use]
pub fn resolve_asset_id(hint: &AssetHint<'_>) -> Option<String> {
    if hint.pod.is_none() && hint.image.is_none() {
        return None;
    }
    let ns = hint.namespace.unwrap_or("default");
    let pod = hint.pod.unwrap_or("-");
    let image = hint.image.unwrap_or("-");
    Some(format!("k8s://{ns}/{pod}/{image}"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn alert_with_fields(fields: &serde_json::Value) -> FalcoAlert {
        let v = serde_json::json!({
            "rule": "x",
            "priority": "Notice",
            "output_fields": fields,
        });
        serde_json::from_value(v).unwrap()
    }

    #[test]
    fn hint_extracts_three_keys() {
        let a = alert_with_fields(&serde_json::json!({
            "container.image.repository": "nginx",
            "k8s.pod.name": "web-1",
            "k8s.ns.name": "prod"
        }));
        let h = AssetHint::from_alert(&a);
        assert_eq!(h.image, Some("nginx"));
        assert_eq!(h.pod, Some("web-1"));
        assert_eq!(h.namespace, Some("prod"));
    }

    #[test]
    fn resolve_returns_none_when_both_missing() {
        let h = AssetHint {
            image: None,
            pod: None,
            namespace: Some("prod"),
        };
        assert!(resolve_asset_id(&h).is_none());
    }

    #[test]
    fn resolve_defaults_namespace_to_default() {
        let h = AssetHint {
            image: Some("nginx"),
            pod: Some("web-1"),
            namespace: None,
        };
        assert_eq!(
            resolve_asset_id(&h).as_deref(),
            Some("k8s://default/web-1/nginx")
        );
    }

    #[test]
    fn resolve_handles_pod_only() {
        let h = AssetHint {
            image: None,
            pod: Some("web-1"),
            namespace: Some("prod"),
        };
        assert_eq!(resolve_asset_id(&h).as_deref(), Some("k8s://prod/web-1/-"));
    }

    #[test]
    fn resolve_handles_image_only() {
        let h = AssetHint {
            image: Some("nginx"),
            pod: None,
            namespace: None,
        };
        assert_eq!(
            resolve_asset_id(&h).as_deref(),
            Some("k8s://default/-/nginx")
        );
    }
}
