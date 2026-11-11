//! Cloud-inventory DTOs.
//!
//! Wire-shape types backing `POST /v1/cloud/inventory`. The request asks
//! the monolith to fan out across a list of cloud providers and return a
//! homogenised inventory. Provider strings are validated at the HTTP
//! boundary against the closed set `{aws, gcp, azure}` so that the
//! adapter layer never has to deal with an unknown provider name.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use validator::Validate;

/// `POST /v1/cloud/inventory` request body.
///
/// `providers` enumerates which hyperscaler connectors to invoke. Each
/// entry must be one of the canonical lowercase identifiers (`aws`,
/// `gcp`, `azure`); unknown values trip a 422 at the validation layer
/// before the controller even sees the request.
#[derive(Debug, Clone, Deserialize, Serialize, Validate)]
pub struct CloudInventoryRequestView {
    /// Tenant uuid (string at the wire boundary, parsed downstream).
    #[validate(length(min = 1))]
    pub tenant_id: String,

    /// Providers to fan out across. Must be non-empty and every entry
    /// must be one of `aws`/`gcp`/`azure`.
    #[validate(length(min = 1), custom(function = "validate_providers"))]
    pub providers: Vec<String>,

    /// Cap on results from any single provider. Clamped to `1..=10_000`
    /// at the boundary so a misconfigured client cannot starve the
    /// connector layer.
    #[validate(range(min = 1, max = 10_000))]
    pub max_per_provider: u32,
}

/// A single inventory record, normalised across providers.
///
/// Mirrors [`sx_cloud::model::CloudResource`] but elides the `raw` JSON
/// payload — the wire format is intentionally narrow.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CloudResourceView {
    /// Canonical upstream identifier (ARN, GCP resource path, Azure id).
    pub id: String,
    /// Provider name in lowercase (`aws`, `gcp`, `azure`).
    pub provider: String,
    /// Region / location, when applicable.
    pub region: Option<String>,
    /// Short service identifier (`iam`, `compute`, `storage`, ...).
    pub service: String,
    /// Kind within the service (`user`, `instance`, `bucket`, ...).
    pub kind: String,
    /// Display name (often the last path segment of `id`).
    pub name: String,
    /// Tag set, normalised to `BTreeMap` for stable serialisation.
    pub tags: BTreeMap<String, String>,
}

/// `POST /v1/cloud/inventory` response body.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CloudInventoryResponseView {
    /// Aggregated inventory across every requested connector. Empty when
    /// the monolith has no connectors registered (Phase-3.5 default).
    pub resources: Vec<CloudResourceView>,
}

/// Validate every entry in `providers` is one of the canonical strings.
///
/// We re-implement the match inline rather than depend on
/// [`sx_cloud::model::CloudProvider`]'s parser so the view crate does
/// not inherit cloud-specific error types just to compile.
fn validate_providers(values: &[String]) -> Result<(), validator::ValidationError> {
    for v in values {
        match v.as_str() {
            "aws" | "gcp" | "azure" => {}
            _ => return Err(validator::ValidationError::new("invalid_provider")),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_accepts_valid_payload() {
        let r = CloudInventoryRequestView {
            tenant_id: "t-1".into(),
            providers: vec!["aws".into(), "gcp".into(), "azure".into()],
            max_per_provider: 100,
        };
        assert!(r.validate().is_ok());
    }

    #[test]
    fn request_rejects_unknown_provider() {
        let r = CloudInventoryRequestView {
            tenant_id: "t-1".into(),
            providers: vec!["aws".into(), "oracle".into()],
            max_per_provider: 100,
        };
        assert!(r.validate().is_err());
    }

    #[test]
    fn request_rejects_zero_max() {
        let r = CloudInventoryRequestView {
            tenant_id: "t-1".into(),
            providers: vec!["aws".into()],
            max_per_provider: 0,
        };
        assert!(r.validate().is_err());
    }

    #[test]
    fn request_rejects_empty_providers() {
        let r = CloudInventoryRequestView {
            tenant_id: "t-1".into(),
            providers: vec![],
            max_per_provider: 10,
        };
        assert!(r.validate().is_err());
    }

    #[test]
    fn request_rejects_empty_tenant() {
        let r = CloudInventoryRequestView {
            tenant_id: String::new(),
            providers: vec!["aws".into()],
            max_per_provider: 10,
        };
        assert!(r.validate().is_err());
    }

    #[test]
    fn request_rejects_max_over_limit() {
        let r = CloudInventoryRequestView {
            tenant_id: "t-1".into(),
            providers: vec!["aws".into()],
            max_per_provider: 10_001,
        };
        assert!(r.validate().is_err());
    }
}
