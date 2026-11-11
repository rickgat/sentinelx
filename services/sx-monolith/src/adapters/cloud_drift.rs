//! Cloud-drift adapter (P2-004).
//!
//! Wires the in-memory [`InMemoryCloudDriftService`] from `sx_cloud::drift`
//! behind the [`CloudDriftPort`] HTTP trait. The adapter is responsible
//! for:
//!
//! 1. Parsing the uploaded IaC payload (Terraform JSON or CloudFormation
//!    YAML) into a normalised [`BaselineDoc`] at upload time so the diff
//!    engine never deals with raw bytes.
//! 2. Pulling the live cloud inventory from the shared
//!    [`RunInventoryUseCase`] on every scan request.
//! 3. Projecting [`sx_cloud::drift::DriftEntry`] onto the wire DTO.
//!
//! ## Tenant scoping
//!
//! Every method takes `tenant_id` as a string and parses it into a
//! [`Uuid`] before forwarding to the underlying service. Bad uuids are
//! rejected as [`CloudDriftPortError::Invalid`] without touching state,
//! so a misshapen JWT can never cross-pollinate tenants.
//!
//! ## Most-recent baseline fallback
//!
//! When the controller calls [`Self::scan`] without an explicit
//! `baseline_id` the adapter resolves the lexicographically-first
//! baseline name belonging to the tenant. The MVP does not yet record
//! per-baseline `uploaded_at`; ordering by name keeps behaviour
//! deterministic.

use std::str::FromStr;
use std::sync::Arc;

use async_trait::async_trait;
use sx_api::port::{CloudDriftPort, CloudDriftPortError};
use sx_api::view::cloud_drift_view::{
    BaselineSummaryView, DriftEntryView, DriftListResponse, DriftScanResponse,
    ListBaselinesResponse, UploadBaselineResponse,
};
use sx_cloud::controller::inventory::RunInventoryUseCase;
use sx_cloud::drift::baseline::{self, BaselineFormat, BaselineParseError};
use sx_cloud::drift::{CloudDriftService, DetectDriftError, DriftEntry, InMemoryCloudDriftService};
use sx_cloud::model::ListResourcesRequest;
use tracing::{info, instrument, warn};
use uuid::Uuid;

/// Default page cap used on the live-inventory pull. Matches the
/// validator-enforced upper bound on `POST /v1/cloud/inventory` so the
/// two endpoints share the same starvation guarantees.
const DEFAULT_MAX_PAGES: u32 = 10_000;

/// Bundle handed to the composition root.
pub(crate) struct CloudDriftBundle {
    /// HTTP-facing port.
    pub(crate) port: Arc<dyn CloudDriftPort>,
}

/// Build the bundle.
///
/// Both inputs are `Arc`-wrapped so the adapter can keep them live
/// independently of the call sites that built them.
pub(crate) fn build(inventory: Arc<RunInventoryUseCase>) -> CloudDriftBundle {
    let service = Arc::new(InMemoryCloudDriftService::new());
    let port: Arc<dyn CloudDriftPort> = Arc::new(CloudDriftAdapter { service, inventory });
    CloudDriftBundle { port }
}

/// In-process cloud-drift adapter.
struct CloudDriftAdapter {
    service: Arc<InMemoryCloudDriftService>,
    inventory: Arc<RunInventoryUseCase>,
}

impl std::fmt::Debug for CloudDriftAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CloudDriftAdapter").finish_non_exhaustive()
    }
}

#[async_trait]
impl CloudDriftPort for CloudDriftAdapter {
    #[instrument(
        skip(self, payload),
        fields(tenant_id = %tenant_id, name = %name, format = %format),
    )]
    async fn upload_baseline(
        &self,
        tenant_id: &str,
        name: &str,
        format: &str,
        payload: Vec<u8>,
    ) -> Result<UploadBaselineResponse, CloudDriftPortError> {
        let tenant = parse_tenant(tenant_id)?;
        let fmt = BaselineFormat::parse(format).ok_or_else(|| {
            CloudDriftPortError::Invalid(format!(
                "unknown baseline format `{format}`; expected `terraform_json` or `cloudformation_yaml`"
            ))
        })?;

        let doc = parse_baseline(fmt, &payload).map_err(|e| match e {
            BaselineParseError::Malformed { format, reason } => {
                CloudDriftPortError::Invalid(format!("{format}: {reason}"))
            }
            BaselineParseError::Empty => CloudDriftPortError::Invalid(
                "baseline contained no supported resource types".to_owned(),
            ),
        })?;
        let resource_count = doc.resources.len();

        let id = self
            .service
            .store_baseline(tenant, name.to_owned(), fmt, payload, doc)
            .await
            .map_err(map_detect_err)?;

        info!(
            target: "adapters.cloud_drift",
            tenant_id = %tenant,
            baseline_id = %id,
            format = fmt.as_str(),
            resource_count,
            "baseline uploaded",
        );

        // `resource_count` is a `usize`. The HTTP DTO uses `u32` because the
        // wire shape is plumbed into JS clients that get unhappy with
        // anything wider. Clamp instead of panicking on overflow.
        let resource_count_u32 = u32::try_from(resource_count).unwrap_or(u32::MAX);

        Ok(UploadBaselineResponse {
            id: id.to_string(),
            name: name.to_owned(),
            format: fmt.as_str().to_owned(),
            resource_count: resource_count_u32,
        })
    }

    #[instrument(skip(self), fields(tenant_id = %tenant_id))]
    async fn list_baselines(
        &self,
        tenant_id: &str,
    ) -> Result<ListBaselinesResponse, CloudDriftPortError> {
        let tenant = parse_tenant(tenant_id)?;
        let rows = self
            .service
            .list_baselines(tenant)
            .await
            .map_err(map_detect_err)?;
        let items = rows
            .into_iter()
            .map(|r| BaselineSummaryView {
                id: r.id.to_string(),
                name: r.name,
                format: r.format.as_str().to_owned(),
                resource_count: u32::try_from(r.resource_count).unwrap_or(u32::MAX),
            })
            .collect();
        Ok(ListBaselinesResponse { items })
    }

    #[instrument(
        skip(self),
        fields(
            tenant_id = %tenant_id,
            engagement_id = %engagement_id,
            baseline_id = baseline_id.unwrap_or("<latest>"),
        ),
    )]
    async fn scan(
        &self,
        tenant_id: &str,
        engagement_id: &str,
        baseline_id: Option<&str>,
    ) -> Result<DriftScanResponse, CloudDriftPortError> {
        let tenant = parse_tenant(tenant_id)?;
        if engagement_id.is_empty() {
            return Err(CloudDriftPortError::Invalid(
                "engagement_id must not be empty".to_owned(),
            ));
        }

        // Resolve the baseline: explicit when supplied, otherwise the
        // alphabetically-first baseline for the tenant. The
        // `list_baselines` call below is tenant-scoped, so a missing
        // baseline surfaces as `NotFound` and never leaks across tenants.
        let baseline_uuid = if let Some(s) = baseline_id {
            Uuid::parse_str(s)
                .map_err(|e| CloudDriftPortError::Invalid(format!("invalid baseline_id: {e}")))?
        } else {
            let rows = self
                .service
                .list_baselines(tenant)
                .await
                .map_err(map_detect_err)?;
            let first = rows
                .into_iter()
                .next()
                .ok_or(CloudDriftPortError::NotFound)?;
            first.id
        };

        // Live inventory pull. We deliberately do not filter by provider
        // — the diff engine's resource-type whitelist throws away anything
        // it does not understand. A connector failure surfaces as a
        // warn-level log line and an empty inventory; we treat that as a
        // dependency error so the caller knows the report is incomplete.
        let live_req = ListResourcesRequest {
            provider: None,
            service: None,
            max_pages: Some(DEFAULT_MAX_PAGES),
        };
        let live = match self.inventory.execute(live_req).await {
            Ok(v) => v,
            Err(e) => {
                warn!(
                    target: "adapters.cloud_drift",
                    tenant_id = %tenant,
                    engagement_id = %engagement_id,
                    error = %e,
                    "live inventory pull failed",
                );
                return Err(CloudDriftPortError::Dependency(e.to_string()));
            }
        };

        let entries = self
            .service
            .detect_drift(tenant, baseline_uuid, live)
            .await
            .map_err(map_detect_err)?;

        info!(
            target: "adapters.cloud_drift",
            tenant_id = %tenant,
            engagement_id = %engagement_id,
            baseline_id = %baseline_uuid,
            entries = entries.len(),
            "drift scan completed",
        );

        Ok(DriftScanResponse {
            baseline_id: baseline_uuid.to_string(),
            entries: entries.iter().map(project_entry).collect(),
        })
    }

    #[instrument(skip(self), fields(tenant_id = %tenant_id))]
    async fn list_drift(
        &self,
        tenant_id: &str,
        asset_filter: Option<&str>,
    ) -> Result<DriftListResponse, CloudDriftPortError> {
        let tenant = parse_tenant(tenant_id)?;
        let entries = self
            .service
            .list_drift(tenant, asset_filter)
            .await
            .map_err(map_detect_err)?;
        Ok(DriftListResponse {
            items: entries.iter().map(project_entry).collect(),
        })
    }
}

/// Parse `tenant_id` as a uuid or surface a tidy `Invalid`.
fn parse_tenant(s: &str) -> Result<Uuid, CloudDriftPortError> {
    Uuid::from_str(s).map_err(|e| CloudDriftPortError::Invalid(format!("invalid tenant_id: {e}")))
}

/// Dispatch to the right baseline parser.
fn parse_baseline(
    fmt: BaselineFormat,
    payload: &[u8],
) -> Result<sx_cloud::drift::BaselineDoc, BaselineParseError> {
    match fmt {
        BaselineFormat::TerraformJson => baseline::terraform::parse(payload),
        BaselineFormat::CloudformationYaml => baseline::cloudformation::parse(payload),
    }
}

/// Translate the underlying service error into the HTTP-facing one.
fn map_detect_err(err: DetectDriftError) -> CloudDriftPortError {
    match err {
        DetectDriftError::EmptyBaseline => CloudDriftPortError::NotFound,
        DetectDriftError::Internal(m) => CloudDriftPortError::Internal(m),
    }
}

/// Project a [`DriftEntry`] onto the wire DTO.
fn project_entry(e: &DriftEntry) -> DriftEntryView {
    DriftEntryView {
        resource_id: e.resource_id.clone(),
        resource_type: e.resource_type.clone(),
        attribute: e.attribute.clone(),
        baseline_value: e.baseline_value.clone(),
        live_value: e.live_value.clone(),
        severity: e.severity_hint.as_str().to_owned(),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::collections::BTreeMap;

    use sx_cloud::model::{CloudProvider, CloudResource};
    use sx_cloud::service::connector::CloudConnector;

    use super::*;

    /// Minimal terraform-style JSON fixture (one bucket, two attributes).
    const TF_FIXTURE: &[u8] = br#"{
        "values": {
            "root_module": {
                "resources": [
                    {
                        "address": "aws_s3_bucket.evidence",
                        "type": "aws_s3_bucket",
                        "name": "evidence",
                        "values": {
                            "arn": "arn:aws:s3:::evidence-prod",
                            "acl": "private"
                        }
                    }
                ]
            }
        }
    }"#;

    /// Minimal CFN-style YAML fixture.
    const CFN_FIXTURE: &[u8] = br#"
AWSTemplateFormatVersion: "2010-09-09"
Resources:
  Evidence:
    Type: AWS::S3::Bucket
    Properties:
      AccessControl: Private
"#;

    /// Stub connector that always returns a fixed inventory.
    #[derive(Debug)]
    struct StubConnector {
        out: Vec<CloudResource>,
    }

    #[async_trait]
    impl CloudConnector for StubConnector {
        fn provider(&self) -> CloudProvider {
            CloudProvider::Aws
        }
        async fn validate(
            &self,
        ) -> Result<sx_cloud::service::connector::ConnectorIdentity, sx_cloud::error::CloudError>
        {
            Ok(sx_cloud::service::connector::ConnectorIdentity {
                provider: CloudProvider::Aws,
                account_id: "stub".into(),
                principal: "stub-principal".into(),
            })
        }
        async fn list_resources(
            &self,
            _req: &ListResourcesRequest,
        ) -> Result<Vec<CloudResource>, sx_cloud::error::CloudError> {
            Ok(self.out.clone())
        }
    }

    fn live_bucket(acl: &str) -> CloudResource {
        CloudResource {
            id: "arn:aws:s3:::evidence-prod".into(),
            provider: CloudProvider::Aws,
            region: None,
            service: "s3".into(),
            kind: "bucket".into(),
            name: "evidence-prod".into(),
            tags: BTreeMap::new(),
            raw: serde_json::json!({ "acl": acl }),
        }
    }

    fn adapter_with(out: Vec<CloudResource>) -> CloudDriftBundle {
        let conn: Arc<dyn CloudConnector> = Arc::new(StubConnector { out });
        let inv = Arc::new(RunInventoryUseCase::new(vec![conn]));
        build(inv)
    }

    fn tenant_id() -> String {
        Uuid::new_v4().to_string()
    }

    #[tokio::test]
    async fn upload_then_scan_detects_acl_drift() {
        let bundle = adapter_with(vec![live_bucket("public-read")]);
        let tid = tenant_id();
        let resp = bundle
            .port
            .upload_baseline(&tid, "main", "terraform_json", TF_FIXTURE.to_vec())
            .await
            .expect("upload ok");
        assert_eq!(resp.format, "terraform_json");
        assert_eq!(resp.resource_count, 1);

        let scan = bundle
            .port
            .scan(&tid, "engagement-1", Some(&resp.id))
            .await
            .expect("scan ok");
        assert_eq!(scan.baseline_id, resp.id);
        assert!(!scan.entries.is_empty(), "expected drift entries");
        let acl_entry = scan
            .entries
            .iter()
            .find(|e| e.attribute == "acl")
            .expect("acl entry present");
        assert_eq!(acl_entry.severity, "critical");
        assert_eq!(acl_entry.resource_id, "arn:aws:s3:::evidence-prod");
    }

    #[tokio::test]
    async fn scan_falls_back_to_only_baseline() {
        let bundle = adapter_with(vec![live_bucket("public-read")]);
        let tid = tenant_id();
        let _ = bundle
            .port
            .upload_baseline(&tid, "main", "terraform_json", TF_FIXTURE.to_vec())
            .await
            .unwrap();
        let scan = bundle.port.scan(&tid, "engagement-1", None).await.unwrap();
        assert!(!scan.entries.is_empty());
    }

    #[tokio::test]
    async fn scan_without_baseline_returns_not_found() {
        let bundle = adapter_with(vec![]);
        let tid = tenant_id();
        let err = bundle
            .port
            .scan(&tid, "engagement-1", None)
            .await
            .unwrap_err();
        assert!(matches!(err, CloudDriftPortError::NotFound));
    }

    #[tokio::test]
    async fn upload_rejects_unknown_format() {
        let bundle = adapter_with(vec![]);
        let tid = tenant_id();
        let err = bundle
            .port
            .upload_baseline(&tid, "main", "yaml", b"{}".to_vec())
            .await
            .unwrap_err();
        assert!(matches!(err, CloudDriftPortError::Invalid(_)));
    }

    #[tokio::test]
    async fn upload_rejects_malformed_payload() {
        let bundle = adapter_with(vec![]);
        let tid = tenant_id();
        let err = bundle
            .port
            .upload_baseline(&tid, "main", "terraform_json", b"{not json".to_vec())
            .await
            .unwrap_err();
        assert!(matches!(err, CloudDriftPortError::Invalid(_)));
    }

    #[tokio::test]
    async fn upload_accepts_cloudformation_yaml() {
        let bundle = adapter_with(vec![]);
        let tid = tenant_id();
        let resp = bundle
            .port
            .upload_baseline(&tid, "cfn", "cloudformation_yaml", CFN_FIXTURE.to_vec())
            .await
            .expect("ok");
        assert_eq!(resp.format, "cloudformation_yaml");
        assert_eq!(resp.resource_count, 1);
    }

    #[tokio::test]
    async fn bad_tenant_id_rejected_without_state_touch() {
        let bundle = adapter_with(vec![]);
        let err = bundle
            .port
            .upload_baseline("not-a-uuid", "main", "terraform_json", TF_FIXTURE.to_vec())
            .await
            .unwrap_err();
        assert!(matches!(err, CloudDriftPortError::Invalid(_)));
    }

    #[tokio::test]
    async fn tenants_are_isolated() {
        let bundle = adapter_with(vec![live_bucket("public-read")]);
        let t1 = tenant_id();
        let t2 = tenant_id();
        let resp = bundle
            .port
            .upload_baseline(&t1, "main", "terraform_json", TF_FIXTURE.to_vec())
            .await
            .unwrap();
        let _ = bundle
            .port
            .scan(&t1, "engagement-1", Some(&resp.id))
            .await
            .unwrap();

        // Tenant 2 cannot see tenant 1's baseline or findings.
        let baselines = bundle.port.list_baselines(&t2).await.unwrap();
        assert!(baselines.items.is_empty());
        let findings = bundle.port.list_drift(&t2, None).await.unwrap();
        assert!(findings.items.is_empty());
    }

    #[tokio::test]
    async fn list_drift_filters_by_asset_substring() {
        let bundle = adapter_with(vec![live_bucket("public-read")]);
        let tid = tenant_id();
        let resp = bundle
            .port
            .upload_baseline(&tid, "main", "terraform_json", TF_FIXTURE.to_vec())
            .await
            .unwrap();
        let _ = bundle
            .port
            .scan(&tid, "engagement-1", Some(&resp.id))
            .await
            .unwrap();
        let none = bundle
            .port
            .list_drift(&tid, Some("does-not-match"))
            .await
            .unwrap();
        assert!(none.items.is_empty());
        let some = bundle
            .port
            .list_drift(&tid, Some("evidence-prod"))
            .await
            .unwrap();
        assert!(!some.items.is_empty());
    }
}
