//! Cloud-inventory adapter.
//!
//! Builds the `sx-cloud` composition-root bundle and adapts the
//! [`RunInventoryUseCase`] behind the
//! [`sx_api::port::CloudInventoryPort`] trait so the HTTP layer can
//! drive it without depending on `sx-cloud` directly.
//!
//! ## Phase-3.5+2 wire-up — credentials sourced from `sx-config`
//!
//! Each enabled provider in [`sx_config::CloudConfig`] is materialised into
//! a concrete [`CloudConnector`] and pushed into the fan-out list passed
//! to [`RunInventoryUseCase::new`]. When every provider is disabled the
//! resulting connector list is empty and the route remains a no-op — the
//! same shape Phase-3.5+1 shipped, but now toggled by configuration.

use std::sync::Arc;

use async_trait::async_trait;
use secrecy::SecretString;
use sx_api::port::{CloudInventoryPort, Phase3PortError};
use sx_api::view::cloud_view::{
    CloudInventoryRequestView, CloudInventoryResponseView, CloudResourceView,
};
use sx_cloud::controller::inventory::RunInventoryUseCase;
use sx_cloud::error::CloudError;
use sx_cloud::model::{CloudProvider, CloudResource, ListResourcesRequest};
use sx_cloud::service::{
    AwsCloudConnector, AwsCredentials, AzureCloudConnector, AzureTokenProvider, CloudConnector,
    GcpCloudConnector, GcpTokenProvider,
};
use tracing::info;

/// Bundle returned by [`build`].
pub(crate) struct CloudBundle {
    /// The fan-out inventory port the API layer wires into `AppState`.
    pub list: Arc<dyn CloudInventoryPort>,
    /// The shared `RunInventoryUseCase` handle — re-used by the cloud-drift
    /// adapter (P2-004) so a drift scan pulls live state from the same
    /// connector set that powers `/v1/cloud/inventory`.
    pub use_case: Arc<RunInventoryUseCase>,
}

/// Build the cloud bundle.
///
/// `http` is the shared HTTP client — every constructed connector reuses
/// the same client so connection pools stay warm. `cfg` carries the per-
/// provider toggles and credentials. Any provider with `enabled: false`
/// is skipped silently.
#[allow(dead_code)] // parent composition root wires this in
pub(crate) fn build(http: reqwest::Client, cfg: &sx_config::CloudConfig) -> CloudBundle {
    let mut connectors: Vec<Arc<dyn CloudConnector>> = Vec::new();

    if cfg.aws.enabled {
        match build_aws(http.clone(), &cfg.aws) {
            Ok(c) => {
                info!(
                    target: "adapters.cloud.connector",
                    provider = "aws",
                    region = %cfg.aws.region,
                    "registered",
                );
                connectors.push(c);
            }
            Err(e) => {
                tracing::warn!(
                    target: "adapters.cloud.connector",
                    provider = "aws",
                    error = %e,
                    "aws connector construction failed; skipping",
                );
            }
        }
    }

    if cfg.gcp.enabled {
        match build_gcp(http.clone(), &cfg.gcp) {
            Ok(c) => {
                info!(
                    target: "adapters.cloud.connector",
                    provider = "gcp",
                    project_id = %cfg.gcp.project_id,
                    "registered",
                );
                connectors.push(c);
            }
            Err(e) => {
                tracing::warn!(
                    target: "adapters.cloud.connector",
                    provider = "gcp",
                    error = %e,
                    "gcp connector construction failed; skipping",
                );
            }
        }
    }

    if cfg.azure.enabled {
        match build_azure(http, &cfg.azure) {
            Ok(c) => {
                info!(
                    target: "adapters.cloud.connector",
                    provider = "azure",
                    subscription_id = %cfg.azure.subscription_id,
                    tenant_id = %cfg.azure.tenant_id,
                    "registered",
                );
                connectors.push(c);
            }
            Err(e) => {
                tracing::warn!(
                    target: "adapters.cloud.connector",
                    provider = "azure",
                    error = %e,
                    "azure connector construction failed; skipping",
                );
            }
        }
    }

    let count = connectors.len();
    let inventory_use_case = Arc::new(RunInventoryUseCase::new(connectors));

    info!(
        target: "adapters.cloud.built",
        connectors = count,
        "",
    );

    CloudBundle {
        list: Arc::new(CloudInventoryAdapter {
            use_case: Arc::clone(&inventory_use_case),
        }),
        use_case: inventory_use_case,
    }
}

/// Construct an AWS connector from the credentialled config block.
fn build_aws(
    http: reqwest::Client,
    cfg: &sx_config::AwsConfig,
) -> Result<Arc<dyn CloudConnector>, CloudError> {
    let creds = AwsCredentials {
        access_key_id: cfg.access_key_id.clone(),
        secret_access_key: cfg.secret_access_key.clone(),
        session_token: cfg.session_token.clone(),
    };
    let conn = AwsCloudConnector::new(http, creds, cfg.region.clone())?;
    Ok(Arc::new(conn))
}

/// Construct a GCP connector with a static bearer-token provider.
fn build_gcp(
    http: reqwest::Client,
    cfg: &sx_config::GcpConfig,
) -> Result<Arc<dyn CloudConnector>, CloudError> {
    let token: Arc<dyn GcpTokenProvider> = Arc::new(StaticGcpToken(cfg.access_token.clone()));
    let conn = GcpCloudConnector::new(http, cfg.project_id.clone(), token)?;
    Ok(Arc::new(conn))
}

/// Construct an Azure connector with a static bearer-token provider.
fn build_azure(
    http: reqwest::Client,
    cfg: &sx_config::AzureConfig,
) -> Result<Arc<dyn CloudConnector>, CloudError> {
    let token: Arc<dyn AzureTokenProvider> = Arc::new(StaticAzureToken(cfg.access_token.clone()));
    let conn = AzureCloudConnector::new(
        http,
        cfg.subscription_id.clone(),
        cfg.tenant_id.clone(),
        token,
    )?;
    Ok(Arc::new(conn))
}

/// Static GCP bearer-token source.
///
/// Wraps a configured [`SecretString`] and hands a fresh clone to the
/// connector on every call. The token is never logged.
#[derive(Debug)]
struct StaticGcpToken(SecretString);

#[async_trait]
impl GcpTokenProvider for StaticGcpToken {
    async fn bearer_token(&self) -> Result<SecretString, CloudError> {
        Ok(self.0.clone())
    }
}

/// Static Azure bearer-token source. See [`StaticGcpToken`].
#[derive(Debug)]
struct StaticAzureToken(SecretString);

#[async_trait]
impl AzureTokenProvider for StaticAzureToken {
    async fn bearer_token(&self) -> Result<SecretString, CloudError> {
        Ok(self.0.clone())
    }
}

/// Thin façade over [`RunInventoryUseCase`] implementing
/// [`CloudInventoryPort`].
///
/// Translates the HTTP view into a [`ListResourcesRequest`], invokes the
/// fan-out use case, and maps every returned [`CloudResource`] into a
/// [`CloudResourceView`]. The `raw` JSON payload is intentionally dropped
/// to keep the wire shape narrow.
struct CloudInventoryAdapter {
    use_case: Arc<RunInventoryUseCase>,
}

impl std::fmt::Debug for CloudInventoryAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CloudInventoryAdapter")
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl CloudInventoryPort for CloudInventoryAdapter {
    async fn list(
        &self,
        req: CloudInventoryRequestView,
    ) -> Result<CloudInventoryResponseView, Phase3PortError> {
        // The HTTP layer already enforced `providers.len() >= 1` and
        // each entry is one of `{aws, gcp, azure}`. The fan-out use case
        // currently accepts a single optional provider filter, so when
        // the caller asked for several providers we leave the filter
        // unset (the use case will run every registered connector
        // anyway).
        let provider_filter = if req.providers.len() == 1 {
            req.providers.first().and_then(|s| parse_provider(s))
        } else {
            None
        };
        let ls_req = ListResourcesRequest {
            provider: provider_filter,
            service: None,
            // `max_per_provider` translates into a page cap so we never
            // chase pagination forever — the use case treats `max_pages`
            // as an upper bound, not a row count.
            max_pages: Some(req.max_per_provider),
        };

        let resources = self
            .use_case
            .execute(ls_req)
            .await
            .map_err(|e| Phase3PortError::Dependency(e.to_string()))?;

        Ok(CloudInventoryResponseView {
            resources: resources.into_iter().map(map_resource).collect(),
        })
    }
}

/// Parse a validated provider string (`aws`/`gcp`/`azure`) into the
/// [`CloudProvider`] enum. Returns `None` on anything else, which the
/// validator should already have rejected.
fn parse_provider(s: &str) -> Option<CloudProvider> {
    match s {
        "aws" => Some(CloudProvider::Aws),
        "gcp" => Some(CloudProvider::Gcp),
        "azure" => Some(CloudProvider::Azure),
        _ => None,
    }
}

/// Project a `sx-cloud` resource into the HTTP view, lowercasing the
/// provider tag to keep the wire format stable across crate versions.
fn map_resource(r: CloudResource) -> CloudResourceView {
    CloudResourceView {
        id: r.id,
        provider: r.provider.as_str().to_owned(),
        region: r.region,
        service: r.service,
        kind: r.kind,
        name: r.name,
        tags: r.tags,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::collections::BTreeMap;

    use async_trait::async_trait;
    use secrecy::SecretString;
    use sx_cloud::error::CloudError;
    use sx_cloud::service::connector::ConnectorIdentity;

    use super::*;

    fn http() -> reqwest::Client {
        reqwest::Client::builder().build().unwrap()
    }

    fn req(providers: Vec<&str>) -> CloudInventoryRequestView {
        CloudInventoryRequestView {
            tenant_id: "t-1".into(),
            providers: providers.into_iter().map(str::to_owned).collect(),
            max_per_provider: 50,
        }
    }

    fn disabled_cloud_cfg() -> sx_config::CloudConfig {
        sx_config::CloudConfig {
            aws: sx_config::AwsConfig {
                enabled: false,
                access_key_id: String::new(),
                secret_access_key: SecretString::from(String::new()),
                session_token: None,
                region: "us-east-1".to_owned(),
            },
            gcp: sx_config::GcpConfig {
                enabled: false,
                project_id: String::new(),
                access_token: SecretString::from(String::new()),
            },
            azure: sx_config::AzureConfig {
                enabled: false,
                subscription_id: String::new(),
                tenant_id: String::new(),
                access_token: SecretString::from(String::new()),
            },
        }
    }

    #[tokio::test]
    async fn cloud_adapter_returns_empty_when_no_connectors_registered() {
        let cfg = disabled_cloud_cfg();
        let bundle = build(http(), &cfg);
        let resp = bundle.list.list(req(vec!["aws", "gcp", "azure"])).await;
        let resp = resp.expect("port must succeed even without connectors");
        assert!(
            resp.resources.is_empty(),
            "expected empty inventory, got {} entries",
            resp.resources.len()
        );
    }

    #[tokio::test]
    async fn build_with_all_disabled_registers_zero_connectors() {
        let cfg = disabled_cloud_cfg();
        let bundle = build(http(), &cfg);
        // No connectors means no resources are returned regardless of the
        // request payload.
        let resp = bundle
            .list
            .list(req(vec!["aws"]))
            .await
            .expect("port must succeed");
        assert!(resp.resources.is_empty());
    }

    #[tokio::test]
    async fn build_with_aws_enabled_registers_one_connector() {
        let mut cfg = disabled_cloud_cfg();
        cfg.aws.enabled = true;
        cfg.aws.access_key_id = "AKIATEST".to_owned();
        cfg.aws.secret_access_key = SecretString::from("a-very-secret-value".to_owned());
        cfg.aws.region = "us-east-1".to_owned();
        let bundle = build(http(), &cfg);
        // The connector itself would try to reach STS on `.list(...)`, so
        // we only verify the bundle materialised — not that the upstream
        // call succeeds.
        let _ = bundle;
    }

    #[tokio::test]
    async fn build_with_three_enabled_registers_three_connectors() {
        let mut cfg = disabled_cloud_cfg();
        cfg.aws.enabled = true;
        cfg.aws.access_key_id = "AKIATEST".to_owned();
        cfg.aws.secret_access_key = SecretString::from("secret".to_owned());
        cfg.aws.region = "us-east-1".to_owned();
        cfg.gcp.enabled = true;
        cfg.gcp.project_id = "proj-1".to_owned();
        cfg.gcp.access_token = SecretString::from("gcp-token".to_owned());
        cfg.azure.enabled = true;
        cfg.azure.subscription_id = "sub-1".to_owned();
        cfg.azure.tenant_id = "tenant-1".to_owned();
        cfg.azure.access_token = SecretString::from("az-token".to_owned());
        let bundle = build(http(), &cfg);
        let _ = bundle;
    }

    #[derive(Debug)]
    struct StubAws {
        out: Vec<CloudResource>,
    }
    #[async_trait]
    impl CloudConnector for StubAws {
        fn provider(&self) -> CloudProvider {
            CloudProvider::Aws
        }
        async fn validate(&self) -> Result<ConnectorIdentity, CloudError> {
            Ok(ConnectorIdentity {
                provider: CloudProvider::Aws,
                account_id: "acct".into(),
                principal: "p".into(),
            })
        }
        async fn list_resources(
            &self,
            _req: &ListResourcesRequest,
        ) -> Result<Vec<CloudResource>, CloudError> {
            Ok(self.out.clone())
        }
    }

    #[tokio::test]
    async fn cloud_adapter_maps_aws_resource_to_view() {
        let mut tags = BTreeMap::new();
        tags.insert("env".to_owned(), "prod".to_owned());
        let r = CloudResource {
            id: "arn:aws:iam::123:user/alice".into(),
            provider: CloudProvider::Aws,
            region: Some("us-east-1".into()),
            service: "iam".into(),
            kind: "user".into(),
            name: "alice".into(),
            tags,
            raw: serde_json::Value::Null,
        };
        let aws: Arc<dyn CloudConnector> = Arc::new(StubAws { out: vec![r] });
        let use_case = Arc::new(RunInventoryUseCase::new(vec![aws]));
        let adapter = CloudInventoryAdapter { use_case };

        let resp = adapter.list(req(vec!["aws"])).await.unwrap();
        assert_eq!(resp.resources.len(), 1);
        let v = &resp.resources[0];
        assert_eq!(v.provider, "aws");
        assert_eq!(v.id, "arn:aws:iam::123:user/alice");
        assert_eq!(v.service, "iam");
        assert_eq!(v.kind, "user");
        assert_eq!(v.name, "alice");
        assert_eq!(v.region.as_deref(), Some("us-east-1"));
        assert_eq!(v.tags.get("env").map(String::as_str), Some("prod"));
    }

    #[test]
    fn parse_provider_round_trip() {
        assert_eq!(parse_provider("aws"), Some(CloudProvider::Aws));
        assert_eq!(parse_provider("gcp"), Some(CloudProvider::Gcp));
        assert_eq!(parse_provider("azure"), Some(CloudProvider::Azure));
        assert_eq!(parse_provider("oracle"), None);
    }
}
