//! Google Cloud connector — Cloud Asset Inventory `listAssets`.
//!
//! Authentication is delegated to a pluggable [`GcpTokenProvider`] so
//! callers can wire whatever credential source they prefer (service
//! account JWT exchange, workload identity, GCE metadata server, etc.).

use std::sync::Arc;

use async_trait::async_trait;
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;

use crate::error::CloudError;
use crate::model::{CloudProvider, CloudResource, ListResourcesRequest};

use super::connector::{CloudConnector, ConnectorIdentity};
use super::pagination::PaginationToken;

/// Source of GCP bearer tokens.
///
/// Implementations are responsible for refreshing tokens when they expire.
/// The returned [`SecretString`] is consumed immediately and never logged.
#[async_trait]
pub trait GcpTokenProvider: Send + Sync + std::fmt::Debug {
    /// Return a current OAuth2 access token suitable for the
    /// `cloudasset.googleapis.com` and `oauth2.googleapis.com` scopes.
    async fn bearer_token(&self) -> Result<SecretString, CloudError>;
}

/// GCP implementation of [`CloudConnector`].
pub struct GcpCloudConnector {
    http: reqwest::Client,
    project_id: String,
    token: Arc<dyn GcpTokenProvider>,
    asset_base_url: String,
    tokeninfo_base_url: String,
}

impl std::fmt::Debug for GcpCloudConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GcpCloudConnector")
            .field("project_id", &self.project_id)
            .field("asset_base_url", &self.asset_base_url)
            .field("tokeninfo_base_url", &self.tokeninfo_base_url)
            .finish_non_exhaustive()
    }
}

impl GcpCloudConnector {
    /// Construct a connector against the production GCP endpoints. Fails
    /// if `project_id` is empty.
    pub fn new(
        http: reqwest::Client,
        project_id: String,
        token: Arc<dyn GcpTokenProvider>,
    ) -> Result<Self, CloudError> {
        if project_id.trim().is_empty() {
            return Err(CloudError::config("gcp project_id must not be empty"));
        }
        Ok(Self {
            http,
            project_id,
            token,
            asset_base_url: "https://cloudasset.googleapis.com".to_string(),
            tokeninfo_base_url: "https://oauth2.googleapis.com".to_string(),
        })
    }

    /// Test-only: override the upstream endpoints.
    #[doc(hidden)]
    #[must_use]
    pub fn with_endpoints(mut self, asset_base_url: String, tokeninfo_base_url: String) -> Self {
        self.asset_base_url = asset_base_url;
        self.tokeninfo_base_url = tokeninfo_base_url;
        self
    }
}

#[derive(Debug, Deserialize)]
struct TokenInfo {
    #[serde(default)]
    aud: Option<String>,
    #[serde(default)]
    email: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ListAssetsPage {
    #[serde(default)]
    assets: Vec<RawAsset>,
    #[serde(default, rename = "nextPageToken")]
    next_page_token: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawAsset {
    #[serde(default)]
    name: String,
    #[serde(default, rename = "assetType")]
    asset_type: String,
    #[serde(default)]
    resource: Option<serde_json::Value>,
}

#[async_trait]
impl CloudConnector for GcpCloudConnector {
    fn provider(&self) -> CloudProvider {
        CloudProvider::Gcp
    }

    async fn validate(&self) -> Result<ConnectorIdentity, CloudError> {
        let token = self.token.bearer_token().await?;
        let url = format!("{}/tokeninfo", self.tokeninfo_base_url);
        let resp = self
            .http
            .get(&url)
            .query(&[("access_token", token.expose_secret())])
            .send()
            .await
            .map_err(CloudError::from)?;
        let status = resp.status();
        let body = resp.text().await.map_err(CloudError::from)?;
        if !status.is_success() {
            return Err(CloudError::Upstream {
                status: status.as_u16(),
                body,
            });
        }
        let info: TokenInfo = serde_json::from_str(&body)?;
        let aud = info.aud.unwrap_or_default();
        if aud.is_empty() {
            return Err(CloudError::auth("tokeninfo returned empty aud"));
        }
        let principal = info.email.unwrap_or_else(|| aud.clone());
        Ok(ConnectorIdentity {
            provider: CloudProvider::Gcp,
            account_id: self.project_id.clone(),
            principal,
        })
    }

    async fn list_resources(
        &self,
        req: &ListResourcesRequest,
    ) -> Result<Vec<CloudResource>, CloudError> {
        let token = self.token.bearer_token().await?;
        let url = format!(
            "{}/v1/projects/{}:listAssets",
            self.asset_base_url, self.project_id
        );
        let mut out = Vec::new();
        let mut page_token: Option<PaginationToken> = None;
        let mut pages_consumed = 0u32;
        loop {
            let mut body = serde_json::json!({});
            if let Some(t) = page_token.as_ref() {
                if let Some(obj) = body.as_object_mut() {
                    obj.insert(
                        "pageToken".to_string(),
                        serde_json::Value::String(t.as_str().to_string()),
                    );
                }
            }
            let resp = self
                .http
                .post(&url)
                .bearer_auth(token.expose_secret())
                .json(&body)
                .send()
                .await
                .map_err(CloudError::from)?;
            let status = resp.status();
            let text = resp.text().await.map_err(CloudError::from)?;
            if !status.is_success() {
                return Err(CloudError::Upstream {
                    status: status.as_u16(),
                    body: text,
                });
            }
            let page: ListAssetsPage = serde_json::from_str(&text)?;
            for asset in page.assets {
                let raw = serde_json::json!({
                    "name": asset.name,
                    "assetType": asset.asset_type,
                    "resource": asset.resource,
                });
                let kind = asset
                    .asset_type
                    .rsplit('/')
                    .next()
                    .unwrap_or("resource")
                    .to_string();
                let service = asset
                    .asset_type
                    .split('.')
                    .next()
                    .unwrap_or("unknown")
                    .to_string();
                let name = asset
                    .name
                    .rsplit('/')
                    .next()
                    .unwrap_or(asset.name.as_str())
                    .to_string();
                let mut r =
                    CloudResource::new(asset.name.clone(), CloudProvider::Gcp, service, kind, name);
                r.raw = raw;
                out.push(r);
            }
            pages_consumed = pages_consumed.saturating_add(1);
            match page.next_page_token {
                Some(t) if !t.is_empty() => {
                    if let Some(limit) = req.max_pages {
                        if pages_consumed >= limit {
                            break;
                        }
                    }
                    page_token = Some(PaginationToken::new(t));
                }
                _ => break,
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
// Tests construct fixed-size vectors and index them directly.
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[derive(Debug)]
    struct StaticToken(String);
    #[async_trait]
    impl GcpTokenProvider for StaticToken {
        async fn bearer_token(&self) -> Result<SecretString, CloudError> {
            Ok(SecretString::from(self.0.clone()))
        }
    }

    fn connector(server: &MockServer) -> GcpCloudConnector {
        GcpCloudConnector::new(
            reqwest::Client::new(),
            "my-project".to_string(),
            Arc::new(StaticToken("tok".into())),
        )
        .unwrap()
        .with_endpoints(server.uri(), server.uri())
    }

    #[tokio::test]
    async fn gcp_list_assets_consumes_two_pages() {
        let server = MockServer::start().await;
        // First page: one asset + nextPageToken
        Mock::given(method("POST"))
            .and(path("/v1/projects/my-project:listAssets"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "assets": [{
                    "name": "//compute.googleapis.com/projects/my-project/zones/us/instances/vm1",
                    "assetType": "compute.googleapis.com/Instance",
                    "resource": {"data": {"id": "1"}}
                }],
                "nextPageToken": "PAGE2"
            })))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        // Second page: one asset, no token.
        Mock::given(method("POST"))
            .and(path("/v1/projects/my-project:listAssets"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "assets": [{
                    "name": "//storage.googleapis.com/projects/my-project/buckets/b1",
                    "assetType": "storage.googleapis.com/Bucket",
                    "resource": {}
                }]
            })))
            .mount(&server)
            .await;

        let c = connector(&server);
        let resources = c
            .list_resources(&ListResourcesRequest::default())
            .await
            .unwrap();
        assert_eq!(resources.len(), 2);
        assert_eq!(resources[0].kind, "Instance");
        assert_eq!(resources[1].kind, "Bucket");
        assert_eq!(resources[0].name, "vm1");
        assert_eq!(resources[1].name, "b1");
    }

    #[tokio::test]
    async fn gcp_validate_rejects_empty_token_info() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/tokeninfo"))
            .and(query_param("access_token", "tok"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .mount(&server)
            .await;
        let c = connector(&server);
        let err = c.validate().await.err().unwrap();
        assert!(matches!(err, CloudError::Auth(_)));
    }

    #[tokio::test]
    async fn gcp_validate_returns_identity_when_aud_present() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/tokeninfo"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "aud": "client-id-x",
                "email": "sa@my-project.iam.gserviceaccount.com"
            })))
            .mount(&server)
            .await;
        let c = connector(&server);
        let id = c.validate().await.unwrap();
        assert_eq!(id.account_id, "my-project");
        assert_eq!(id.principal, "sa@my-project.iam.gserviceaccount.com");
    }

    #[test]
    fn rejects_empty_project_id() {
        let err = GcpCloudConnector::new(
            reqwest::Client::new(),
            String::new(),
            Arc::new(StaticToken("t".into())),
        )
        .err()
        .unwrap();
        assert!(matches!(err, CloudError::Config(_)));
    }
}
