//! Azure connector — Resource Graph `resources` query.

use std::sync::Arc;

use async_trait::async_trait;
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;

use crate::error::CloudError;
use crate::model::{CloudProvider, CloudResource, ListResourcesRequest};

use super::connector::{CloudConnector, ConnectorIdentity};
use super::pagination::PaginationToken;

/// Source of Azure bearer tokens (an OAuth2 token for
/// `https://management.azure.com/`).
#[async_trait]
pub trait AzureTokenProvider: Send + Sync + std::fmt::Debug {
    /// Return a current management-plane access token.
    async fn bearer_token(&self) -> Result<SecretString, CloudError>;
}

/// Azure implementation of [`CloudConnector`].
pub struct AzureCloudConnector {
    http: reqwest::Client,
    subscription_id: String,
    tenant_id: String,
    token: Arc<dyn AzureTokenProvider>,
    arm_base_url: String,
}

impl std::fmt::Debug for AzureCloudConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AzureCloudConnector")
            .field("subscription_id", &self.subscription_id)
            .field("tenant_id", &self.tenant_id)
            .field("arm_base_url", &self.arm_base_url)
            .finish_non_exhaustive()
    }
}

impl AzureCloudConnector {
    /// Construct a connector against the production ARM endpoint. Fails
    /// when either id is empty.
    pub fn new(
        http: reqwest::Client,
        subscription_id: String,
        tenant_id: String,
        token: Arc<dyn AzureTokenProvider>,
    ) -> Result<Self, CloudError> {
        if subscription_id.trim().is_empty() {
            return Err(CloudError::config(
                "azure subscription_id must not be empty",
            ));
        }
        if tenant_id.trim().is_empty() {
            return Err(CloudError::config("azure tenant_id must not be empty"));
        }
        Ok(Self {
            http,
            subscription_id,
            tenant_id,
            token,
            arm_base_url: "https://management.azure.com".to_string(),
        })
    }

    /// Test-only: override the ARM endpoint.
    #[doc(hidden)]
    #[must_use]
    pub fn with_endpoint(mut self, arm_base_url: String) -> Self {
        self.arm_base_url = arm_base_url;
        self
    }
}

#[derive(Debug, Deserialize)]
struct ResourceGraphPage {
    #[serde(default)]
    data: Vec<serde_json::Value>,
    #[serde(default, rename = "$skipToken")]
    skip_token: Option<String>,
}

#[async_trait]
impl CloudConnector for AzureCloudConnector {
    fn provider(&self) -> CloudProvider {
        CloudProvider::Azure
    }

    async fn validate(&self) -> Result<ConnectorIdentity, CloudError> {
        // Smoke-test the credential by issuing a one-row Resource Graph query.
        let token = self.token.bearer_token().await?;
        let url = format!(
            "{}/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01",
            self.arm_base_url
        );
        let body = serde_json::json!({
            "subscriptions": [self.subscription_id.clone()],
            "query": "Resources | limit 1"
        });
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
        Ok(ConnectorIdentity {
            provider: CloudProvider::Azure,
            account_id: self.subscription_id.clone(),
            principal: self.tenant_id.clone(),
        })
    }

    async fn list_resources(
        &self,
        req: &ListResourcesRequest,
    ) -> Result<Vec<CloudResource>, CloudError> {
        let token = self.token.bearer_token().await?;
        let url = format!(
            "{}/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01",
            self.arm_base_url
        );
        let mut out = Vec::new();
        let mut skip: Option<PaginationToken> = None;
        let mut pages_consumed = 0u32;
        loop {
            let mut body = serde_json::json!({
                "subscriptions": [self.subscription_id.clone()],
                "query": "Resources"
            });
            if let Some(t) = skip.as_ref() {
                if let Some(obj) = body.as_object_mut() {
                    obj.insert(
                        "options".to_string(),
                        serde_json::json!({"$skipToken": t.as_str()}),
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
            let page: ResourceGraphPage = serde_json::from_str(&text)?;
            for row in page.data {
                let id = row
                    .get("id")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("")
                    .to_string();
                let name = row
                    .get("name")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("")
                    .to_string();
                let kind = row
                    .get("type")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("")
                    .to_string();
                let region = row
                    .get("location")
                    .and_then(serde_json::Value::as_str)
                    .map(ToString::to_string);
                let service = kind.split('/').next().unwrap_or("unknown").to_string();
                let mut r = CloudResource::new(id, CloudProvider::Azure, service, kind, name);
                r.region = region;
                r.raw = row;
                out.push(r);
            }
            pages_consumed = pages_consumed.saturating_add(1);
            match page.skip_token {
                Some(t) if !t.is_empty() => {
                    if let Some(limit) = req.max_pages {
                        if pages_consumed >= limit {
                            break;
                        }
                    }
                    skip = Some(PaginationToken::new(t));
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
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[derive(Debug)]
    struct StaticToken(String);
    #[async_trait]
    impl AzureTokenProvider for StaticToken {
        async fn bearer_token(&self) -> Result<SecretString, CloudError> {
            Ok(SecretString::from(self.0.clone()))
        }
    }

    fn connector(server: &MockServer) -> AzureCloudConnector {
        AzureCloudConnector::new(
            reqwest::Client::new(),
            "sub-1".into(),
            "tenant-1".into(),
            Arc::new(StaticToken("tok".into())),
        )
        .unwrap()
        .with_endpoint(server.uri())
    }

    #[tokio::test]
    async fn azure_resource_graph_consumes_two_pages() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/providers/Microsoft.ResourceGraph/resources"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": [{
                    "id": "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/sa1",
                    "name": "sa1",
                    "type": "microsoft.storage/storageaccounts",
                    "location": "eastus"
                }],
                "$skipToken": "PAGE2"
            })))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/providers/Microsoft.ResourceGraph/resources"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": [{
                    "id": "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm1",
                    "name": "vm1",
                    "type": "microsoft.compute/virtualmachines",
                    "location": "westus"
                }]
            })))
            .mount(&server)
            .await;
        let c = connector(&server);
        let r = c
            .list_resources(&ListResourcesRequest::default())
            .await
            .unwrap();
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].name, "sa1");
        assert_eq!(r[0].region.as_deref(), Some("eastus"));
        assert_eq!(r[1].name, "vm1");
        assert_eq!(r[1].region.as_deref(), Some("westus"));
    }

    #[tokio::test]
    async fn azure_validate_returns_identity() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/providers/Microsoft.ResourceGraph/resources"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": []
            })))
            .mount(&server)
            .await;
        let c = connector(&server);
        let id = c.validate().await.unwrap();
        assert_eq!(id.account_id, "sub-1");
        assert_eq!(id.principal, "tenant-1");
    }

    #[test]
    fn rejects_empty_ids() {
        let err = AzureCloudConnector::new(
            reqwest::Client::new(),
            String::new(),
            "t".into(),
            Arc::new(StaticToken("x".into())),
        )
        .err()
        .unwrap();
        assert!(matches!(err, CloudError::Config(_)));
        let err = AzureCloudConnector::new(
            reqwest::Client::new(),
            "s".into(),
            String::new(),
            Arc::new(StaticToken("x".into())),
        )
        .err()
        .unwrap();
        assert!(matches!(err, CloudError::Config(_)));
    }
}
