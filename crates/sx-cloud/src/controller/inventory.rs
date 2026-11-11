//! Fan-out inventory use-case.
//!
//! Drives every registered [`CloudConnector`] in parallel and aggregates
//! their results. Failures from individual connectors are logged at
//! `warn` and elided from the aggregate; the caller receives whatever
//! succeeded.

use std::sync::Arc;

use tokio::task::JoinSet;
use tracing::warn;

use crate::error::CloudError;
use crate::model::{CloudResource, ListResourcesRequest};
use crate::service::CloudConnector;

/// Aggregates inventory across many connectors.
#[derive(Debug)]
pub struct RunInventoryUseCase {
    connectors: Vec<Arc<dyn CloudConnector>>,
}

impl RunInventoryUseCase {
    /// Construct with a fixed set of connectors. Order is not significant.
    #[must_use]
    pub fn new(connectors: Vec<Arc<dyn CloudConnector>>) -> Self {
        Self { connectors }
    }

    /// Run every connector concurrently. Failures are logged and skipped;
    /// the aggregate of successful pulls is returned. If every connector
    /// fails, the returned vec is empty (not an error) — the failure log
    /// lines are the source of truth.
    pub async fn execute(
        &self,
        req: ListResourcesRequest,
    ) -> Result<Vec<CloudResource>, CloudError> {
        let mut tasks: JoinSet<(
            crate::model::CloudProvider,
            Result<Vec<CloudResource>, CloudError>,
        )> = JoinSet::new();
        for conn in &self.connectors {
            if !req.applies_to(conn.provider()) {
                continue;
            }
            let conn = Arc::clone(conn);
            let req = req.clone();
            tasks.spawn(async move {
                let provider = conn.provider();
                let list_res = conn.list_resources(&req).await;
                (provider, list_res)
            });
        }
        let mut aggregate = Vec::new();
        while let Some(joined) = tasks.join_next().await {
            match joined {
                Ok((_provider, Ok(mut items))) => aggregate.append(&mut items),
                Ok((provider, Err(e))) => {
                    warn!(target: "sx_cloud::inventory", provider = %provider, error = %e, "connector failed");
                }
                Err(join_err) => {
                    warn!(target: "sx_cloud::inventory", error = %join_err, "connector task join error");
                }
            }
        }
        Ok(aggregate)
    }
}

#[cfg(test)]
// Tests construct fixed-size vectors and index them directly.
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::model::{CloudProvider, CloudResource};
    use crate::service::connector::ConnectorIdentity;
    use async_trait::async_trait;

    #[derive(Debug)]
    struct StubOk {
        provider: CloudProvider,
        out: Vec<CloudResource>,
    }
    #[async_trait]
    impl CloudConnector for StubOk {
        fn provider(&self) -> CloudProvider {
            self.provider
        }
        async fn validate(&self) -> Result<ConnectorIdentity, CloudError> {
            Ok(ConnectorIdentity {
                provider: self.provider,
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

    #[derive(Debug)]
    struct StubFail {
        provider: CloudProvider,
    }
    #[async_trait]
    impl CloudConnector for StubFail {
        fn provider(&self) -> CloudProvider {
            self.provider
        }
        async fn validate(&self) -> Result<ConnectorIdentity, CloudError> {
            Err(CloudError::auth("nope"))
        }
        async fn list_resources(
            &self,
            _req: &ListResourcesRequest,
        ) -> Result<Vec<CloudResource>, CloudError> {
            Err(CloudError::Upstream {
                status: 503,
                body: "service unavailable".into(),
            })
        }
    }

    fn res(p: CloudProvider, id: &str) -> CloudResource {
        CloudResource::new(id, p, "svc", "kind", id)
    }

    #[tokio::test]
    async fn inventory_use_case_fans_out_and_aggregates() {
        let aws: Arc<dyn CloudConnector> = Arc::new(StubOk {
            provider: CloudProvider::Aws,
            out: vec![res(CloudProvider::Aws, "a1"), res(CloudProvider::Aws, "a2")],
        });
        let gcp: Arc<dyn CloudConnector> = Arc::new(StubOk {
            provider: CloudProvider::Gcp,
            out: vec![res(CloudProvider::Gcp, "g1")],
        });
        let azure: Arc<dyn CloudConnector> = Arc::new(StubOk {
            provider: CloudProvider::Azure,
            out: vec![res(CloudProvider::Azure, "z1")],
        });
        let uc = RunInventoryUseCase::new(vec![aws, gcp, azure]);
        let out = uc.execute(ListResourcesRequest::default()).await.unwrap();
        assert_eq!(out.len(), 4);
        let aws_count = out
            .iter()
            .filter(|r| r.provider == CloudProvider::Aws)
            .count();
        let gcp_count = out
            .iter()
            .filter(|r| r.provider == CloudProvider::Gcp)
            .count();
        let azure_count = out
            .iter()
            .filter(|r| r.provider == CloudProvider::Azure)
            .count();
        assert_eq!(aws_count, 2);
        assert_eq!(gcp_count, 1);
        assert_eq!(azure_count, 1);
    }

    #[tokio::test]
    async fn inventory_use_case_logs_failures_but_continues() {
        let ok: Arc<dyn CloudConnector> = Arc::new(StubOk {
            provider: CloudProvider::Aws,
            out: vec![res(CloudProvider::Aws, "a1")],
        });
        let bad: Arc<dyn CloudConnector> = Arc::new(StubFail {
            provider: CloudProvider::Gcp,
        });
        let uc = RunInventoryUseCase::new(vec![ok, bad]);
        let out = uc.execute(ListResourcesRequest::default()).await.unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].provider, CloudProvider::Aws);
    }

    #[tokio::test]
    async fn inventory_use_case_filters_by_provider() {
        let aws: Arc<dyn CloudConnector> = Arc::new(StubOk {
            provider: CloudProvider::Aws,
            out: vec![res(CloudProvider::Aws, "a1")],
        });
        let gcp: Arc<dyn CloudConnector> = Arc::new(StubOk {
            provider: CloudProvider::Gcp,
            out: vec![res(CloudProvider::Gcp, "g1")],
        });
        let uc = RunInventoryUseCase::new(vec![aws, gcp]);
        let req = ListResourcesRequest {
            provider: Some(CloudProvider::Aws),
            ..Default::default()
        };
        let out = uc.execute(req).await.unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].provider, CloudProvider::Aws);
    }
}
