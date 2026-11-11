//! The polymorphic [`CloudConnector`] trait.

use async_trait::async_trait;

use crate::error::CloudError;
use crate::model::{CloudProvider, CloudResource, ListResourcesRequest};

/// Identity returned by [`CloudConnector::validate`].
///
/// Shapes vary by provider:
/// - **AWS**: `account_id` is the 12-digit account id; `principal` is the
///   ARN returned by `sts:GetCallerIdentity`.
/// - **GCP**: `account_id` is the project id; `principal` is the service
///   account email (or `aud`) reported by `tokeninfo`.
/// - **Azure**: `account_id` is the subscription id; `principal` is the
///   service-principal object id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectorIdentity {
    /// Which cloud this identity came from.
    pub provider: CloudProvider,
    /// Provider-specific account / tenant / subscription identifier.
    pub account_id: String,
    /// Provider-specific principal identifier (arn / email / object id).
    pub principal: String,
}

/// The single abstraction every connector implements.
///
/// Implementations MUST:
/// - never log secrets (use [`secrecy::SecretString`] in storage),
/// - fail fast on construction-time configuration errors,
/// - normalize upstream errors into [`CloudError`].
#[async_trait]
pub trait CloudConnector: Send + Sync + std::fmt::Debug {
    /// Which provider this connector talks to.
    fn provider(&self) -> CloudProvider;

    /// Round-trips a low-cost identity call and returns who the connector
    /// authenticated as. Used as a smoke test before invoking
    /// [`Self::list_resources`].
    async fn validate(&self) -> Result<ConnectorIdentity, CloudError>;

    /// Lists resources matching `req`. Implementations handle pagination
    /// internally and return the aggregated set; respect `req.max_pages`
    /// when present.
    async fn list_resources(
        &self,
        req: &ListResourcesRequest,
    ) -> Result<Vec<CloudResource>, CloudError>;
}
