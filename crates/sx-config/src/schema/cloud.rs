//! Cloud-provider credentials.
//!
//! Each provider section ships disabled by default. When an operator flips
//! `enabled: true`, the corresponding credentials become mandatory and the
//! monolith's `cloud::build` constructs a real
//! [`sx_cloud::service::CloudConnector`] for that provider.

use secrecy::SecretString;
use serde::Deserialize;
use validator::Validate;

/// Root cloud-provider configuration.
///
/// Every provider section ships with `enabled: false` in the example YAML so
/// a freshly cloned checkout boots without attempting any outbound cloud
/// API calls. Operators flip individual providers on by setting
/// `cloud.<provider>.enabled: true` (or the equivalent `SENTINELX__CLOUD__*__ENABLED`
/// environment variable) and supplying the credential fields below.
#[derive(Debug, Clone, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
pub struct CloudConfig {
    /// AWS credentials.
    #[validate(nested)]
    pub aws: AwsConfig,

    /// GCP credentials.
    #[validate(nested)]
    pub gcp: GcpConfig,

    /// Azure credentials.
    #[validate(nested)]
    pub azure: AzureConfig,
}

/// AWS credentials.
///
/// `secret_access_key` and `session_token` are wrapped in
/// [`SecretString`] so they never appear in `Debug` output and their backing
/// memory is zeroed on drop.
#[derive(Debug, Clone, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
pub struct AwsConfig {
    /// Whether to construct an [`sx_cloud::service::AwsCloudConnector`].
    pub enabled: bool,

    /// `AKIA...` / `ASIA...` style access key id. Mandatory iff `enabled`.
    #[serde(default)]
    pub access_key_id: String,

    /// Secret access key. Mandatory iff `enabled`.
    #[serde(default)]
    pub secret_access_key: SecretString,

    /// Optional STS session token, when using temporary credentials.
    #[serde(default)]
    pub session_token: Option<SecretString>,

    /// AWS region used for the STS endpoint. Defaults to `us-east-1` when
    /// not supplied.
    #[serde(default = "default_aws_region")]
    pub region: String,
}

fn default_aws_region() -> String {
    "us-east-1".to_owned()
}

/// GCP credentials.
///
/// The current scaffold uses a static `OAuth2` bearer token sourced from
/// configuration. Real deployments will swap in a JWT-exchange or workload-
/// identity provider; the schema is intentionally narrow so that swap stays
/// inside the monolith adapter and does not bleed into `sx-config`.
#[derive(Debug, Clone, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
pub struct GcpConfig {
    /// Whether to construct an [`sx_cloud::service::GcpCloudConnector`].
    pub enabled: bool,

    /// GCP project id (the connector hits `cloudasset.googleapis.com` under
    /// this project). Mandatory iff `enabled`.
    #[serde(default)]
    pub project_id: String,

    /// Static `OAuth2` access token. Mandatory iff `enabled`.
    #[serde(default)]
    pub access_token: SecretString,
}

/// Azure credentials.
///
/// Like [`GcpConfig`], the current scaffold uses a static bearer token. Real
/// deployments will plug in a service-principal or managed-identity provider
/// at the adapter boundary.
#[derive(Debug, Clone, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
pub struct AzureConfig {
    /// Whether to construct an [`sx_cloud::service::AzureCloudConnector`].
    pub enabled: bool,

    /// Azure subscription id. Mandatory iff `enabled`.
    #[serde(default)]
    pub subscription_id: String,

    /// Azure tenant id. Mandatory iff `enabled`.
    #[serde(default)]
    pub tenant_id: String,

    /// Static management-plane access token. Mandatory iff `enabled`.
    #[serde(default)]
    pub access_token: SecretString,
}

impl CloudConfig {
    /// Cross-field invariants: every enabled provider must carry a complete
    /// credential set. Disabled providers may leave every other field empty.
    pub(crate) fn check_invariants(&self) -> Result<(), crate::ConfigError> {
        if self.aws.enabled {
            if self.aws.access_key_id.is_empty() {
                return Err(crate::ConfigError::missing("cloud.aws.access_key_id"));
            }
            if crate::secret::is_empty(&self.aws.secret_access_key) {
                return Err(crate::ConfigError::missing("cloud.aws.secret_access_key"));
            }
            if self.aws.region.is_empty() {
                return Err(crate::ConfigError::missing("cloud.aws.region"));
            }
        }
        if self.gcp.enabled {
            if self.gcp.project_id.is_empty() {
                return Err(crate::ConfigError::missing("cloud.gcp.project_id"));
            }
            if crate::secret::is_empty(&self.gcp.access_token) {
                return Err(crate::ConfigError::missing("cloud.gcp.access_token"));
            }
        }
        if self.azure.enabled {
            if self.azure.subscription_id.is_empty() {
                return Err(crate::ConfigError::missing("cloud.azure.subscription_id"));
            }
            if self.azure.tenant_id.is_empty() {
                return Err(crate::ConfigError::missing("cloud.azure.tenant_id"));
            }
            if crate::secret::is_empty(&self.azure.access_token) {
                return Err(crate::ConfigError::missing("cloud.azure.access_token"));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::{AwsConfig, AzureConfig, CloudConfig, GcpConfig};
    use crate::secret;

    fn disabled_aws() -> AwsConfig {
        AwsConfig {
            enabled: false,
            access_key_id: String::new(),
            secret_access_key: secret::wrap(""),
            session_token: None,
            region: "us-east-1".to_owned(),
        }
    }

    fn disabled_gcp() -> GcpConfig {
        GcpConfig {
            enabled: false,
            project_id: String::new(),
            access_token: secret::wrap(""),
        }
    }

    fn disabled_azure() -> AzureConfig {
        AzureConfig {
            enabled: false,
            subscription_id: String::new(),
            tenant_id: String::new(),
            access_token: secret::wrap(""),
        }
    }

    fn all_disabled() -> CloudConfig {
        CloudConfig {
            aws: disabled_aws(),
            gcp: disabled_gcp(),
            azure: disabled_azure(),
        }
    }

    #[test]
    fn aws_enabled_without_key_returns_missing() {
        let mut cfg = all_disabled();
        cfg.aws.enabled = true;
        cfg.aws.secret_access_key = secret::wrap("filled");
        let err = cfg
            .check_invariants()
            .expect_err("missing access_key_id must surface");
        match err {
            crate::ConfigError::MissingValue { key } => {
                assert_eq!(key, "cloud.aws.access_key_id");
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn gcp_enabled_without_project_returns_missing() {
        let mut cfg = all_disabled();
        cfg.gcp.enabled = true;
        cfg.gcp.access_token = secret::wrap("filled");
        let err = cfg
            .check_invariants()
            .expect_err("missing project_id must surface");
        match err {
            crate::ConfigError::MissingValue { key } => {
                assert_eq!(key, "cloud.gcp.project_id");
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn azure_enabled_without_subscription_returns_missing() {
        let mut cfg = all_disabled();
        cfg.azure.enabled = true;
        cfg.azure.tenant_id = "tenant".to_owned();
        cfg.azure.access_token = secret::wrap("filled");
        let err = cfg
            .check_invariants()
            .expect_err("missing subscription_id must surface");
        match err {
            crate::ConfigError::MissingValue { key } => {
                assert_eq!(key, "cloud.azure.subscription_id");
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn all_disabled_passes_invariants() {
        let cfg = all_disabled();
        cfg.check_invariants()
            .expect("all-disabled baseline must pass");
    }
}
