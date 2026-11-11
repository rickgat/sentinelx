//! Domain services: the [`CloudConnector`] trait, three concrete
//! implementations, supporting token-provider traits, and pagination helpers.

pub mod aws;
pub mod aws_sdk;
pub mod azure;
pub mod connector;
pub mod gcp;
pub mod pagination;

pub use aws::{AwsCloudConnector, AwsCredentials};
pub use aws_sdk::AwsSdkInventory;
pub use azure::{AzureCloudConnector, AzureTokenProvider};
pub use connector::{CloudConnector, ConnectorIdentity};
pub use gcp::{GcpCloudConnector, GcpTokenProvider};
pub use pagination::PaginationToken;
