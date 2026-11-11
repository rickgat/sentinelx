//! Value objects shared across all connectors.
//!
//! Sub-modules:
//!
//! - [`provider`] — [`CloudProvider`] enum.
//! - [`resource`] — the unified [`CloudResource`] record.
//! - [`request`] — [`ListResourcesRequest`] driver input.

pub mod provider;
pub mod request;
pub mod resource;

pub use provider::CloudProvider;
pub use request::ListResourcesRequest;
pub use resource::CloudResource;
