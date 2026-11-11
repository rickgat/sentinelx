//! # `sx-cloud`
//!
//! Cloud connectors for **`SentinelX`**: a unified, read-only inventory layer
//! across the three major hyperscalers.
//!
//! The crate exposes a single polymorphic abstraction —
//! [`service::CloudConnector`] — implemented by three concrete adapters:
//!
//! 1. [`service::AwsCloudConnector`] — calls AWS STS `GetCallerIdentity` to
//!    validate credentials and IAM `ListUsers` for an initial inventory.
//!    Authentication uses an in-house AWS Signature Version 4 implementation
//!    (no `aws-sdk-*` dependency).
//! 2. [`service::GcpCloudConnector`] — calls Google Cloud Asset Inventory's
//!    `listAssets` endpoint with a bearer token sourced from a pluggable
//!    [`service::GcpTokenProvider`].
//! 3. [`service::AzureCloudConnector`] — calls the Azure Resource Graph
//!    `resources` query endpoint with a bearer token sourced from a
//!    pluggable [`service::AzureTokenProvider`].
//!
//! Each connector emits a homogeneous stream of [`model::CloudResource`]
//! records keyed by [`model::CloudProvider`]. Pagination is normalized
//! across providers via [`service::PaginationToken`].
//!
//! ## Layout
//!
//! - [`model`] — value objects: `CloudProvider`, `CloudResource`,
//!   `ListResourcesRequest`.
//! - [`service`] — domain services: connectors, token providers, SigV4
//!   helpers, pagination.
//! - [`controller`] — use-cases consumed from upper layers, notably
//!   [`controller::RunInventoryUseCase`] which fans out across registered
//!   connectors in parallel.
//! - [`error`] — [`error::CloudError`], the crate's single error type.
//! - [`prelude`] — re-exports for typical call sites.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
// Crate docs reference acronyms and identifiers (SigV4, IAM, RoE, etc.) as
// prose; backticking each occurrence does not improve readability.
#![allow(clippy::doc_markdown)]

pub mod controller;
pub mod drift;
pub mod error;
pub mod model;
pub mod prelude;
pub mod service;

pub use crate::error::CloudError;
