//! DTOs exchanged with the API layer (or any external caller).
//!
//! Views are deliberately simple `serde` structs — no domain logic. They
//! bridge plain HTTP / RPC inputs into the typed value objects defined in
//! [`crate::contracts`] and [`crate::model`].

pub mod scan_result_view;
pub mod start_discovery_request;

pub use scan_result_view::ScanResultView;
pub use start_discovery_request::StartDiscoveryRequest;
