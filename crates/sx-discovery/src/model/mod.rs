//! Value objects describing the output of a scan.

pub mod discovered_asset;
pub mod observation;
pub mod scan_result;

pub use discovered_asset::{DiscoveredAsset, DiscoveredAssetKind};
pub use observation::{CertificateInfo, DnsRecordKind, Observation};
pub use scan_result::ScanResult;
