//! Anonymised threat-share payloads.
//!
//! The wire format intentionally omits any per-asset detail: only CVE id,
//! an opaque asset-kind hash, and a count.

use serde::{Deserialize, Serialize};
use sx_core::value_object::ids::CveId;
use time::OffsetDateTime;

/// A pre-anonymisation observation of one CVE on a class of assets.
///
/// `asset_kind` is a coarse free-form classifier (e.g. `"web-server"`,
/// `"linux-kernel"`); the client hashes it with the tenant pepper before
/// transmission. Tests assert that the raw value never reaches the wire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreatObservation {
    /// CVE id observed.
    pub cve_id: CveId,
    /// Coarse asset-kind classifier (hashed before transmission).
    pub asset_kind: String,
    /// Count of assets in this category exhibiting `cve_id`.
    pub count: u32,
}

impl ThreatObservation {
    /// Build a new observation.
    #[must_use]
    pub fn new(cve_id: CveId, asset_kind: impl Into<String>, count: u32) -> Self {
        Self {
            cve_id,
            asset_kind: asset_kind.into(),
            count,
        }
    }
}

/// Wire-format anonymised observation. `asset_kind_hash` is
/// `hex(sha256(asset_kind || pepper))`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnonymisedObservation {
    /// CVE id.
    pub cve_id: String,
    /// Hex SHA-256 of `asset_kind || pepper`.
    pub asset_kind_hash: String,
    /// Count of assets.
    pub count: u32,
}

/// Wire-format submission body posted to the threat-network endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreatShareBundle {
    /// RFC-3339 timestamp at submission time.
    pub shared_at: OffsetDateTime,
    /// `hex(sha256(tenant_id || pepper))`.
    pub tenant_hash: String,
    /// Anonymised per-CVE observations.
    pub observations: Vec<AnonymisedObservation>,
}
