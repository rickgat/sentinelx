//! Vendor advisory value objects.
//!
//! A [`VendorAdvisory`] is a normalised view of a single advisory document
//! published by a vendor security feed (MSRC, Red Hat OVAL, Ubuntu USN,
//! Cisco PSIRT). Every concrete
//! [`crate::service::source::VendorAdvisorySource`] implementation produces
//! values of this type.

use serde::{Deserialize, Serialize};
use sx_core::prelude::CveId;
use time::OffsetDateTime;
use url::Url;

/// A single patch — typically a vendor-published fix package or KB article.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Patch {
    /// Vendor-specific patch identifier (e.g. `KB5031356`, `RHSA-2024:1234`).
    pub id: String,
    /// Human-readable summary of what the patch fixes.
    pub summary: String,
    /// Authoritative URL for the patch, when published.
    pub url: Option<Url>,
}

impl Patch {
    /// Build a new patch record.
    #[must_use]
    pub fn new(id: impl Into<String>, summary: impl Into<String>, url: Option<Url>) -> Self {
        Self {
            id: id.into(),
            summary: summary.into(),
            url,
        }
    }
}

/// A normalised vendor advisory.
///
/// Identity (`vendor` + `advisory_id`) is unique within the mirror. The set of
/// CVEs the advisory addresses, the patches it ships, and the reference URLs
/// it cites are all carried in-line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VendorAdvisory {
    /// Vendor slug — matches
    /// [`crate::service::source::VendorAdvisorySource::vendor`] (e.g.
    /// `"msrc"`, `"redhat"`, `"ubuntu"`, `"cisco"`).
    pub vendor: String,
    /// Vendor-assigned advisory identifier (e.g. `RHSA-2024:1234`,
    /// `USN-1234-1`).
    pub advisory_id: String,
    /// CVEs this advisory addresses.
    pub cves: Vec<CveId>,
    /// Patches shipped by this advisory.
    pub patches: Vec<Patch>,
    /// Reference URLs (used downstream by the copilot's citation enforcer —
    /// the LLM may cite only URLs that appear here).
    pub references: Vec<Url>,
    /// Publication timestamp.
    pub published_at: OffsetDateTime,
}

impl VendorAdvisory {
    /// Build a new advisory record.
    #[must_use]
    pub fn new(
        vendor: impl Into<String>,
        advisory_id: impl Into<String>,
        cves: Vec<CveId>,
        patches: Vec<Patch>,
        references: Vec<Url>,
        published_at: OffsetDateTime,
    ) -> Self {
        Self {
            vendor: vendor.into(),
            advisory_id: advisory_id.into(),
            cves,
            patches,
            references,
            published_at,
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::single_char_pattern
)]
mod tests {
    use super::*;

    #[test]
    fn patch_round_trip() {
        let p = Patch::new(
            "KB1",
            "fix",
            Some(Url::parse("https://example.com/p").unwrap()),
        );
        assert_eq!(p.id, "KB1");
    }

    #[test]
    fn advisory_round_trip() {
        let cve = CveId::new("CVE-2024-12345").unwrap();
        let url = Url::parse("https://example.com/a").unwrap();
        let a = VendorAdvisory::new(
            "redhat",
            "RHSA-2024:1234",
            vec![cve.clone()],
            vec![],
            vec![url.clone()],
            OffsetDateTime::UNIX_EPOCH,
        );
        assert_eq!(a.vendor, "redhat");
        assert_eq!(a.references[0], url);
        assert_eq!(a.cves[0], cve);
    }
}
