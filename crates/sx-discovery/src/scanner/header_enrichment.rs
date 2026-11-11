//! HDR.* header-audit enrichment table (TOP5-#3 Phase 1).
//!
//! The canonical table lives in
//! [`sx_core::reference::header_enrichment`] so the live
//! `services/sx-monolith` HTTP-header probe and this discovery-side
//! scanner share one source of truth (SX-REVIEW-002 C1 fix). This
//! module simply re-exports the canonical surface so existing
//! callers in this crate keep compiling unchanged.

pub use sx_core::reference::header_enrichment::{hdr_enrichment, HdrEnrichment};

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// Sanity test that the re-export reaches the canonical table.
    /// Detailed coverage lives in
    /// `sx-core::reference::header_enrichment::tests`.
    #[test]
    fn reexport_resolves_known_check_id() {
        let e = hdr_enrichment("missing-hsts").expect("re-export resolves HSTS");
        assert!(e.cvss.is_some());
        assert!(!e.cwe.is_empty());
    }

    #[test]
    fn reexport_returns_none_for_unknown() {
        assert!(hdr_enrichment("missing-totally-fake-header").is_none());
    }
}
