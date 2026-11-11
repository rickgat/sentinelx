//! US Social Security Number matcher.
//!
//! Matches `AAA-GG-SSSS` runs with the SSA "never assigned" filter:
//!
//! - Area must be `001..=899` and not `666`.
//! - Group must be `01..=99`.
//! - Serial must be `0001..=9999`.
//!
//! The `9XX` series is reserved for ITINs but is left out of this
//! matcher to avoid surfacing legitimate tax identifiers as PII —
//! tighten if the customer's policy demands.

use std::sync::OnceLock;

use regex::Regex;

use crate::patterns::{DlpMatch, DlpMatchKind};
use crate::preview::redact;

fn re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\b([0-9]{3})-([0-9]{2})-([0-9]{4})\b").unwrap_or_else(|_| {
            #[allow(clippy::unwrap_used)]
            Regex::new(r"\d{3}-\d{2}-\d{4}").unwrap()
        })
    })
}

/// True for an `(area, group, serial)` triple that the SSA actually
/// assigns. Excludes `000`, `666`, `9XX` areas, `00` groups, and
/// `0000` serials.
#[must_use]
pub const fn ssa_valid(area: u32, group: u32, serial: u32) -> bool {
    if area == 0 || area == 666 || area > 899 {
        return false;
    }
    if group == 0 || group > 99 {
        return false;
    }
    if serial == 0 || serial > 9999 {
        return false;
    }
    true
}

/// Scan `text` for SSNs.
#[must_use]
pub fn scan(text: &str) -> Vec<DlpMatch> {
    let mut out = Vec::new();
    for caps in re().captures_iter(text) {
        let Some(whole) = caps.get(0) else { continue };
        let Some(area_s) = caps.get(1) else { continue };
        let Some(group_s) = caps.get(2) else { continue };
        let Some(serial_s) = caps.get(3) else {
            continue;
        };
        let Ok(area) = area_s.as_str().parse::<u32>() else {
            continue;
        };
        let Ok(group) = group_s.as_str().parse::<u32>() else {
            continue;
        };
        let Ok(serial) = serial_s.as_str().parse::<u32>() else {
            continue;
        };
        if !ssa_valid(area, group, serial) {
            continue;
        }
        let s = whole.as_str();
        out.push(DlpMatch {
            kind: DlpMatchKind::SsnUs,
            offset: whole.start(),
            length: s.len(),
            redacted_preview: redact(s),
            ..Default::default()
        });
    }
    out
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn finds_canonical_ssn() {
        let t = "ssn: 123-45-6789 confidential";
        let m = scan(t);
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].kind, DlpMatchKind::SsnUs);
        assert_eq!(&t[m[0].offset..m[0].offset + m[0].length], "123-45-6789");
        // 11 chars → first 4 + 5 stars + last 2.
        assert_eq!(m[0].redacted_preview, "123-*****89");
    }

    #[test]
    fn rejects_disallowed_areas() {
        assert!(scan("000-12-3456").is_empty());
        assert!(scan("666-12-3456").is_empty());
        assert!(scan("900-12-3456").is_empty());
    }

    #[test]
    fn rejects_zero_group_or_serial() {
        assert!(scan("123-00-6789").is_empty());
        assert!(scan("123-45-0000").is_empty());
    }

    #[test]
    fn ignores_text_with_no_ssn() {
        assert!(scan("phone is 555-1212 only").is_empty());
        // No hyphens.
        assert!(scan("123456789").is_empty());
    }

    #[test]
    fn ssa_valid_is_pure() {
        assert!(ssa_valid(123, 45, 6789));
        assert!(!ssa_valid(666, 1, 1));
        assert!(!ssa_valid(123, 0, 1));
        assert!(!ssa_valid(123, 1, 0));
    }
}
