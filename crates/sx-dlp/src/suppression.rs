//! False-positive suppression list (HIGH-004).
//!
//! Well-known test/synthetic identifiers that pass the regex + Luhn
//! check but are documented as non-sensitive. The list is loaded at
//! startup into a [`SuppressionList`] and consulted before a
//! [`crate::detector::DlpDetector`] emits a finding.
//!
//! Coverage:
//!
//! - **PANs**: Visa / Mastercard / Amex / Discover test cards published
//!   by every major processor (Stripe, Adyen, Authorize.Net, Worldpay)
//!   plus the canonical "all-ones" Visa.
//! - **SSNs**: RFC and HHS example numbers, plus the "Anna May Wong"
//!   single most-published-in-error SSN (`078-05-1120`) and the
//!   canonical `123-45-6789`.
//! - **AWS keys**: `AKIAIOSFODNN7EXAMPLE` from the AWS docs sample.
//! - **JWT**: the jwt.io demo token.
//!
//! This is *additive*: matching the suppression list drops the finding
//! silently. Real PII that happens to collide with a suppression entry
//! is therefore a security concern only if the list itself is wrong —
//! every entry is documented inline so an auditor can verify.

use std::collections::HashSet;

use crate::patterns::DlpMatchKind;

/// In-memory FP-suppression set. Cheap to clone (`Arc`-free) because
/// the inner hash set is small (under 100 entries) and read-only after
/// construction.
#[derive(Debug, Clone, Default)]
pub struct SuppressionList {
    entries: HashSet<SuppressionEntry>,
}

/// One suppression rule — match by `(kind, normalised_literal)`.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct SuppressionEntry {
    /// Which kind this entry suppresses.
    pub kind: DlpMatchKind,
    /// Normalised literal — separators stripped, lower-cased. See
    /// [`SuppressionList::normalise`].
    pub literal: String,
}

impl SuppressionList {
    /// Empty list — every match passes through.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            entries: HashSet::new(),
        }
    }

    /// Builtin `SentinelX` suppression list. Loaded at startup.
    #[must_use]
    pub fn builtin() -> Self {
        let mut s = Self::empty();
        // PANs — well-known test cards.
        for pan in [
            // Visa.
            "4111111111111111",
            "4242424242424242",
            "4012888888881881",
            "4000056655665556",
            "4012000033330026",
            // Mastercard.
            "5555555555554444",
            "5105105105105100",
            "5200828282828210",
            "2223003122003222",
            // Amex (15-digit).
            "378282246310005",
            "371449635398431",
            "340000000000009",
            // Discover.
            "6011111111111117",
            "6011000990139424",
            // Diners.
            "30569309025904",
            "38520000023237",
            // JCB.
            "3530111333300000",
            "3566002020360505",
        ] {
            let _ = s.add(DlpMatchKind::CreditCard, pan);
        }

        // SSNs — RFC / HHS / documented examples.
        for ssn in [
            "123-45-6789",
            "111-11-1111",
            "999-99-9999",
            "078-05-1120", // Anna May Wong, the most-printed-in-error SSN.
            "219-09-9999",
            "457-55-5462",
        ] {
            let _ = s.add(DlpMatchKind::SsnUs, ssn);
        }

        // AWS — docs / SDK example values.
        let _ = s.add(DlpMatchKind::AwsAccessKey, "AKIAIOSFODNN7EXAMPLE");
        let _ = s.add(
            DlpMatchKind::AwsSecretKey,
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        );

        // JWT — jwt.io demo token (header.payload.signature).
        let _ = s.add(
            DlpMatchKind::Jwt,
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
        );

        s
    }

    /// Normalisation rule used by both `add` and `contains`. Strips
    /// whitespace + hyphens, lower-cases ASCII, so `4111-1111-1111-1111`,
    /// `4111 1111 1111 1111` and `4111111111111111` all hash the same.
    #[must_use]
    pub fn normalise(literal: &str) -> String {
        literal
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '-' && *c != '_')
            .map(|c| c.to_ascii_lowercase())
            .collect()
    }

    /// Insert one entry. Returns `true` if it was newly added.
    pub fn add(&mut self, kind: DlpMatchKind, literal: &str) -> bool {
        self.entries.insert(SuppressionEntry {
            kind,
            literal: Self::normalise(literal),
        })
    }

    /// Does `literal` match a suppression entry of `kind`?
    #[must_use]
    pub fn contains(&self, kind: DlpMatchKind, literal: &str) -> bool {
        self.entries.contains(&SuppressionEntry {
            kind,
            literal: Self::normalise(literal),
        })
    }

    /// Entry count — used by tests.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when the list has no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn empty_is_empty() {
        let s = SuppressionList::empty();
        assert!(s.is_empty());
        assert!(!s.contains(DlpMatchKind::CreditCard, "4111111111111111"));
    }

    #[test]
    fn builtin_has_canonical_test_pans() {
        let s = SuppressionList::builtin();
        assert!(s.contains(DlpMatchKind::CreditCard, "4111111111111111"));
        assert!(s.contains(DlpMatchKind::CreditCard, "4111-1111-1111-1111"));
        assert!(s.contains(DlpMatchKind::CreditCard, "4111 1111 1111 1111"));
    }

    #[test]
    fn builtin_has_rfc_ssn() {
        let s = SuppressionList::builtin();
        assert!(s.contains(DlpMatchKind::SsnUs, "123-45-6789"));
        assert!(s.contains(DlpMatchKind::SsnUs, "078-05-1120"));
    }

    #[test]
    fn kind_must_match() {
        // Same digits but wrong kind → no suppression.
        let s = SuppressionList::builtin();
        assert!(!s.contains(DlpMatchKind::AwsAccessKey, "4111111111111111"));
    }

    #[test]
    fn add_returns_true_only_first_time() {
        let mut s = SuppressionList::empty();
        assert!(s.add(DlpMatchKind::SsnUs, "555-66-7777"));
        assert!(!s.add(DlpMatchKind::SsnUs, "555-66-7777"));
    }

    #[test]
    fn aws_demo_key_suppressed() {
        let s = SuppressionList::builtin();
        assert!(s.contains(DlpMatchKind::AwsAccessKey, "AKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn jwt_demo_token_suppressed() {
        let s = SuppressionList::builtin();
        let demo = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        assert!(s.contains(DlpMatchKind::Jwt, demo));
    }
}
