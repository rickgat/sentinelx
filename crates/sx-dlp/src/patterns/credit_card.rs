//! Credit card / PAN matcher.
//!
//! Two-stage detection:
//!
//! 1. Locate runs of 13-19 digits, optionally separated by spaces or
//!    hyphens (e.g. `4111 1111 1111 1111`, `4111-1111-1111-1111`).
//! 2. Strip separators, verify the issuer prefix (Visa, Mastercard,
//!    Amex, Discover, JCB, Diners), then verify the Luhn checksum.
//!
//! Only digits that survive both checks emit a `DlpMatch`. The reported
//! `offset` / `length` cover the **original** run (separators included).
//!
//! ## False-positive budget
//!
//! The Luhn check eliminates random digit sequences with ~90% recall on
//! 16-digit inputs. The issuer-prefix gate eliminates timestamps,
//! sequential test numbers, etc. Combined these two stages keep the
//! false-positive rate manageable for the inline scan endpoint.

use std::sync::OnceLock;

use regex::Regex;

use crate::patterns::{DlpMatch, DlpMatchKind};
use crate::preview::redact;

/// Compile + memoise the run-locator. Matches 13–19 digits, possibly
/// broken by single space or hyphen separators. Anchored on word
/// boundaries so we do not split mid-number.
fn run_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    // Unwrap is allowed at compile-time fixture init; we test the
    // pattern below. If the pattern is malformed the test will fail.
    RE.get_or_init(|| {
        Regex::new(
            r"(?x)
            \b
            (?:\d[\s-]?){12,18}    # 13..=19 digits with optional space/hyphen
            \d
            \b
        ",
        )
        .unwrap_or_else(|_| {
            #[allow(clippy::unwrap_used)]
            Regex::new(r"\d{13,19}").unwrap()
        })
    })
}

/// Verify the supplied digits via the Luhn algorithm (ISO/IEC 7812-1).
#[must_use]
pub fn luhn_ok(digits: &[u8]) -> bool {
    if digits.is_empty() {
        return false;
    }
    let mut sum: u32 = 0;
    let mut double = false;
    for &d in digits.iter().rev() {
        if !d.is_ascii_digit() {
            return false;
        }
        let mut v: u32 = u32::from(d - b'0');
        if double {
            v *= 2;
            if v > 9 {
                v -= 9;
            }
        }
        sum += v;
        double = !double;
    }
    sum.is_multiple_of(10)
}

/// Issuer-prefix gate. Returns `true` for any digit run with a
/// recognised issuer prefix. Length is checked alongside the prefix
/// so a `4XXX...` short string doesn't get accepted.
#[must_use]
pub fn issuer_prefix_ok(digits: &[u8]) -> bool {
    let len = digits.len();
    if !(13..=19).contains(&len) {
        return false;
    }
    // Visa: 4xxx, 13/16/19 digits.
    if digits.first() == Some(&b'4') && (len == 13 || len == 16 || len == 19) {
        return true;
    }
    // Mastercard: 51-55 (16) or 2221-2720 (16).
    if len == 16 {
        let prefix2 = two_digit_prefix(digits);
        if (51..=55).contains(&prefix2) {
            return true;
        }
        let prefix4 = four_digit_prefix(digits);
        if (2221..=2720).contains(&prefix4) {
            return true;
        }
    }
    // Amex: 34 / 37, length 15.
    if len == 15 {
        let prefix2 = two_digit_prefix(digits);
        if prefix2 == 34 || prefix2 == 37 {
            return true;
        }
    }
    // Discover: 6011 / 65 / 644-649, length 16 or 19.
    if len == 16 || len == 19 {
        let prefix2 = two_digit_prefix(digits);
        let prefix3 = three_digit_prefix(digits);
        let prefix4 = four_digit_prefix(digits);
        if prefix4 == 6011 || prefix2 == 65 || (644..=649).contains(&prefix3) {
            return true;
        }
    }
    // JCB: 3528-3589, length 16 or 19.
    if (len == 16 || len == 19) && (3528..=3589).contains(&four_digit_prefix(digits)) {
        return true;
    }
    // Diners Club: 300-305, 3095, 36, 38, 39 — length 14-19.
    if (14..=19).contains(&len) {
        let prefix2 = two_digit_prefix(digits);
        let prefix3 = three_digit_prefix(digits);
        let prefix4 = four_digit_prefix(digits);
        if (300..=305).contains(&prefix3)
            || prefix4 == 3095
            || prefix2 == 36
            || prefix2 == 38
            || prefix2 == 39
        {
            return true;
        }
    }
    false
}

fn two_digit_prefix(digits: &[u8]) -> u32 {
    digits
        .iter()
        .take(2)
        .fold(0u32, |acc, &c| acc * 10 + u32::from(c - b'0'))
}
fn three_digit_prefix(digits: &[u8]) -> u32 {
    digits
        .iter()
        .take(3)
        .fold(0u32, |acc, &c| acc * 10 + u32::from(c - b'0'))
}
fn four_digit_prefix(digits: &[u8]) -> u32 {
    digits
        .iter()
        .take(4)
        .fold(0u32, |acc, &c| acc * 10 + u32::from(c - b'0'))
}

/// Scan `text` for credit-card numbers.
#[must_use]
pub fn scan(text: &str) -> Vec<DlpMatch> {
    let mut out = Vec::new();
    let bytes = text.as_bytes();
    for m in run_regex().find_iter(text) {
        let run = m.as_str();
        // Strip non-digits to feed Luhn + prefix.
        let digits: Vec<u8> = run.bytes().filter(u8::is_ascii_digit).collect();
        if !issuer_prefix_ok(&digits) {
            continue;
        }
        if !luhn_ok(&digits) {
            continue;
        }
        // Skip if we drifted past EOF — defensive.
        let start = m.start();
        let end = m.end();
        if end > bytes.len() {
            continue;
        }
        out.push(DlpMatch {
            kind: DlpMatchKind::CreditCard,
            offset: start,
            length: end - start,
            redacted_preview: redact(run),
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
    fn luhn_accepts_known_good_pan() {
        // Test PAN (Visa) — passes Luhn.
        assert!(luhn_ok(b"4111111111111111"));
        // Mastercard test.
        assert!(luhn_ok(b"5500000000000004"));
        // Amex test.
        assert!(luhn_ok(b"340000000000009"));
    }

    #[test]
    fn luhn_rejects_bad_checksum() {
        assert!(!luhn_ok(b"4111111111111112"));
        assert!(!luhn_ok(b"5500000000000005"));
    }

    #[test]
    fn luhn_rejects_empty() {
        assert!(!luhn_ok(b""));
    }

    #[test]
    fn issuer_prefix_recognises_visa() {
        assert!(issuer_prefix_ok(b"4111111111111111"));
    }

    #[test]
    fn issuer_prefix_recognises_mastercard() {
        assert!(issuer_prefix_ok(b"5500000000000004"));
        // 2221..=2720
        assert!(issuer_prefix_ok(b"2221000000000009"));
    }

    #[test]
    fn issuer_prefix_recognises_amex() {
        assert!(issuer_prefix_ok(b"340000000000009"));
    }

    #[test]
    fn issuer_prefix_rejects_phone_number() {
        // 1234567890123 — Luhn could pass for some but prefix won't.
        assert!(!issuer_prefix_ok(b"1234567890123"));
    }

    #[test]
    fn scan_finds_pan_in_text() {
        let text = "card on file: 4111 1111 1111 1111 thanks";
        let matches = scan(text);
        assert_eq!(matches.len(), 1);
        let m = &matches[0];
        assert_eq!(m.kind, DlpMatchKind::CreditCard);
        // Offset is into the original text.
        assert!(m.offset < text.len());
        assert_eq!(&text[m.offset..m.offset + m.length], "4111 1111 1111 1111");
        // Redacted preview is first 4 + asterisks + last 2.
        assert!(m.redacted_preview.starts_with("4111"));
        assert!(m.redacted_preview.ends_with("11"));
    }

    #[test]
    fn scan_finds_hyphen_separated_pan() {
        let text = "test: 4111-1111-1111-1111 ok";
        let matches = scan(text);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].kind, DlpMatchKind::CreditCard);
    }

    #[test]
    fn scan_rejects_invalid_luhn() {
        let text = "fake card: 4111 1111 1111 1112";
        let matches = scan(text);
        assert!(matches.is_empty());
    }

    #[test]
    fn scan_rejects_random_digit_run() {
        // 16 random digits without valid issuer prefix.
        let text = "ref no: 1234567890123456";
        let matches = scan(text);
        assert!(matches.is_empty());
    }

    #[test]
    fn scan_finds_amex_15_digits() {
        // Amex 15-digit test
        let text = "amex 3400 000000 00009";
        let matches = scan(text);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].kind, DlpMatchKind::CreditCard);
    }

    #[test]
    fn scan_handles_no_match_quickly() {
        let text = "nothing sensitive here";
        let matches = scan(text);
        assert!(matches.is_empty());
    }
}
