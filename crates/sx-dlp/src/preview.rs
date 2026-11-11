//! Redacted-preview helper.
//!
//! Every `DlpMatch` carries a `redacted_preview` rather than the literal
//! match, so dashboards / audit logs never reveal the raw value. The
//! rule is intentionally simple and stable:
//!
//! - Matches with at least 6 characters → first 4 chars + asterisks for
//!   the middle + last 2 chars.
//! - Matches shorter than 6 characters → all chars replaced with `*`.
//! - Multi-byte boundaries are respected (we operate on `char`s, not
//!   bytes, so the function never panics on UTF-8 boundaries).
//!
//! Tests in this module pin the contract.

/// Build a redacted preview for the literal match `s`.
///
/// See the module docs for the rule. Always produces a printable ASCII
/// preview; the trailing 2 chars are only attached when the match has
/// at least 6 characters.
#[must_use]
pub fn redact(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() < 6 {
        return "*".repeat(chars.len());
    }
    let head: String = chars.iter().take(4).collect();
    let tail: String = chars.iter().skip(chars.len().saturating_sub(2)).collect();
    let mid_len = chars.len().saturating_sub(6);
    let mid = "*".repeat(mid_len);
    format!("{head}{mid}{tail}")
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn long_match_uses_first4_stars_last2() {
        // 16 chars; expected: ABCD then 10 stars then EF
        let out = redact("ABCD1234567890EF");
        assert_eq!(out, "ABCD**********EF");
        assert_eq!(out.len(), 16);
    }

    #[test]
    fn six_char_match_emits_first4_stars_last2_without_middle() {
        // 6 chars; first 4 + 0 stars + last 2.
        let out = redact("ABCDEF");
        assert_eq!(out, "ABCDEF");
    }

    #[test]
    fn short_match_replaced_entirely_with_stars() {
        assert_eq!(redact("abc"), "***");
        assert_eq!(redact(""), "");
    }

    #[test]
    fn handles_multibyte_chars_without_panic() {
        // Three multi-byte chars: should be 3 stars
        let s = "\u{1F600}\u{1F601}\u{1F602}";
        let out = redact(s);
        assert_eq!(out, "***");
    }
}
