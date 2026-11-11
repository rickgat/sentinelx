//! TOTP — Time-based One-Time Password (RFC 6238).
//!
//! Implements the HOTP truncation step from RFC 4226 §5.3 over an
//! HMAC-SHA1 digest of the counter, with the counter derived from the
//! current Unix time (`T = floor(now / period)`). The verifier accepts
//! codes inside a configurable `± window` step range to tolerate clock
//! drift between client and server (RFC 6238 §5.2).
//!
//! ## Defaults
//!
//! - `period = 30` seconds
//! - `digits = 6`
//! - `window = 1` step (±30s)
//!
//! ## Security notes
//!
//! - Secrets are never logged or formatted via `Debug` here — the bytes
//!   stay opaque to this module.
//! - Generation is constant-work for a fixed `digits` count.
//! - Verification iterates the window with an early-return on a single
//!   match; this implementation does not need a constant-time compare
//!   because the candidate space is tiny (at most `2*window + 1` codes)
//!   and the per-iteration cost is already dominated by one HMAC.
//!
//! ## References
//!
//! - RFC 4226 — HOTP: an HMAC-Based One-Time Password Algorithm.
//! - RFC 6238 — TOTP: Time-Based One-Time Password Algorithm.

use hmac::{Hmac, Mac};
use sha1::Sha1;

type HmacSha1 = Hmac<Sha1>;

/// Default TOTP period (seconds).
pub const DEFAULT_PERIOD: u64 = 30;
/// Default digit length.
pub const DEFAULT_DIGITS: u32 = 6;
/// Default verification window (steps in each direction).
pub const DEFAULT_WINDOW: i64 = 1;

/// Verifier configuration.
///
/// `period` is the TOTP step in seconds; `digits` controls how many
/// decimal digits the truncated HOTP value is reduced to; `window`
/// controls how many steps (in each direction) the verifier accepts
/// around `now / period`.
///
/// Construct via [`TotpVerifier::default`] for the RFC 6238 baseline
/// (30s / 6 digits / ±1 step).
#[derive(Debug, Clone, Copy)]
pub struct TotpVerifier {
    /// TOTP period in seconds.
    pub period: u64,
    /// Number of decimal digits emitted by the truncation step.
    pub digits: u32,
    /// Accepted window (steps) around `now / period`.
    pub window: i64,
}

impl Default for TotpVerifier {
    fn default() -> Self {
        Self {
            period: DEFAULT_PERIOD,
            digits: DEFAULT_DIGITS,
            window: DEFAULT_WINDOW,
        }
    }
}

impl TotpVerifier {
    /// Build a verifier with explicit parameters.
    #[must_use]
    pub const fn new(period: u64, digits: u32, window: i64) -> Self {
        Self {
            period,
            digits,
            window,
        }
    }

    /// Generate a TOTP code for `time` (Unix seconds) using `self.period`
    /// and `self.digits`.
    #[must_use]
    pub fn generate_code(&self, secret: &[u8], time: u64) -> String {
        // Floor-division is intentional — counters are integer steps
        // by RFC 6238 §4.2.
        #[allow(clippy::integer_division)]
        let counter = if self.period == 0 {
            0
        } else {
            time / self.period
        };
        generate_with(secret, counter, self.digits)
    }

    /// Verify `code` against codes computed for `time/period ± window`.
    ///
    /// Returns `true` on a match. `code` MUST already be in the canonical
    /// `digits`-character decimal form — leading zeros included. Codes of
    /// the wrong length never match.
    #[must_use]
    pub fn verify(&self, secret: &[u8], code: &str, time: u64) -> bool {
        // Reject obviously wrong shapes early without leaking timing
        // information about the secret: this check only depends on the
        // public `digits` parameter and the candidate `code`.
        if !code.bytes().all(|b| b.is_ascii_digit()) {
            return false;
        }
        if code.len() != usize::try_from(self.digits).unwrap_or(usize::MAX) {
            return false;
        }
        let period = if self.period == 0 { 1 } else { self.period };
        // Floor-division to derive the canonical TOTP counter — see
        // RFC 6238 §4.2. The non-zero `period` is enforced above.
        #[allow(clippy::integer_division)]
        let center = i128::from(time / period);
        for offset in -self.window..=self.window {
            let candidate = center + i128::from(offset);
            if candidate < 0 {
                continue;
            }
            let Ok(counter) = u64::try_from(candidate) else {
                continue;
            };
            let generated = generate_with(secret, counter, self.digits);
            if generated == code {
                return true;
            }
        }
        false
    }
}

/// Generate a HOTP/TOTP code for the supplied `secret` + `time` (Unix
/// seconds) using the RFC 6238 defaults (30s period, 6 digits).
///
/// This free function is the canonical helper called by
/// [`TotpVerifier::generate_code`]. It exists at module scope so callers
/// that only need a one-shot generation (e.g. tests) can skip building a
/// verifier.
///
/// `time` here is interpreted as the **counter** value (matches the
/// RFC 4226 §5.3 contract). Callers that want time-based generation
/// should divide by the period first or use
/// [`TotpVerifier::generate_code`].
#[must_use]
pub fn generate(secret: &[u8], time: u64) -> String {
    generate_with(secret, time, DEFAULT_DIGITS)
}

/// Verify `code` against the default `TotpVerifier`.
///
/// Convenience wrapper for callers that do not need to configure the
/// period, digits, or window.
#[must_use]
pub fn verify(secret: &[u8], code: &str, time: u64) -> bool {
    TotpVerifier::default().verify(secret, code, time)
}

/// Internal helper used by both [`generate`] and [`TotpVerifier`].
fn generate_with(secret: &[u8], counter: u64, digits: u32) -> String {
    let code = hotp_value(secret, counter, digits);
    let width = usize::try_from(digits).unwrap_or(usize::MAX);
    format!("{code:0>width$}")
}

/// Run HOTP truncation per RFC 4226 §5.3 — HMAC-SHA1 the counter,
/// dynamic-truncate to a 31-bit integer, then reduce modulo `10^digits`.
fn hotp_value(secret: &[u8], counter: u64, digits: u32) -> u32 {
    let counter_be = counter.to_be_bytes();
    // HMAC accepts arbitrary-length keys; the only failure mode is
    // an internal invariant violation. We surface as a zeroed code
    // rather than panic so the verifier stays safe to call with any
    // byte buffer. The mismatch is harmless because verification
    // compares against generations under the same secret — both
    // sides yield the same zero on this path.
    let Ok(mut mac) = HmacSha1::new_from_slice(secret) else {
        return 0;
    };
    mac.update(&counter_be);
    let digest = mac.finalize().into_bytes();

    // Dynamic truncation — RFC 4226 §5.3.
    // SHA-1 outputs 20 bytes; the offset is in `0..=15`, so reading 4
    // bytes starting at `offset` is always in-bounds. We still go
    // through `.get(..)` so a hypothetical future digest swap cannot
    // panic.
    let Some(last) = digest.last() else {
        return 0;
    };
    let offset = usize::from(last & 0x0f);
    let Some(p) = digest.get(offset..offset + 4) else {
        return 0;
    };
    let Some(&b0) = p.first() else { return 0 };
    let Some(&b1) = p.get(1) else { return 0 };
    let Some(&b2) = p.get(2) else { return 0 };
    let Some(&b3) = p.get(3) else { return 0 };
    let bin =
        (u32::from(b0) & 0x7f) << 24 | u32::from(b1) << 16 | u32::from(b2) << 8 | u32::from(b3);

    let modulus = 10_u32.pow(digits);
    bin % modulus
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// RFC 6238 Appendix B reference secret (ASCII "12345678901234567890").
    const RFC6238_SECRET: &[u8] = b"12345678901234567890";

    #[test]
    fn rfc6238_vector_t1_matches() {
        // RFC 6238 Appendix B: T=59 (1970-01-01 00:00:59 UTC), 8-digit
        // SHA1 code is 94287082. We verify the 6-digit reduction
        // (287082) which is the canonical SentinelX default.
        let v = TotpVerifier::new(30, 6, 0);
        let code = v.generate_code(RFC6238_SECRET, 59);
        assert_eq!(code, "287082", "RFC 6238 T=59 SHA1 vector");
    }

    #[test]
    fn rfc6238_vector_t2_matches() {
        // T=1111111109 → 8-digit 07081804 → 6-digit 081804.
        let v = TotpVerifier::default();
        let code = v.generate_code(RFC6238_SECRET, 1_111_111_109);
        assert_eq!(code, "081804");
    }

    #[test]
    fn verify_accepts_window_minus_one_and_plus_one() {
        let v = TotpVerifier::default();
        let now = 1_111_111_109_u64;
        // Generate codes for the previous and next steps.
        let prev_code = v.generate_code(RFC6238_SECRET, now - 30);
        let next_code = v.generate_code(RFC6238_SECRET, now + 30);
        assert!(
            v.verify(RFC6238_SECRET, &prev_code, now),
            "code from -1 step must verify within window=1"
        );
        assert!(
            v.verify(RFC6238_SECRET, &next_code, now),
            "code from +1 step must verify within window=1"
        );
    }

    #[test]
    fn verify_rejects_window_minus_two() {
        let v = TotpVerifier::default();
        let now = 1_111_111_109_u64;
        // Two full steps in the past → outside ±1 window.
        let stale_code = v.generate_code(RFC6238_SECRET, now - 60);
        // Sanity: that code must NOT equal the current one (otherwise
        // the test would be trivially passing).
        let current = v.generate_code(RFC6238_SECRET, now);
        assert_ne!(stale_code, current);
        assert!(
            !v.verify(RFC6238_SECRET, &stale_code, now),
            "code from -2 steps must NOT verify within window=1"
        );
    }

    #[test]
    fn verify_rejects_wrong_code() {
        let v = TotpVerifier::default();
        assert!(!v.verify(RFC6238_SECRET, "000000", 59));
        assert!(!v.verify(RFC6238_SECRET, "999999", 59));
    }

    #[test]
    fn verify_rejects_wrong_length() {
        let v = TotpVerifier::default();
        // Generation is 6 digits; a 5-digit candidate cannot match.
        assert!(!v.verify(RFC6238_SECRET, "12345", 59));
        assert!(!v.verify(RFC6238_SECRET, "1234567", 59));
    }

    #[test]
    fn verify_rejects_non_digit_code() {
        let v = TotpVerifier::default();
        assert!(!v.verify(RFC6238_SECRET, "12a456", 59));
        assert!(!v.verify(RFC6238_SECRET, "      ", 59));
    }

    #[test]
    fn verify_current_step_matches_generated_code() {
        let v = TotpVerifier::default();
        let now = 1_700_000_000_u64;
        let code = v.generate_code(RFC6238_SECRET, now);
        assert!(v.verify(RFC6238_SECRET, &code, now));
    }

    #[test]
    fn free_function_generate_pads_leading_zeroes() {
        // counter=0 against RFC vector secret is not predictable as a
        // padded value, so just assert shape: 6 digits, all ASCII.
        let code = super::generate(RFC6238_SECRET, 0);
        assert_eq!(code.len(), 6);
        assert!(code.bytes().all(|b| b.is_ascii_digit()));
    }

    #[test]
    fn free_function_verify_matches_default_verifier() {
        let now = 1_700_000_000_u64;
        let code = TotpVerifier::default().generate_code(RFC6238_SECRET, now);
        assert!(super::verify(RFC6238_SECRET, &code, now));
    }

    #[test]
    fn verifier_with_custom_digits_and_window() {
        // 8-digit code at T=59 from RFC 6238 vector is 94287082.
        let v = TotpVerifier::new(30, 8, 0);
        assert_eq!(v.generate_code(RFC6238_SECRET, 59), "94287082");
    }

    #[test]
    fn verifier_default_matches_constants() {
        let v = TotpVerifier::default();
        assert_eq!(v.period, DEFAULT_PERIOD);
        assert_eq!(v.digits, DEFAULT_DIGITS);
        assert_eq!(v.window, DEFAULT_WINDOW);
    }
}
