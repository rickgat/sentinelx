//! Luhn-checksum signal — PAN-only validator.
//!
//! For [`DlpMatchKind::CreditCard`] this signal re-runs the Luhn check
//! over the matched digit run and emits `1.00` on success, `0.00` on
//! failure. For every non-PAN kind the signal is *neutral*: it returns
//! `0.50` to mean "n/a — does not penalise the fusion either way".
//!
//! The 0.50 neutral value is important because the fusion weight is
//! a constant `0.30`. If we returned 0.0 for non-PAN kinds we would
//! cap their max confidence at `0.70`, which would defeat per-tenant
//! thresholding on SSNs / tokens.

use super::{DlpSignal, SignalContext, SignalEvidence, SignalKind};
use crate::patterns::credit_card::luhn_ok;
use crate::patterns::DlpMatchKind;

/// Luhn-check signal.
#[derive(Debug, Default, Clone, Copy)]
pub struct LuhnSignal;

impl DlpSignal for LuhnSignal {
    fn kind(&self) -> SignalKind {
        SignalKind::LuhnCheck
    }

    fn evaluate(&self, ctx: &SignalContext<'_>) -> SignalEvidence {
        if !matches!(ctx.kind, DlpMatchKind::CreditCard) {
            // N/A — emit a neutral 0.5 so this signal does not bias
            // non-PAN kinds' confidence either way.
            return SignalEvidence::new(SignalKind::LuhnCheck, 0.5, "n/a (non-PAN kind)");
        }
        // Strip separators (the orchestrator hands us the original
        // matched substring) before running Luhn.
        let digits: Vec<u8> = ctx.matched.bytes().filter(u8::is_ascii_digit).collect();
        if luhn_ok(&digits) {
            SignalEvidence::new(SignalKind::LuhnCheck, 1.0, "luhn ok")
        } else {
            SignalEvidence::new(SignalKind::LuhnCheck, 0.0, "luhn failed")
        }
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn pan_good_luhn_full_credit() {
        let t = "card 4111 1111 1111 1111 end";
        let ctx = SignalContext::new(t, 5, 24, DlpMatchKind::CreditCard);
        let e = LuhnSignal.evaluate(&ctx);
        assert!((e.sub_score - 1.0).abs() < f32::EPSILON);
        assert!(e.rationale.contains("ok"));
    }

    #[test]
    fn pan_bad_luhn_zero() {
        let t = "card 4111 1111 1111 1112 end";
        let ctx = SignalContext::new(t, 5, 24, DlpMatchKind::CreditCard);
        let e = LuhnSignal.evaluate(&ctx);
        assert!(e.sub_score.abs() < f32::EPSILON);
        assert!(e.rationale.contains("failed"));
    }

    #[test]
    fn non_pan_is_neutral_half() {
        let t = "ssn 123-45-6789 end";
        let ctx = SignalContext::new(t, 4, 15, DlpMatchKind::SsnUs);
        let e = LuhnSignal.evaluate(&ctx);
        assert!((e.sub_score - 0.5).abs() < f32::EPSILON);
        assert!(e.rationale.contains("n/a"));
    }
}
