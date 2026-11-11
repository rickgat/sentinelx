//! Regex-match signal — the literal-pattern matcher already fired.
//!
//! This is the "baseline" signal: if the kind-specific inspector
//! emitted a hit, the regex layer has corroborated it. We score this
//! at `1.00` always; the orchestrator weights it at `0.40` during
//! fusion. Lower confidence comes from the *other* signals failing,
//! not from this one being uncertain.

use super::{DlpSignal, SignalContext, SignalEvidence, SignalKind};

/// Stateless wrapper around the regex-fired event.
#[derive(Debug, Default, Clone, Copy)]
pub struct RegexMatchSignal;

impl DlpSignal for RegexMatchSignal {
    fn kind(&self) -> SignalKind {
        SignalKind::RegexMatch
    }

    fn evaluate(&self, ctx: &SignalContext<'_>) -> SignalEvidence {
        // We are only invoked once the pattern matcher has produced
        // a candidate — by construction the sub-score is full credit.
        let rationale = if ctx.matched.is_empty() {
            "regex match (empty span)".to_owned()
        } else {
            format!("regex match ({} bytes)", ctx.matched.len())
        };
        SignalEvidence::new(SignalKind::RegexMatch, 1.0, rationale)
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::patterns::DlpMatchKind;

    #[test]
    fn always_full_credit() {
        let t = "card 4111111111111111 here";
        let ctx = SignalContext::new(t, 5, 21, DlpMatchKind::CreditCard);
        let e = RegexMatchSignal.evaluate(&ctx);
        assert_eq!(e.kind, SignalKind::RegexMatch);
        assert!((e.sub_score - 1.0).abs() < f32::EPSILON);
        assert!(e.rationale.contains("regex"));
    }

    #[test]
    fn empty_span_still_fires() {
        let t = "";
        let ctx = SignalContext::new(t, 0, 0, DlpMatchKind::SsnUs);
        let e = RegexMatchSignal.evaluate(&ctx);
        assert!((e.sub_score - 1.0).abs() < f32::EPSILON);
    }
}
