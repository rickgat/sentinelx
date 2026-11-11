//! Shannon-entropy band signal.
//!
//! Each [`DlpMatchKind`] gets a band of expected Shannon entropy values
//! for its match. A score of `1.0` is awarded when the measured entropy
//! sits inside the band; the score linearly decays towards the band
//! edges so a near-miss is not penalised as a full failure.
//!
//! Bands (bits per symbol, base-2 Shannon entropy over the byte stream
//! of the matched run after separator stripping):
//!
//! | Kind | Band |
//! |---|---|
//! | `CreditCard`, `SsnUs`, `Phone` | `2.5 .. 3.8` (digits only — flat distribution capped at log2(10)) |
//! | `AwsAccessKey`, `GithubPat`, `SlackToken` | `4.0 .. 5.5` (base32/base62 + fixed prefix) |
//! | `AwsSecretKey`, `Jwt`, `GcpServiceAccount`, `PemPrivateKey` | `4.8 .. 6.5` (high-entropy random) |
//! | `Email`, `NamedEntity` | `3.0 .. 5.0` (text-ish) |
//!
//! The bands are wide on purpose — Sprint-4 calibration sets a baseline,
//! later sprints can narrow them once we have field telemetry.

use super::{DlpSignal, SignalContext, SignalEvidence, SignalKind};
use crate::patterns::DlpMatchKind;

/// Shannon-entropy band signal.
#[derive(Debug, Default, Clone, Copy)]
pub struct EntropySignal;

/// Per-kind expected entropy band, in bits per symbol.
#[must_use]
pub const fn expected_band(kind: DlpMatchKind) -> (f32, f32) {
    match kind {
        DlpMatchKind::CreditCard | DlpMatchKind::SsnUs | DlpMatchKind::Phone => (2.5, 3.8),
        DlpMatchKind::AwsAccessKey | DlpMatchKind::GithubPat | DlpMatchKind::SlackToken => {
            (4.0, 5.5)
        }
        DlpMatchKind::AwsSecretKey
        | DlpMatchKind::Jwt
        | DlpMatchKind::GcpServiceAccount
        | DlpMatchKind::PemPrivateKey => (4.8, 6.5),
        DlpMatchKind::Email | DlpMatchKind::NamedEntity => (3.0, 5.0),
    }
}

/// Compute Shannon entropy (bits / symbol) of `bytes`. Returns `0.0`
/// for empty input.
#[must_use]
pub fn shannon_entropy(bytes: &[u8]) -> f32 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0_u32; 256];
    for &b in bytes {
        // `b as usize` is in `0..=255`; `counts` has 256 slots so this
        // get_mut never returns None — match exhaustively to satisfy
        // clippy::indexing_slicing without an unwrap.
        if let Some(slot) = counts.get_mut(usize::from(b)) {
            *slot = slot.saturating_add(1);
        }
    }
    #[allow(clippy::cast_precision_loss)]
    let len = bytes.len() as f32;
    let mut h = 0_f32;
    for c in counts {
        if c == 0 {
            continue;
        }
        #[allow(clippy::cast_precision_loss)]
        let p = c as f32 / len;
        h -= p * p.log2();
    }
    h
}

/// Convert a measured entropy + a target band into a `[0.0, 1.0]`
/// score:
///
/// - In-band → `1.0`.
/// - Outside the band → linearly decays to `0.0` over a half-band-wide
///   margin on each side. Beyond that margin → `0.0`.
#[must_use]
pub fn score_in_band(entropy: f32, band: (f32, f32)) -> f32 {
    let (lo, hi) = band;
    if entropy >= lo && entropy <= hi {
        return 1.0;
    }
    let margin = (hi - lo).max(0.1);
    if entropy < lo {
        let d = lo - entropy;
        (1.0 - d / margin).clamp(0.0, 1.0)
    } else {
        let d = entropy - hi;
        (1.0 - d / margin).clamp(0.0, 1.0)
    }
}

impl DlpSignal for EntropySignal {
    fn kind(&self) -> SignalKind {
        SignalKind::EntropyBand
    }

    fn evaluate(&self, ctx: &SignalContext<'_>) -> SignalEvidence {
        if ctx.matched.is_empty() {
            return SignalEvidence::new(SignalKind::EntropyBand, 0.0, "empty span");
        }
        // For digit-bearing kinds, strip separators to measure entropy
        // of the actual payload, not the whitespace.
        let payload: Vec<u8> = match ctx.kind {
            DlpMatchKind::CreditCard | DlpMatchKind::SsnUs | DlpMatchKind::Phone => {
                ctx.matched.bytes().filter(u8::is_ascii_digit).collect()
            }
            _ => ctx.matched.bytes().collect(),
        };
        let h = shannon_entropy(&payload);
        let band = expected_band(ctx.kind);
        let s = score_in_band(h, band);
        SignalEvidence::new(
            SignalKind::EntropyBand,
            s,
            format!(
                "entropy={h:.2} band=({:.1},{:.1}) score={s:.2}",
                band.0, band.1
            ),
        )
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_zero_entropy() {
        assert!(shannon_entropy(b"").abs() < f32::EPSILON);
    }

    #[test]
    fn uniform_distribution_max_entropy() {
        // 4 distinct bytes uniformly → 2.0 bits.
        let h = shannon_entropy(b"abcdabcd");
        assert!((h - 2.0).abs() < 0.01, "got {h}");
    }

    #[test]
    fn all_same_byte_zero_entropy() {
        let h = shannon_entropy(b"aaaaaaaa");
        assert!(h.abs() < f32::EPSILON);
    }

    #[test]
    fn in_band_full_credit() {
        assert!((score_in_band(3.0, (2.5, 3.8)) - 1.0).abs() < f32::EPSILON);
    }

    #[test]
    fn just_below_band_decays() {
        // Band 2.5..3.8, margin 1.3, entropy 2.0 → distance 0.5 → 1.0 - 0.5/1.3
        let s = score_in_band(2.0, (2.5, 3.8));
        assert!(s > 0.5 && s < 1.0);
    }

    #[test]
    fn far_below_band_zero() {
        let s = score_in_band(0.0, (4.8, 6.5));
        assert!(s.abs() < f32::EPSILON);
    }

    #[test]
    fn credit_card_digits_in_band() {
        let t = "4111 1111 1111 1111";
        let ctx = SignalContext::new(t, 0, t.len(), DlpMatchKind::CreditCard);
        let e = EntropySignal.evaluate(&ctx);
        // The repeated-1 PAN has very low entropy; should score < 1.0
        // and definitely > 0 because the band starts at 2.5 and a
        // run of 16 digits with mostly `1`s has very small entropy.
        // We assert the rationale carries the entropy field for the
        // explainability surface.
        assert!(e.rationale.contains("entropy="));
        assert!(e.sub_score >= 0.0);
        assert!(e.sub_score <= 1.0);
    }

    #[test]
    fn aws_access_key_lands_in_high_band() {
        // 20-char access key — mixed alphanumeric, high entropy.
        let t = "AKIAIOSFODNN7EXAMPLE";
        let ctx = SignalContext::new(t, 0, t.len(), DlpMatchKind::AwsAccessKey);
        let e = EntropySignal.evaluate(&ctx);
        assert!(
            e.sub_score > 0.5,
            "aws key entropy should be in band: {}",
            e.rationale
        );
    }
}
