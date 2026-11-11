//! Heuristic scoring for kill-chain steps.
//!
//! The score model is deliberately small and inspectable. Two layers:
//!
//! 1. **Per-step score** — the value a composer assigns to a candidate
//!    technique before it is bound into a [`crate::redteam::chain::ChainStep`].
//!    Formula:
//!
//!    ```text
//!    step_score = phase_weight(phase) * technique_confidence * target_fit
//!    ```
//!
//!    All three inputs are in `[0.0, 1.0]`, so the output is in
//!    `[0.0, 1.0]`. `target_fit` is supplied by the caller and reflects
//!    how well the technique matches the [`crate::redteam::selector::TargetSpec`].
//!
//! 2. **Chain score** — once a chain has been composed, the final score
//!    is the product of every step's `confidence`, with a hard floor of
//!    `1e-6` so a single weak step can't collapse the chain to zero in a
//!    way that hides the rest of the heuristic signal:
//!
//!    ```text
//!    chain_score = max(prod(step.confidence for step in chain.steps), 1e-6)
//!    ```
//!
//!    An empty chain returns the floor `1e-6` (well-defined, low signal).

use crate::redteam::chain::{AttackChain, KillChainPhase};

/// Floor applied to [`chain_score`] so the heuristic remains differentiable
/// (in the colloquial sense) when one weak step drags the product down.
pub const MIN_CHAIN_SCORE: f64 = 1e-6;

/// Static weight assigned to each ATT&CK phase.
///
/// The shape is bowl-shaped: foothold (`InitialAccess`, `Execution`) and
/// impact phases score high; reconnaissance and resource-development —
/// useful but cheap and noisy — score lower. Values are in `[0.0, 1.0]`.
#[must_use]
pub const fn phase_weight(phase: KillChainPhase) -> f64 {
    match phase {
        KillChainPhase::Reconnaissance => 0.40,
        KillChainPhase::ResourceDevelopment => 0.45,
        KillChainPhase::InitialAccess | KillChainPhase::Impact => 0.95,
        KillChainPhase::Execution => 0.90,
        KillChainPhase::Persistence | KillChainPhase::LateralMovement => 0.80,
        KillChainPhase::PrivilegeEscalation
        | KillChainPhase::CredentialAccess
        | KillChainPhase::Exfiltration => 0.85,
        KillChainPhase::DefenseEvasion => 0.70,
        KillChainPhase::Discovery => 0.60,
        KillChainPhase::Collection => 0.65,
        KillChainPhase::CommandAndControl => 0.75,
    }
}

/// Compute the per-step heuristic score.
///
/// Inputs outside `[0.0, 1.0]` (including non-finite values) are clamped
/// before the multiplication so the output is always in `[0.0, 1.0]`.
#[must_use]
pub fn step_score(phase: KillChainPhase, technique_confidence: f64, target_fit: f64) -> f64 {
    let tc = sanitise_unit(technique_confidence);
    let tf = sanitise_unit(target_fit);
    let raw = phase_weight(phase) * tc * tf;
    sanitise_unit(raw)
}

/// Compute the chain-wide score: product of per-step confidences, floored
/// at [`MIN_CHAIN_SCORE`].
#[must_use]
pub fn chain_score(chain: &AttackChain) -> f64 {
    if chain.is_empty() {
        return MIN_CHAIN_SCORE;
    }
    let product: f64 = chain
        .steps
        .iter()
        .map(|s| sanitise_unit(s.confidence))
        .product();
    product.max(MIN_CHAIN_SCORE)
}

#[inline]
#[allow(clippy::missing_const_for_fn)]
fn sanitise_unit(x: f64) -> f64 {
    if x.is_finite() {
        x.clamp(0.0, 1.0)
    } else {
        0.0
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::float_cmp)]
mod tests {
    use super::*;
    use crate::redteam::chain::{AttackChain, ChainStep};

    fn approx(a: f64, b: f64) -> bool {
        (a - b).abs() < 1e-9
    }

    #[test]
    fn phase_weights_are_in_unit_interval() {
        for p in KillChainPhase::all() {
            let w = phase_weight(p);
            assert!((0.0..=1.0).contains(&w), "weight out of range for {p}");
        }
    }

    #[test]
    fn step_score_multiplies_inputs() {
        let s = step_score(KillChainPhase::InitialAccess, 0.8, 0.5);
        // 0.95 * 0.8 * 0.5 = 0.38
        assert!(approx(s, 0.38));
    }

    #[test]
    fn step_score_clamps_out_of_range_inputs() {
        let s = step_score(KillChainPhase::Execution, 1.5, -0.3);
        // Clamped to 1.0 and 0.0 -> product is 0.0
        assert_eq!(s, 0.0);
    }

    #[test]
    fn chain_score_is_product_of_confidences() {
        let c = AttackChain::from_steps(vec![
            ChainStep::new(KillChainPhase::InitialAccess, "T1190", 0.9),
            ChainStep::new(KillChainPhase::Execution, "T1059", 0.8),
            ChainStep::new(KillChainPhase::Impact, "T1486", 0.5),
        ]);
        // 0.9 * 0.8 * 0.5 = 0.36
        assert!(approx(chain_score(&c), 0.36));
    }

    #[test]
    fn chain_score_floored_for_empty_chain() {
        let c = AttackChain::empty();
        assert_eq!(chain_score(&c), MIN_CHAIN_SCORE);
    }

    #[test]
    fn chain_score_floor_kicks_in_for_zero_step() {
        let c = AttackChain::from_steps(vec![
            ChainStep::new(KillChainPhase::InitialAccess, "T1190", 0.9),
            ChainStep::new(KillChainPhase::Execution, "T1059", 0.0),
        ]);
        assert_eq!(chain_score(&c), MIN_CHAIN_SCORE);
    }
}
