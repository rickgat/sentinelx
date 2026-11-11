//! AI Red Team chain-composer DTOs.
//!
//! Wire-shape request and response types for the single Red Team route:
//!
//! - `POST /v1/redteam/chain` — compose a MITRE ATT&CK kill chain for a
//!   specific engagement, capped at `max_steps` steps.
//!
//! ## Validation
//!
//! - `engagement_id` must be a non-empty string. The adapter parses it as a
//!   UUID and surfaces `NotFound` / `Invalid` as appropriate; the wire
//!   layer only enforces non-emptiness so we never round-trip empty
//!   identifiers into the port layer.
//! - `max_steps` must be in `1..=14`. The lower bound rejects the
//!   degenerate `0` (which would produce an empty chain — useless to a
//!   caller) and the upper bound matches the 14 canonical ATT&CK phases:
//!   composing more than one step per phase yields no extra signal.
//!
//! The response mirrors `sx_autonomy::redteam`'s `AttackChain` projection:
//! - [`RedteamChainView`] — the composed chain.
//! - [`ChainStepView`] — one phase-anchored technique with a confidence in
//!   `[0.0, 1.0]`.

use serde::{Deserialize, Serialize};
use validator::Validate;

/// `POST /v1/redteam/chain` request body.
#[derive(Debug, Clone, Deserialize, Serialize, Validate)]
pub struct RedteamComposeRequest {
    /// Engagement uuid the chain is composed for. The adapter parses it as
    /// a UUID; an unparseable string surfaces as `422 Unprocessable`.
    #[validate(length(min = 1))]
    pub engagement_id: String,
    /// Cap on the number of emitted steps. Bounded to `1..=14` (14 MITRE
    /// ATT&CK Enterprise phases).
    #[validate(range(min = 1, max = 14))]
    pub max_steps: u8,
}

/// `POST /v1/redteam/chain` response body — projection of an
/// `sx_autonomy::redteam::AttackChain`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RedteamChainView {
    /// Ordered list of steps, lowest phase first.
    pub steps: Vec<ChainStepView>,
    /// Product of every step's `confidence`, floored at `1e-6`.
    pub chain_score: f64,
}

/// One step in a composed kill chain.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ChainStepView {
    /// MITRE ATT&CK tactic the step belongs to (e.g. `initial_access`).
    pub phase: String,
    /// MITRE ATT&CK technique identifier (e.g. `T1190`).
    pub technique_id: String,
    /// Per-step heuristic confidence in `[0.0, 1.0]`.
    pub confidence: f64,
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn baseline() -> RedteamComposeRequest {
        RedteamComposeRequest {
            engagement_id: "01010101-0101-0101-0101-010101010101".into(),
            max_steps: 8,
        }
    }

    #[test]
    fn accepts_well_formed_request() {
        assert!(baseline().validate().is_ok());
    }

    #[test]
    fn rejects_empty_engagement_id() {
        let mut req = baseline();
        req.engagement_id = String::new();
        assert!(req.validate().is_err());
    }

    #[test]
    fn rejects_max_steps_zero() {
        let mut req = baseline();
        req.max_steps = 0;
        assert!(req.validate().is_err());
    }

    #[test]
    fn rejects_max_steps_above_fourteen() {
        let mut req = baseline();
        req.max_steps = 15;
        assert!(req.validate().is_err());
    }

    #[test]
    fn accepts_max_steps_at_bounds() {
        for n in [1u8, 14u8] {
            let mut req = baseline();
            req.max_steps = n;
            assert!(req.validate().is_ok(), "expected {n} to validate");
        }
    }

    #[test]
    fn view_round_trips_through_json() {
        let v = RedteamChainView {
            steps: vec![ChainStepView {
                phase: "initial_access".into(),
                technique_id: "T1190".into(),
                confidence: 0.5,
            }],
            chain_score: 0.5,
        };
        let s = serde_json::to_string(&v).expect("serialise");
        let back: RedteamChainView = serde_json::from_str(&s).expect("deserialise");
        assert_eq!(back.steps.len(), 1);
        assert_eq!(back.steps[0].technique_id, "T1190");
        assert!((back.chain_score - 0.5).abs() < 1e-12);
    }
}
