//! Mode gate.
//!
//! Rejects any technique whose declared `max_mode` exceeds the engagement's
//! active operating mode ceiling. The check is a single comparison —
//! `technique.max_mode() <= active_mode` — but it is the **single most
//! important** safety invariant in the platform: a technique cannot escalate
//! itself by lying about which mode it requires; if its `max_mode` is too
//! high for the engagement, the gate denies the run regardless of any other
//! signal.

use tracing::warn;

use crate::error::BasError;
use crate::model::mode::AttackMode;
use crate::model::technique::AttackTechnique;

/// Stateless gate that enforces the technique-ceiling invariant.
#[derive(Debug, Default, Clone, Copy)]
pub struct ModeGate;

impl ModeGate {
    /// Construct the gate.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Evaluate the gate.
    ///
    /// Returns `Ok(())` when the technique's `max_mode` is at or below the
    /// engagement's `active_mode`; otherwise emits a structured warn-level
    /// trace and returns [`BasError::ModeViolation`].
    // `self` is a stateless gate token for fluent call sites.
    #[allow(clippy::unused_self)]
    pub fn evaluate(
        self,
        engagement_id: &str,
        active_mode: AttackMode,
        technique: &dyn AttackTechnique,
    ) -> Result<(), BasError> {
        let tmax = technique.max_mode();
        if tmax > active_mode {
            warn!(
                target = "sx_bas::gate",
                gate = "mode",
                engagement_id = engagement_id,
                technique_id = technique.id(),
                technique_max = %tmax,
                active_mode = %active_mode,
                reason = "technique max_mode exceeds active ceiling",
                "mode gate denied",
            );
            return Err(BasError::ModeViolation {
                technique_id: technique.id().to_owned(),
                technique_max: tmax,
                active: active_mode,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
// Tests use `panic!` to assert on unexpected enum variants.
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::ModeGate;
    use crate::error::BasError;
    use crate::model::mode::AttackMode;
    use crate::technique::theoretical_reachability::TheoreticalReachability;

    #[test]
    fn mode_gate_allows_technique_at_or_below_ceiling() {
        let gate = ModeGate::new();
        let t = TheoreticalReachability::new(Vec::new(), "entry".into(), None);
        // Theoretical technique under SafeInteractive ceiling is allowed.
        assert!(gate.evaluate("e1", AttackMode::SafeInteractive, &t).is_ok());
        // Equal ceiling is allowed.
        assert!(gate.evaluate("e1", AttackMode::Theoretical, &t).is_ok());
    }

    #[test]
    fn mode_gate_denies_technique_above_ceiling() {
        let gate = ModeGate::new();
        // SafeSsrfProbe declares max_mode = SafeInteractive.
        let t = crate::technique::safe_ssrf_probe::SafeSsrfProbe::new(
            "https://target.example".into(),
            "https://oob.example".into(),
        );
        let err = gate
            .evaluate("e1", AttackMode::PassiveValidation, &t)
            .unwrap_err();
        match err {
            BasError::ModeViolation {
                technique_max,
                active,
                ..
            } => {
                assert_eq!(technique_max, AttackMode::SafeInteractive);
                assert_eq!(active, AttackMode::PassiveValidation);
            }
            other => panic!("expected ModeViolation, got {other:?}"),
        }
    }
}
