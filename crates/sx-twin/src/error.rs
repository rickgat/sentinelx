//! Error type returned across the `sx-twin` public surface.
//!
//! Every variant is safe to log via `Display`: no secrets, no PII, no
//! payload material is ever embedded in the message.

use thiserror::Error;

use crate::state::AssetId;

/// Public error surface of the `sx-twin` crate.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum TwinError {
    /// A cycle was detected at a point in the traversal where cycle-freedom
    /// was required as a precondition (currently reserved for future use by
    /// non-tick consumers; the tick algorithm itself is cycle-safe by
    /// construction).
    #[error("cycle detected in twin graph")]
    CycleDetected,

    /// An edge or operation referenced an asset id that has not been
    /// registered in the twin.
    #[error("unknown asset: {0}")]
    UnknownAsset(AssetId),

    /// A structural invariant of the twin was violated (for example, an
    /// attempt to register the same asset id twice).
    #[error("twin invariant violated: {0}")]
    Invariant(String),
}

impl TwinError {
    /// Convenience constructor for [`TwinError::Invariant`].
    #[must_use]
    pub fn invariant(msg: impl Into<String>) -> Self {
        Self::Invariant(msg.into())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::TwinError;
    use crate::state::AssetId;

    #[test]
    fn display_cycle() {
        assert_eq!(
            TwinError::CycleDetected.to_string(),
            "cycle detected in twin graph",
        );
    }

    #[test]
    fn display_unknown_asset_includes_id() {
        let id = AssetId::new();
        let msg = TwinError::UnknownAsset(id).to_string();
        assert!(msg.starts_with("unknown asset: "));
        assert!(msg.contains(&id.to_string()));
    }

    #[test]
    fn display_invariant() {
        let err = TwinError::invariant("duplicate asset");
        assert_eq!(err.to_string(), "twin invariant violated: duplicate asset");
    }
}
