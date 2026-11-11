//! Error type for the `sx-soc` crate.
//!
//! All fallible operations in this crate return [`SocError`]. The enum is
//! intentionally minimal: configuration / input parsing failures (`Config`)
//! and runtime event-shape failures (`BadEvent`).

use thiserror::Error;

/// Errors produced by the SOC subsystem.
#[derive(Debug, Error)]
pub enum SocError {
    /// A configuration problem prevented the engine from being assembled.
    /// Examples: a [`crate::rule::Rule`] with an empty `id`, a rule pack
    /// referencing an unknown field, or a duration that overflowed.
    #[error("config error: {0}")]
    Config(String),

    /// An incoming event was structurally invalid — for example, not a JSON
    /// object, or a [`crate::rule::Condition::WithinLast`] was evaluated
    /// against an event whose `ts` field could not be parsed as RFC3339.
    #[error("bad event: {0}")]
    BadEvent(String),
}
