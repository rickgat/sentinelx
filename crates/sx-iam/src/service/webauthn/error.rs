//! Error type for the `WebAuthn` (FIDO2 / passkey) MFA service.
//!
//! Variants are intentionally coarse: at the HTTP boundary we never want
//! to disclose whether the failure was "challenge expired" vs "signature
//! mismatch" vs "counter regressed" — both leak about the underlying
//! authenticator and the verifier state. Operators get the precise
//! cause via `tracing` (the service layer logs the wrapped
//! `webauthn_rs::prelude::WebauthnError` with `Debug`), but external
//! callers only see a generic [`WebauthnError::Registration`] /
//! [`WebauthnError::Authentication`] / [`WebauthnError::CounterRegression`]
//! decision.
//!
//! All variants are safe to render via `Display` — no public-key bodies,
//! no raw credential IDs, no challenge values end up in the message.

use thiserror::Error;

/// Public error surface of [`crate::service::webauthn`].
#[derive(Debug, Error)]
pub enum WebauthnError {
    /// The [`webauthn_rs::WebauthnBuilder`] rejected the supplied
    /// `rp_id` / `rp_origin` pair — typically a misconfiguration
    /// (origin domain does not end with `rp_id`).
    #[error("invalid relying-party configuration")]
    Configuration,

    /// `start_registration` failed inside `webauthn-rs` (challenge
    /// generation, extension negotiation, etc.). The underlying cause
    /// is logged but never surfaced to the caller.
    #[error("registration challenge could not be generated")]
    Registration,

    /// `finish_registration` rejected the authenticator's attestation
    /// or client-data validation. Catch-all for any registration
    /// verification failure.
    #[error("registration verification failed")]
    RegistrationVerification,

    /// `start_authentication` failed (e.g. no credentials supplied for
    /// the user) inside `webauthn-rs`.
    #[error("authentication challenge could not be generated")]
    Authentication,

    /// `finish_authentication` rejected the assertion (signature,
    /// `clientDataJSON`, allowed credential, RP-ID hash, etc.).
    #[error("authentication verification failed")]
    AuthenticationVerification,

    /// The authenticator returned a signature counter that did not
    /// strictly increase over the stored counter — a strong signal of
    /// a cloned credential per [W3C WebAuthn §7.2 step 21][0]. The
    /// service treats this as a hard reject and the caller MUST
    /// invalidate the stored credential rather than reuse it.
    ///
    /// `stored` is the counter the verifier last persisted; `presented`
    /// is the value the authenticator just returned. Both are surfaced
    /// here for operator triage (audit log only — never returned over
    /// the HTTP boundary).
    ///
    /// [0]: https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion
    #[error("counter regression detected: stored={stored} presented={presented}")]
    CounterRegression {
        /// Last counter the verifier persisted for this credential.
        stored: u32,
        /// Counter the authenticator reported on this assertion.
        presented: u32,
    },

    /// Caller supplied an empty credential set to `start_authentication`.
    /// Passkey authentication requires at least one allow-listed
    /// credential or it cannot construct a challenge.
    #[error("no credentials registered for user")]
    NoCredentials,

    /// The authenticator's AAGUID is explicitly blocked, or the tenant
    /// operates in allowlist-only mode and the AAGUID is not on the
    /// allowlist (HIGH-002). Returned by the per-tenant policy
    /// enforcement layer in `controller::webauthn::register_finish`.
    ///
    /// `reason` carries the operator-supplied justification text from
    /// the matching policy row (or a synthesised string for the implicit
    /// allowlist-only default-deny case). Safe to surface to operators
    /// over audit-log channels; never echoed to unauthenticated callers.
    #[error("authenticator aaguid is not permitted: {reason}")]
    AaguidBlocked {
        /// Operator-supplied reason or synthesised explanation.
        reason: String,
    },

    /// The local cache of FIDO Alliance MDS3 metadata is older than the
    /// configured tolerance (default: seven days). In strict mode this
    /// prevents accepting any unverified authenticator; in lenient mode
    /// the controller surfaces a warning but proceeds.
    #[error("FIDO MDS3 metadata cache is stale")]
    MdsCacheStale,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::WebauthnError;

    #[test]
    fn display_does_not_leak_internals() {
        // Coarse-grained errors must NOT echo the underlying webauthn-rs
        // failure path — operators get that via tracing, callers see only
        // a generic decision.
        let cases = [
            WebauthnError::Configuration,
            WebauthnError::Registration,
            WebauthnError::RegistrationVerification,
            WebauthnError::Authentication,
            WebauthnError::AuthenticationVerification,
            WebauthnError::NoCredentials,
            WebauthnError::MdsCacheStale,
        ];
        for e in cases {
            let s = e.to_string();
            assert!(
                !s.contains("WebauthnError::"),
                "Display leaks variant path: {s}"
            );
            assert!(!s.contains("rp_id"), "Display leaks rp_id: {s}");
            // The word "challenge" appears in legitimate descriptive copy
            // ("registration challenge could not be generated"). What we
            // forbid is raw bytes — challenge values would surface as long
            // hex/base64 runs, not the English noun.
            let suspicious = s
                .split_whitespace()
                .any(|tok| tok.len() >= 16 && tok.chars().all(|c| c.is_ascii_hexdigit()));
            assert!(!suspicious, "Display leaks hex-looking value: {s}");
        }
    }

    #[test]
    fn counter_regression_reports_both_values() {
        let e = WebauthnError::CounterRegression {
            stored: 42,
            presented: 7,
        };
        let s = e.to_string();
        assert!(s.contains("stored=42"));
        assert!(s.contains("presented=7"));
    }
}
