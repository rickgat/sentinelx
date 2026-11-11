//! SAML 2.0 Service Provider configuration (P0-004).
//!
//! Per-tenant `IdP` configuration (`entity_id`, `sso_url`, `slo_url`,
//! `x509_cert`, `signing_algo`) is persisted in the database and looked
//! up at runtime; this schema is the **global** SP-side configuration
//! that controls how the SP exposes itself to all tenants.
//!
//! Disabled by default — when an operator flips `enabled: true`, the
//! three `/v1/auth/saml/{metadata,acs,logout}` endpoints become active.
//! When disabled, the endpoints respond with a deterministic 422 so the
//! deployment is observable without external dependencies.
//!
//! The SP entity id is global (one SAML metadata document per SP);
//! per-tenant `IdP` records carry their own entity id which is matched
//! against the `<Issuer>` on incoming responses to select the correct
//! signing certificate.

use std::time::Duration;

use serde::Deserialize;
use serde_with::{serde_as, DurationSeconds};
use tracing::warn;
use validator::Validate;

/// Default ACS path appended to `entity_id` when no override is given.
fn default_acs_path() -> String {
    "/v1/auth/saml/acs".to_string()
}

/// Default SLO path appended to `entity_id`.
fn default_slo_path() -> String {
    "/v1/auth/saml/logout".to_string()
}

/// Default skew tolerance — 30 seconds (per the P0-004 spec).
const fn default_clock_skew_secs() -> u64 {
    30
}

/// Default replay-cache TTL — 5 minutes (per the P0-004 spec).
const fn default_replay_ttl_secs() -> u64 {
    300
}

/// SAML 2.0 Service Provider configuration.
///
/// Disabled by default. When `enabled = true`:
///
/// * `entity_id` MUST be a non-empty absolute URL.
/// * `clock_skew_secs` MUST be `<= 600` (10 minutes — the SAML deployment
///   profile maximum).
/// * `replay_ttl_secs` MUST be `>= 60` (otherwise the dedup window is too
///   short to defeat a slow replay).
#[serde_as]
#[derive(Debug, Clone, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
pub struct SamlConfig {
    /// Whether the SAML SP endpoints (`/v1/auth/saml/*`) are wired up.
    pub enabled: bool,

    /// Stable SP entity identifier. Also published in the SP metadata
    /// document and matched against `Audience` on every incoming
    /// assertion.
    #[serde(default)]
    pub entity_id: String,

    /// ACS path under the SP root. Defaults to `/v1/auth/saml/acs` and is
    /// generally not overridden — it must match the SP metadata document
    /// the `IdP` holds.
    #[serde(default = "default_acs_path")]
    pub acs_path: String,

    /// SLO path under the SP root. Defaults to `/v1/auth/saml/logout`.
    #[serde(default = "default_slo_path")]
    pub slo_path: String,

    /// Clock skew tolerance applied to assertion `NotBefore` /
    /// `NotOnOrAfter`. Defaults to 30 seconds.
    #[serde_as(as = "DurationSeconds<u64>")]
    #[serde(default = "default_clock_skew_duration")]
    pub clock_skew: Duration,

    /// Replay-cache TTL — how long an assertion id is remembered to
    /// reject duplicate responses. Defaults to 5 minutes (the spec).
    #[serde_as(as = "DurationSeconds<u64>")]
    #[serde(default = "default_replay_ttl_duration")]
    pub replay_ttl: Duration,

    /// TOP5-#1-PHASE-2A: `XMLDSig` verifier policy declaration.
    ///
    /// Selects which backing `XMLDSig` verifier implementation the SP
    /// will use for incoming SAML responses. See [`XmlDsigConfig`] for
    /// the per-mode semantics. PHASE-2A's note: this field is **read
    /// but not yet consumed** in production — the SAML SP path in
    /// `sx-iam`'s `verify_assertion` still calls the hand-rolled
    /// verifier directly. The factory in `sx-iam` reads this value
    /// to construct a [`sx_xmlsec::XmlDsigVerifier`] of the requested
    /// shape; PHASE-2B's cutover will replace the direct call with the
    /// factory output.
    #[serde(default)]
    #[validate(nested)]
    pub xmldsig: XmlDsigConfig,
}

/// TOP5-#1-PHASE-2A: `XMLDSig` verifier policy sub-block.
///
/// Lives under `saml.xmldsig` in the operator YAML. Defaults match
/// today's production behaviour: hand-rolled verifier only.
///
/// ## Operator-visible knobs
///
/// ```yaml
/// saml:
///   xmldsig:
///     verifier: "handrolled"   # one of: handrolled | shadow | xmlsec1
/// ```
///
/// ## Compile-time requirement (not enforced at runtime)
///
/// The `shadow` and `xmlsec1` modes both require `sx-xmlsec` to have
/// been built with the `xmlsec1` Cargo feature, which in turn requires
/// the operator's host to have `libxmlsec1-dev` / `libxml2-dev`
/// system packages installed (or the `vendored-libxmlsec1` Cargo
/// feature on a release-image build). The schema cannot verify this
/// at runtime — instead, `check_invariants` emits a `tracing::warn!`
/// when a non-`HandRolled` value is set, reminding the operator that
/// PHASE-2A does not yet consume the field in production. PHASE-2B's
/// cutover will both consume the field AND tighten this to a hard
/// error when the feature flag is off.
#[derive(Debug, Clone, Default, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
pub struct XmlDsigConfig {
    /// Which verifier implementation to wire up. See
    /// [`XmlDsigVerifierKind`] for the per-mode semantics. Default is
    /// [`XmlDsigVerifierKind::HandRolled`] so unmodified
    /// configurations preserve today's production behaviour.
    #[serde(default)]
    pub verifier: XmlDsigVerifierKind,
}

/// TOP5-#1-PHASE-2A: `XMLDSig` verifier mode selector.
///
/// Serialised as the wire-stable lowercase tokens `handrolled` /
/// `shadow` / `xmlsec1` (NOT auto-derived from the variant name).
/// The dispatch task contract spells out these exact strings so the
/// kebab-case rename is applied per-variant rather than via the
/// `rename_all` shortcut, which would produce `hand-rolled` /
/// `xml-sec1`. The default is [`Self::HandRolled`] — see the
/// type-level docs on [`XmlDsigConfig`] for the rollout plan
/// behind each value.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Default)]
pub enum XmlDsigVerifierKind {
    /// Hand-rolled `verify_xmldsig` in `sx-iam`. Today's production
    /// path; the entire HIGH-003 fuzz corpus + 21-test XSW suite is
    /// scoped to this implementation.
    #[default]
    #[serde(rename = "handrolled")]
    HandRolled,
    /// Shadow mode: run hand-rolled (authoritative) + libxmlsec1
    /// (observation) in parallel. Disagreements are surfaced via the
    /// `xmldsig_shadow_mismatch_total` Prometheus counter and the
    /// `xmldsig.shadow.mismatch.*` tracing events. Requires the
    /// `xmlsec1` Cargo feature in `sx-xmlsec`.
    #[serde(rename = "shadow")]
    Shadow,
    /// libxmlsec1-backed verifier only (no shadow comparison). This
    /// is the post-cutover steady-state — gated behind PHASE-2B's
    /// 14-day zero-disagreement SLO. Requires the `xmlsec1` Cargo
    /// feature in `sx-xmlsec`.
    #[serde(rename = "xmlsec1")]
    XmlSec1,
}

impl XmlDsigConfig {
    /// Stable lowercase label for log lines + telemetry. Matches the
    /// serde-renamed wire format.
    #[must_use]
    pub const fn verifier_label(&self) -> &'static str {
        match self.verifier {
            XmlDsigVerifierKind::HandRolled => "handrolled",
            XmlDsigVerifierKind::Shadow => "shadow",
            XmlDsigVerifierKind::XmlSec1 => "xmlsec1",
        }
    }

    /// Cross-field invariants for the `XMLDSig` sub-block.
    ///
    /// PHASE-2A's invariant set is intentionally narrow: we cannot
    /// detect the `xmlsec1` Cargo feature at runtime (it lives in
    /// `sx-xmlsec`'s `[features]` table, not in the binary's
    /// runtime-reachable state). Instead we emit a `tracing::warn!`
    /// whenever the operator selects a non-`HandRolled` value,
    /// reminding them that the field is policy-declaration only
    /// until PHASE-2B's cutover. PHASE-2B will harden this into a
    /// `ConfigError` when the feature flag is off — at which point
    /// the `Result` return type stops being theoretical.
    //
    // `unnecessary_wraps` is silenced because the `Result<(),
    // ConfigError>` signature is the stable contract every sibling
    // `*::check_invariants()` shares (see `SamlConfig`, `IamConfig`,
    // etc.), AND because PHASE-2B will start returning `Err` from
    // this exact function when the feature flag check goes live.
    // Changing the signature now would create churn at the cutover
    // commit.
    #[allow(clippy::unnecessary_wraps)]
    pub(crate) fn check_invariants(&self) -> Result<(), crate::ConfigError> {
        if self.verifier != XmlDsigVerifierKind::HandRolled {
            warn!(
                event = "saml.xmldsig.verifier.policy_declared",
                verifier = self.verifier_label(),
                "saml.xmldsig.verifier is set to a non-default value but PHASE-2A does not yet consume it — the production SAML SP path still uses the hand-rolled verifier; PHASE-2B will honour this knob",
            );
        }
        Ok(())
    }
}

const fn default_clock_skew_duration() -> Duration {
    Duration::from_secs(default_clock_skew_secs())
}

const fn default_replay_ttl_duration() -> Duration {
    Duration::from_secs(default_replay_ttl_secs())
}

impl Default for SamlConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            entity_id: String::new(),
            acs_path: default_acs_path(),
            slo_path: default_slo_path(),
            clock_skew: default_clock_skew_duration(),
            replay_ttl: default_replay_ttl_duration(),
            xmldsig: XmlDsigConfig::default(),
        }
    }
}

impl SamlConfig {
    /// Cross-field invariants — only enforced when `enabled`.
    pub(crate) fn check_invariants(&self) -> Result<(), crate::ConfigError> {
        if !self.enabled {
            return Ok(());
        }
        if self.entity_id.trim().is_empty() {
            return Err(crate::ConfigError::missing("saml.entity_id"));
        }
        if !(self.entity_id.starts_with("https://") || self.entity_id.starts_with("http://")) {
            return Err(crate::ConfigError::invalid(
                "saml.entity_id",
                "must be an absolute http(s):// URL",
            ));
        }
        if self.clock_skew.as_secs() > 600 {
            return Err(crate::ConfigError::invalid(
                "saml.clock_skew",
                "must be <= 600 seconds (10 minutes)",
            ));
        }
        if self.replay_ttl.as_secs() < 60 {
            return Err(crate::ConfigError::invalid(
                "saml.replay_ttl",
                "must be >= 60 seconds",
            ));
        }
        if !self.acs_path.starts_with('/') {
            return Err(crate::ConfigError::invalid(
                "saml.acs_path",
                "must start with '/'",
            ));
        }
        if !self.slo_path.starts_with('/') {
            return Err(crate::ConfigError::invalid(
                "saml.slo_path",
                "must start with '/'",
            ));
        }
        // TOP5-#1-PHASE-2A: delegate to the XMLDSig sub-block's own
        // invariant check. Currently warning-only (the field is
        // policy-declaration until PHASE-2B); kept as a delegated
        // call so the hardening seam stays in one place.
        self.xmldsig.check_invariants()?;
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn enabled() -> SamlConfig {
        SamlConfig {
            enabled: true,
            entity_id: "https://sp.example.com/saml".into(),
            ..SamlConfig::default()
        }
    }

    #[test]
    fn disabled_default_passes() {
        SamlConfig::default()
            .check_invariants()
            .expect("disabled must pass");
    }

    #[test]
    fn enabled_requires_entity_id() {
        let mut c = enabled();
        c.entity_id = String::new();
        let err = c.check_invariants().expect_err("missing entity_id");
        assert!(
            matches!(err, crate::ConfigError::MissingValue { ref key } if key == "saml.entity_id"),
            "got {err:?}"
        );
    }

    #[test]
    fn enabled_requires_absolute_url() {
        let mut c = enabled();
        c.entity_id = "not-a-url".into();
        let err = c.check_invariants().expect_err("not a url");
        assert!(
            matches!(err, crate::ConfigError::InvalidValue { ref key, .. } if key == "saml.entity_id"),
            "got {err:?}"
        );
    }

    #[test]
    fn rejects_excessive_clock_skew() {
        let mut c = enabled();
        c.clock_skew = Duration::from_secs(601);
        let err = c.check_invariants().expect_err("skew too large");
        assert!(
            matches!(err, crate::ConfigError::InvalidValue { ref key, .. } if key == "saml.clock_skew"),
            "got {err:?}"
        );
    }

    #[test]
    fn rejects_short_replay_ttl() {
        let mut c = enabled();
        c.replay_ttl = Duration::from_secs(30);
        let err = c.check_invariants().expect_err("ttl too short");
        assert!(
            matches!(err, crate::ConfigError::InvalidValue { ref key, .. } if key == "saml.replay_ttl"),
            "got {err:?}"
        );
    }

    #[test]
    fn rejects_acs_path_without_leading_slash() {
        let mut c = enabled();
        c.acs_path = "v1/auth/saml/acs".into();
        let err = c.check_invariants().expect_err("path missing /");
        assert!(
            matches!(err, crate::ConfigError::InvalidValue { ref key, .. } if key == "saml.acs_path"),
            "got {err:?}"
        );
    }

    #[test]
    fn default_clock_skew_is_30s_per_spec() {
        assert_eq!(SamlConfig::default().clock_skew, Duration::from_secs(30));
    }

    #[test]
    fn default_replay_ttl_is_5_min_per_spec() {
        assert_eq!(SamlConfig::default().replay_ttl, Duration::from_secs(300));
    }

    // ----- TOP5-#1-PHASE-2A: XMLDSig sub-block tests -----

    #[test]
    fn xmldsig_default_is_handrolled() {
        let c = XmlDsigConfig::default();
        assert_eq!(c.verifier, XmlDsigVerifierKind::HandRolled);
        assert_eq!(c.verifier_label(), "handrolled");
    }

    #[test]
    fn xmldsig_deserialises_kebab_case_handrolled() {
        let c: XmlDsigConfig = serde_json::from_str(r#"{"verifier":"handrolled"}"#).unwrap();
        assert_eq!(c.verifier, XmlDsigVerifierKind::HandRolled);
    }

    #[test]
    fn xmldsig_deserialises_kebab_case_shadow() {
        let c: XmlDsigConfig = serde_json::from_str(r#"{"verifier":"shadow"}"#).unwrap();
        assert_eq!(c.verifier, XmlDsigVerifierKind::Shadow);
        assert_eq!(c.verifier_label(), "shadow");
    }

    #[test]
    fn xmldsig_deserialises_kebab_case_xmlsec1() {
        let c: XmlDsigConfig = serde_json::from_str(r#"{"verifier":"xmlsec1"}"#).unwrap();
        assert_eq!(c.verifier, XmlDsigVerifierKind::XmlSec1);
        assert_eq!(c.verifier_label(), "xmlsec1");
    }

    #[test]
    fn xmldsig_rejects_unknown_verifier_value() {
        let result: Result<XmlDsigConfig, _> = serde_json::from_str(r#"{"verifier":"gpg"}"#);
        assert!(result.is_err(), "unknown verifier value must error");
    }

    #[test]
    fn xmldsig_invariants_ok_for_handrolled() {
        let c = XmlDsigConfig::default();
        c.check_invariants().expect("handrolled default ok");
    }

    #[test]
    fn xmldsig_invariants_warn_only_for_shadow() {
        // Shadow / XmlSec1 are POLICY-DECLARATION only in PHASE-2A.
        // The invariant check emits a tracing warning but MUST NOT
        // return Err — PHASE-2B will tighten this.
        let c = XmlDsigConfig {
            verifier: XmlDsigVerifierKind::Shadow,
        };
        c.check_invariants()
            .expect("shadow is warn-only in PHASE-2A");

        let c = XmlDsigConfig {
            verifier: XmlDsigVerifierKind::XmlSec1,
        };
        c.check_invariants()
            .expect("xmlsec1 is warn-only in PHASE-2A");
    }

    #[test]
    fn saml_config_default_carries_handrolled_xmldsig() {
        let c = SamlConfig::default();
        assert_eq!(c.xmldsig.verifier, XmlDsigVerifierKind::HandRolled);
    }
}
