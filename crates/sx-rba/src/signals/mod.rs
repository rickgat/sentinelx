//! Login-time signal collectors.
//!
//! Each submodule produces ONE input to the scorer:
//!
//! * [`ip_geo`] resolves an IP address to an ISO-3166 alpha-2 country
//!   code via a tiny baked-in CSV.
//! * [`velocity`] counts login attempts per (`tenant`, identity-key) in
//!   a sliding window.
//! * [`business_hours`] checks whether a timestamp falls inside the
//!   tenant's configured working hours.
//! * [`device_fp`] resolves a device fingerprint (HIGH-001).
//! * [`mfa_recent`] surfaces the recency of the last MFA completion
//!   (HIGH-001).
//! * [`success_rate`] computes a 7-day rolling login success rate
//!   per user (HIGH-001).
//! * [`impossible_travel`] checks whether the implied travel speed
//!   between two consecutive logins exceeds a physically-plausible
//!   ceiling (HIGH-001).
//!
//! The signal types are deliberately small so they can be cheaply
//! serialised into the audit row as `signals: JSONB`.
//!
//! ## The [`RiskSignal`] trait
//!
//! Every signal exposed by the rule-based scorer can be invoked
//! polymorphically via the [`RiskSignal`] trait. Production code rarely
//! goes through the trait — the [`crate::scorer::rule_based::RuleBasedScorer`]
//! pulls signal sub-scores directly from the [`crate::service::SignalSnapshot`]
//! for speed and clarity — but the trait surface lets the per-tenant
//! [`crate::config::RbaFeatureFlags`] mask individual signals on/off at
//! runtime, lets tests drive each signal in isolation, and lets future
//! scorers (e.g. the GBDT skeleton in [`crate::scorer::gbdt`]) iterate
//! over a dynamic signal set without hard-coding the field projection.

pub mod business_hours;
pub mod device_fp;
pub mod device_fp_pg;
pub mod impossible_travel;
pub mod ip_geo;
pub mod ip_geo_centroid;
pub mod mfa_recent;
pub mod success_rate;
pub mod travel_pg;
pub mod velocity;

use serde::{Deserialize, Serialize};

use crate::config::RbaFeatureFlags;
use crate::service::SignalSnapshot;

/// Stable identifier for each signal. Used both as the JSON key in the
/// audit `signals` column and as the toggle key in
/// [`crate::config::RbaFeatureFlags`].
///
/// The `serde` representation uses `snake_case` strings — matching
/// [`SignalKind::as_str`] — so the JSONB rows persisted by LOW-007
/// (`rba_decisions.signal_contributions`) stay human-readable and
/// diffable between schema versions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalKind {
    /// IPv4 → country lookup.
    IpGeo,
    /// Sliding-window attempt counter.
    Velocity,
    /// Business-hours window.
    BusinessHours,
    /// Device fingerprint ledger (HIGH-001).
    #[serde(rename = "device_fp")]
    DeviceFingerprint,
    /// MFA recency (HIGH-001).
    MfaRecent,
    /// 7-day rolling success rate (HIGH-001).
    SuccessRate,
    /// Impossible-travel detector (HIGH-001).
    ImpossibleTravel,
}

impl SignalKind {
    /// Stable string form for logging / metrics.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::IpGeo => "ip_geo",
            Self::Velocity => "velocity",
            Self::BusinessHours => "business_hours",
            Self::DeviceFingerprint => "device_fp",
            Self::MfaRecent => "mfa_recent",
            Self::SuccessRate => "success_rate",
            Self::ImpossibleTravel => "impossible_travel",
        }
    }

    /// Is this signal enabled by `flags`?
    #[must_use]
    pub const fn enabled_in(self, flags: RbaFeatureFlags) -> bool {
        match self {
            Self::IpGeo => flags.enable_ip_geo,
            Self::Velocity => flags.enable_velocity,
            Self::BusinessHours => flags.enable_business_hours,
            Self::DeviceFingerprint => flags.enable_device_fp,
            Self::MfaRecent => flags.enable_mfa_recent,
            Self::SuccessRate => flags.enable_success_rate,
            Self::ImpossibleTravel => flags.enable_impossible_travel,
        }
    }
}

/// Pluggable signal abstraction.
///
/// A [`RiskSignal`] reads its inputs from a [`SignalSnapshot`] and
/// returns a `[0, 100]` sub-score. The actual signal collectors
/// (geo / fingerprint ledger / MFA tracker / ...) live on
/// [`crate::service::RbaService`]; this trait only describes the
/// score-extraction step so a scorer can iterate over an enabled set.
pub trait RiskSignal: Send + Sync + std::fmt::Debug {
    /// Which signal this is — used by the scorer to look up the per-signal
    /// weight and the feature-flag toggle.
    fn kind(&self) -> SignalKind;
    /// Compute the sub-score in `[0, 100]` from a fully populated
    /// snapshot. Implementors must clamp out-of-range values.
    fn sub_score(&self, snapshot: &SignalSnapshot) -> i32;
}

/// IP-geo signal. Stateless wrapper that delegates to
/// [`crate::scorer::rule_based::RuleBasedScorer::ip_score`].
#[derive(Debug, Default, Clone, Copy)]
pub struct IpGeoSignal;

impl RiskSignal for IpGeoSignal {
    fn kind(&self) -> SignalKind {
        SignalKind::IpGeo
    }
    fn sub_score(&self, snapshot: &SignalSnapshot) -> i32 {
        crate::scorer::rule_based::RuleBasedScorer::ip_score(snapshot)
    }
}

/// Velocity signal wrapper.
#[derive(Debug, Default, Clone, Copy)]
pub struct VelocitySignal;

impl RiskSignal for VelocitySignal {
    fn kind(&self) -> SignalKind {
        SignalKind::Velocity
    }
    fn sub_score(&self, snapshot: &SignalSnapshot) -> i32 {
        crate::scorer::rule_based::RuleBasedScorer::velocity_score(snapshot)
    }
}

/// Business-hours signal wrapper.
#[derive(Debug, Default, Clone, Copy)]
pub struct BusinessHoursSignal;

impl RiskSignal for BusinessHoursSignal {
    fn kind(&self) -> SignalKind {
        SignalKind::BusinessHours
    }
    fn sub_score(&self, snapshot: &SignalSnapshot) -> i32 {
        crate::scorer::rule_based::RuleBasedScorer::hours_score(snapshot)
    }
}

/// Device-fingerprint signal wrapper.
#[derive(Debug, Default, Clone, Copy)]
pub struct DeviceFingerprintSignalAdapter;

impl RiskSignal for DeviceFingerprintSignalAdapter {
    fn kind(&self) -> SignalKind {
        SignalKind::DeviceFingerprint
    }
    fn sub_score(&self, snapshot: &SignalSnapshot) -> i32 {
        crate::scorer::rule_based::RuleBasedScorer::device_fp_score(snapshot)
    }
}

/// MFA-recency signal wrapper.
#[derive(Debug, Default, Clone, Copy)]
pub struct MfaRecentSignalAdapter;

impl RiskSignal for MfaRecentSignalAdapter {
    fn kind(&self) -> SignalKind {
        SignalKind::MfaRecent
    }
    fn sub_score(&self, snapshot: &SignalSnapshot) -> i32 {
        crate::scorer::rule_based::RuleBasedScorer::mfa_recent_score(snapshot)
    }
}

/// Success-rate signal wrapper.
#[derive(Debug, Default, Clone, Copy)]
pub struct SuccessRateSignalAdapter;

impl RiskSignal for SuccessRateSignalAdapter {
    fn kind(&self) -> SignalKind {
        SignalKind::SuccessRate
    }
    fn sub_score(&self, snapshot: &SignalSnapshot) -> i32 {
        crate::scorer::rule_based::RuleBasedScorer::success_rate_score(snapshot)
    }
}

/// Impossible-travel signal wrapper.
#[derive(Debug, Default, Clone, Copy)]
pub struct ImpossibleTravelSignalAdapter;

impl RiskSignal for ImpossibleTravelSignalAdapter {
    fn kind(&self) -> SignalKind {
        SignalKind::ImpossibleTravel
    }
    fn sub_score(&self, snapshot: &SignalSnapshot) -> i32 {
        crate::scorer::rule_based::RuleBasedScorer::impossible_travel_score(snapshot)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod trait_tests {
    use super::*;

    #[test]
    fn kind_strings_are_stable() {
        assert_eq!(SignalKind::IpGeo.as_str(), "ip_geo");
        assert_eq!(SignalKind::Velocity.as_str(), "velocity");
        assert_eq!(SignalKind::BusinessHours.as_str(), "business_hours");
        assert_eq!(SignalKind::DeviceFingerprint.as_str(), "device_fp");
        assert_eq!(SignalKind::MfaRecent.as_str(), "mfa_recent");
        assert_eq!(SignalKind::SuccessRate.as_str(), "success_rate");
        assert_eq!(SignalKind::ImpossibleTravel.as_str(), "impossible_travel");
    }

    #[test]
    fn default_feature_flags_enable_all_signals() {
        let f = RbaFeatureFlags::default();
        for k in [
            SignalKind::IpGeo,
            SignalKind::Velocity,
            SignalKind::BusinessHours,
            SignalKind::DeviceFingerprint,
            SignalKind::MfaRecent,
            SignalKind::SuccessRate,
            SignalKind::ImpossibleTravel,
        ] {
            assert!(k.enabled_in(f), "default flag must enable {}", k.as_str());
        }
    }

    #[test]
    fn signal_kind_round_trip_via_adapter() {
        let s: Box<dyn RiskSignal> = Box::new(IpGeoSignal);
        assert_eq!(s.kind(), SignalKind::IpGeo);
        let s: Box<dyn RiskSignal> = Box::new(ImpossibleTravelSignalAdapter);
        assert_eq!(s.kind(), SignalKind::ImpossibleTravel);
    }
}
