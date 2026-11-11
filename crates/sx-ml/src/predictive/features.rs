//! Feature extraction for the predictive risk classifier.
//!
//! The classifier consumes a fixed-length `[f64; FEATURE_VECTOR_LEN]`
//! vector. This module owns:
//!
//! - The wire-style view shapes that callers project into ([`FindingViewLike`]
//!   and [`AssetViewLike`]) — they mirror the relevant fields of the
//!   `FindingView` and `AssetView` types that live in `sx-api`, but stay
//!   crate-local so `sx-ml` never depends on the API layer.
//! - The canonical enum shapes ([`SeverityEnum`], [`AssetKindEnum`]) used
//!   for one-hot encoding.
//! - [`FindingFeatures`], the structured intermediate, and its
//!   [`FindingFeatures::to_vector`] flattening.

use serde::{Deserialize, Serialize};

/// Number of slots in a flattened feature vector.
///
/// Layout (indices):
///
/// | Slot | Name                          |
/// |------|-------------------------------|
/// | 0    | `cvss`                        |
/// | 1    | `epss`                        |
/// | 2    | `kev_flag`                    |
/// | 3    | `days_since_first_seen`       |
/// | 4    | severity = `info`             |
/// | 5    | severity = `low`              |
/// | 6    | severity = `medium`           |
/// | 7    | severity = `high`             |
/// | 8    | severity = `critical`         |
/// | 9    | asset_kind = `host`           |
/// | 10   | asset_kind = `container`      |
/// | 11   | asset_kind = `identity`       |
/// | 12   | asset_kind = `repo`           |
/// | 13   | asset_kind = `bucket`         |
/// | 14   | asset_kind = `service`        |
/// | 15   | `business_impact`             |
/// | 16   | `chain_amplifier`             |
pub const FEATURE_VECTOR_LEN: usize = 17;

/// Version of the feature-vector schema — the slot layout, ordering, and
/// encoding semantics described by [`FEATURE_SCHEMA`].
///
/// Bump this on ANY change to the slot count, order, or meaning so a model
/// artifact trained against an older layout is **rejected at load**
/// ([`super::model::PredictiveModel::from_json`]) instead of silently
/// scoring against mismatched columns. The `sx-rba` auth-risk schema
/// (`sx_rba::scorer::gbdt`, 7 slots) is versioned independently — the two
/// score different domains and evolve separately.
pub const FEATURE_SCHEMA_VERSION: u32 = 1;

/// Encoding class of a feature slot, surfaced by [`FEATURE_SCHEMA`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeatureKind {
    /// A continuous numeric value.
    Numeric,
    /// One element of a one-hot group.
    OneHot,
    /// A 0.0 / 1.0 boolean flag.
    Flag,
}

/// Ordered `(name, kind)` descriptor of the feature vector.
///
/// The array type pins its length to [`FEATURE_VECTOR_LEN`] at compile
/// time, so arity can never drift silently; a unit test additionally
/// asserts the names line up with the one-hot offsets produced by
/// [`FindingFeatures::to_vector`]. Trainers and model-card tooling read
/// this to label columns without hard-coding the layout.
pub const FEATURE_SCHEMA: [(&str, FeatureKind); FEATURE_VECTOR_LEN] = [
    ("cvss", FeatureKind::Numeric),
    ("epss", FeatureKind::Numeric),
    ("kev_flag", FeatureKind::Flag),
    ("days_since_first_seen", FeatureKind::Numeric),
    ("severity_info", FeatureKind::OneHot),
    ("severity_low", FeatureKind::OneHot),
    ("severity_medium", FeatureKind::OneHot),
    ("severity_high", FeatureKind::OneHot),
    ("severity_critical", FeatureKind::OneHot),
    ("asset_kind_host", FeatureKind::OneHot),
    ("asset_kind_container", FeatureKind::OneHot),
    ("asset_kind_identity", FeatureKind::OneHot),
    ("asset_kind_repo", FeatureKind::OneHot),
    ("asset_kind_bucket", FeatureKind::OneHot),
    ("asset_kind_service", FeatureKind::OneHot),
    ("business_impact", FeatureKind::Numeric),
    ("chain_amplifier", FeatureKind::Numeric),
];

/// Severity bucket for one-hot encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SeverityEnum {
    /// Informational only.
    Info,
    /// Low impact.
    Low,
    /// Medium impact.
    Medium,
    /// High impact.
    High,
    /// Critical impact.
    Critical,
}

impl SeverityEnum {
    /// Map a lowercase severity tag (`"info"`, `"low"`, …) to a variant.
    ///
    /// Unknown / empty strings fall back to [`SeverityEnum::Info`] — the
    /// classifier treats the no-information case as "lowest band".
    #[must_use]
    pub fn from_tag(tag: &str) -> Self {
        match tag.trim().to_ascii_lowercase().as_str() {
            "critical" => Self::Critical,
            "high" => Self::High,
            "medium" | "med" => Self::Medium,
            "low" => Self::Low,
            _ => Self::Info,
        }
    }

    /// Stable index used for one-hot encoding (0 = `Info`, 4 = `Critical`).
    #[must_use]
    pub const fn one_hot_index(self) -> usize {
        match self {
            Self::Info => 0,
            Self::Low => 1,
            Self::Medium => 2,
            Self::High => 3,
            Self::Critical => 4,
        }
    }

    /// Number of variants — used to size the one-hot slice.
    pub const CARDINALITY: usize = 5;
}

/// Asset-kind bucket for one-hot encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssetKindEnum {
    /// Bare-metal / VM host.
    Host,
    /// Container or pod.
    Container,
    /// IAM principal (human or workload).
    Identity,
    /// Source-code repository.
    Repo,
    /// Object-store bucket.
    Bucket,
    /// Logical service / endpoint.
    Service,
}

impl AssetKindEnum {
    /// Map a lowercase asset-kind tag to a variant. Unknown tags become
    /// [`AssetKindEnum::Service`] — the most generic catch-all.
    #[must_use]
    pub fn from_tag(tag: &str) -> Self {
        match tag.trim().to_ascii_lowercase().as_str() {
            "host" => Self::Host,
            "container" | "pod" => Self::Container,
            "identity" | "principal" | "iam" => Self::Identity,
            "repo" | "repository" => Self::Repo,
            "bucket" | "s3" | "gcs" => Self::Bucket,
            _ => Self::Service,
        }
    }

    /// Stable index used for one-hot encoding (0 = `Host`, 5 = `Service`).
    #[must_use]
    pub const fn one_hot_index(self) -> usize {
        match self {
            Self::Host => 0,
            Self::Container => 1,
            Self::Identity => 2,
            Self::Repo => 3,
            Self::Bucket => 4,
            Self::Service => 5,
        }
    }

    /// Number of variants — used to size the one-hot slice.
    pub const CARDINALITY: usize = 6;
}

/// Minimal projection of a `FindingView` needed for feature extraction.
///
/// `sx-ml` never depends on `sx-api`, so callers project the wire view
/// into this local shape before calling
/// [`FindingFeatures::from_views`]. Optional fields default to safe
/// neutrals (zero CVSS, zero EPSS, no KEV) when missing.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FindingViewLike {
    /// CVSS base score in `[0, 10]`. `None` is treated as zero.
    #[serde(default)]
    pub cvss: Option<f64>,
    /// EPSS exploitation probability in `[0, 1]`. `None` is treated as zero.
    #[serde(default)]
    pub epss: Option<f64>,
    /// Whether CISA KEV lists this finding's CVE.
    #[serde(default)]
    pub kev_flag: bool,
    /// Severity tag (`info`, `low`, `medium`, `high`, `critical`).
    pub severity: String,
    /// Days elapsed since the finding was first seen.
    #[serde(default)]
    pub days_since_first_seen: f64,
    /// Business-impact multiplier (typically `0.5..=5.0`).
    #[serde(default = "default_business_impact")]
    pub business_impact: f64,
    /// Attack-chain amplifier (typically `1.0..=3.0`).
    #[serde(default = "default_chain_amplifier")]
    pub chain_amplifier: f64,
}

const fn default_business_impact() -> f64 {
    1.0
}

const fn default_chain_amplifier() -> f64 {
    1.0
}

/// Minimal projection of an `AssetView` needed for feature extraction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetViewLike {
    /// Asset-kind tag (`host`, `container`, `identity`, `repo`, `bucket`,
    /// `service`).
    pub kind: String,
}

/// Structured features derived from a `(FindingViewLike, AssetViewLike)`
/// pair.
///
/// Use [`Self::to_vector`] to flatten into the dense `f64` representation
/// the GBDT consumes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FindingFeatures {
    /// CVSS base score, clamped to `[0, 10]`.
    pub cvss: f64,
    /// EPSS probability, clamped to `[0, 1]`.
    pub epss: f64,
    /// `1.0` if KEV-listed, else `0.0`.
    pub kev_flag: f64,
    /// Days since the finding was first observed, clamped to `>= 0`.
    pub days_since_first_seen: f64,
    /// Severity bucket.
    pub severity: SeverityEnum,
    /// Asset-kind bucket.
    pub asset_kind: AssetKindEnum,
    /// Business-impact multiplier.
    pub business_impact: f64,
    /// Attack-chain amplifier.
    pub chain_amplifier: f64,
}

impl FindingFeatures {
    /// Derive structured features from the two wire-style projections.
    ///
    /// Sanitisation applied:
    /// - `cvss` clamped to `[0, 10]` and NaN/inf replaced with `0.0`.
    /// - `epss` clamped to `[0, 1]` and NaN/inf replaced with `0.0`.
    /// - `days_since_first_seen` clamped to `>= 0`, NaN/inf to `0.0`.
    /// - `business_impact` defaults to `1.0` on non-finite input.
    /// - `chain_amplifier` defaults to `1.0` on non-finite input.
    #[must_use]
    pub fn from_views(finding: &FindingViewLike, asset: &AssetViewLike) -> Self {
        Self {
            cvss: sanitize(finding.cvss.unwrap_or(0.0), 0.0, 10.0, 0.0),
            epss: sanitize(finding.epss.unwrap_or(0.0), 0.0, 1.0, 0.0),
            kev_flag: if finding.kev_flag { 1.0 } else { 0.0 },
            days_since_first_seen: sanitize(finding.days_since_first_seen, 0.0, f64::MAX, 0.0),
            severity: SeverityEnum::from_tag(&finding.severity),
            asset_kind: AssetKindEnum::from_tag(&asset.kind),
            business_impact: sanitize_with_default(finding.business_impact, 1.0),
            chain_amplifier: sanitize_with_default(finding.chain_amplifier, 1.0),
        }
    }

    /// Build features directly from risk signals — the canonical bridge
    /// for a caller holding an `sx_risk::RiskInput`-shaped record (which
    /// carries `cvss` / `epss` / `kev` / severity / `business_impact` /
    /// `chain_amplifier`, a superset of the overlapping slots).
    ///
    /// Kept decoupled: takes plain fields so `sx-ml` never depends on
    /// `sx-risk`. The two ML slots a risk input does not carry
    /// (`asset_kind`, `days_since_first_seen`) are explicit parameters —
    /// pass neutral values (`"service"`, `0.0`) when unknown. All inputs
    /// are sanitised by [`Self::from_views`].
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn from_risk_input(
        cvss: f64,
        epss: f64,
        kev: bool,
        severity: &str,
        asset_kind: &str,
        days_since_first_seen: f64,
        business_impact: f64,
        chain_amplifier: f64,
    ) -> Self {
        Self::from_views(
            &FindingViewLike {
                cvss: Some(cvss),
                epss: Some(epss),
                kev_flag: kev,
                severity: severity.to_owned(),
                days_since_first_seen,
                business_impact,
                chain_amplifier,
            },
            &AssetViewLike {
                kind: asset_kind.to_owned(),
            },
        )
    }

    /// Flatten into a fixed-layout `[f64; FEATURE_VECTOR_LEN]` vector.
    ///
    /// See [`FEATURE_VECTOR_LEN`] for the slot-by-slot layout.
    #[must_use]
    pub fn to_vector(&self) -> [f64; FEATURE_VECTOR_LEN] {
        let mut v = [0.0_f64; FEATURE_VECTOR_LEN];
        v[0] = self.cvss;
        v[1] = self.epss;
        v[2] = self.kev_flag;
        v[3] = self.days_since_first_seen;
        // Severity one-hot at slots 4..=8.
        let sev_offset = 4 + self.severity.one_hot_index();
        if let Some(slot) = v.get_mut(sev_offset) {
            *slot = 1.0;
        }
        // Asset-kind one-hot at slots 9..=14.
        let kind_offset = 4 + SeverityEnum::CARDINALITY + self.asset_kind.one_hot_index();
        if let Some(slot) = v.get_mut(kind_offset) {
            *slot = 1.0;
        }
        v[15] = self.business_impact;
        v[16] = self.chain_amplifier;
        v
    }
}

const fn sanitize(value: f64, min: f64, max: f64, fallback: f64) -> f64 {
    if value.is_nan() || value.is_infinite() {
        return fallback;
    }
    if value < min {
        min
    } else if value > max {
        max
    } else {
        value
    }
}

const fn sanitize_with_default(value: f64, default: f64) -> f64 {
    if value.is_nan() || value.is_infinite() {
        default
    } else {
        value
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn finding(severity: &str, cvss: Option<f64>, kev: bool) -> FindingViewLike {
        FindingViewLike {
            cvss,
            epss: Some(0.2),
            kev_flag: kev,
            severity: severity.into(),
            days_since_first_seen: 7.0,
            business_impact: 2.0,
            chain_amplifier: 1.5,
        }
    }

    fn asset(kind: &str) -> AssetViewLike {
        AssetViewLike { kind: kind.into() }
    }

    #[test]
    fn severity_tag_parses_known_values() {
        assert_eq!(SeverityEnum::from_tag("critical"), SeverityEnum::Critical);
        assert_eq!(SeverityEnum::from_tag("HIGH"), SeverityEnum::High);
        assert_eq!(SeverityEnum::from_tag("medium"), SeverityEnum::Medium);
        assert_eq!(SeverityEnum::from_tag("low"), SeverityEnum::Low);
        assert_eq!(SeverityEnum::from_tag("info"), SeverityEnum::Info);
    }

    #[test]
    fn severity_unknown_defaults_info() {
        assert_eq!(SeverityEnum::from_tag(""), SeverityEnum::Info);
        assert_eq!(SeverityEnum::from_tag("bogus"), SeverityEnum::Info);
    }

    #[test]
    fn asset_kind_tag_parses_known_values() {
        assert_eq!(AssetKindEnum::from_tag("host"), AssetKindEnum::Host);
        assert_eq!(
            AssetKindEnum::from_tag("container"),
            AssetKindEnum::Container
        );
        assert_eq!(AssetKindEnum::from_tag("repo"), AssetKindEnum::Repo);
    }

    #[test]
    fn features_clamp_out_of_range_cvss() {
        let f = finding("high", Some(42.0), false);
        let a = asset("host");
        let feats = FindingFeatures::from_views(&f, &a);
        assert!((feats.cvss - 10.0).abs() < f64::EPSILON);
    }

    #[test]
    fn features_replace_nan_inputs() {
        let f = FindingViewLike {
            cvss: Some(f64::NAN),
            epss: Some(f64::INFINITY),
            kev_flag: false,
            severity: "high".into(),
            days_since_first_seen: f64::NAN,
            business_impact: f64::NAN,
            chain_amplifier: f64::INFINITY,
        };
        let a = asset("service");
        let feats = FindingFeatures::from_views(&f, &a);
        assert!((feats.cvss - 0.0).abs() < f64::EPSILON);
        assert!((feats.epss - 0.0).abs() < f64::EPSILON);
        assert!((feats.days_since_first_seen - 0.0).abs() < f64::EPSILON);
        assert!((feats.business_impact - 1.0).abs() < f64::EPSILON);
        assert!((feats.chain_amplifier - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn from_risk_input_matches_equivalent_from_views() {
        // The risk-signal bridge must produce the identical feature record
        // as the wire-view path for the same inputs.
        let via_risk = FindingFeatures::from_risk_input(
            9.1, 0.7, true, "critical", "identity", 12.0, 2.0, 1.5,
        );
        let via_views = FindingFeatures::from_views(
            &FindingViewLike {
                cvss: Some(9.1),
                epss: Some(0.7),
                kev_flag: true,
                severity: "critical".into(),
                days_since_first_seen: 12.0,
                business_impact: 2.0,
                chain_amplifier: 1.5,
            },
            &AssetViewLike {
                kind: "identity".into(),
            },
        );
        assert_eq!(via_risk, via_views);
        // Spot-check the headline slots land where the schema says.
        let v = via_risk.to_vector();
        assert!((v[0] - 9.1).abs() < f64::EPSILON); // cvss
        assert!((v[1] - 0.7).abs() < f64::EPSILON); // epss
        assert!((v[2] - 1.0).abs() < f64::EPSILON); // kev
        assert_eq!(via_risk.severity, SeverityEnum::Critical);
        assert_eq!(via_risk.asset_kind, AssetKindEnum::Identity);
    }

    #[test]
    fn schema_descriptor_matches_vector_layout() {
        // Array type already pins arity to FEATURE_VECTOR_LEN; assert the
        // descriptor names line up with the one-hot offsets to-vector uses,
        // so a slot reorder can't pass silently.
        assert_eq!(FEATURE_SCHEMA.len(), FEATURE_VECTOR_LEN);
        assert_eq!(FEATURE_SCHEMA[0].0, "cvss");
        assert_eq!(FEATURE_SCHEMA[1].0, "epss");
        assert_eq!(FEATURE_SCHEMA[2].0, "kev_flag");
        assert_eq!(FEATURE_SCHEMA[3].0, "days_since_first_seen");
        // Severity one-hot block at 4..=8.
        assert_eq!(
            FEATURE_SCHEMA[4 + SeverityEnum::Critical.one_hot_index()].0,
            "severity_critical"
        );
        assert_eq!(
            FEATURE_SCHEMA[4 + SeverityEnum::Info.one_hot_index()].0,
            "severity_info"
        );
        // Asset-kind one-hot block at 9..=14.
        let base = 4 + SeverityEnum::CARDINALITY;
        assert_eq!(
            FEATURE_SCHEMA[base + AssetKindEnum::Host.one_hot_index()].0,
            "asset_kind_host"
        );
        assert_eq!(
            FEATURE_SCHEMA[base + AssetKindEnum::Service.one_hot_index()].0,
            "asset_kind_service"
        );
        assert_eq!(FEATURE_SCHEMA[15].0, "business_impact");
        assert_eq!(FEATURE_SCHEMA[16].0, "chain_amplifier");
    }

    #[test]
    fn vector_layout_one_hots_severity_and_kind() {
        let f = finding("critical", Some(9.5), true);
        let a = asset("identity");
        let v = FindingFeatures::from_views(&f, &a).to_vector();
        // severity = critical → slot 8
        assert!((v.get(8).copied().unwrap_or(0.0) - 1.0).abs() < f64::EPSILON);
        // all other severity slots zero
        for (i, slot) in v.iter().enumerate().skip(4).take(4) {
            assert!(slot.abs() < f64::EPSILON, "slot {i}");
        }
        // identity → slot 9 + 2 = 11
        assert!((v.get(11).copied().unwrap_or(0.0) - 1.0).abs() < f64::EPSILON);
        for (i, slot) in v.iter().enumerate().skip(9).take(6) {
            if i == 11 {
                continue;
            }
            assert!(slot.abs() < f64::EPSILON, "slot {i}");
        }
        assert!((v.first().copied().unwrap_or(0.0) - 9.5).abs() < f64::EPSILON);
        assert!((v.get(2).copied().unwrap_or(0.0) - 1.0).abs() < f64::EPSILON);
    }
}
