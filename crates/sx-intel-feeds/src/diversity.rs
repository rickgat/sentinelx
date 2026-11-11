//! Feed-source diversity enforcement and Bayesian confidence fusion (HIGH-011).
//!
//! Threat-intelligence indicators arrive from a heterogeneous pool of
//! feeds: commercial vendors (Mandiant, `CrowdStrike`, Recorded Future),
//! open-source projects (`abuse.ch`, `AlienVault` OTX), Information Sharing
//! and Analysis Centres (FS-ISAC, H-ISAC), and customer-private "custom"
//! feeds. Treating a hit from one feed as carrying the same weight as a
//! hit corroborated by three independent sources is bad practice — it
//! inflates false positives when a single noisy feed mis-reports an IOC
//! and it under-weights the strong "multiple independent sources agree"
//! signal that real incident-responders care about.
//!
//! This module introduces:
//!
//! * [`FeedFamily`] — categorises a feed by *trust-correlation family*.
//!   Two feeds in the same family are treated as **partially correlated**
//!   (e.g. two FS-ISAC products may republish each other's data); two
//!   feeds in different families are treated as **independent** evidence.
//! * [`FeedSource`] — a registered feed's identity (id + family + prior
//!   reliability `0..=1`).
//! * [`IndicatorConfidence`] — the fused output: which sources matched
//!   and the Bayesian-fused score on `0..=1`.
//! * [`DiversityConfig`] — per-tenant threshold for *minimum independent
//!   sources* required before a finding is emitted (default 2).
//! * [`DiversityMatcher`] — applies the gate + fusion to a slice of
//!   matching [`FeedSource`]s. Returns `None` when the diversity
//!   threshold is not met (the IOC matcher must NOT emit a finding) and
//!   `Some(IndicatorConfidence)` otherwise.
//!
//! ## Fusion math (intuition)
//!
//! The fusion is a *noisy-OR Bayesian update* with **family damping**:
//!
//! 1. Sort matching sources into family buckets (`Commercial(Vendor)`,
//!    `Oss(Project)`, `Isac(Sector)`, `Custom`).
//! 2. Within a family bucket, the FIRST source contributes its full
//!    prior `p_1`. Each subsequent source `p_k (k>=2)` is **damped** by
//!    the [`FAMILY_CORRELATION_DAMPING`] factor — they still raise the
//!    posterior, but each additional same-family hit contributes
//!    progressively less (it is correlated evidence, not independent
//!    evidence).
//! 3. Across family buckets the contributions are combined as
//!    independent (no damping).
//! 4. The classic noisy-OR posterior update is
//!    `posterior <- 1 - (1 - posterior) * (1 - p_effective)` applied
//!    once per (damped or undamped) `p_effective`.
//!
//! Properties this gives us (and that the test-suite pins down):
//!
//! * **Single-source = low.** One commercial feed with prior 0.7 yields
//!   `fused = 0.7`. The diversity gate refuses to emit at the default
//!   `min_independent_sources = 2` regardless, but if a tenant lowered
//!   the threshold to 1 they would still see a *visibly-not-corroborated*
//!   score.
//! * **3-of-3 same commercial vendor = saturated but NOT 1.0.** Three
//!   priors of 0.7 in the SAME family bucket produce damped contributions
//!   `0.7, 0.7*d, 0.7*d^2` (with `d = 0.4`). The posterior climbs but
//!   plateaus well below 1.0 because we treat them as correlated
//!   evidence — there is no scenario where adding a third report from
//!   the same vendor proves the IOC.
//! * **1-commercial + 1-OSS + 1-ISAC = highest.** Three sources in
//!   THREE different families each contribute their FULL prior. The
//!   posterior climbs much higher than the 3-of-3-same-vendor case.
//!
//! ## Independence accounting
//!
//! For the *diversity gate* (NOT the fusion math), the number of
//! "independent sources" is simply the count of distinct **family
//! bucket keys** matched. A 3-of-3-same-vendor match counts as ONE
//! independent source; a 1-commercial + 1-OSS + 1-ISAC match counts as
//! THREE. The default per-tenant minimum is 2 — i.e. a finding must be
//! corroborated by at least two distinct family buckets to surface.

use serde::{Deserialize, Serialize};

/// Damping factor applied to the 2nd, 3rd, ... source in the same family bucket.
///
/// A value of `0.4` means a second same-family hit
/// contributes 40 % of its raw prior; a third contributes 16 % (0.4²),
/// and so on. The choice is conservative — small enough that
/// three-of-the-same-family cannot saturate to 1.0, large enough that
/// genuine repeated commercial coverage still bumps the posterior.
pub const FAMILY_CORRELATION_DAMPING: f32 = 0.4;

/// Default tenant minimum for distinct family buckets that must
/// corroborate an indicator before it can be emitted as a finding.
pub const DEFAULT_MIN_INDEPENDENT_SOURCES: u8 = 2;

/// Commercial vendor identity used by [`FeedFamily::Commercial`].
///
/// We carry the vendor by ASCII identifier so two `Mandiant` feeds
/// (e.g. their "advanced" and "fundamental" collections) collapse into
/// the same family bucket and are treated as correlated evidence.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Vendor {
    /// Mandiant Advantage Threat Intelligence.
    Mandiant,
    /// `CrowdStrike` Falcon Intelligence.
    CrowdStrike,
    /// Recorded Future.
    RecordedFuture,
    /// IBM X-Force Exchange (paid tier).
    XForce,
    /// ESET Threat Intelligence.
    Eset,
    /// Any other commercial vendor — carry the lowercased name so
    /// distinct vendors stay distinct family buckets. Use sparingly;
    /// prefer adding a named variant when adopting a new vendor.
    Other(String),
}

/// Open-source project identity used by [`FeedFamily::Oss`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Project {
    /// `abuse.ch` umbrella (`URLhaus`, `ThreatFox`, `MalwareBazaar`, …).
    AbuseCh,
    /// `AlienVault` Open Threat Exchange (OTX) — community pulses.
    AlienVaultOtx,
    /// CIRCL MISP communities (open instance).
    CirclMisp,
    /// Emerging Threats open ruleset / IOC list.
    EmergingThreats,
    /// CISA Known-Exploited-Vulnerabilities feed (catalog).
    CisaKev,
    /// Any other OSS project.
    Other(String),
}

/// Sector identity used by [`FeedFamily::Isac`].
///
/// Two feeds from the same sector ISAC are treated as correlated
/// because they typically re-publish from the same source pool inside
/// that sector.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Sector {
    /// Financial Services ISAC.
    Financial,
    /// Health ISAC.
    Health,
    /// Energy ISAC (E-ISAC).
    Energy,
    /// Information Technology ISAC (IT-ISAC).
    InformationTechnology,
    /// Defense Industrial Base ISAC (DIB-ISAC).
    Defense,
    /// Any other sector ISAC.
    Other(String),
}

/// Trust-correlation family for a feed.
///
/// Two feeds with the SAME family value (per `PartialEq`) are treated
/// as correlated evidence during fusion. Two feeds with DIFFERENT
/// family values are independent.
///
/// `Custom` is a catch-all bucket for customer-private feeds. We treat
/// every distinct `Custom(label)` as its OWN family bucket, so two
/// custom feeds with different labels are independent. Two customer
/// feeds that share a label collapse into one bucket — this is the
/// intended behaviour for "two redundant exports of the same upstream
/// SIEM" or similar.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "id")]
pub enum FeedFamily {
    /// Paid commercial vendor.
    Commercial(Vendor),
    /// Open-source project.
    Oss(Project),
    /// Information Sharing and Analysis Centre, sectoral.
    Isac(Sector),
    /// Customer-private / bespoke feed. The label is the correlation
    /// key — distinct labels are independent.
    Custom(String),
}

impl FeedFamily {
    /// Stable string family-bucket key used by the diversity counter
    /// and by the family-damping fusion. Two sources with the same
    /// `bucket_key()` are treated as correlated.
    #[must_use]
    pub fn bucket_key(&self) -> String {
        match self {
            Self::Commercial(v) => format!("commercial:{}", vendor_key(v)),
            Self::Oss(p) => format!("oss:{}", project_key(p)),
            Self::Isac(s) => format!("isac:{}", sector_key(s)),
            Self::Custom(label) => format!("custom:{label}"),
        }
    }
}

fn vendor_key(v: &Vendor) -> String {
    match v {
        Vendor::Mandiant => "mandiant".to_owned(),
        Vendor::CrowdStrike => "crowdstrike".to_owned(),
        Vendor::RecordedFuture => "recorded_future".to_owned(),
        Vendor::XForce => "xforce".to_owned(),
        Vendor::Eset => "eset".to_owned(),
        Vendor::Other(name) => format!("other:{}", name.to_ascii_lowercase()),
    }
}

fn project_key(p: &Project) -> String {
    match p {
        Project::AbuseCh => "abuse_ch".to_owned(),
        Project::AlienVaultOtx => "alienvault_otx".to_owned(),
        Project::CirclMisp => "circl_misp".to_owned(),
        Project::EmergingThreats => "emerging_threats".to_owned(),
        Project::CisaKev => "cisa_kev".to_owned(),
        Project::Other(name) => format!("other:{}", name.to_ascii_lowercase()),
    }
}

fn sector_key(s: &Sector) -> String {
    match s {
        Sector::Financial => "financial".to_owned(),
        Sector::Health => "health".to_owned(),
        Sector::Energy => "energy".to_owned(),
        Sector::InformationTechnology => "it".to_owned(),
        Sector::Defense => "defense".to_owned(),
        Sector::Other(name) => format!("other:{}", name.to_ascii_lowercase()),
    }
}

/// Registered feed identity used during fusion.
///
/// `prior` is the feed's *baseline reliability* — the prior probability
/// that an indicator reported by THIS feed is a true positive, in
/// `0..=1`. It is supplied by the operator at feed-registration time
/// (see `sx-config`/`sx-monolith` composition). Typical defaults:
///
/// | Family                           | Suggested prior |
/// |----------------------------------|-----------------|
/// | Commercial (Mandiant, CS, RF)    | 0.80 – 0.90     |
/// | OSS (`abuse.ch`, ET)             | 0.55 – 0.70     |
/// | ISAC (sectoral, peer-validated)  | 0.70 – 0.85     |
/// | Custom (customer-private)        | 0.40 – 0.80     |
///
/// Values outside `0..=1` are clamped during fusion.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FeedSource {
    /// Stable feed identifier (matches `FeedId::as_str()` in the
    /// orchestrator). Two feeds with the same `id` must NEVER appear
    /// twice in the same fusion call.
    pub id: String,
    /// Family the feed belongs to. Drives independence accounting.
    pub family: FeedFamily,
    /// Operator-supplied prior reliability in `0..=1`.
    pub prior: f32,
}

impl FeedSource {
    /// Convenience constructor.
    #[must_use]
    pub fn new(id: impl Into<String>, family: FeedFamily, prior: f32) -> Self {
        Self {
            id: id.into(),
            family,
            prior,
        }
    }
}

/// Fused per-indicator confidence, returned by [`DiversityMatcher::fuse`]
/// (or by [`DiversityMatcher::evaluate`] alongside the emit/suppress
/// decision).
///
/// `fused` is the noisy-OR Bayesian-update posterior on `0..=1`. By
/// construction it can approach 1.0 only when MULTIPLE independent
/// family buckets contribute high priors — same-family repeated
/// reports saturate below 1.0.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IndicatorConfidence {
    /// The set of feed sources that matched this indicator (in the
    /// order they were provided to the fusion call).
    pub sources: Vec<FeedSource>,
    /// Fused posterior probability that the indicator is a true
    /// positive, in `0..=1`.
    pub fused: f32,
    /// Count of distinct family buckets observed across `sources`.
    /// This is the value compared against
    /// [`DiversityConfig::min_independent_sources`] for the gate.
    pub independent_sources: u8,
}

/// Per-tenant diversity configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiversityConfig {
    /// Minimum number of *distinct family buckets* that must
    /// corroborate an indicator before a finding can be emitted. The
    /// default is [`DEFAULT_MIN_INDEPENDENT_SOURCES`] (`2`); tenants
    /// may lower it (e.g. `1` for the high-noise / no-corroboration
    /// stance) or raise it (e.g. `3` for high-assurance environments).
    pub min_independent_sources: u8,
}

impl Default for DiversityConfig {
    fn default() -> Self {
        Self {
            min_independent_sources: DEFAULT_MIN_INDEPENDENT_SOURCES,
        }
    }
}

impl DiversityConfig {
    /// Build a config with a custom minimum. `0` is sanitised to `1`
    /// because a threshold of `0` would degenerate to "always emit"
    /// which is never what an operator wants.
    #[must_use]
    pub fn with_minimum(min_independent_sources: u8) -> Self {
        Self {
            min_independent_sources: min_independent_sources.max(1),
        }
    }
}

/// Outcome of [`DiversityMatcher::evaluate`].
#[derive(Debug, Clone, PartialEq)]
pub enum MatchOutcome {
    /// Indicator passes the diversity gate; the matcher SHOULD emit a
    /// finding with this confidence record attached.
    Emit(IndicatorConfidence),
    /// Indicator was matched by at least one feed but did NOT meet the
    /// per-tenant `min_independent_sources` threshold. The matcher
    /// MUST NOT emit a finding; the rejected confidence record is
    /// returned for observability (audit log / metric labelling).
    Suppress(IndicatorConfidence),
    /// No feeds matched the indicator. Nothing to emit, nothing to
    /// log.
    NoMatch,
}

/// Stateless fusion + gate evaluator.
///
/// The matcher itself holds only the per-tenant [`DiversityConfig`].
/// The list of feed sources that matched an IOC is supplied per call —
/// it comes from the upstream lookup (TAXII collection, commercial
/// adapter, Bloom-filter hit, etc.) and is the responsibility of the
/// IOC matcher in the monolith composition root.
#[derive(Debug, Clone)]
pub struct DiversityMatcher {
    config: DiversityConfig,
}

impl DiversityMatcher {
    /// Build a matcher with the per-tenant config.
    #[must_use]
    pub const fn new(config: DiversityConfig) -> Self {
        Self { config }
    }

    /// The active configuration. Useful for admin-API echo + tests.
    #[must_use]
    pub const fn config(&self) -> &DiversityConfig {
        &self.config
    }

    /// Fuse a non-empty slice of matching sources into an
    /// [`IndicatorConfidence`] WITHOUT applying the diversity gate.
    ///
    /// Returns `None` only when `sources` is empty. Callers that want
    /// the gate as well should use [`Self::evaluate`].
    // `&self` retained for API symmetry with `evaluate` and to keep the
    // matcher's public surface uniform; current fusion is config-free
    // but future per-tenant tuning hooks will read `self.config`.
    #[allow(clippy::unused_self)]
    #[must_use]
    pub fn fuse(&self, sources: &[FeedSource]) -> Option<IndicatorConfidence> {
        if sources.is_empty() {
            return None;
        }
        let fused = bayesian_noisy_or_with_family_damping(sources);
        let independent = count_independent_buckets(sources);
        Some(IndicatorConfidence {
            sources: sources.to_vec(),
            fused,
            independent_sources: independent,
        })
    }

    /// Apply the gate. Returns whether the IOC matcher should emit a
    /// finding for this indicator + the fused confidence record.
    #[must_use]
    pub fn evaluate(&self, sources: &[FeedSource]) -> MatchOutcome {
        let Some(confidence) = self.fuse(sources) else {
            return MatchOutcome::NoMatch;
        };
        if confidence.independent_sources >= self.config.min_independent_sources {
            MatchOutcome::Emit(confidence)
        } else {
            MatchOutcome::Suppress(confidence)
        }
    }
}

/// Count distinct family buckets across `sources`. Used both for the
/// gate (`>= min_independent_sources`) and for the field surfaced on
/// [`IndicatorConfidence`].
///
/// This is a tiny linear scan — feed counts per IOC are realistically
/// in single digits.
fn count_independent_buckets(sources: &[FeedSource]) -> u8 {
    let mut seen: Vec<String> = Vec::with_capacity(sources.len());
    for s in sources {
        let key = s.family.bucket_key();
        if !seen.iter().any(|k| k == &key) {
            seen.push(key);
        }
    }
    // Source counts per IOC are bounded by the number of registered
    // feeds (well under 255 in any realistic deployment). Clamp
    // defensively rather than panic on a hypothetical overflow.
    u8::try_from(seen.len()).unwrap_or(u8::MAX)
}

/// Core Bayesian fusion. Returns posterior on `0..=1`.
fn bayesian_noisy_or_with_family_damping(sources: &[FeedSource]) -> f32 {
    // Group by bucket while preserving the input order so test
    // expectations are stable. Within a bucket, the FIRST source
    // contributes full prior; the kth source contributes
    // `prior * d^(k-1)` where `d = FAMILY_CORRELATION_DAMPING`.
    let mut per_bucket_counts: Vec<(String, u32)> = Vec::with_capacity(sources.len());
    let mut posterior: f32 = 0.0;
    for source in sources {
        let key = source.family.bucket_key();
        // How many sources have we already consumed from this bucket?
        // Two-phase lookup avoids holding a mutable borrow across the
        // `push` branch (which would conflict with the borrow-checker).
        let existing = per_bucket_counts.iter().position(|(k, _)| k == &key);
        let prior_count = if let Some(idx) = existing {
            // INVARIANT: `idx` came from `position()` on this same vec,
            // and the vec is not mutated between the lookup and the
            // index — the entry is guaranteed to exist.
            if let Some(entry) = per_bucket_counts.get_mut(idx) {
                let n = entry.1;
                entry.1 = n + 1;
                n
            } else {
                0
            }
        } else {
            per_bucket_counts.push((key, 1));
            0
        };

        let raw_prior = clamp_unit(source.prior);
        let damped = raw_prior
            * FAMILY_CORRELATION_DAMPING.powi(i32::try_from(prior_count).unwrap_or(i32::MAX));
        // Noisy-OR posterior update:
        //   posterior <- 1 - (1 - posterior) * (1 - damped)
        // Equivalent to combining independent Bernoulli trials.
        // Re-expressed with `mul_add` for FMA precision + speed.
        posterior = (1.0 - posterior).mul_add(-(1.0 - damped), 1.0);
    }
    // Defensive clamp — float drift in long chains can push this a
    // hair outside [0, 1].
    clamp_unit(posterior)
}

const fn clamp_unit(x: f32) -> f32 {
    if x.is_nan() {
        0.0
    } else {
        x.clamp(0.0, 1.0)
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::float_cmp,
    clippy::expect_used,
    clippy::panic
)]
mod tests {
    use super::*;

    fn commercial_source(id: &str, vendor: Vendor, prior: f32) -> FeedSource {
        FeedSource::new(id, FeedFamily::Commercial(vendor), prior)
    }

    fn oss_source(id: &str, project: Project, prior: f32) -> FeedSource {
        FeedSource::new(id, FeedFamily::Oss(project), prior)
    }

    fn isac_source(id: &str, sector: Sector, prior: f32) -> FeedSource {
        FeedSource::new(id, FeedFamily::Isac(sector), prior)
    }

    #[test]
    fn diversity_single_source_yields_low_confidence_and_is_suppressed_by_default() {
        // Acceptance: a single commercial feed with prior 0.7 yields
        // exactly that as fused (no corroboration). Default min is 2,
        // so the matcher MUST NOT emit a finding.
        let matcher = DiversityMatcher::new(DiversityConfig::default());
        let sources = vec![commercial_source("mandiant", Vendor::Mandiant, 0.7)];
        let outcome = matcher.evaluate(&sources);
        match outcome {
            MatchOutcome::Suppress(conf) => {
                assert_eq!(conf.independent_sources, 1);
                assert!(
                    (conf.fused - 0.7).abs() < 1e-6,
                    "single-source fused should equal raw prior, got {}",
                    conf.fused
                );
            }
            other => panic!("expected Suppress for single source, got {other:?}"),
        }
    }

    #[test]
    fn diversity_three_of_three_same_commercial_vendor_saturates_below_one() {
        // Acceptance: 3 feeds from the SAME commercial vendor each
        // with prior 0.7 produce a saturated but NOT 1.0 fused score.
        // Three damped contributions: 0.7, 0.7 * 0.4 = 0.28,
        // 0.7 * 0.16 = 0.112.
        //
        // posterior = 1 - (1 - 0.7) * (1 - 0.28) * (1 - 0.112)
        //           = 1 - 0.3 * 0.72 * 0.888
        //           = 1 - 0.191808
        //           = 0.808192
        let matcher = DiversityMatcher::new(DiversityConfig::with_minimum(1));
        let sources = vec![
            commercial_source("mandiant-a", Vendor::Mandiant, 0.7),
            commercial_source("mandiant-b", Vendor::Mandiant, 0.7),
            commercial_source("mandiant-c", Vendor::Mandiant, 0.7),
        ];
        let conf = matcher.fuse(&sources).expect("non-empty");
        // Saturated but not 1.0.
        assert!(
            conf.fused > 0.75 && conf.fused < 0.95,
            "3-of-3-same-vendor fused should saturate but stay below 1.0, got {}",
            conf.fused
        );
        assert!(
            conf.fused < 0.999,
            "3-of-3-same-vendor MUST NOT reach 1.0, got {}",
            conf.fused
        );
        // Independent-source COUNT stays at 1 — same family, same
        // bucket. The diversity gate at default min=2 would suppress
        // even though the fused score is high.
        assert_eq!(conf.independent_sources, 1);
        let outcome = DiversityMatcher::new(DiversityConfig::default()).evaluate(&sources);
        match outcome {
            MatchOutcome::Suppress(_) => {}
            other => panic!(
                "default gate should suppress 3-of-3-same-vendor (no diversity), got {other:?}"
            ),
        }
    }

    #[test]
    fn diversity_one_commercial_one_oss_one_isac_yields_highest_score() {
        // Acceptance: three sources, one per family — each contributes
        // its FULL prior (no damping). Even with the SAME priors as
        // the 3-of-3-same-vendor test, this case must score higher.
        let matcher = DiversityMatcher::new(DiversityConfig::default());

        let same_vendor = vec![
            commercial_source("mandiant-a", Vendor::Mandiant, 0.7),
            commercial_source("mandiant-b", Vendor::Mandiant, 0.7),
            commercial_source("mandiant-c", Vendor::Mandiant, 0.7),
        ];
        let mixed = vec![
            commercial_source("mandiant", Vendor::Mandiant, 0.7),
            oss_source("abuse-ch", Project::AbuseCh, 0.7),
            isac_source("fs-isac", Sector::Financial, 0.7),
        ];

        let same_conf = matcher.fuse(&same_vendor).expect("non-empty");
        let mixed_conf = matcher.fuse(&mixed).expect("non-empty");

        assert!(
            mixed_conf.fused > same_conf.fused,
            "diverse-family fusion ({}) must exceed same-family fusion ({})",
            mixed_conf.fused,
            same_conf.fused
        );
        // Three distinct families ⇒ 3 independent sources.
        assert_eq!(mixed_conf.independent_sources, 3);
        // Gate passes at default min=2.
        match matcher.evaluate(&mixed) {
            MatchOutcome::Emit(conf) => {
                assert_eq!(conf.independent_sources, 3);
            }
            other => panic!("mixed-family should pass the default gate, got {other:?}"),
        }
        // Same-family case gated out at default min=2.
        match matcher.evaluate(&same_vendor) {
            MatchOutcome::Suppress(_) => {}
            other => panic!("same-vendor should be suppressed at default gate, got {other:?}"),
        }
    }

    #[test]
    fn diversity_empty_source_list_yields_no_match() {
        let matcher = DiversityMatcher::new(DiversityConfig::default());
        let outcome = matcher.evaluate(&[]);
        assert_eq!(outcome, MatchOutcome::NoMatch);
        assert!(matcher.fuse(&[]).is_none());
    }

    #[test]
    fn diversity_two_independent_families_pass_default_gate() {
        let matcher = DiversityMatcher::new(DiversityConfig::default());
        let sources = vec![
            commercial_source("crowdstrike", Vendor::CrowdStrike, 0.85),
            oss_source("abuse-ch", Project::AbuseCh, 0.6),
        ];
        match matcher.evaluate(&sources) {
            MatchOutcome::Emit(conf) => {
                assert_eq!(conf.independent_sources, 2);
                assert!(
                    conf.fused > 0.85,
                    "fused {} must exceed strongest single prior",
                    conf.fused
                );
            }
            other => panic!("expected Emit for 2-family case, got {other:?}"),
        }
    }

    #[test]
    fn diversity_config_with_minimum_zero_sanitises_to_one() {
        let cfg = DiversityConfig::with_minimum(0);
        assert_eq!(cfg.min_independent_sources, 1);
    }

    #[test]
    fn diversity_custom_family_labels_segregate_into_distinct_buckets() {
        // Two custom feeds with DIFFERENT labels are independent.
        let matcher = DiversityMatcher::new(DiversityConfig::default());
        let sources = vec![
            FeedSource::new(
                "siem-export-a",
                FeedFamily::Custom("siem-export-a".to_owned()),
                0.6,
            ),
            FeedSource::new(
                "siem-export-b",
                FeedFamily::Custom("siem-export-b".to_owned()),
                0.6,
            ),
        ];
        let outcome = matcher.evaluate(&sources);
        match outcome {
            MatchOutcome::Emit(conf) => assert_eq!(conf.independent_sources, 2),
            other => panic!("distinct custom labels must be independent, got {other:?}"),
        }
    }

    #[test]
    fn diversity_same_custom_label_collapses_to_one_bucket() {
        let matcher = DiversityMatcher::new(DiversityConfig::default());
        let sources = vec![
            FeedSource::new(
                "siem-export-a",
                FeedFamily::Custom("shared".to_owned()),
                0.6,
            ),
            FeedSource::new(
                "siem-export-b",
                FeedFamily::Custom("shared".to_owned()),
                0.6,
            ),
        ];
        match matcher.evaluate(&sources) {
            MatchOutcome::Suppress(conf) => {
                assert_eq!(conf.independent_sources, 1);
            }
            other => panic!("same custom label must collapse, got {other:?}"),
        }
    }

    #[test]
    fn diversity_prior_above_one_is_clamped() {
        // Adapter mis-supplying prior=1.5 must not produce nonsense.
        let matcher = DiversityMatcher::new(DiversityConfig::with_minimum(1));
        let sources = vec![commercial_source("oops", Vendor::Mandiant, 1.5)];
        let conf = matcher.fuse(&sources).expect("non-empty");
        assert!((conf.fused - 1.0).abs() < 1e-6);
    }

    #[test]
    fn diversity_negative_prior_is_clamped_to_zero() {
        let matcher = DiversityMatcher::new(DiversityConfig::with_minimum(1));
        let sources = vec![commercial_source("oops", Vendor::Mandiant, -0.5)];
        let conf = matcher.fuse(&sources).expect("non-empty");
        assert!(conf.fused.abs() < 1e-6);
    }

    #[test]
    fn diversity_high_threshold_can_gate_out_two_family_match() {
        // Tenant raises bar to 3 for high-assurance — two families is
        // not enough.
        let matcher = DiversityMatcher::new(DiversityConfig::with_minimum(3));
        let sources = vec![
            commercial_source("crowdstrike", Vendor::CrowdStrike, 0.85),
            oss_source("abuse-ch", Project::AbuseCh, 0.6),
        ];
        match matcher.evaluate(&sources) {
            MatchOutcome::Suppress(conf) => assert_eq!(conf.independent_sources, 2),
            other => panic!("expected Suppress at min=3 with 2 families, got {other:?}"),
        }
    }

    #[test]
    fn feed_family_bucket_keys_are_stable_per_kind() {
        assert_eq!(
            FeedFamily::Commercial(Vendor::Mandiant).bucket_key(),
            "commercial:mandiant"
        );
        assert_eq!(
            FeedFamily::Oss(Project::AbuseCh).bucket_key(),
            "oss:abuse_ch"
        );
        assert_eq!(
            FeedFamily::Isac(Sector::Financial).bucket_key(),
            "isac:financial"
        );
        assert_eq!(
            FeedFamily::Custom("acme-siem".to_owned()).bucket_key(),
            "custom:acme-siem"
        );
        // Other(...) variants preserve the label.
        assert_eq!(
            FeedFamily::Commercial(Vendor::Other("Anomali".to_owned())).bucket_key(),
            "commercial:other:anomali"
        );
    }

    #[test]
    fn indicator_confidence_round_trips_through_json() {
        let conf = IndicatorConfidence {
            sources: vec![commercial_source("mandiant", Vendor::Mandiant, 0.8)],
            fused: 0.8,
            independent_sources: 1,
        };
        let json = serde_json::to_string(&conf).unwrap();
        let back: IndicatorConfidence = serde_json::from_str(&json).unwrap();
        assert_eq!(conf, back);
    }
}
