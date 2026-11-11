//! Technique catalogue + composer.
//!
//! - [`TargetSpec`] is a minimal description of the engagement the
//!   composer is reasoning about (platforms, exposure, whether the
//!   target is internet-facing). Only library-internal — no DB row, no
//!   serde wire shape needed for this round.
//! - [`TechniqueCatalogue`] is the pluggable trait every catalogue
//!   implements. The crate ships [`EmbeddedCatalogue`], a static list
//!   of ~25 safe-mode techniques tagged by phase.
//! - [`compose`] turns a `TargetSpec` + catalogue + cap into an
//!   [`AttackChain`]. The composer:
//!   * walks the 14 ATT&CK phases in canonical order;
//!   * for each phase, picks the best-scoring eligible technique;
//!   * skips phases with no eligible candidate (so the chain may be
//!     shorter than 14 but is always monotonic);
//!   * stops once `max_steps` have been emitted;
//!   * **hard-fails** any candidate whose
//!     [`TechniqueEntry::required_intensity`] is `ActiveExploit` or
//!     stronger, even if the catalogue forgot to flag it.

use sx_core::value_object::intensity::ScanIntensity;

use crate::redteam::chain::{AttackChain, ChainStep, KillChainPhase};
use crate::redteam::scoring::step_score;

/// A coarse description of the engagement the composer is reasoning over.
///
/// The fields are intentionally narrow — this is a heuristic input, not a
/// full engagement aggregate. Catalogue entries declare which platforms
/// they apply to and whether they need the target to be internet-facing;
/// the composer matches those tags against the spec to drive `target_fit`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetSpec {
    /// Platforms in scope (e.g. `"linux"`, `"windows"`, `"web"`,
    /// `"cloud"`). Match is case-insensitive on the catalogue side.
    pub platforms: Vec<String>,
    /// `true` when the target has at least one internet-facing surface.
    pub internet_facing: bool,
    /// Highest intensity the engagement allows. The composer rejects
    /// any technique whose minimum required intensity exceeds this.
    pub max_intensity: ScanIntensity,
}

impl TargetSpec {
    /// Construct a new spec.
    #[must_use]
    pub fn new(
        platforms: impl IntoIterator<Item = impl Into<String>>,
        internet_facing: bool,
        max_intensity: ScanIntensity,
    ) -> Self {
        Self {
            platforms: platforms.into_iter().map(Into::into).collect(),
            internet_facing,
            max_intensity,
        }
    }

    /// Sensible default for tests: a Linux web target, internet-facing,
    /// capped at `SafeInteractive`.
    #[must_use]
    pub fn safe_web() -> Self {
        Self::new(["linux", "web"], true, ScanIntensity::SafeInteractive)
    }

    fn matches_platform(&self, needle: &str) -> bool {
        self.platforms
            .iter()
            .any(|p| p.eq_ignore_ascii_case(needle))
    }
}

/// One entry in a technique catalogue.
///
/// Fields are owned `&'static str`s so the static [`EmbeddedCatalogue`]
/// can be a `const` table — zero allocations at startup, zero alloc per
/// compose call beyond the output `Vec`.
#[derive(Debug, Clone, Copy)]
pub struct TechniqueEntry {
    /// Stable MITRE ATT&CK technique id (e.g. `T1190`).
    pub technique_id: &'static str,
    /// Human-readable name. Not load-bearing; used in tracing only.
    pub name: &'static str,
    /// Phase this technique is tagged to.
    pub phase: KillChainPhase,
    /// Base confidence the catalogue assigns to this technique, in
    /// `[0.0, 1.0]`. Higher = more likely to succeed in a generic
    /// engagement.
    pub base_confidence: f64,
    /// Platform tag list. Empty means "platform-agnostic".
    pub platforms: &'static [&'static str],
    /// Set when the technique only really makes sense against an
    /// internet-facing target (e.g. exploit a public-facing app).
    pub needs_internet_facing: bool,
    /// Minimum intensity required to safely simulate the technique.
    /// `ActiveExploit` or stronger flags the entry as unsafe — the
    /// composer hard-fails it.
    pub required_intensity: ScanIntensity,
}

impl TechniqueEntry {
    /// `true` when this technique is allowed under `SentinelX` safe-mode
    /// rules (i.e. its minimum required intensity is `<= SafeInteractive`).
    #[must_use]
    pub const fn is_safe_mode(&self) -> bool {
        matches!(
            self.required_intensity,
            ScanIntensity::Theoretical
                | ScanIntensity::PassiveValidation
                | ScanIntensity::SafeInteractive
        )
    }
}

/// Pluggable source of technique entries.
///
/// Implementations must return entries in a deterministic order — the
/// composer is deterministic only if its input is.
pub trait TechniqueCatalogue {
    /// Every technique known to this catalogue, in a stable order.
    fn entries(&self) -> &[TechniqueEntry];
}

/// Static, embedded catalogue of ~25 safe-mode ATT&CK techniques.
///
/// Entries are hand-picked to cover the full 14-phase kill chain at
/// least once, biased toward techniques that have well-known passive or
/// safe-interactive analogues in BAS simulators.
#[derive(Debug, Clone, Copy, Default)]
pub struct EmbeddedCatalogue;

impl EmbeddedCatalogue {
    /// The static list of 25 entries. Public so tests can introspect it
    /// without going through the trait.
    pub const ENTRIES: &'static [TechniqueEntry] = &[
        // --- Reconnaissance (TA0043) ---
        TechniqueEntry {
            technique_id: "T1595",
            name: "Active Scanning",
            phase: KillChainPhase::Reconnaissance,
            base_confidence: 0.80,
            platforms: &[],
            needs_internet_facing: true,
            required_intensity: ScanIntensity::SafeInteractive,
        },
        TechniqueEntry {
            technique_id: "T1592",
            name: "Gather Victim Host Information",
            phase: KillChainPhase::Reconnaissance,
            base_confidence: 0.70,
            platforms: &[],
            needs_internet_facing: false,
            required_intensity: ScanIntensity::PassiveValidation,
        },
        // --- Resource Development (TA0042) ---
        TechniqueEntry {
            technique_id: "T1583",
            name: "Acquire Infrastructure",
            phase: KillChainPhase::ResourceDevelopment,
            base_confidence: 0.55,
            platforms: &[],
            needs_internet_facing: false,
            required_intensity: ScanIntensity::Theoretical,
        },
        TechniqueEntry {
            technique_id: "T1587",
            name: "Develop Capabilities",
            phase: KillChainPhase::ResourceDevelopment,
            base_confidence: 0.50,
            platforms: &[],
            needs_internet_facing: false,
            required_intensity: ScanIntensity::Theoretical,
        },
        // --- Initial Access (TA0001) ---
        TechniqueEntry {
            technique_id: "T1190",
            name: "Exploit Public-Facing Application",
            phase: KillChainPhase::InitialAccess,
            base_confidence: 0.85,
            platforms: &["web", "linux", "windows"],
            needs_internet_facing: true,
            required_intensity: ScanIntensity::SafeInteractive,
        },
        TechniqueEntry {
            technique_id: "T1566",
            name: "Phishing",
            phase: KillChainPhase::InitialAccess,
            base_confidence: 0.75,
            platforms: &[],
            needs_internet_facing: false,
            required_intensity: ScanIntensity::SafeInteractive,
        },
        // --- Execution (TA0002) ---
        TechniqueEntry {
            technique_id: "T1059",
            name: "Command and Scripting Interpreter",
            phase: KillChainPhase::Execution,
            base_confidence: 0.80,
            platforms: &["linux", "windows", "macos"],
            needs_internet_facing: false,
            required_intensity: ScanIntensity::SafeInteractive,
        },
        TechniqueEntry {
            technique_id: "T1204",
            name: "User Execution",
            phase: KillChainPhase::Execution,
            base_confidence: 0.65,
            platforms: &[],
            needs_internet_facing: false,
            required_intensity: ScanIntensity::SafeInteractive,
        },
        // --- Persistence (TA0003) ---
        TechniqueEntry {
            technique_id: "T1053",
            name: "Scheduled Task/Job",
            phase: KillChainPhase::Persistence,
            base_confidence: 0.70,
            platforms: &["linux", "windows"],
            needs_internet_facing: false,
            required_intensity: ScanIntensity::SafeInteractive,
        },
        // --- Privilege Escalation (TA0004) ---
        TechniqueEntry {
            technique_id: "T1068",
            name: "Exploitation for Privilege Escalation",
            phase: KillChainPhase::PrivilegeEscalation,
            base_confidence: 0.60,
            platforms: &["linux", "windows"],
            needs_internet_facing: false,
            required_intensity: ScanIntensity::SafeInteractive,
        },
        TechniqueEntry {
            technique_id: "T1548",
            name: "Abuse Elevation Control Mechanism",
            phase: KillChainPhase::PrivilegeEscalation,
            base_confidence: 0.55,
            platforms: &["linux", "windows", "macos"],
            needs_internet_facing: false,
            required_intensity: ScanIntensity::SafeInteractive,
        },
        // --- Defense Evasion (TA0005) ---
        TechniqueEntry {
            technique_id: "T1027",
            name: "Obfuscated Files or Information",
            phase: KillChainPhase::DefenseEvasion,
            base_confidence: 0.65,
            platforms: &[],
            needs_internet_facing: false,
            required_intensity: ScanIntensity::SafeInteractive,
        },
        TechniqueEntry {
            technique_id: "T1070",
            name: "Indicator Removal",
            phase: KillChainPhase::DefenseEvasion,
            base_confidence: 0.55,
            platforms: &["linux", "windows"],
            needs_internet_facing: false,
            required_intensity: ScanIntensity::SafeInteractive,
        },
        // --- Credential Access (TA0006) ---
        TechniqueEntry {
            technique_id: "T1110",
            name: "Brute Force",
            phase: KillChainPhase::CredentialAccess,
            base_confidence: 0.60,
            platforms: &[],
            needs_internet_facing: false,
            required_intensity: ScanIntensity::SafeInteractive,
        },
        TechniqueEntry {
            technique_id: "T1003",
            name: "OS Credential Dumping",
            phase: KillChainPhase::CredentialAccess,
            base_confidence: 0.70,
            platforms: &["linux", "windows"],
            needs_internet_facing: false,
            required_intensity: ScanIntensity::SafeInteractive,
        },
        // --- Discovery (TA0007) ---
        TechniqueEntry {
            technique_id: "T1018",
            name: "Remote System Discovery",
            phase: KillChainPhase::Discovery,
            base_confidence: 0.80,
            platforms: &[],
            needs_internet_facing: false,
            required_intensity: ScanIntensity::SafeInteractive,
        },
        TechniqueEntry {
            technique_id: "T1083",
            name: "File and Directory Discovery",
            phase: KillChainPhase::Discovery,
            base_confidence: 0.75,
            platforms: &[],
            needs_internet_facing: false,
            required_intensity: ScanIntensity::SafeInteractive,
        },
        // --- Lateral Movement (TA0008) ---
        TechniqueEntry {
            technique_id: "T1021",
            name: "Remote Services",
            phase: KillChainPhase::LateralMovement,
            base_confidence: 0.70,
            platforms: &["linux", "windows"],
            needs_internet_facing: false,
            required_intensity: ScanIntensity::SafeInteractive,
        },
        // --- Collection (TA0009) ---
        TechniqueEntry {
            technique_id: "T1005",
            name: "Data from Local System",
            phase: KillChainPhase::Collection,
            base_confidence: 0.70,
            platforms: &[],
            needs_internet_facing: false,
            required_intensity: ScanIntensity::SafeInteractive,
        },
        TechniqueEntry {
            technique_id: "T1119",
            name: "Automated Collection",
            phase: KillChainPhase::Collection,
            base_confidence: 0.60,
            platforms: &[],
            needs_internet_facing: false,
            required_intensity: ScanIntensity::SafeInteractive,
        },
        // --- Command and Control (TA0011) ---
        TechniqueEntry {
            technique_id: "T1071",
            name: "Application Layer Protocol",
            phase: KillChainPhase::CommandAndControl,
            base_confidence: 0.75,
            platforms: &[],
            needs_internet_facing: false,
            required_intensity: ScanIntensity::SafeInteractive,
        },
        TechniqueEntry {
            technique_id: "T1095",
            name: "Non-Application Layer Protocol",
            phase: KillChainPhase::CommandAndControl,
            base_confidence: 0.55,
            platforms: &[],
            needs_internet_facing: false,
            required_intensity: ScanIntensity::SafeInteractive,
        },
        // --- Exfiltration (TA0010) ---
        TechniqueEntry {
            technique_id: "T1041",
            name: "Exfiltration Over C2 Channel",
            phase: KillChainPhase::Exfiltration,
            base_confidence: 0.70,
            platforms: &[],
            needs_internet_facing: false,
            required_intensity: ScanIntensity::SafeInteractive,
        },
        // --- Impact (TA0040) ---
        TechniqueEntry {
            technique_id: "T1486",
            name: "Data Encrypted for Impact",
            phase: KillChainPhase::Impact,
            base_confidence: 0.75,
            platforms: &["linux", "windows"],
            needs_internet_facing: false,
            required_intensity: ScanIntensity::SafeInteractive,
        },
        TechniqueEntry {
            technique_id: "T1499",
            name: "Endpoint Denial of Service",
            phase: KillChainPhase::Impact,
            base_confidence: 0.60,
            platforms: &[],
            needs_internet_facing: true,
            required_intensity: ScanIntensity::SafeInteractive,
        },
    ];
}

impl TechniqueCatalogue for EmbeddedCatalogue {
    fn entries(&self) -> &[TechniqueEntry] {
        Self::ENTRIES
    }
}

/// Compose a kill chain for the given target.
///
/// Algorithm (deterministic given a stable catalogue ordering):
///
/// 1. Walk every ATT&CK phase in canonical order.
/// 2. For each phase, scan the catalogue for entries tagged with that
///    phase whose
///    [`TechniqueEntry::is_safe_mode`] is `true` **and**
///    `required_intensity <= target.max_intensity`.
///    A non-safe-mode entry is silently dropped — never emitted.
/// 3. For each eligible entry, compute a per-step score via
///    [`step_score`]; the highest score wins. Ties are broken by the
///    entry's order in [`TechniqueCatalogue::entries`], so a stable
///    catalogue means a stable output.
/// 4. The winning entry becomes a [`ChainStep`] whose `confidence` is
///    its per-step score.
/// 5. Stop once `max_steps` steps have been emitted (`max_steps == 0`
///    yields an empty chain).
#[must_use]
pub fn compose<C: TechniqueCatalogue>(
    target: &TargetSpec,
    catalogue: &C,
    max_steps: u8,
) -> AttackChain {
    if max_steps == 0 {
        return AttackChain::empty();
    }

    let entries = catalogue.entries();
    let mut steps: Vec<ChainStep> = Vec::with_capacity(usize::from(max_steps));

    for phase in KillChainPhase::all() {
        if steps.len() >= usize::from(max_steps) {
            break;
        }

        let best = entries
            .iter()
            .enumerate()
            .filter(|(_, e)| e.phase == phase)
            .filter(|(_, e)| e.is_safe_mode())
            .filter(|(_, e)| e.required_intensity <= target.max_intensity)
            .filter_map(|(idx, e)| {
                let score = step_score(e.phase, e.base_confidence, target_fit(target, e));
                if score > 0.0 {
                    Some((idx, e, score))
                } else {
                    None
                }
            })
            .fold(None::<(usize, &TechniqueEntry, f64)>, |acc, cand| {
                match acc {
                    // Strictly greater wins; equal scores keep the earlier
                    // catalogue position (stable, deterministic).
                    Some((_, _, best_score)) if cand.2 > best_score => Some(cand),
                    None => Some(cand),
                    other => other,
                }
            });

        if let Some((_, entry, score)) = best {
            steps.push(ChainStep::new(entry.phase, entry.technique_id, score));
        }
    }

    AttackChain::from_steps(steps)
}

/// `target_fit` heuristic for a single catalogue entry.
///
/// Returns a value in `[0.0, 1.0]`:
/// - 1.0 when the entry is platform-agnostic and the target either has
///   internet exposure or the entry doesn't need it;
/// - reduced when the entry needs an internet-facing target but the
///   target isn't;
/// - reduced when the entry's platform tags don't overlap with the
///   target's platforms.
#[must_use]
fn target_fit(target: &TargetSpec, entry: &TechniqueEntry) -> f64 {
    let mut fit = 1.0_f64;

    if entry.needs_internet_facing && !target.internet_facing {
        fit *= 0.2;
    }

    if !entry.platforms.is_empty() {
        let any_match = entry.platforms.iter().any(|p| target.matches_platform(p));
        if !any_match {
            fit *= 0.3;
        }
    }

    fit.clamp(0.0, 1.0)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::float_cmp, clippy::panic)]
mod tests {
    use super::*;
    use crate::redteam::scoring::{chain_score, MIN_CHAIN_SCORE};

    /// Catalogue that contains a single, deliberately-unsafe technique.
    /// Used to prove the composer's hard-fail guard works even when a
    /// catalogue tries to smuggle a non-safe entry through.
    struct UnsafeOnlyCatalogue;

    static UNSAFE_ENTRIES: &[TechniqueEntry] = &[TechniqueEntry {
        technique_id: "T9999",
        name: "Unsafe Test Entry",
        phase: KillChainPhase::InitialAccess,
        base_confidence: 0.99,
        platforms: &[],
        needs_internet_facing: false,
        required_intensity: ScanIntensity::ActiveExploit,
    }];

    impl TechniqueCatalogue for UnsafeOnlyCatalogue {
        fn entries(&self) -> &[TechniqueEntry] {
            UNSAFE_ENTRIES
        }
    }

    struct EmptyCatalogue;
    impl TechniqueCatalogue for EmptyCatalogue {
        fn entries(&self) -> &[TechniqueEntry] {
            &[]
        }
    }

    #[test]
    fn embedded_catalogue_size_around_twenty_five() {
        // The spec says "~25". Lock the bound so future edits to the
        // table are intentional.
        let n = EmbeddedCatalogue::ENTRIES.len();
        assert!(
            (24..=30).contains(&n),
            "embedded catalogue should be roughly 25 entries, got {n}"
        );
    }

    #[test]
    fn embedded_catalogue_is_entirely_safe_mode() {
        for e in EmbeddedCatalogue::ENTRIES {
            assert!(
                e.is_safe_mode(),
                "entry {} ({}) is not safe-mode",
                e.technique_id,
                e.name,
            );
        }
    }

    #[test]
    fn embedded_catalogue_covers_every_phase() {
        // Sanity: every phase is reachable from the embedded table.
        for p in KillChainPhase::all() {
            let count = EmbeddedCatalogue::ENTRIES
                .iter()
                .filter(|e| e.phase == p)
                .count();
            assert!(count >= 1, "no entry for phase {p}");
        }
    }

    #[test]
    fn compose_basic_engagement_produces_meaningful_chain() {
        let target = TargetSpec::safe_web();
        let chain = compose(&target, &EmbeddedCatalogue, 14);
        assert!(chain.len() >= 3, "expected >=3 steps, got {}", chain.len());
        let phases = chain.distinct_phases();
        assert!(
            phases.len() >= 3,
            "expected >=3 distinct phases, got {}",
            phases.len()
        );
    }

    #[test]
    fn compose_respects_max_steps_cap() {
        let target = TargetSpec::safe_web();
        let chain = compose(&target, &EmbeddedCatalogue, 3);
        assert!(chain.len() <= 3);
        assert_eq!(chain.len(), 3);
    }

    #[test]
    fn compose_phases_are_monotonic() {
        let target = TargetSpec::safe_web();
        let chain = compose(&target, &EmbeddedCatalogue, 14);
        assert!(chain.is_monotonic(), "chain phases must be non-decreasing");
    }

    #[test]
    fn compose_is_deterministic() {
        let target = TargetSpec::safe_web();
        let a = compose(&target, &EmbeddedCatalogue, 14);
        let b = compose(&target, &EmbeddedCatalogue, 14);
        assert_eq!(a, b);
    }

    #[test]
    fn compose_with_empty_catalogue_returns_empty_chain() {
        let target = TargetSpec::safe_web();
        let chain = compose(&target, &EmptyCatalogue, 14);
        assert!(chain.is_empty());
        assert_eq!(chain_score(&chain), MIN_CHAIN_SCORE);
    }

    #[test]
    fn compose_with_zero_max_steps_returns_empty() {
        let target = TargetSpec::safe_web();
        let chain = compose(&target, &EmbeddedCatalogue, 0);
        assert!(chain.is_empty());
    }

    #[test]
    fn compose_rejects_unsafe_entries_even_if_offered() {
        // The catalogue offers a single ActiveExploit-only entry. The
        // composer MUST refuse to emit it even though the target's max
        // intensity is RedTeam (so the intensity check alone would allow
        // it). The safe-mode guard is independent.
        let target = TargetSpec::new(["linux"], true, ScanIntensity::RedTeam);
        let chain = compose(&target, &UnsafeOnlyCatalogue, 14);
        assert!(chain.is_empty(), "unsafe technique leaked into chain");
        assert!(chain.steps.iter().all(|s| s.technique_id != "T9999"));
    }

    #[test]
    fn compose_skips_techniques_above_max_intensity() {
        // A target capped at Theoretical can't run anything that needs
        // SafeInteractive — and the embedded catalogue is almost
        // entirely SafeInteractive, so only Theoretical/Passive entries
        // should survive.
        let target = TargetSpec::new(["linux"], true, ScanIntensity::Theoretical);
        let chain = compose(&target, &EmbeddedCatalogue, 14);
        for step in &chain.steps {
            let entry = EmbeddedCatalogue::ENTRIES
                .iter()
                .find(|e| e.technique_id == step.technique_id)
                .unwrap_or_else(|| panic!("emitted unknown technique {}", step.technique_id));
            assert!(entry.required_intensity <= ScanIntensity::Theoretical);
        }
    }

    #[test]
    fn chain_score_matches_product_of_step_confidences() {
        let target = TargetSpec::safe_web();
        let chain = compose(&target, &EmbeddedCatalogue, 5);
        let manual: f64 = chain.steps.iter().map(|s| s.confidence).product();
        let expected = manual.max(MIN_CHAIN_SCORE);
        assert!((chain_score(&chain) - expected).abs() < 1e-12);
    }

    #[test]
    fn compose_with_no_platform_match_still_emits_when_agnostic_entries_exist() {
        // A target with an obscure platform should still receive steps
        // from platform-agnostic entries (most of the catalogue).
        let target = TargetSpec::new(["bespoke-os"], false, ScanIntensity::SafeInteractive);
        let chain = compose(&target, &EmbeddedCatalogue, 14);
        assert!(!chain.is_empty());
    }
}
