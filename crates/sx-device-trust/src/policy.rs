//! Per-tenant posture policy model.
//!
//! A [`PosturePolicy`] is a small declarative ruleset evaluated against the
//! decoded [`crate::posture::PostureClaims`] for each request. Rules cover
//! the typical baseline a security team enforces on managed devices:
//!
//! * OS allow- / block-list (`os_name`),
//! * Minimum OS versions per family (Lexicographic over dotted-integer
//!   tuples — `"14.5.0" >= "14.4.0"`).
//! * Required flags: disk encryption, EDR running, screen-lock enabled.
//! * EDR vendor allow-list.
//! * Maximum screen-lock minutes (anything above is treated as a violation).
//!
//! Default policy ([`PosturePolicy::permissive`]) accepts everything and is
//! used at boot before the operator uploads a tenant-specific policy. The
//! evaluator gracefully tolerates missing rules (an empty `os_allow_list`
//! means "any OS is acceptable").

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// One declarative posture rule.
// Reason: the whole enum is, by design, a set of `Require*` rules — the
// shared prefix mirrors the policy vocabulary security teams use. Renaming
// the variants (e.g. to `DiskEncryption`) would lose that semantic and force
// every call-site to add an awkward `// require:` comment.
#[allow(clippy::enum_variant_names)]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PostureRule {
    /// Require an encrypted system disk.
    RequireDiskEncryption,
    /// Require an EDR agent.
    RequireEdr,
    /// Require a configured screen lock (`screen_lock_minutes <= max`).
    RequireScreenLock,
}

/// Per-tenant policy. Stored as JSON in the `device_posture_policy` table.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct PosturePolicy {
    /// OS family allow-list. Empty = any OS accepted.
    #[serde(default)]
    pub os_allow_list: Vec<String>,
    /// OS family block-list (takes precedence over the allow-list).
    #[serde(default)]
    pub os_block_list: Vec<String>,
    /// Minimum dotted-integer OS versions, keyed by OS family. Use a
    /// `BTreeMap` so the serialised form is deterministic.
    #[serde(default)]
    pub minimum_os_versions: BTreeMap<String, String>,
    /// EDR vendor allow-list. Empty = any vendor accepted.
    #[serde(default)]
    pub edr_vendor_allow_list: Vec<String>,
    /// Maximum acceptable `screen_lock_minutes` value. `None` = no upper
    /// bound check.
    #[serde(default)]
    pub max_screen_lock_minutes: Option<u32>,
    /// Active rules.
    #[serde(default)]
    pub rules: Vec<PostureRule>,
}

impl PosturePolicy {
    /// Permissive default — no rules active. Used at boot before a tenant
    /// has uploaded a policy of its own.
    #[must_use]
    pub fn permissive() -> Self {
        Self::default()
    }

    /// Strict baseline — encrypted disk + EDR + screen-lock <= 15 minutes.
    /// Mostly useful for documentation / tests.
    #[must_use]
    pub fn strict_baseline() -> Self {
        Self {
            os_allow_list: vec![],
            os_block_list: vec![],
            minimum_os_versions: BTreeMap::new(),
            edr_vendor_allow_list: vec![],
            max_screen_lock_minutes: Some(15),
            rules: vec![
                PostureRule::RequireDiskEncryption,
                PostureRule::RequireEdr,
                PostureRule::RequireScreenLock,
            ],
        }
    }
}

/// Compare two dotted-integer version strings (`"14.5.0"` vs. `"14.4.10"`).
///
/// Returns `Ordering::Greater` when `lhs` is strictly higher than `rhs`. Any
/// component that fails to parse as a `u64` is treated as `0` so a stray
/// trailing identifier (e.g. `"14.5.0-beta"`) compares as the lowest
/// integer prefix.
#[must_use]
pub fn compare_versions(lhs: &str, rhs: &str) -> std::cmp::Ordering {
    let lhs_parts: Vec<u64> = lhs
        .split('.')
        .map(|p| p.trim().parse::<u64>().unwrap_or(0))
        .collect();
    let rhs_parts: Vec<u64> = rhs
        .split('.')
        .map(|p| p.trim().parse::<u64>().unwrap_or(0))
        .collect();
    let len = lhs_parts.len().max(rhs_parts.len());
    for i in 0..len {
        let a = lhs_parts.get(i).copied().unwrap_or(0);
        let b = rhs_parts.get(i).copied().unwrap_or(0);
        match a.cmp(&b) {
            std::cmp::Ordering::Equal => (),
            other => return other,
        }
    }
    std::cmp::Ordering::Equal
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn permissive_round_trips() {
        let p = PosturePolicy::permissive();
        let json = serde_json::to_string(&p).unwrap();
        let back: PosturePolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(back, p);
    }

    #[test]
    fn strict_baseline_contains_three_rules() {
        let p = PosturePolicy::strict_baseline();
        assert_eq!(p.rules.len(), 3);
        assert_eq!(p.max_screen_lock_minutes, Some(15));
    }

    #[test]
    fn compare_versions_lexicographic() {
        assert_eq!(
            compare_versions("14.5.0", "14.4.10"),
            std::cmp::Ordering::Greater
        );
        assert_eq!(
            compare_versions("14.5.0", "14.5.0"),
            std::cmp::Ordering::Equal
        );
        assert_eq!(
            compare_versions("14.4.10", "14.5.0"),
            std::cmp::Ordering::Less
        );
        // Different lengths
        assert_eq!(compare_versions("14", "14.0.0"), std::cmp::Ordering::Equal);
        assert_eq!(
            compare_versions("14.1", "14.0.99"),
            std::cmp::Ordering::Greater
        );
    }

    #[test]
    fn compare_versions_tolerates_unparseable() {
        // `"14.5.0-beta"` -> [14, 5, 0] under the lenient parser.
        assert_eq!(
            compare_versions("14.5.0-beta", "14.5.0"),
            std::cmp::Ordering::Equal
        );
    }
}
