//! Per-tenant detector configuration.
//!
//! Tenants opt their detectors in / out via a [`TenantDetectorConfig`]
//! stored in a [`TenantDetectorConfigStore`]. The [`crate::DlpService`]
//! consults the store on every `scan_text` call; missing entries fall
//! back to a permissive default (everything on).
//!
//! The store is intentionally a small in-memory map — production
//! deployments will swap it for a persistent table without touching
//! the controller or the orchestrator.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::patterns::DlpMatchKind;

/// Default minimum-confidence threshold applied when a tenant has not written a row.
///
/// `0.0` means "emit every finding regardless of fused confidence" — the
/// permissive default preserves pre-HIGH-004 behaviour so adopting the
/// multi-signal detector is opt-in per-tenant.
pub const DEFAULT_MIN_CONFIDENCE: f32 = 0.0;

/// Detector enable/disable list + minimum-confidence threshold for a
/// single tenant.
///
/// `enabled` is the source of truth — kinds not in the set are skipped
/// during scan. `min_confidence` (HIGH-004) filters out individual
/// findings below the per-tenant threshold; a value of `0.0` is the
/// permissive default and emits everything.
///
/// The default value enables every shipped detector with
/// `min_confidence = 0.0` — this mirrors what
/// `InMemoryDlpService::with_defaults` does, so a tenant that never
/// touches their config still scans everything.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TenantDetectorConfig {
    /// Allow-listed detector kinds. An empty set disables ALL detectors
    /// — which is intentionally a no-op scan, not an error. Callers that
    /// want to scrub a tenant from the surface set `enabled: {}` rather
    /// than dropping the row.
    pub enabled: BTreeSet<DlpMatchKind>,
    /// HIGH-004 per-tenant minimum-confidence threshold in `[0.0, 1.0]`.
    /// Findings whose fused confidence falls below this value are dropped
    /// silently. Defaults to [`DEFAULT_MIN_CONFIDENCE`] on missing rows.
    #[serde(default = "default_min_confidence")]
    pub min_confidence: f32,
}

/// Serde default used by [`TenantDetectorConfig::min_confidence`] so the
/// field is optional on the wire (HIGH-004 backwards-compat).
#[must_use]
pub const fn default_min_confidence() -> f32 {
    DEFAULT_MIN_CONFIDENCE
}

impl Default for TenantDetectorConfig {
    fn default() -> Self {
        Self::all_enabled()
    }
}

impl TenantDetectorConfig {
    /// Enable every shipped detector kind.
    #[must_use]
    pub fn all_enabled() -> Self {
        let mut set = BTreeSet::new();
        let _ = set.insert(DlpMatchKind::CreditCard);
        let _ = set.insert(DlpMatchKind::SsnUs);
        let _ = set.insert(DlpMatchKind::AwsAccessKey);
        let _ = set.insert(DlpMatchKind::AwsSecretKey);
        let _ = set.insert(DlpMatchKind::GithubPat);
        let _ = set.insert(DlpMatchKind::Jwt);
        let _ = set.insert(DlpMatchKind::PemPrivateKey);
        let _ = set.insert(DlpMatchKind::Email);
        let _ = set.insert(DlpMatchKind::Phone);
        let _ = set.insert(DlpMatchKind::GcpServiceAccount);
        let _ = set.insert(DlpMatchKind::SlackToken);
        let _ = set.insert(DlpMatchKind::NamedEntity);
        Self {
            enabled: set,
            min_confidence: DEFAULT_MIN_CONFIDENCE,
        }
    }

    /// Build with a custom minimum-confidence threshold (HIGH-004). The
    /// value is clamped into `[0.0, 1.0]` and `NaN` is folded to
    /// [`DEFAULT_MIN_CONFIDENCE`].
    #[must_use]
    pub const fn with_min_confidence(mut self, value: f32) -> Self {
        self.min_confidence = if value.is_nan() {
            DEFAULT_MIN_CONFIDENCE
        } else if value < 0.0 {
            0.0
        } else if value > 1.0 {
            1.0
        } else {
            value
        };
        self
    }

    /// Sanitised `min_confidence` value — used by every consumer so we
    /// never honour a NaN or out-of-range number that snuck in via the
    /// wire layer.
    #[must_use]
    pub const fn effective_min_confidence(&self) -> f32 {
        if self.min_confidence.is_nan() {
            DEFAULT_MIN_CONFIDENCE
        } else if self.min_confidence < 0.0 {
            0.0
        } else if self.min_confidence > 1.0 {
            1.0
        } else {
            self.min_confidence
        }
    }

    /// Return `true` when `kind` is enabled for the tenant.
    #[must_use]
    pub fn is_enabled(&self, kind: DlpMatchKind) -> bool {
        self.enabled.contains(&kind)
    }

    /// Return the configured kinds as a sorted vec — used by the HTTP
    /// view layer to render the policy.
    #[must_use]
    pub fn enabled_vec(&self) -> Vec<DlpMatchKind> {
        self.enabled.iter().copied().collect()
    }
}

/// In-memory store mapping `tenant_id → TenantDetectorConfig`.
///
/// `Default` returns an empty store: every tenant resolves to
/// [`TenantDetectorConfig::all_enabled`] until they explicitly write a
/// row. The store is `Send + Sync` — the inner mutex serialises both
/// reads and writes, which is fine for a config surface that is read
/// once per scan.
#[derive(Debug, Default)]
pub struct TenantDetectorConfigStore {
    inner: Mutex<BTreeMap<String, TenantDetectorConfig>>,
}

impl TenantDetectorConfigStore {
    /// Build a fresh empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Fetch the config for `tenant_id`. Missing rows fall back to the
    /// permissive default.
    #[must_use]
    pub fn get(&self, tenant_id: &str) -> TenantDetectorConfig {
        match self.inner.lock() {
            Ok(g) => g
                .get(tenant_id)
                .cloned()
                .unwrap_or_else(TenantDetectorConfig::all_enabled),
            Err(poisoned) => {
                tracing::error!(
                    target: "sx_dlp",
                    tenant_id = %tenant_id,
                    "tenant config store mutex poisoned; falling back to permissive default",
                );
                poisoned
                    .into_inner()
                    .get(tenant_id)
                    .cloned()
                    .unwrap_or_else(TenantDetectorConfig::all_enabled)
            }
        }
    }

    /// Replace the config for `tenant_id` and return the stored value.
    pub fn put(&self, tenant_id: &str, cfg: TenantDetectorConfig) -> TenantDetectorConfig {
        if let Ok(mut g) = self.inner.lock() {
            let _ = g.insert(tenant_id.to_owned(), cfg.clone());
        } else {
            tracing::error!(
                target: "sx_dlp",
                tenant_id = %tenant_id,
                "tenant config store mutex poisoned; put skipped",
            );
        }
        cfg
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn default_enables_every_kind() {
        let cfg = TenantDetectorConfig::default();
        assert!(cfg.is_enabled(DlpMatchKind::CreditCard));
        assert!(cfg.is_enabled(DlpMatchKind::SsnUs));
        assert!(cfg.is_enabled(DlpMatchKind::AwsAccessKey));
        assert!(cfg.is_enabled(DlpMatchKind::AwsSecretKey));
        assert!(cfg.is_enabled(DlpMatchKind::GithubPat));
        assert!(cfg.is_enabled(DlpMatchKind::Jwt));
        assert!(cfg.is_enabled(DlpMatchKind::PemPrivateKey));
        assert!(cfg.is_enabled(DlpMatchKind::Email));
        assert!(cfg.is_enabled(DlpMatchKind::Phone));
        assert!(cfg.is_enabled(DlpMatchKind::GcpServiceAccount));
        assert!(cfg.is_enabled(DlpMatchKind::SlackToken));
        assert!(cfg.is_enabled(DlpMatchKind::NamedEntity));
    }

    #[test]
    fn empty_config_disables_everything() {
        let cfg = TenantDetectorConfig {
            enabled: BTreeSet::new(),
            min_confidence: DEFAULT_MIN_CONFIDENCE,
        };
        assert!(!cfg.is_enabled(DlpMatchKind::CreditCard));
        assert!(!cfg.is_enabled(DlpMatchKind::Email));
    }

    #[test]
    fn default_min_confidence_is_permissive() {
        let cfg = TenantDetectorConfig::default();
        assert!((cfg.effective_min_confidence() - DEFAULT_MIN_CONFIDENCE).abs() < f32::EPSILON);
    }

    #[test]
    fn with_min_confidence_clamps_into_unit() {
        let cfg = TenantDetectorConfig::all_enabled().with_min_confidence(1.7);
        assert!((cfg.effective_min_confidence() - 1.0).abs() < f32::EPSILON);
        let cfg = TenantDetectorConfig::all_enabled().with_min_confidence(-0.4);
        assert!(cfg.effective_min_confidence().abs() < f32::EPSILON);
        let cfg = TenantDetectorConfig::all_enabled().with_min_confidence(f32::NAN);
        assert!((cfg.effective_min_confidence() - DEFAULT_MIN_CONFIDENCE).abs() < f32::EPSILON);
    }

    #[test]
    fn missing_min_confidence_in_json_deserialises_as_default() {
        // Back-compat: legacy callers that emit `{ "enabled": [...] }`
        // without a `min_confidence` field must keep working.
        let body = r#"{"enabled":["email"]}"#;
        let cfg: TenantDetectorConfig = serde_json::from_str(body).unwrap();
        assert!(cfg.is_enabled(DlpMatchKind::Email));
        assert!((cfg.effective_min_confidence() - DEFAULT_MIN_CONFIDENCE).abs() < f32::EPSILON);
    }

    #[test]
    fn store_falls_back_to_permissive_default_when_missing() {
        let s = TenantDetectorConfigStore::new();
        let cfg = s.get("never-touched");
        assert!(cfg.is_enabled(DlpMatchKind::Email));
    }

    #[test]
    fn store_round_trips_put_then_get() {
        let s = TenantDetectorConfigStore::new();
        let mut set = BTreeSet::new();
        let _ = set.insert(DlpMatchKind::Email);
        let cfg = TenantDetectorConfig {
            enabled: set,
            min_confidence: DEFAULT_MIN_CONFIDENCE,
        };
        let _ = s.put("t1", cfg.clone());
        let back = s.get("t1");
        assert_eq!(back, cfg);
        assert!(back.is_enabled(DlpMatchKind::Email));
        assert!(!back.is_enabled(DlpMatchKind::CreditCard));
    }

    #[test]
    fn enabled_vec_matches_btreeset_iteration_order() {
        let cfg = TenantDetectorConfig::all_enabled();
        let v = cfg.enabled_vec();
        // BTreeSet sorts by `Ord` (enum declaration order). We only
        // require the vec to be stable and de-duplicated — i.e. equal
        // length to the underlying set with the same content.
        assert_eq!(v.len(), cfg.enabled.len());
        for kind in &v {
            assert!(cfg.enabled.contains(kind));
        }
    }

    #[test]
    fn config_round_trips_json() {
        let cfg = TenantDetectorConfig::all_enabled();
        let raw = serde_json::to_string(&cfg).unwrap();
        let back: TenantDetectorConfig = serde_json::from_str(&raw).unwrap();
        assert_eq!(back, cfg);
    }
}
