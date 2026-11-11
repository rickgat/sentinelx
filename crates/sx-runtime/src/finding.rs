//! [`RuntimeFinding`] — the SentinelX-side DTO emitted per Falco alert.
//!
//! Findings are produced after the alert has been authenticated, parsed,
//! and normalised to OCSF. They carry both the normalised OCSF event and
//! a small set of cherry-picked fields (rule, severity, `asset_id`) so the
//! SOC pipeline can fan-out without re-parsing the OCSF payload.

use serde::{Deserialize, Serialize};
use sx_log_ingest::schema::ocsf::Severity as OcsfSeverity;

use crate::alert::FalcoPriority;

/// SentinelX-side severity bucket for runtime findings.
///
/// Numerically aligned with the SOC severity ladder used elsewhere in the
/// monorepo, plus a canonical lowercase label suitable for tracing fields,
/// metrics labels, and database columns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RuntimeSeverity {
    /// Informational signal — surfaced for visibility, no escalation.
    Info,
    /// Low-impact finding.
    Low,
    /// Medium-impact finding.
    Medium,
    /// High-impact finding — typical for shell-in-container.
    High,
    /// Critical-impact finding — typical for privileged escape / token
    /// mount.
    Critical,
}

impl RuntimeSeverity {
    /// Canonical lowercase label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    /// Project onto the canonical OCSF severity id.
    #[must_use]
    pub const fn to_ocsf(self) -> OcsfSeverity {
        match self {
            Self::Info => OcsfSeverity::Informational,
            Self::Low => OcsfSeverity::Low,
            Self::Medium => OcsfSeverity::Medium,
            Self::High => OcsfSeverity::High,
            Self::Critical => OcsfSeverity::Critical,
        }
    }

    /// Bump the severity one tier up the ladder, saturating at
    /// [`RuntimeSeverity::Critical`]. Used by HIGH-006
    /// `OverrideAction::Escalate`.
    #[must_use]
    pub const fn escalate(self) -> Self {
        match self {
            Self::Info => Self::Low,
            Self::Low => Self::Medium,
            Self::Medium => Self::High,
            Self::High | Self::Critical => Self::Critical,
        }
    }

    /// Drop the severity one tier down the ladder, saturating at
    /// [`RuntimeSeverity::Info`]. Used by HIGH-006
    /// `OverrideAction::Downgrade`.
    #[must_use]
    pub const fn downgrade(self) -> Self {
        match self {
            Self::Critical => Self::High,
            Self::High => Self::Medium,
            Self::Medium => Self::Low,
            Self::Low | Self::Info => Self::Info,
        }
    }
}

/// Deterministic Falco-priority -> SentinelX-severity mapping.
///
/// The mapping is conservative: anything `Emergency`/`Alert`/`Critical`
/// becomes [`RuntimeSeverity::Critical`]; `Error` -> `High`; `Warning` ->
/// `Medium`; `Notice` -> `Low`; everything informational / debug stays
/// `Info`.
#[must_use]
pub const fn map_priority(p: FalcoPriority) -> RuntimeSeverity {
    match p {
        FalcoPriority::Emergency | FalcoPriority::Alert | FalcoPriority::Critical => {
            RuntimeSeverity::Critical
        }
        FalcoPriority::Error => RuntimeSeverity::High,
        FalcoPriority::Warning => RuntimeSeverity::Medium,
        FalcoPriority::Notice => RuntimeSeverity::Low,
        FalcoPriority::Informational | FalcoPriority::Debug => RuntimeSeverity::Info,
    }
}

/// `SentinelX` runtime finding emitted per accepted Falco alert.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeFinding {
    /// Stable UUID-v7 finding id, generated at acceptance time.
    pub finding_id: String,

    /// Owning tenant.
    pub tenant_id: String,

    /// Matched Falco rule, mirrored verbatim.
    pub rule: String,

    /// Lowercase canonical severity (`info` / `low` / `medium` / `high` /
    /// `critical`).
    pub severity: RuntimeSeverity,

    /// RFC 3339 event time — equals the OCSF `time` field.
    pub time: String,

    /// Best-effort `SentinelX` `asset_id` resolved from container image +
    /// pod name. `None` when the asset graph could not resolve a match.
    pub asset_id: Option<String>,

    /// Container image repository pulled out of the Falco output fields.
    pub container_image: Option<String>,

    /// Kubernetes pod name, when present in the Falco output fields.
    pub pod_name: Option<String>,

    /// Kubernetes namespace, when present.
    pub namespace: Option<String>,

    /// Falco source label (`syscall`, `k8s_audit`, ...).
    pub source: String,

    /// Falco-stamped MITRE ATT&CK / capability tags, preserved verbatim.
    pub tags: Vec<String>,

    /// Rendered Falco alert text. Capped before persistence by callers.
    pub output: String,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn severity_labels_canonical() {
        assert_eq!(RuntimeSeverity::Critical.as_str(), "critical");
        assert_eq!(RuntimeSeverity::Info.as_str(), "info");
    }

    #[test]
    fn priority_to_severity_is_deterministic() {
        assert_eq!(
            map_priority(FalcoPriority::Emergency),
            RuntimeSeverity::Critical
        );
        assert_eq!(
            map_priority(FalcoPriority::Alert),
            RuntimeSeverity::Critical
        );
        assert_eq!(
            map_priority(FalcoPriority::Critical),
            RuntimeSeverity::Critical
        );
        assert_eq!(map_priority(FalcoPriority::Error), RuntimeSeverity::High);
        assert_eq!(
            map_priority(FalcoPriority::Warning),
            RuntimeSeverity::Medium
        );
        assert_eq!(map_priority(FalcoPriority::Notice), RuntimeSeverity::Low);
        assert_eq!(
            map_priority(FalcoPriority::Informational),
            RuntimeSeverity::Info
        );
        assert_eq!(map_priority(FalcoPriority::Debug), RuntimeSeverity::Info);
    }

    #[test]
    fn severity_escalate_climbs_one_tier_and_saturates_at_critical() {
        assert_eq!(RuntimeSeverity::Info.escalate(), RuntimeSeverity::Low);
        assert_eq!(RuntimeSeverity::Low.escalate(), RuntimeSeverity::Medium);
        assert_eq!(RuntimeSeverity::Medium.escalate(), RuntimeSeverity::High);
        assert_eq!(RuntimeSeverity::High.escalate(), RuntimeSeverity::Critical);
        assert_eq!(
            RuntimeSeverity::Critical.escalate(),
            RuntimeSeverity::Critical
        );
    }

    #[test]
    fn severity_downgrade_drops_one_tier_and_saturates_at_info() {
        assert_eq!(RuntimeSeverity::Critical.downgrade(), RuntimeSeverity::High);
        assert_eq!(RuntimeSeverity::High.downgrade(), RuntimeSeverity::Medium);
        assert_eq!(RuntimeSeverity::Medium.downgrade(), RuntimeSeverity::Low);
        assert_eq!(RuntimeSeverity::Low.downgrade(), RuntimeSeverity::Info);
        assert_eq!(RuntimeSeverity::Info.downgrade(), RuntimeSeverity::Info);
    }

    #[test]
    fn ocsf_projection_matches_severity_ladder() {
        assert_eq!(RuntimeSeverity::Critical.to_ocsf(), OcsfSeverity::Critical);
        assert_eq!(RuntimeSeverity::High.to_ocsf(), OcsfSeverity::High);
        assert_eq!(RuntimeSeverity::Medium.to_ocsf(), OcsfSeverity::Medium);
        assert_eq!(RuntimeSeverity::Low.to_ocsf(), OcsfSeverity::Low);
        assert_eq!(RuntimeSeverity::Info.to_ocsf(), OcsfSeverity::Informational);
    }

    #[test]
    fn finding_round_trips_through_json() {
        let f = RuntimeFinding {
            finding_id: "01010101-0101-7000-8000-000000000001".into(),
            tenant_id: "t1".into(),
            rule: "Terminal shell in container".into(),
            severity: RuntimeSeverity::High,
            time: "2026-06-12T10:30:01Z".into(),
            asset_id: Some("asset-123".into()),
            container_image: Some("nginx".into()),
            pod_name: Some("web-1".into()),
            namespace: Some("prod".into()),
            source: "syscall".into(),
            tags: vec!["shell".into(), "mitre_execution".into()],
            output: "shell spawned".into(),
        };
        let s = serde_json::to_string(&f).unwrap();
        let back: RuntimeFinding = serde_json::from_str(&s).unwrap();
        assert_eq!(f, back);
    }
}
