//! Falco alert wire shape.
//!
//! Falco emits a stream of newline-delimited JSON alerts over its HTTP
//! sink, gRPC stream, or `falcosidekick` fan-out. The wire shape is
//! documented at <https://falco.org/docs/alerts/>. The fields used by this
//! crate are intentionally a stable subset:
//!
//! - `rule` — the matched Falco rule name.
//! - `priority` — `Emergency`, `Alert`, `Critical`, `Error`, `Warning`,
//!   `Notice`, `Informational`, or `Debug`.
//! - `output` — the rendered alert text.
//! - `time` — the alert timestamp (RFC 3339).
//! - `output_fields` — a free-form map; we cherry-pick
//!   `container.id`, `container.image.repository`, `k8s.pod.name`,
//!   `k8s.ns.name`, `proc.name`, `proc.cmdline`, `user.name`, plus the
//!   originating host.
//!
//! Unknown fields on the wire are tolerated via `#[serde(default)]` and
//! the `output_fields` catch-all.

use serde::{Deserialize, Serialize};

/// Falco priority bucket as emitted on the wire.
///
/// The `Debug` and `Informational` levels are tolerated but never escalate
/// to a `SentinelX` finding above `Low`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FalcoPriority {
    /// `Emergency` — highest Falco severity. System is unusable.
    #[serde(alias = "Emergency", alias = "EMERGENCY")]
    Emergency,
    /// `Alert` — action must be taken immediately.
    #[serde(alias = "Alert", alias = "ALERT")]
    Alert,
    /// `Critical` — critical conditions, escalates to `SentinelX` `Critical`.
    #[serde(alias = "Critical", alias = "CRITICAL")]
    Critical,
    /// `Error` — error conditions.
    #[serde(alias = "Error", alias = "ERROR")]
    Error,
    /// `Warning` — warning conditions.
    #[serde(alias = "Warning", alias = "WARNING")]
    Warning,
    /// `Notice` — normal but significant condition.
    #[serde(alias = "Notice", alias = "NOTICE")]
    Notice,
    /// `Informational` — informational messages only.
    #[serde(
        alias = "Informational",
        alias = "INFORMATIONAL",
        alias = "Info",
        alias = "INFO"
    )]
    Informational,
    /// `Debug` — debug-level messages.
    #[serde(alias = "Debug", alias = "DEBUG")]
    Debug,
}

impl FalcoPriority {
    /// Canonical lowercase label, used for tracing fields and metrics
    /// labels.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Emergency => "emergency",
            Self::Alert => "alert",
            Self::Critical => "critical",
            Self::Error => "error",
            Self::Warning => "warning",
            Self::Notice => "notice",
            Self::Informational => "informational",
            Self::Debug => "debug",
        }
    }
}

/// Falco alert projection — a stable subset of the wire JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FalcoAlert {
    /// Matched Falco rule name, e.g. `"Terminal shell in container"`.
    pub rule: String,

    /// Falco priority bucket.
    pub priority: FalcoPriority,

    /// Rendered alert text. Capped before persistence by callers.
    #[serde(default)]
    pub output: String,

    /// Alert timestamp in RFC 3339 / ISO 8601. Defaults to the empty
    /// string when the Falco source did not stamp one; callers replace
    /// the value with the receive-time when normalising.
    #[serde(default)]
    pub time: String,

    /// Falco source label — `syscall`, `k8s_audit`, etc. Defaults to
    /// `"syscall"` because it is the dominant source by volume.
    #[serde(default = "default_source")]
    pub source: String,

    /// Free-form map of Falco output fields.
    #[serde(default)]
    pub output_fields: serde_json::Map<String, serde_json::Value>,

    /// Originating host name, when stamped by Falco's `host` envelope.
    #[serde(default)]
    pub hostname: Option<String>,

    /// Falco-stamped tags. Often used to carry MITRE ATT&CK technique
    /// IDs (e.g. `T1611`).
    #[serde(default)]
    pub tags: Vec<String>,
}

fn default_source() -> String {
    "syscall".to_owned()
}

impl FalcoAlert {
    /// Helper accessor — pull a string-valued output field by key.
    #[must_use]
    pub fn field_str(&self, key: &str) -> Option<&str> {
        self.output_fields.get(key)?.as_str()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn priority_round_trips() {
        let json = r#""Critical""#;
        let p: FalcoPriority = serde_json::from_str(json).unwrap();
        assert_eq!(p, FalcoPriority::Critical);
        assert_eq!(p.as_str(), "critical");
        let back = serde_json::to_string(&p).unwrap();
        assert_eq!(back, r#""Critical""#);
    }

    #[test]
    fn parses_minimal_alert() {
        let json = r#"{
            "rule": "Test rule",
            "priority": "Warning",
            "output": "something happened",
            "time": "2026-06-12T10:30:01.123456Z"
        }"#;
        let a: FalcoAlert = serde_json::from_str(json).unwrap();
        assert_eq!(a.rule, "Test rule");
        assert_eq!(a.priority, FalcoPriority::Warning);
        assert_eq!(a.source, "syscall");
    }

    #[test]
    fn field_str_returns_string_value() {
        let json = r#"{
            "rule": "r",
            "priority": "Notice",
            "output_fields": { "k8s.pod.name": "web-1", "n": 42 }
        }"#;
        let a: FalcoAlert = serde_json::from_str(json).unwrap();
        assert_eq!(a.field_str("k8s.pod.name"), Some("web-1"));
        assert_eq!(a.field_str("n"), None);
    }
}
