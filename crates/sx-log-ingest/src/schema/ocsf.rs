//! OCSF (Open Cybersecurity Schema Framework) v1.x canonical event model.
//!
//! This is a minimal, MVP-shaped subset of OCSF aimed at carrying enough
//! signal for the SOC correlator and downstream analytics without
//! committing to the full per-class schema surface. Classes the platform
//! ingests today (e.g. CloudTrail API activity, syslog, Suricata EVE) are
//! mapped onto the `class_uid` + `category_uid` UID space defined by the
//! schema; richer per-class projections will follow.
//!
//! ## Wire shape
//!
//! ```json
//! {
//!   "class_uid": 6003,
//!   "category_uid": 6,
//!   "time": "2026-06-12T10:30:01Z",
//!   "severity_id": 3,
//!   "raw": "<original payload>",
//!   "metadata": {
//!     "version": "1.1.0",
//!     "product": "AWS CloudTrail",
//!     "source_type": "cloudtrail",
//!     "tenant_id": "01010101-…"
//!   },
//!   "observables": [
//!     { "name": "src_ip", "type": "ip", "value": "203.0.113.5" }
//!   ]
//! }
//! ```

use serde::{Deserialize, Serialize};

/// OCSF severity bucket — drives downstream alerting weight.
///
/// Mirrors the OCSF `severity_id` 0..6 enumeration. We keep the canonical
/// `i32` representation in [`OcsfEvent::severity_id`]; this enum is a
/// convenience helper for parsers and tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(i32)]
pub enum Severity {
    /// Severity could not be determined.
    Unknown = 0,
    /// Informational signal.
    Informational = 1,
    /// Low-severity event.
    Low = 2,
    /// Medium-severity event.
    Medium = 3,
    /// High-severity event.
    High = 4,
    /// Critical-severity event.
    Critical = 5,
    /// Fatal severity.
    Fatal = 6,
}

impl Severity {
    /// Convert the enum to its canonical OCSF `severity_id` integer.
    #[must_use]
    pub const fn as_id(self) -> i32 {
        self as i32
    }

    /// Lowercase canonical label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Informational => "informational",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
            Self::Fatal => "fatal",
        }
    }
}

/// OCSF metadata sub-object.
///
/// Carries provenance + tenant binding. The `source_type` is set by the
/// parser registry and is used to route the event through the correct
/// parser. `tenant_id` is set by the ingestion controller from the
/// caller's authenticated claims.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OcsfMetadata {
    /// OCSF schema version, e.g. `"1.1.0"`.
    pub version: String,
    /// Origin product (e.g. `"AWS CloudTrail"`, `"Suricata"`, `"syslog"`).
    pub product: String,
    /// Parser/source token (e.g. `"cloudtrail"`, `"syslog_rfc5424"`,
    /// `"suricata_eve"`) — keyed against [`crate::registry::LogParserRegistry`].
    pub source_type: String,
    /// Owning tenant (UUID string). Populated by the ingestion service.
    pub tenant_id: String,
}

impl OcsfMetadata {
    /// Construct a metadata bundle. `tenant_id` is left empty when the
    /// parser is called outside the ingestion service — the service then
    /// stamps it before persistence.
    #[must_use]
    pub fn new(product: impl Into<String>, source_type: impl Into<String>) -> Self {
        Self {
            version: "1.1.0".to_owned(),
            product: product.into(),
            source_type: source_type.into(),
            tenant_id: String::new(),
        }
    }
}

/// OCSF observable — a typed (key, value) pair for IOCs and entities.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Observable {
    /// Friendly name (e.g. `"src_ip"`, `"user.name"`).
    pub name: String,
    /// Observable type label (e.g. `"ip"`, `"user"`, `"hostname"`).
    #[serde(rename = "type")]
    pub kind: String,
    /// Observable value.
    pub value: String,
}

impl Observable {
    /// Helper constructor for parser sites.
    #[must_use]
    pub fn new(name: impl Into<String>, kind: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            kind: kind.into(),
            value: value.into(),
        }
    }
}

/// Canonical OCSF event projection.
///
/// Minimal MVP shape: each parser produces one of these per input record.
/// `raw` carries the original payload (capped by callers) so analysts can
/// retrieve the source verbatim. The `class_uid` and `category_uid` follow
/// OCSF's UID taxonomy (e.g. category 4 = Network Activity, class 4001 =
/// Network Activity).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OcsfEvent {
    /// OCSF class identifier — e.g. `3002` (Authentication), `4001`
    /// (Network Activity), `6003` (API Activity).
    pub class_uid: i32,
    /// OCSF category identifier — e.g. `3` (IAM), `4` (Network Activity),
    /// `6` (Application Activity).
    pub category_uid: i32,
    /// Event time in RFC 3339 / ISO 8601. Parsers preserve the upstream
    /// timestamp when available, else stamp `now_utc()`.
    pub time: String,
    /// Canonical OCSF severity_id (0..6). See [`Severity`].
    pub severity_id: i32,
    /// Original payload bytes/text. Capped by the ingest service.
    pub raw: String,
    /// Metadata bundle. Carries source-type + tenant binding.
    pub metadata: OcsfMetadata,
    /// Typed observable pairs for IOC extraction.
    pub observables: Vec<Observable>,
}

impl OcsfEvent {
    /// Length cap applied to `raw` by the ingestion service before
    /// persistence — keeps the in-memory ring buffer footprint bounded
    /// even under adversarial input.
    pub const MAX_RAW_BYTES: usize = 16 * 1024;

    /// Construct a new event with empty observables. Helper for parsers.
    #[must_use]
    pub fn new(
        class_uid: i32,
        category_uid: i32,
        time: impl Into<String>,
        severity: Severity,
        raw: impl Into<String>,
        metadata: OcsfMetadata,
    ) -> Self {
        Self {
            class_uid,
            category_uid,
            time: time.into(),
            severity_id: severity.as_id(),
            raw: raw.into(),
            metadata,
            observables: Vec::new(),
        }
    }

    /// Append an observable and return self for chaining.
    #[must_use]
    pub fn with_observable(mut self, observable: Observable) -> Self {
        self.observables.push(observable);
        self
    }

    /// Truncate `raw` to [`Self::MAX_RAW_BYTES`] on a UTF-8 char boundary.
    pub fn cap_raw(&mut self) {
        if self.raw.len() <= Self::MAX_RAW_BYTES {
            return;
        }
        // Walk back to a char boundary to avoid splitting a UTF-8 sequence.
        let mut idx = Self::MAX_RAW_BYTES;
        while idx > 0 && !self.raw.is_char_boundary(idx) {
            idx -= 1;
        }
        self.raw.truncate(idx);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn severity_as_id_matches_repr() {
        assert_eq!(Severity::Unknown.as_id(), 0);
        assert_eq!(Severity::Informational.as_id(), 1);
        assert_eq!(Severity::Low.as_id(), 2);
        assert_eq!(Severity::Medium.as_id(), 3);
        assert_eq!(Severity::High.as_id(), 4);
        assert_eq!(Severity::Critical.as_id(), 5);
        assert_eq!(Severity::Fatal.as_id(), 6);
    }

    #[test]
    fn severity_labels_canonical() {
        assert_eq!(Severity::High.as_str(), "high");
        assert_eq!(Severity::Informational.as_str(), "informational");
    }

    #[test]
    fn event_round_trips_through_json() {
        let ev = OcsfEvent::new(
            6003,
            6,
            "2026-06-12T10:30:01Z",
            Severity::Medium,
            "raw payload",
            OcsfMetadata::new("AWS CloudTrail", "cloudtrail"),
        )
        .with_observable(Observable::new("src_ip", "ip", "203.0.113.5"));
        let s = serde_json::to_string(&ev).unwrap();
        let back: OcsfEvent = serde_json::from_str(&s).unwrap();
        assert_eq!(ev, back);
        assert!(s.contains("\"class_uid\":6003"));
        assert!(s.contains("\"category_uid\":6"));
        assert!(s.contains("\"severity_id\":3"));
    }

    #[test]
    fn cap_raw_truncates_oversized_payload() {
        let big = "a".repeat(OcsfEvent::MAX_RAW_BYTES + 4096);
        let mut ev = OcsfEvent::new(
            0,
            0,
            "1970-01-01T00:00:00Z",
            Severity::Unknown,
            big,
            OcsfMetadata::new("p", "s"),
        );
        ev.cap_raw();
        assert!(ev.raw.len() <= OcsfEvent::MAX_RAW_BYTES);
    }

    #[test]
    fn cap_raw_respects_utf8_boundary() {
        // Build a payload where the cut would land mid-codepoint.
        let mut s = "a".repeat(OcsfEvent::MAX_RAW_BYTES - 1);
        s.push('é'); // 2-byte
        s.push_str(&"b".repeat(100));
        let mut ev = OcsfEvent::new(
            0,
            0,
            "1970-01-01T00:00:00Z",
            Severity::Unknown,
            s,
            OcsfMetadata::new("p", "s"),
        );
        ev.cap_raw();
        // Must still be valid UTF-8 (i.e. not panic on as_str()).
        let _ = ev.raw.as_str();
        assert!(ev.raw.len() <= OcsfEvent::MAX_RAW_BYTES);
    }

    #[test]
    fn cap_raw_noop_when_small() {
        let mut ev = OcsfEvent::new(
            0,
            0,
            "1970-01-01T00:00:00Z",
            Severity::Unknown,
            "small",
            OcsfMetadata::new("p", "s"),
        );
        ev.cap_raw();
        assert_eq!(ev.raw, "small");
    }
}
