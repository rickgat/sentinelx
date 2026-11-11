//! Suricata EVE JSON → OCSF parser.
//!
//! Suricata's EVE JSON event log is a single JSON object per record.
//! Common `event_type`s include `alert`, `dns`, `http`, `tls`, `flow`,
//! `fileinfo`. We map `alert` records to OCSF Detection Finding
//! (category 2, class 2004) and the network/flow types to OCSF Network
//! Activity (category 4, class 4001). The full payload is preserved
//! verbatim in `raw`.

use serde_json::Value;

use super::LogParser;
use crate::error::ParseError;
use crate::schema::{Observable, OcsfEvent, OcsfMetadata, Severity};

/// OCSF class — Network Activity.
pub const CLASS_NETWORK_ACTIVITY: i32 = 4001;
/// OCSF category — Network Activity.
pub const CATEGORY_NETWORK_ACTIVITY: i32 = 4;
/// OCSF class — Detection Finding.
pub const CLASS_DETECTION_FINDING: i32 = 2004;
/// OCSF category — Findings.
pub const CATEGORY_FINDINGS: i32 = 2;
/// Source-type token for the registry.
pub const SOURCE_TYPE: &str = "suricata_eve";

/// Stateless Suricata EVE JSON parser.
#[derive(Debug, Default, Clone, Copy)]
pub struct SuricataEveParser;

impl SuricataEveParser {
    /// Construct a new parser.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl LogParser for SuricataEveParser {
    fn source_type(&self) -> &'static str {
        SOURCE_TYPE
    }

    fn parse(&self, payload: &str) -> Result<OcsfEvent, ParseError> {
        if payload.len() > OcsfEvent::MAX_RAW_BYTES {
            return Err(ParseError::TooLarge(payload.len()));
        }
        let v: Value = serde_json::from_str(payload)
            .map_err(|e| ParseError::Malformed(format!("invalid JSON: {e}")))?;

        let timestamp = string_field(&v, "timestamp")
            .ok_or_else(|| ParseError::MissingField("timestamp".into()))?;
        let event_type = string_field(&v, "event_type").unwrap_or_else(|| "unknown".to_owned());
        let src_ip = string_field(&v, "src_ip");
        let dest_ip = string_field(&v, "dest_ip");
        let src_port = number_field(&v, "src_port");
        let dest_port = number_field(&v, "dest_port");
        let proto = string_field(&v, "proto");
        let app_proto = string_field(&v, "app_proto");

        let (class_uid, category_uid, severity) = if event_type == "alert" {
            let sev_id = v
                .get("alert")
                .and_then(|a| a.get("severity"))
                .and_then(Value::as_i64)
                .map_or(Severity::Medium, suricata_severity);
            (CLASS_DETECTION_FINDING, CATEGORY_FINDINGS, sev_id)
        } else {
            (
                CLASS_NETWORK_ACTIVITY,
                CATEGORY_NETWORK_ACTIVITY,
                Severity::Informational,
            )
        };

        let metadata = OcsfMetadata::new(format!("Suricata ({event_type})"), SOURCE_TYPE);

        let mut event = OcsfEvent::new(
            class_uid,
            category_uid,
            timestamp,
            severity,
            payload,
            metadata,
        );

        event.observables.push(Observable::new(
            "event.type",
            "event_type",
            event_type.clone(),
        ));
        if let Some(ip) = src_ip {
            event.observables.push(Observable::new("src_ip", "ip", ip));
        }
        if let Some(ip) = dest_ip {
            event.observables.push(Observable::new("dest_ip", "ip", ip));
        }
        if let Some(p) = src_port {
            event
                .observables
                .push(Observable::new("src_port", "port", p.to_string()));
        }
        if let Some(p) = dest_port {
            event
                .observables
                .push(Observable::new("dest_port", "port", p.to_string()));
        }
        if let Some(p) = proto {
            event
                .observables
                .push(Observable::new("proto", "protocol", p));
        }
        if let Some(p) = app_proto {
            event
                .observables
                .push(Observable::new("app_proto", "application_protocol", p));
        }

        if event_type == "alert" {
            if let Some(alert) = v.get("alert") {
                if let Some(sig) = alert.get("signature").and_then(Value::as_str) {
                    event
                        .observables
                        .push(Observable::new("alert.signature", "signature", sig));
                }
                if let Some(sid) = alert.get("signature_id").and_then(Value::as_i64) {
                    event.observables.push(Observable::new(
                        "alert.signature_id",
                        "signature_id",
                        sid.to_string(),
                    ));
                }
                if let Some(category) = alert.get("category").and_then(Value::as_str) {
                    event
                        .observables
                        .push(Observable::new("alert.category", "category", category));
                }
            }
        }

        event.cap_raw();
        Ok(event)
    }
}

fn string_field(v: &Value, name: &str) -> Option<String> {
    v.get(name).and_then(Value::as_str).map(ToOwned::to_owned)
}

fn number_field(v: &Value, name: &str) -> Option<i64> {
    v.get(name).and_then(Value::as_i64)
}

/// Suricata alert severity 1..3 (1 = high, 3 = low). Map to OCSF.
const fn suricata_severity(s: i64) -> Severity {
    match s {
        1 => Severity::High,
        2 => Severity::Medium,
        3 => Severity::Low,
        _ => Severity::Informational,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const FIXTURE_ALERT: &str = r#"{
        "timestamp": "2026-06-12T10:30:01.234567+0000",
        "flow_id": 1234567890,
        "event_type": "alert",
        "src_ip": "203.0.113.5",
        "src_port": 51234,
        "dest_ip": "10.0.0.20",
        "dest_port": 80,
        "proto": "TCP",
        "app_proto": "http",
        "alert": {
            "action": "allowed",
            "gid": 1,
            "signature_id": 2027390,
            "rev": 1,
            "signature": "ET WEB_SERVER PHP tags in HTTP POST",
            "category": "Web Application Attack",
            "severity": 1
        }
    }"#;

    const FIXTURE_DNS: &str = r#"{
        "timestamp": "2026-06-12T10:31:00.000Z",
        "event_type": "dns",
        "src_ip": "10.0.0.20",
        "src_port": 33333,
        "dest_ip": "8.8.8.8",
        "dest_port": 53,
        "proto": "UDP",
        "dns": {"type": "query", "rrname": "evil.example.com"}
    }"#;

    #[test]
    fn parser_advertises_source_type() {
        let p = SuricataEveParser::new();
        assert_eq!(p.source_type(), "suricata_eve");
    }

    #[test]
    fn alert_record_maps_to_detection_finding() {
        let p = SuricataEveParser::new();
        let ev = p.parse(FIXTURE_ALERT).unwrap();
        assert_eq!(ev.class_uid, CLASS_DETECTION_FINDING);
        assert_eq!(ev.category_uid, CATEGORY_FINDINGS);
        assert_eq!(ev.severity_id, Severity::High.as_id());
        assert!(ev
            .observables
            .iter()
            .any(|o| o.name == "alert.signature" && o.value.contains("PHP tags")));
        assert!(ev
            .observables
            .iter()
            .any(|o| o.name == "alert.signature_id" && o.value == "2027390"));
    }

    #[test]
    fn dns_record_maps_to_network_activity() {
        let p = SuricataEveParser::new();
        let ev = p.parse(FIXTURE_DNS).unwrap();
        assert_eq!(ev.class_uid, CLASS_NETWORK_ACTIVITY);
        assert_eq!(ev.category_uid, CATEGORY_NETWORK_ACTIVITY);
        assert_eq!(ev.severity_id, Severity::Informational.as_id());
        assert!(ev
            .observables
            .iter()
            .any(|o| o.name == "src_ip" && o.value == "10.0.0.20"));
        assert!(ev
            .observables
            .iter()
            .any(|o| o.name == "dest_port" && o.value == "53"));
    }

    #[test]
    fn missing_timestamp_rejected() {
        let p = SuricataEveParser::new();
        let err = p.parse(r#"{"event_type":"dns"}"#).unwrap_err();
        assert!(matches!(err, ParseError::MissingField(f) if f == "timestamp"));
    }

    #[test]
    fn malformed_json_rejected() {
        let p = SuricataEveParser::new();
        let err = p.parse("{bad").unwrap_err();
        assert!(matches!(err, ParseError::Malformed(_)));
    }

    #[test]
    fn oversized_payload_rejected() {
        let p = SuricataEveParser::new();
        let big = format!(
            r#"{{"timestamp":"2026-06-12T10:30:01Z","event_type":"dns","pad":"{}"}}"#,
            "x".repeat(OcsfEvent::MAX_RAW_BYTES + 1024)
        );
        let err = p.parse(&big).unwrap_err();
        assert!(matches!(err, ParseError::TooLarge(_)));
    }

    #[test]
    fn unknown_event_type_defaults_to_network() {
        let p = SuricataEveParser::new();
        let ev = p
            .parse(r#"{"timestamp":"2026-06-12T10:30:01Z","event_type":"flow"}"#)
            .unwrap();
        assert_eq!(ev.class_uid, CLASS_NETWORK_ACTIVITY);
    }
}
