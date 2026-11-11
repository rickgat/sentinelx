//! Syslog (RFC 5424) → OCSF parser.
//!
//! Implements a tolerant subset of RFC 5424:
//!
//! ```text
//! <PRI>VER TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [SD-DATA...] MSG
//! ```
//!
//! Single dashes (`-`) signal a NIL field per RFC 5424 §6.2.1. Structured
//! data is captured verbatim; the message tail is preserved in `raw`.
//!
//! Output class maps to OCSF System Activity (category 1, class 1003 —
//! OS-Type process activity).

use super::LogParser;
use crate::error::ParseError;
use crate::schema::{Observable, OcsfEvent, OcsfMetadata, Severity};

/// OCSF class — Process Activity.
pub const CLASS_PROCESS_ACTIVITY: i32 = 1003;
/// OCSF category — System Activity.
pub const CATEGORY_SYSTEM_ACTIVITY: i32 = 1;
/// Source-type token for the registry.
pub const SOURCE_TYPE: &str = "syslog_rfc5424";

/// Stateless RFC 5424 syslog parser.
#[derive(Debug, Default, Clone, Copy)]
pub struct Rfc5424Parser;

impl Rfc5424Parser {
    /// Construct a new parser.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl LogParser for Rfc5424Parser {
    fn source_type(&self) -> &'static str {
        SOURCE_TYPE
    }

    fn parse(&self, payload: &str) -> Result<OcsfEvent, ParseError> {
        if payload.len() > OcsfEvent::MAX_RAW_BYTES {
            return Err(ParseError::TooLarge(payload.len()));
        }
        let trimmed = payload.trim_end_matches(['\n', '\r']);
        let Some(parsed) = parse_rfc5424(trimmed) else {
            return Err(ParseError::Malformed(
                "header did not match RFC 5424 grammar".into(),
            ));
        };

        let severity = severity_from_pri(parsed.pri);
        let mut metadata = OcsfMetadata::new("syslog", SOURCE_TYPE);
        if !parsed.app_name.is_empty() {
            metadata.product = format!("syslog ({})", parsed.app_name);
        }

        let mut event = OcsfEvent::new(
            CLASS_PROCESS_ACTIVITY,
            CATEGORY_SYSTEM_ACTIVITY,
            parsed.timestamp,
            severity,
            payload,
            metadata,
        );

        if !parsed.hostname.is_empty() {
            event
                .observables
                .push(Observable::new("hostname", "hostname", parsed.hostname));
        }
        if !parsed.app_name.is_empty() {
            event
                .observables
                .push(Observable::new("process.name", "process", parsed.app_name));
        }
        if !parsed.procid.is_empty() {
            event
                .observables
                .push(Observable::new("process.pid", "pid", parsed.procid));
        }
        if !parsed.msgid.is_empty() {
            event
                .observables
                .push(Observable::new("msg.id", "msg_id", parsed.msgid));
        }
        if !parsed.message.is_empty() {
            event
                .observables
                .push(Observable::new("msg", "message", parsed.message));
        }

        event.cap_raw();
        Ok(event)
    }
}

/// Parsed RFC 5424 header + message.
#[derive(Debug)]
struct Parsed5424<'a> {
    pri: u16,
    timestamp: String,
    hostname: &'a str,
    app_name: &'a str,
    procid: &'a str,
    msgid: &'a str,
    message: String,
}

/// Parse a tolerant subset of RFC 5424.
///
/// Returns `None` if the priority header is missing or malformed.
#[allow(clippy::indexing_slicing)] // bounds checked before each slice
fn parse_rfc5424(line: &str) -> Option<Parsed5424<'_>> {
    if !line.starts_with('<') {
        return None;
    }
    let close = line.find('>')?;
    let pri_str = &line[1..close];
    let pri: u16 = pri_str.parse().ok()?;
    let after_pri = &line[close + 1..];

    // VERSION (single digit) is required immediately after PRI.
    let mut chars = after_pri.char_indices();
    let (_, first_char) = chars.next()?;
    if !first_char.is_ascii_digit() {
        return None;
    }
    // Skip the version digits up to the next space.
    let version_end = after_pri.find(' ')?;
    let rest = after_pri.get(version_end + 1..)?;

    let mut parts = rest.splitn(6, ' ');
    let timestamp = parts.next()?;
    let hostname = parts.next()?;
    let app_name = parts.next()?;
    let procid = parts.next()?;
    let msgid = parts.next()?;
    let tail = parts.next().unwrap_or("");

    Some(Parsed5424 {
        pri,
        timestamp: nil_to_empty(timestamp).to_owned(),
        hostname: nil_to_empty(hostname),
        app_name: nil_to_empty(app_name),
        procid: nil_to_empty(procid),
        msgid: nil_to_empty(msgid),
        message: strip_sd_prefix(tail),
    })
}

/// RFC 5424 §6.2.1: a single `-` denotes NIL; treat as empty.
fn nil_to_empty(s: &str) -> &str {
    if s == "-" {
        ""
    } else {
        s
    }
}

/// Pull the structured-data block out of the tail if present so the
/// `message` observable holds only the human-readable suffix.
#[allow(clippy::indexing_slicing)] // bounds re-checked inside
fn strip_sd_prefix(tail: &str) -> String {
    let trimmed = tail.trim_start();
    if !trimmed.starts_with('[') {
        return trimmed.to_owned();
    }
    // Walk until the matching `]` followed by space — minimal heuristic.
    let mut depth = 0_i32;
    let bytes = trimmed.as_bytes();
    let mut end_idx: Option<usize> = None;
    for (i, b) in bytes.iter().enumerate() {
        match *b {
            b'[' => depth += 1,
            b']' => {
                depth -= 1;
                if depth == 0 {
                    end_idx = Some(i + 1);
                    break;
                }
            }
            _ => {}
        }
    }
    let Some(idx) = end_idx else {
        return trimmed.to_owned();
    };
    if idx >= trimmed.len() {
        return String::new();
    }
    trimmed[idx..].trim_start().to_owned()
}

/// RFC 5424 PRI = facility * 8 + severity (0..7).
const fn severity_from_pri(pri: u16) -> Severity {
    let sev = (pri & 0b111) as u8;
    match sev {
        0..=2 => Severity::Critical,
        3 => Severity::High,
        4 => Severity::Medium,
        5..=6 => Severity::Informational,
        _ => Severity::Low,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    const FIXTURE_FULL: &str = "<134>1 2026-06-12T10:30:01.000Z host01 sshd 1234 ID47 [exampleSDID@32473 iut=\"3\" eventSource=\"App\"] BOM Failed password for user alice from 198.51.100.1 port 22";
    const FIXTURE_NIL: &str = "<13>1 2026-06-12T10:31:00Z - - - - simple message";
    const FIXTURE_CRITICAL: &str = "<2>1 2026-06-12T10:32:00Z fw01 kernel - ID01 - panic detected";

    #[test]
    fn parser_advertises_source_type() {
        let p = Rfc5424Parser::new();
        assert_eq!(p.source_type(), "syslog_rfc5424");
    }

    #[test]
    fn happy_path_parses_full_header_and_sd() {
        let p = Rfc5424Parser::new();
        let ev = p.parse(FIXTURE_FULL).unwrap();
        assert_eq!(ev.class_uid, CLASS_PROCESS_ACTIVITY);
        assert_eq!(ev.category_uid, CATEGORY_SYSTEM_ACTIVITY);
        assert_eq!(ev.time, "2026-06-12T10:30:01.000Z");
        assert!(ev
            .observables
            .iter()
            .any(|o| o.name == "hostname" && o.value == "host01"));
        assert!(ev
            .observables
            .iter()
            .any(|o| o.name == "process.name" && o.value == "sshd"));
        assert!(ev
            .observables
            .iter()
            .any(|o| o.name == "process.pid" && o.value == "1234"));
        // Structured data block must be stripped before the message capture.
        let msg = ev
            .observables
            .iter()
            .find(|o| o.name == "msg")
            .expect("msg observable");
        assert!(msg.value.contains("Failed password"));
        assert!(!msg.value.contains("exampleSDID"));
    }

    #[test]
    fn nil_fields_resolve_to_empty_observables() {
        let p = Rfc5424Parser::new();
        let ev = p.parse(FIXTURE_NIL).unwrap();
        // hostname/app/proc/msgid were NIL → those observables omitted.
        assert!(!ev.observables.iter().any(|o| o.name == "hostname"));
        assert!(!ev.observables.iter().any(|o| o.name == "process.name"));
        assert!(!ev.observables.iter().any(|o| o.name == "process.pid"));
        assert!(!ev.observables.iter().any(|o| o.name == "msg.id"));
        // Message still captured.
        assert!(ev
            .observables
            .iter()
            .any(|o| o.name == "msg" && o.value == "simple message"));
    }

    #[test]
    fn malformed_priority_rejected() {
        let p = Rfc5424Parser::new();
        let err = p.parse("not a syslog line").unwrap_err();
        assert!(matches!(err, ParseError::Malformed(_)));
    }

    #[test]
    fn missing_version_rejected() {
        let p = Rfc5424Parser::new();
        // No version digit after PRI.
        let err = p
            .parse("<134> 2026-06-12T10:30:01Z host app 1 ID -")
            .unwrap_err();
        assert!(matches!(err, ParseError::Malformed(_)));
    }

    #[test]
    fn critical_severity_derived_from_low_pri() {
        let p = Rfc5424Parser::new();
        let ev = p.parse(FIXTURE_CRITICAL).unwrap();
        assert_eq!(ev.severity_id, Severity::Critical.as_id());
    }

    #[test]
    fn raw_preserved_verbatim() {
        let p = Rfc5424Parser::new();
        let ev = p.parse(FIXTURE_FULL).unwrap();
        assert!(ev.raw.contains("exampleSDID"));
    }

    #[test]
    fn oversized_payload_rejected() {
        let p = Rfc5424Parser::new();
        let big = format!(
            "<13>1 2026-06-12T00:00:00Z h a 1 ID - {}",
            "X".repeat(OcsfEvent::MAX_RAW_BYTES + 10)
        );
        let err = p.parse(&big).unwrap_err();
        assert!(matches!(err, ParseError::TooLarge(_)));
    }
}
