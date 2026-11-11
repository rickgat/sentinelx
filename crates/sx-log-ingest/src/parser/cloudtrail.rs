//! AWS CloudTrail JSON → OCSF parser.
//!
//! Accepts the standard CloudTrail event-record JSON shape (one record per
//! payload). Output is mapped to OCSF API Activity (category 6, class
//! 6003). The full payload is preserved verbatim in `raw`.

use serde_json::Value;

use super::LogParser;
use crate::error::ParseError;
use crate::schema::{Observable, OcsfEvent, OcsfMetadata, Severity};

/// CloudTrail OCSF class — API Activity.
pub const CLASS_API_ACTIVITY: i32 = 6003;
/// CloudTrail OCSF category — Application Activity.
pub const CATEGORY_APPLICATION_ACTIVITY: i32 = 6;
/// Source-type token for the registry.
pub const SOURCE_TYPE: &str = "cloudtrail";

/// Stateless CloudTrail parser.
#[derive(Debug, Default, Clone, Copy)]
pub struct CloudTrailParser;

impl CloudTrailParser {
    /// Construct a new parser.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl LogParser for CloudTrailParser {
    fn source_type(&self) -> &'static str {
        SOURCE_TYPE
    }

    fn parse(&self, payload: &str) -> Result<OcsfEvent, ParseError> {
        if payload.len() > OcsfEvent::MAX_RAW_BYTES {
            return Err(ParseError::TooLarge(payload.len()));
        }
        let v: Value = serde_json::from_str(payload)
            .map_err(|e| ParseError::Malformed(format!("invalid JSON: {e}")))?;

        let event_time = string_field(&v, "eventTime")
            .ok_or_else(|| ParseError::MissingField("eventTime".into()))?;
        let event_name = string_field(&v, "eventName").unwrap_or_else(|| "Unknown".to_owned());
        let event_source = string_field(&v, "eventSource").unwrap_or_default();
        let aws_region = string_field(&v, "awsRegion").unwrap_or_default();
        let source_ip = string_field(&v, "sourceIPAddress");
        let user_agent = string_field(&v, "userAgent");
        let error_code = string_field(&v, "errorCode");

        // Severity heuristic: failed API calls (errorCode present) lift to
        // medium; successes default to informational.
        let severity = if error_code.is_some() {
            Severity::Medium
        } else {
            Severity::Informational
        };

        let mut metadata = OcsfMetadata::new("AWS CloudTrail", SOURCE_TYPE);
        if !aws_region.is_empty() {
            metadata.product = format!("AWS CloudTrail ({aws_region})");
        }

        let mut event = OcsfEvent::new(
            CLASS_API_ACTIVITY,
            CATEGORY_APPLICATION_ACTIVITY,
            event_time,
            severity,
            payload,
            metadata,
        );

        if let Some(ip) = source_ip {
            event.observables.push(Observable::new("src_ip", "ip", ip));
        }
        if !event_name.is_empty() {
            event.observables.push(Observable::new(
                "api.operation",
                "api_operation",
                event_name,
            ));
        }
        if !event_source.is_empty() {
            event
                .observables
                .push(Observable::new("api.service", "service", event_source));
        }
        if let Some(ua) = user_agent {
            event
                .observables
                .push(Observable::new("user_agent", "user_agent", ua));
        }
        if let Some(user) = user_identity_arn(&v) {
            event
                .observables
                .push(Observable::new("user.arn", "arn", user));
        }
        if let Some(err) = error_code {
            event
                .observables
                .push(Observable::new("error.code", "error_code", err));
        }

        event.cap_raw();
        Ok(event)
    }
}

fn string_field(v: &Value, name: &str) -> Option<String> {
    v.get(name).and_then(Value::as_str).map(ToOwned::to_owned)
}

fn user_identity_arn(v: &Value) -> Option<String> {
    v.get("userIdentity")
        .and_then(|u| u.get("arn"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// Real-world-shaped CloudTrail record fixture.
    const FIXTURE_OK: &str = r#"{
        "eventVersion": "1.08",
        "userIdentity": {
            "type": "IAMUser",
            "principalId": "AIDA...",
            "arn": "arn:aws:iam::123456789012:user/alice",
            "accountId": "123456789012",
            "userName": "alice"
        },
        "eventTime": "2026-06-12T10:30:01Z",
        "eventSource": "ec2.amazonaws.com",
        "eventName": "RunInstances",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "203.0.113.5",
        "userAgent": "aws-cli/2.15",
        "requestParameters": {"instanceType": "t3.micro"},
        "responseElements": {"reservationId": "r-abc"}
    }"#;

    const FIXTURE_FAILED: &str = r#"{
        "eventTime": "2026-06-12T10:31:01Z",
        "eventSource": "s3.amazonaws.com",
        "eventName": "DeleteObject",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "198.51.100.7",
        "errorCode": "AccessDenied",
        "errorMessage": "Access Denied"
    }"#;

    #[test]
    fn parser_advertises_source_type() {
        let p = CloudTrailParser::new();
        assert_eq!(p.source_type(), "cloudtrail");
    }

    #[test]
    fn happy_path_parses_into_api_activity() {
        let p = CloudTrailParser::new();
        let event = p.parse(FIXTURE_OK).unwrap();
        assert_eq!(event.class_uid, CLASS_API_ACTIVITY);
        assert_eq!(event.category_uid, CATEGORY_APPLICATION_ACTIVITY);
        assert_eq!(event.time, "2026-06-12T10:30:01Z");
        assert_eq!(event.severity_id, Severity::Informational.as_id());
        assert_eq!(event.metadata.source_type, "cloudtrail");
        assert!(event.metadata.product.contains("us-east-1"));
        assert!(event
            .observables
            .iter()
            .any(|o| o.name == "src_ip" && o.value == "203.0.113.5"));
        assert!(event
            .observables
            .iter()
            .any(|o| o.name == "api.operation" && o.value == "RunInstances"));
        assert!(event
            .observables
            .iter()
            .any(|o| o.name == "user.arn" && o.value.contains("alice")));
    }

    #[test]
    fn failed_call_lifts_severity_to_medium() {
        let p = CloudTrailParser::new();
        let event = p.parse(FIXTURE_FAILED).unwrap();
        assert_eq!(event.severity_id, Severity::Medium.as_id());
        assert!(event
            .observables
            .iter()
            .any(|o| o.name == "error.code" && o.value == "AccessDenied"));
    }

    #[test]
    fn missing_event_time_rejected() {
        let p = CloudTrailParser::new();
        let err = p
            .parse(r#"{"eventName":"X","eventSource":"x","awsRegion":"us-east-1"}"#)
            .unwrap_err();
        assert!(matches!(err, ParseError::MissingField(f) if f == "eventTime"));
    }

    #[test]
    fn malformed_json_rejected() {
        let p = CloudTrailParser::new();
        let err = p.parse("{not json").unwrap_err();
        assert!(matches!(err, ParseError::Malformed(_)));
    }

    #[test]
    fn oversized_payload_rejected() {
        let p = CloudTrailParser::new();
        let big = format!(
            "{{\"eventTime\":\"2026-06-12T10:30:01Z\",\"pad\":\"{}\"}}",
            "x".repeat(OcsfEvent::MAX_RAW_BYTES + 1024)
        );
        let err = p.parse(&big).unwrap_err();
        assert!(matches!(err, ParseError::TooLarge(_)));
    }

    #[test]
    fn raw_payload_preserved_verbatim() {
        let p = CloudTrailParser::new();
        let event = p.parse(FIXTURE_OK).unwrap();
        assert!(event.raw.contains("RunInstances"));
    }
}
