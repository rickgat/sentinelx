//! DLP (P2-006) view layer.
//!
//! Wire shapes returned and accepted by:
//!
//! * `POST /v1/dlp/scan` — multipart upload (`field: payload`) capped at
//!   10 MB. Body is scanned by the registered detector set; the response
//!   is a [`DlpScanResponse`] with per-category roll-up + the full hit
//!   list (each hit carries a redacted preview only).
//! * `GET /v1/dlp/config` — current per-tenant detector configuration.
//! * `PUT /v1/dlp/config` — replace the per-tenant detector
//!   configuration.
//!
//! The view layer never owns DLP business logic — it only projects the
//! port shapes ([`crate::port::DlpScanResultView`],
//! [`crate::port::DlpDetectorConfigView`]) onto a stable wire schema.

use serde::{Deserialize, Serialize};

use crate::port::{DlpDetectorConfigView, DlpDetectorKind, DlpScanResultView, DlpThresholdView};

/// `POST /v1/dlp/scan` JSON-body shape — used when the caller would
/// rather not assemble a multipart payload. The multipart handler
/// upgrades the body into the same shape internally.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DlpScanJsonBody {
    /// UTF-8 payload to inspect. May be empty (no-op scan).
    #[serde(default)]
    pub payload: String,
}

/// `POST /v1/dlp/scan` response body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DlpScanResponse {
    /// Projected scan result.
    pub result: DlpScanResultView,
}

/// `PUT /v1/dlp/config` request body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DlpPutConfigRequest {
    /// Detector kinds to enable. An empty list opts the tenant out of
    /// every detector (no-op scan); missing detectors stay disabled.
    pub enabled: Vec<DlpDetectorKind>,
    /// Optional HIGH-004 fusion threshold. `None` preserves whatever
    /// value the `/v1/admin/dlp/thresholds` endpoint last wrote.
    #[serde(default)]
    pub min_confidence: Option<f32>,
}

/// `GET|PUT /v1/dlp/config` response body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DlpConfigResponse {
    /// Active configuration.
    pub config: DlpDetectorConfigView,
}

/// `PUT /v1/admin/dlp/thresholds` request body (HIGH-004).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DlpPutThresholdRequest {
    /// Minimum fused confidence in `[0.0, 1.0]` required to emit a
    /// finding. Implementations clamp out-of-range values; NaN is
    /// rejected with a 422.
    pub min_confidence: f32,
}

/// `GET|PUT /v1/admin/dlp/thresholds` response body (HIGH-004).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DlpThresholdResponse {
    /// Active threshold for the caller's tenant.
    pub threshold: DlpThresholdView,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn scan_json_body_defaults_to_empty_payload() {
        let body: DlpScanJsonBody = serde_json::from_str("{}").unwrap();
        assert!(body.payload.is_empty());
    }

    #[test]
    fn scan_json_body_round_trips() {
        let body = DlpScanJsonBody {
            payload: "alice@example.com".into(),
        };
        let raw = serde_json::to_string(&body).unwrap();
        let back: DlpScanJsonBody = serde_json::from_str(&raw).unwrap();
        assert_eq!(back.payload, body.payload);
    }

    #[test]
    fn put_config_request_round_trips() {
        let req = DlpPutConfigRequest {
            enabled: vec![DlpDetectorKind::Email, DlpDetectorKind::CreditCard],
            min_confidence: Some(0.75),
        };
        let raw = serde_json::to_string(&req).unwrap();
        let back: DlpPutConfigRequest = serde_json::from_str(&raw).unwrap();
        assert_eq!(back.enabled, req.enabled);
        assert_eq!(back.min_confidence, req.min_confidence);
    }

    #[test]
    fn put_config_request_min_confidence_optional() {
        // Back-compat: legacy callers without `min_confidence` deserialise.
        let raw = r#"{"enabled":["email"]}"#;
        let back: DlpPutConfigRequest = serde_json::from_str(raw).unwrap();
        assert_eq!(back.enabled.len(), 1);
        assert!(back.min_confidence.is_none());
    }

    #[test]
    fn put_threshold_request_round_trips() {
        let req = DlpPutThresholdRequest {
            min_confidence: 0.9,
        };
        let raw = serde_json::to_string(&req).unwrap();
        let back: DlpPutThresholdRequest = serde_json::from_str(&raw).unwrap();
        assert!((back.min_confidence - req.min_confidence).abs() < f32::EPSILON);
    }
}
