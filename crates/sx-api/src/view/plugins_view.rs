//! Plugin marketplace + SDK view layer (P3-007).
//!
//! Wire shapes returned + accepted by:
//!
//! * `GET    /v1/plugins`               — list installed plugins.
//! * `POST   /v1/plugins/install`       — register a new plugin.
//! * `DELETE /v1/plugins/{id}`          — uninstall.
//! * `GET    /v1/plugins/{id}/dispatches` — recent dispatch history.
//!
//! Every response is wrapped in the standard
//! [`crate::view::envelope::ApiResponse`] envelope by the controller.

use serde::{Deserialize, Serialize};
use validator::Validate;

use sx_plugins::{EventKind, RegisteredPlugin};

/// Hard ceiling on the human-facing plugin name surfaced through the
/// install request. Keeps the dashboard render path bounded and resists
/// log-injection (we strip control characters server-side anyway).
pub const MAX_NAME_LEN: usize = 128;
/// Hard ceiling on the vendor / publisher string.
pub const MAX_VENDOR_LEN: usize = 128;
/// Hard ceiling on the plugin version string (semver + pre-release).
pub const MAX_VERSION_LEN: usize = 64;
/// Hard ceiling on the webhook URL.
pub const MAX_WEBHOOK_URL_LEN: usize = 1_024;
/// Hard ceiling on the shared secret. 16-byte minimum mirrors the
/// security floor for HMAC-SHA256 keys.
pub const MIN_SECRET_LEN: usize = 16;
/// Hard ceiling on the shared secret length — anything longer is almost
/// always a bug (operators pasted the wrong thing).
pub const MAX_SECRET_LEN: usize = 512;
/// Per-plugin ceiling on the supported-events list to bound the fan-out
/// work for any single dispatch tick.
pub const MAX_SUPPORTED_EVENTS: usize = 32;

/// `POST /v1/plugins/install` request body.
///
/// The validator-derived bounds also gate the manifest before it ever
/// reaches the storage layer.
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct InstallPluginRequest {
    /// Human-readable plugin name (e.g. `"Acme Risk Enricher"`).
    #[validate(length(min = 1, max = 128))]
    pub name: String,
    /// Vendor / publisher.
    #[validate(length(min = 1, max = 128))]
    pub vendor: String,
    /// Plugin version (operator-supplied; semver is conventional but not
    /// enforced — we treat it as opaque).
    #[validate(length(min = 1, max = 64))]
    pub version: String,
    /// Outbound webhook URL — must be HTTPS in production. The
    /// dispatcher's URL-scheme policy is enforced again at dispatch
    /// time so an operator cannot bypass it by flipping `allow_http`
    /// after install.
    #[validate(url, length(min = 1, max = 1024))]
    pub webhook_url: String,
    /// HMAC signing secret. Persisted encrypted (DEK pipeline) by the
    /// Postgres-backed `PluginService`; the in-memory variant retains
    /// the cleartext for the dev loop.
    #[validate(length(min = 16, max = 512))]
    pub secret: String,
    /// Event kinds the plugin subscribes to. The controller projects
    /// these onto the strongly-typed `EventKind` set.
    #[validate(length(min = 1, max = 32))]
    pub supported_events: Vec<EventKind>,
    /// Capability scopes the plugin needs (e.g. `findings:read`,
    /// `findings:annotate`, `http:fetch`). Optional — pass-through
    /// enrichment plugins typically declare none.
    #[serde(default)]
    #[validate(length(max = 16))]
    pub required_scopes: Vec<String>,
}

/// Single-row projection used by the list + install endpoints.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PluginView {
    /// Server-minted plugin id (UUID v4).
    pub id: String,
    /// Tenant scope (always the caller's tenant in the read path).
    pub tenant_id: String,
    /// Human-readable plugin name.
    pub name: String,
    /// Vendor / publisher.
    pub vendor: String,
    /// Plugin version string.
    pub version: String,
    /// Webhook URL.
    pub webhook_url: String,
    /// Event kinds the plugin subscribes to.
    pub supported_events: Vec<EventKind>,
    /// Capability scopes granted at registration.
    #[serde(default)]
    pub required_scopes: Vec<String>,
    /// Whether the plugin is currently enabled.
    pub enabled: bool,
    /// Registration timestamp (RFC 3339 UTC).
    pub registered_at: String,
}

impl From<RegisteredPlugin> for PluginView {
    fn from(p: RegisteredPlugin) -> Self {
        Self {
            id: p.id.to_string(),
            tenant_id: p.tenant_id,
            name: p.name,
            vendor: p.vendor,
            version: p.version,
            webhook_url: p.webhook_url,
            supported_events: p.supported_events,
            required_scopes: p.required_scopes,
            enabled: p.enabled,
            registered_at: p.registered_at,
        }
    }
}

/// `GET /v1/plugins` response body.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ListPluginsResponse {
    /// Newest-first.
    pub plugins: Vec<PluginView>,
}

/// Single-row projection used by the dispatch-history endpoint.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PluginDispatchView {
    /// Dispatch id (UUID v4).
    pub id: String,
    /// Event kind that triggered the dispatch.
    pub event_kind: EventKind,
    /// Outcome category (`success` / `failed` / `timeout` / `rejected`).
    pub status: String,
    /// Round-trip latency in milliseconds.
    pub latency_ms: u32,
    /// First N bytes of the plugin response body, UTF-8 lossy.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_excerpt: Option<String>,
    /// RFC 3339 dispatch timestamp.
    pub ts: String,
}

/// `GET /v1/plugins/{id}/dispatches` response body.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ListPluginDispatchesResponse {
    /// Newest-first.
    pub dispatches: Vec<PluginDispatchView>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use sx_plugins::PluginId;

    #[test]
    fn plugin_view_round_trips() {
        let v = PluginView {
            id: PluginId::new().to_string(),
            tenant_id: "t".into(),
            name: "n".into(),
            vendor: "v".into(),
            version: "1.0.0".into(),
            webhook_url: "https://x.example/hook".into(),
            supported_events: vec![EventKind::FindingCreated],
            required_scopes: vec!["findings:read".into()],
            enabled: true,
            registered_at: "2026-06-12T00:00:00Z".into(),
        };
        let raw = serde_json::to_string(&v).unwrap();
        let back: PluginView = serde_json::from_str(&raw).unwrap();
        assert_eq!(back, v);
    }

    #[test]
    fn install_request_rejects_short_secret() {
        let req = InstallPluginRequest {
            name: "Acme".into(),
            vendor: "Acme".into(),
            version: "0.1.0".into(),
            webhook_url: "https://x.example/hook".into(),
            secret: "short".into(),
            supported_events: vec![EventKind::FindingCreated],
            required_scopes: vec![],
        };
        let err = req.validate().expect_err("short secret must fail");
        assert!(err.to_string().contains("secret"));
    }

    #[test]
    fn install_request_rejects_non_url() {
        let req = InstallPluginRequest {
            name: "Acme".into(),
            vendor: "Acme".into(),
            version: "0.1.0".into(),
            webhook_url: "not-a-url".into(),
            secret: "0123456789abcdef0123".into(),
            supported_events: vec![EventKind::FindingCreated],
            required_scopes: vec![],
        };
        let err = req.validate().expect_err("bad URL must fail");
        assert!(err.to_string().contains("webhook_url"));
    }

    #[test]
    fn install_request_rejects_empty_event_list() {
        let req = InstallPluginRequest {
            name: "Acme".into(),
            vendor: "Acme".into(),
            version: "0.1.0".into(),
            webhook_url: "https://x.example/hook".into(),
            secret: "0123456789abcdef0123".into(),
            supported_events: vec![],
            required_scopes: vec![],
        };
        let err = req.validate().expect_err("empty events must fail");
        assert!(err.to_string().contains("supported_events"));
    }

    #[test]
    fn install_request_round_trips_through_json() {
        let raw = r#"{
            "name": "Acme",
            "vendor": "Acme Inc",
            "version": "0.1.0",
            "webhook_url": "https://x.example/hook",
            "secret": "0123456789abcdef0123",
            "supported_events": ["finding.created", "asset.discovered"],
            "required_scopes": ["findings:read"]
        }"#;
        let req: InstallPluginRequest = serde_json::from_str(raw).unwrap();
        req.validate().unwrap();
        assert_eq!(req.name, "Acme");
        assert_eq!(req.supported_events.len(), 2);
        assert_eq!(req.required_scopes, vec!["findings:read".to_owned()]);
    }

    #[test]
    fn install_request_required_scopes_optional() {
        let raw = r#"{
            "name": "Acme",
            "vendor": "Acme Inc",
            "version": "0.1.0",
            "webhook_url": "https://x.example/hook",
            "secret": "0123456789abcdef0123",
            "supported_events": ["finding.created"]
        }"#;
        let req: InstallPluginRequest = serde_json::from_str(raw).unwrap();
        req.validate().unwrap();
        assert!(req.required_scopes.is_empty());
    }

    #[test]
    fn registered_plugin_projects_into_view() {
        let p = RegisteredPlugin {
            id: PluginId::new(),
            tenant_id: "t".into(),
            name: "n".into(),
            vendor: "v".into(),
            version: "1.0.0".into(),
            webhook_url: "https://x.example/hook".into(),
            supported_events: vec![EventKind::BasCompleted],
            required_scopes: vec!["http:fetch".into()],
            enabled: true,
            registered_at: "2026-06-12T00:00:00Z".into(),
        };
        let v: PluginView = p.clone().into();
        assert_eq!(v.id, p.id.to_string());
        assert_eq!(v.tenant_id, "t");
        assert_eq!(v.supported_events, vec![EventKind::BasCompleted]);
        assert_eq!(v.required_scopes, vec!["http:fetch".to_owned()]);
    }
}
