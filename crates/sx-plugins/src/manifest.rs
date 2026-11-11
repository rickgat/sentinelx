//! Plugin manifest types.
//!
//! A [`PluginManifest`] is the operator-supplied registration payload —
//! it carries the plugin's identity, the webhook URL the dispatcher will
//! POST to, the secret used to compute the HMAC signature, and the list
//! of event kinds the plugin wants to subscribe to.
//!
//! Once persisted, the manifest is paired with a server-minted [`PluginId`]
//! to form a [`RegisteredPlugin`] — the read-side projection returned by
//! the plugin service.

use std::fmt;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::envelope::EventKind;

/// Server-minted plugin identifier (UUID v4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PluginId(pub Uuid);

impl PluginId {
    /// Generate a fresh random [`PluginId`].
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Parse a [`PluginId`] from its canonical hyphenated UUID form.
    ///
    /// # Errors
    ///
    /// Returns the underlying [`uuid::Error`] if the input is not a
    /// well-formed UUID string.
    pub fn parse(s: &str) -> Result<Self, uuid::Error> {
        Uuid::parse_str(s).map(Self)
    }
}

impl fmt::Display for PluginId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl Default for PluginId {
    fn default() -> Self {
        Self::new()
    }
}

/// Registration payload posted by an operator (or third-party developer)
/// to mount a plugin against a tenant.
///
/// All string fields are bounded by the controller's validator (see
/// `crates/sx-api/src/view/plugins_view.rs`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginManifest {
    /// Human-readable plugin name (e.g. `"Acme Risk Enricher"`).
    pub name: String,
    /// Vendor / publisher (e.g. `"Acme Corp"`).
    pub vendor: String,
    /// Plugin version string — opaque to the dispatcher; surfaced in the
    /// envelope so the plugin can perform version-conditional logic.
    pub version: String,
    /// Webhook URL the dispatcher POSTs envelopes to. Validated upstream
    /// to be a well-formed `http(s)://` URL; the dispatcher additionally
    /// rejects HTTP unless [`crate::DispatcherConfig::allow_http`] is set.
    pub webhook_url: String,
    /// Event kinds the plugin subscribes to. The dispatcher fans out an
    /// envelope per (kind, plugin) match.
    pub supported_events: Vec<EventKind>,
    /// Capability scopes the plugin needs to operate. Treated as the
    /// allow-list for the host-function surface (see
    /// [`crate::sdk::HostContext`]). Empty list means the plugin can
    /// receive webhooks but cannot call back into the host — that's the
    /// default for pure pass-through enrichment plugins.
    #[serde(default)]
    pub required_scopes: Vec<String>,
}

/// A registered plugin as projected to the read-side.
///
/// The secret itself is **not** part of this projection — it is held only
/// by the [`crate::service::PluginService`] implementation and surfaced to
/// the dispatcher on demand.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisteredPlugin {
    /// Server-minted plugin id.
    pub id: PluginId,
    /// Tenant the plugin is mounted against.
    pub tenant_id: String,
    /// Human-readable plugin name.
    pub name: String,
    /// Vendor / publisher.
    pub vendor: String,
    /// Plugin version string.
    pub version: String,
    /// Webhook URL the dispatcher POSTs envelopes to.
    pub webhook_url: String,
    /// Event kinds the plugin subscribes to.
    pub supported_events: Vec<EventKind>,
    /// Capability scopes the plugin was granted at registration.
    #[serde(default)]
    pub required_scopes: Vec<String>,
    /// Whether the plugin is currently active.
    pub enabled: bool,
    /// Registration timestamp (RFC 3339 UTC).
    pub registered_at: String,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn plugin_id_round_trips_through_string() {
        let id = PluginId::new();
        let s = id.to_string();
        let back = PluginId::parse(&s).unwrap();
        assert_eq!(id, back);
    }

    #[test]
    fn manifest_serialises_with_supported_events() {
        let m = PluginManifest {
            name: "Test".into(),
            vendor: "Acme".into(),
            version: "0.1.0".into(),
            webhook_url: "https://plugin.example/hook".into(),
            supported_events: vec![EventKind::FindingCreated, EventKind::AssetDiscovered],
            required_scopes: vec!["findings:read".into()],
        };
        let v = serde_json::to_value(&m).unwrap();
        assert_eq!(v["name"], "Test");
        assert_eq!(v["supported_events"][0], "finding.created");
        assert_eq!(v["supported_events"][1], "asset.discovered");
        assert_eq!(v["required_scopes"][0], "findings:read");
    }

    #[test]
    fn manifest_required_scopes_defaults_when_omitted_in_json() {
        let raw = r#"{
            "name": "T",
            "vendor": "V",
            "version": "0.1.0",
            "webhook_url": "https://x.example/hook",
            "supported_events": ["finding.created"]
        }"#;
        let m: PluginManifest = serde_json::from_str(raw).unwrap();
        assert!(m.required_scopes.is_empty());
    }
}
