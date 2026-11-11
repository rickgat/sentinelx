//! Versioned event envelope shipped to plugin webhooks.
//!
//! Every outbound dispatch carries a [`PluginEnvelope`] serialised as
//! JSON. The envelope shape is intentionally minimal and stable: any
//! future expansion (e.g. correlation ids, replay nonces) bumps the
//! [`ENVELOPE_VERSION`] string and is feature-gated on the plugin side.
//!
//! The `payload` field is the source event's projection — its shape is
//! event-kind-specific and treated as opaque by the dispatcher.
//!
//! ## Signature semantics
//!
//! The envelope is canonicalised through [`PluginEnvelope::to_bytes`],
//! which uses `serde_json::to_vec` with the in-memory field order.
//! Plugins MUST verify the signature against the **raw request body**
//! they receive (not a re-serialisation) to remain immune to encoder
//! drift. The [`crate::dispatcher::sign_body`] helper computes the same
//! HMAC and is exposed so SDKs can re-verify in-process.

use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// Current envelope format version.
///
/// Incremented when the wire schema changes in a way that requires
/// plugin-side awareness (e.g. a new top-level field). The dispatcher
/// always emits the current version; plugins inspect this field to
/// decide which features they can rely on.
pub const ENVELOPE_VERSION: &str = "1";

/// Event kinds the dispatcher can fan out to a subscribed plugin.
///
/// The serialised form is dot-separated lowercase
/// (`"finding.created"`, `"asset.discovered"`, …) to leave room for
/// future sub-kinds without changing the variant set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    /// Emitted when a new finding lands in the platform.
    #[serde(rename = "finding.created")]
    FindingCreated,
    /// Emitted when discovery surfaces a previously-unseen asset.
    #[serde(rename = "asset.discovered")]
    AssetDiscovered,
    /// Emitted when a BAS run finishes (pass or fail).
    #[serde(rename = "bas.completed")]
    BasCompleted,
    /// Synchronous-style query: ask the plugin for a vendor lookup.
    ///
    /// The plugin's response body is merged into the source event by
    /// the caller.
    #[serde(rename = "remediation.vendor_lookup")]
    RemediationVendorLookup,
}

impl EventKind {
    /// Stable wire string — matches the serde rename.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FindingCreated => "finding.created",
            Self::AssetDiscovered => "asset.discovered",
            Self::BasCompleted => "bas.completed",
            Self::RemediationVendorLookup => "remediation.vendor_lookup",
        }
    }

    /// All variants — used by the controller validator to project
    /// "supported events" onto a strongly-typed enum set.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::FindingCreated,
            Self::AssetDiscovered,
            Self::BasCompleted,
            Self::RemediationVendorLookup,
        ]
    }
}

/// The wire payload posted to every plugin webhook.
///
/// `payload` is the source event projected as JSON. `signature_hint` is
/// purely informational — the *real* signature is in the HTTP header,
/// not inside the body — but plugins can echo it back in their response
/// for debugging.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginEnvelope {
    /// Envelope schema version — see [`ENVELOPE_VERSION`].
    pub version: String,
    /// Event kind triggering this dispatch.
    pub event_kind: EventKind,
    /// Source event payload (opaque to the dispatcher).
    pub payload: serde_json::Value,
    /// Tenant the event belongs to.
    pub tenant_id: String,
    /// RFC 3339 dispatch timestamp.
    pub ts: String,
    /// First 8 hex chars of the HMAC over this body — surfaced so the
    /// plugin can correlate logs without inspecting the header.
    pub signature_hint: String,
}

impl PluginEnvelope {
    /// Build an envelope with `version = ENVELOPE_VERSION` and the
    /// current UTC timestamp.
    ///
    /// `signature_hint` is left empty — the dispatcher fills it after
    /// the HMAC is computed (the envelope is serialised once, signed,
    /// then re-emitted with the hint patched in).
    #[must_use]
    pub fn new(event_kind: EventKind, tenant_id: String, payload: serde_json::Value) -> Self {
        let ts = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .unwrap_or_else(|_| String::from("1970-01-01T00:00:00Z"));
        Self {
            version: ENVELOPE_VERSION.to_owned(),
            event_kind,
            payload,
            tenant_id,
            ts,
            signature_hint: String::new(),
        }
    }

    /// Serialise to canonical JSON bytes used for HMAC computation.
    ///
    /// # Errors
    ///
    /// Returns the underlying [`serde_json::Error`] if the payload
    /// contains a non-serialisable value (e.g. `f64::NAN`).
    pub fn to_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn event_kind_round_trip_through_json() {
        let kinds = [
            EventKind::FindingCreated,
            EventKind::AssetDiscovered,
            EventKind::BasCompleted,
            EventKind::RemediationVendorLookup,
        ];
        for k in kinds {
            let s = serde_json::to_string(&k).unwrap();
            let back: EventKind = serde_json::from_str(&s).unwrap();
            assert_eq!(k, back);
        }
    }

    #[test]
    fn event_kind_as_str_matches_serde() {
        assert_eq!(EventKind::FindingCreated.as_str(), "finding.created");
        assert_eq!(EventKind::AssetDiscovered.as_str(), "asset.discovered");
        assert_eq!(EventKind::BasCompleted.as_str(), "bas.completed");
        assert_eq!(
            EventKind::RemediationVendorLookup.as_str(),
            "remediation.vendor_lookup"
        );
    }

    #[test]
    fn envelope_carries_current_version() {
        let e = PluginEnvelope::new(
            EventKind::FindingCreated,
            "tenant-a".into(),
            serde_json::json!({"finding_id": "f1"}),
        );
        assert_eq!(e.version, ENVELOPE_VERSION);
        assert_eq!(e.tenant_id, "tenant-a");
        assert_eq!(e.payload["finding_id"], "f1");
    }

    #[test]
    fn envelope_to_bytes_is_valid_json() {
        let e = PluginEnvelope::new(
            EventKind::BasCompleted,
            "t".into(),
            serde_json::json!({"run_id": "r1"}),
        );
        let bytes = e.to_bytes().unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["event_kind"], "bas.completed");
    }
}
