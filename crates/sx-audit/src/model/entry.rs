//! [`AuditEntry`] — the unit of an audit chain.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use sx_core::value_object::ids::TenantId;

use crate::error::AuditError;
use crate::model::action::AuditAction;
use crate::model::actor::Actor;

/// Length, in bytes, of the SHA-256 digest used for chain hashes.
pub const HASH_LEN: usize = 32;

/// A 32-byte SHA-256 digest.
pub type Hash = [u8; HASH_LEN];

/// Hex-serialised 32-byte digest helper for serde.
pub mod hex_array {
    use serde::{Deserialize, Deserializer, Serializer};

    use super::{Hash, HASH_LEN};

    /// Serialise a 32-byte array as a lowercase hex string.
    pub fn serialize<S>(bytes: &Hash, ser: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let s = hex::encode(bytes);
        ser.serialize_str(&s)
    }

    /// Deserialise a lowercase hex string of exactly 64 chars into a `[u8; 32]`.
    pub fn deserialize<'de, D>(de: D) -> Result<Hash, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(de)?;
        let v = hex::decode(&s).map_err(serde::de::Error::custom)?;
        if v.len() != HASH_LEN {
            return Err(serde::de::Error::custom(format!(
                "expected {HASH_LEN} bytes, got {}",
                v.len()
            )));
        }
        let mut out = [0u8; HASH_LEN];
        out.copy_from_slice(&v);
        Ok(out)
    }
}

/// A single entry in a tamper-evident audit log.
///
/// Entries are immutable once written. Each entry stores the SHA-256
/// `hash` of the previous entry's `hash` concatenated with its own
/// canonical bytes (see [`AuditEntry::to_canonical_bytes`]). The first
/// (genesis) entry of any tenant's chain stores `prev_hash = [0u8; 32]`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditEntry {
    /// 1-based monotonic sequence within the tenant's chain.
    pub seq: u64,
    /// Tenant whose chain this entry belongs to.
    pub tenant_id: TenantId,
    /// Timestamp at which the action occurred (UTC).
    #[serde(with = "time::serde::rfc3339")]
    pub ts: OffsetDateTime,
    /// Principal that performed the action.
    pub actor: Actor,
    /// Discriminator for what kind of action this was.
    pub action: AuditAction,
    /// Kind of resource that was acted upon (e.g. `"engagement"`).
    pub resource_kind: String,
    /// Identifier of the resource (free-form; usually a UUID string).
    pub resource_id: String,
    /// Optional pre-image snapshot (e.g. before an update).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before: Option<serde_json::Value>,
    /// Optional post-image snapshot (e.g. after an update).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after: Option<serde_json::Value>,
    /// Correlation identifier of the originating request, if any.
    pub request_id: String,
    /// SHA-256 hash of the previous entry. Genesis: `[0u8; 32]`.
    #[serde(with = "hex_array")]
    pub prev_hash: Hash,
    /// SHA-256 hash of `prev_hash || canonical_bytes(self)`.
    #[serde(with = "hex_array")]
    pub hash: Hash,
    /// Hex-encoded HMAC-SHA256 anchor of this event in the per-tenant
    /// HMAC chain. Empty string when no HMAC anchor has been computed
    /// yet (e.g. a freshly-built entry that has not been stamped by
    /// the sink). See [`crate::chain::HashChain`].
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub chain_hash: String,
    /// Hex-encoded HMAC-SHA256 anchor of the **previous** event in the
    /// per-tenant HMAC chain. `None` for the genesis event and for
    /// entries that have not yet been stamped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_prev_hash: Option<String>,
}

impl AuditEntry {
    /// Produce the deterministic canonical byte representation of this
    /// entry, **excluding** the `hash` field, suitable for hashing.
    ///
    /// # Algorithm
    ///
    /// The canonical form is a single JSON object with the following keys,
    /// in this exact order (lexicographic, enforced via [`BTreeMap`]):
    ///
    /// - `action` — the [`AuditAction`] serialised in its default snake-case form.
    /// - `actor` — the [`Actor`] serialised with `null`-skipping for
    ///   `ip` and `user_agent`.
    /// - `after` — present only if `Some`; the inner JSON value.
    /// - `before` — present only if `Some`; the inner JSON value.
    /// - `prev_hash` — lowercase hex string (64 chars).
    /// - `request_id` — the request id string.
    /// - `resource_id` — the resource id string.
    /// - `resource_kind` — the resource kind string.
    /// - `seq` — JSON number.
    /// - `tenant_id` — the tenant id as its UUID string.
    /// - `ts` — RFC 3339 timestamp string.
    ///
    /// The output is `serde_json::to_vec` applied to a [`BTreeMap`], which
    /// guarantees lexicographic key order and no extraneous whitespace.
    ///
    /// External verifiers SHOULD reproduce this exact sequence to validate
    /// the chain.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, AuditError> {
        let mut map: BTreeMap<&'static str, serde_json::Value> = BTreeMap::new();

        let action_v = serde_json::to_value(&self.action)
            .map_err(|e| AuditError::Serialization(e.to_string()))?;
        map.insert("action", action_v);

        let actor_v = serde_json::to_value(&self.actor)
            .map_err(|e| AuditError::Serialization(e.to_string()))?;
        map.insert("actor", actor_v);

        if let Some(after) = &self.after {
            map.insert("after", after.clone());
        }
        if let Some(before) = &self.before {
            map.insert("before", before.clone());
        }

        map.insert(
            "prev_hash",
            serde_json::Value::String(hex::encode(self.prev_hash)),
        );
        map.insert(
            "request_id",
            serde_json::Value::String(self.request_id.clone()),
        );
        map.insert(
            "resource_id",
            serde_json::Value::String(self.resource_id.clone()),
        );
        map.insert(
            "resource_kind",
            serde_json::Value::String(self.resource_kind.clone()),
        );
        map.insert("seq", serde_json::Value::Number(self.seq.into()));
        map.insert(
            "tenant_id",
            serde_json::Value::String(self.tenant_id.to_string()),
        );

        let ts_str = self
            .ts
            .format(&Rfc3339)
            .map_err(|e| AuditError::Serialization(e.to_string()))?;
        map.insert("ts", serde_json::Value::String(ts_str));

        // Walk each value to ensure inner JSON objects are also sorted.
        let normalised = canonicalise_value(serde_json::Value::Object(
            map.into_iter().map(|(k, v)| (k.to_owned(), v)).collect(),
        ));

        serde_json::to_vec(&normalised).map_err(|e| AuditError::Serialization(e.to_string()))
    }
}

/// Recursively reorder all JSON object keys lexicographically.
fn canonicalise_value(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let mut sorted: BTreeMap<String, serde_json::Value> = BTreeMap::new();
            for (k, v) in map {
                sorted.insert(k, canonicalise_value(v));
            }
            serde_json::Value::Object(sorted.into_iter().collect())
        }
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.into_iter().map(canonicalise_value).collect())
        }
        other => other,
    }
}
