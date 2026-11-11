//! Device-fingerprint signal (HIGH-001).
//!
//! Modern adversaries that pass IP-geo + business-hours checks (e.g. via
//! cheap residential proxies) still typically come in from devices the
//! tenant has never seen. The fingerprint signal closes that gap by
//! comparing a stable opaque hash (cookie + UA + canvas, computed by the
//! client) against a per-tenant ledger.
//!
//! ## Status values
//!
//! * [`DeviceFingerprintStatus::Known`] — the fingerprint has been
//!   recorded against this `(tenant, user)` pair before and is not
//!   revoked.
//! * [`DeviceFingerprintStatus::Unknown`] — first time we see the
//!   fingerprint. The collector decides whether to admit it (after MFA,
//!   say) or treat it as transient.
//! * [`DeviceFingerprintStatus::Revoked`] — operator or self-service has
//!   explicitly revoked the device. Any subsequent login from the
//!   fingerprint receives the maximum sub-score (`100`) so the composite
//!   score lands in the block bucket regardless of the other signals.
//!
//! The signal trait surface ([`DeviceFingerprintStore`]) is intentionally
//! small: `record`, `lookup`, `revoke`, `list_for_user`. The default
//! in-process implementor — [`MemDeviceFingerprintLedger`] — uses a
//! sharded `DashMap`. LOW-004 added [`crate::signals::device_fp_pg`] as
//! a Postgres-backed implementor over the same trait, so the engine can
//! survive a `sx-monolith` restart without losing every known device.

use std::sync::Arc;

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

/// Sub-score awarded to a known, non-revoked fingerprint.
pub const SCORE_KNOWN: i32 = 0;
/// Sub-score awarded to a fingerprint the tenant has never seen.
pub const SCORE_UNKNOWN: i32 = 30;
/// Sub-score awarded to a fingerprint explicitly revoked by the operator
/// or end-user (theft / lost device flow).
pub const SCORE_REVOKED: i32 = 100;

/// Status of a fingerprint relative to the `(tenant, user)` ledger.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceFingerprintStatus {
    /// Previously observed and not revoked.
    Known,
    /// Not yet recorded for `(tenant, user)`.
    Unknown,
    /// Recorded once but operator/user has revoked the device.
    Revoked,
}

impl DeviceFingerprintStatus {
    /// Stable string form for SQL / JSON.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Known => "known",
            Self::Unknown => "unknown",
            Self::Revoked => "revoked",
        }
    }
}

/// Materialised per-login signal handed to the scorer.
///
/// Carries the opaque fingerprint hash plus the resolved status. The
/// `last_seen_at` is `None` for unknown fingerprints (no row exists
/// yet) and `Some(...)` for known / revoked entries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceFingerprintSignal {
    /// Opaque, caller-supplied SHA-256 (hex) or equivalent hash.
    pub fp_hash: String,
    /// Wall-clock time the fingerprint was last seen, if any.
    pub last_seen_at: Option<OffsetDateTime>,
    /// Status relative to the ledger.
    pub status: DeviceFingerprintStatus,
}

impl DeviceFingerprintSignal {
    /// Convenience constructor for the "unknown fingerprint" sentinel.
    #[must_use]
    pub fn unknown(fp_hash: impl Into<String>) -> Self {
        Self {
            fp_hash: fp_hash.into(),
            last_seen_at: None,
            status: DeviceFingerprintStatus::Unknown,
        }
    }
}

/// One row returned by [`DeviceFingerprintStore::list_for_user`].
///
/// The shape matches the public-facing inventory view, not any
/// implementor's internal row type. Callers project further into wire
/// DTOs as needed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceFingerprintRow {
    /// Opaque fingerprint hash (SHA-256 hex or equivalent).
    pub fp_hash: String,
    /// Wall-clock time of the most recent successful login from this
    /// fingerprint. For revoked rows this is the time of the last
    /// successful login *before* revocation.
    pub last_seen_at: OffsetDateTime,
    /// `Known` for actively enrolled rows, `Revoked` for explicitly
    /// locked rows. `Unknown` is never returned here — the listing
    /// surface only enumerates rows that exist.
    pub status: DeviceFingerprintStatus,
}

/// Storage backend for the per-tenant device-fingerprint ledger.
///
/// Two implementors ship with the crate:
///
/// * [`MemDeviceFingerprintLedger`] — in-process `DashMap` ledger used
///   by tests and the legacy in-memory monolith path.
/// * [`crate::signals::device_fp_pg::PgDeviceFingerprintLedger`] —
///   Postgres-backed implementor wired into the production monolith
///   composition root (LOW-004). Built over the existing
///   `rba_known_devices` migration with FORCE-RLS keyed off
///   `app_current_tenant()`.
///
/// The trait surface is intentionally sync to keep the existing
/// synchronous [`crate::service::RbaService::evaluate`] hot path
/// unchanged — async I/O implementors (the Postgres one) bridge with
/// `tokio::task::block_in_place` + `Handle::block_on(...)` so the trait
/// stays callable from sync contexts inside the engine.
///
/// ## Revoke-survival invariant
///
/// Every implementor MUST honour the "revoke-survival" invariant: once
/// a fingerprint has been [`Self::revoke`]d, a subsequent [`Self::record`]
/// call must NOT clear the revoked flag. A recovered stolen laptop must
/// not silently re-arm itself by hitting the login page; explicit
/// operator-side re-enrollment is required. The `MemDeviceFingerprintLedger`
/// enforces this via its in-process `LedgerEntry::revoked` field; the
/// Postgres implementor relies on the table's `revoked_at` column +
/// `INSERT ... ON CONFLICT (...) DO UPDATE SET last_seen = GREATEST(...)`
/// upsert that intentionally does NOT clear `revoked_at`.
pub trait DeviceFingerprintStore: Send + Sync + std::fmt::Debug {
    /// Record a successful login from `(tenant, user, fp_hash)` at `at`.
    ///
    /// Implementors must NOT clear the revoked flag on an existing
    /// revoked row — see the revoke-survival invariant on the trait.
    fn record(&self, tenant_id: Uuid, user_id: Uuid, fp_hash: &str, at: OffsetDateTime);

    /// Resolve a fingerprint's status without mutating the ledger.
    fn lookup(&self, tenant_id: Uuid, user_id: Uuid, fp_hash: &str) -> DeviceFingerprintSignal;

    /// Mark a fingerprint as revoked (idempotent). If no row exists yet,
    /// implementors must create one in the revoked state so a subsequent
    /// `lookup` returns `Revoked` rather than `Unknown` — operator
    /// pre-revocation of a leaked fingerprint hash is a supported flow.
    fn revoke(&self, tenant_id: Uuid, user_id: Uuid, fp_hash: &str);

    /// List every known fingerprint for `(tenant, user)`. Used by the
    /// admin REST endpoint backing the dashboard's "all my devices" view.
    ///
    /// Order is unspecified — callers sort.
    fn list_for_user(&self, tenant_id: Uuid, user_id: Uuid) -> Vec<DeviceFingerprintRow>;
}

#[derive(Debug, Clone)]
struct LedgerEntry {
    last_seen_at: OffsetDateTime,
    revoked: bool,
}

/// In-memory implementor of [`DeviceFingerprintStore`].
///
/// Cheap to clone (`Arc<DashMap>` internally) and concurrency-safe. The
/// production deployment installs the Postgres-backed
/// [`crate::signals::device_fp_pg::PgDeviceFingerprintLedger`] instead;
/// this implementor is used in unit + integration tests as well as the
/// monolith's adapter unit tests so they don't require a live Postgres.
#[derive(Debug, Clone, Default)]
pub struct MemDeviceFingerprintLedger {
    rows: Arc<DashMap<String, LedgerEntry>>,
}

impl MemDeviceFingerprintLedger {
    /// Build an empty ledger.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of rows currently tracked. Test-only.
    #[must_use]
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    /// True when the ledger holds no rows.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    fn key(tenant_id: Uuid, user_id: Uuid, fp_hash: &str) -> String {
        format!("{tenant_id}|{user_id}|{fp_hash}")
    }
}

impl DeviceFingerprintStore for MemDeviceFingerprintLedger {
    /// Record a successful login from `(tenant, user, fp_hash)` at `at`.
    ///
    /// If the row is currently revoked the call is a no-op — revoked
    /// devices must be explicitly re-enrolled by the operator before
    /// they can score `Known` again. This is a deliberate footgun
    /// avoidance: a recovered stolen laptop must not silently re-arm
    /// itself by hitting the login page.
    fn record(&self, tenant_id: Uuid, user_id: Uuid, fp_hash: &str, at: OffsetDateTime) {
        let key = Self::key(tenant_id, user_id, fp_hash);
        let mut entry = self.rows.entry(key).or_insert(LedgerEntry {
            last_seen_at: at,
            revoked: false,
        });
        if !entry.revoked {
            // Use GREATEST semantics so out-of-order replay
            // (NTP skew, queue reordering) doesn't drag last_seen
            // backwards — mirrors the SQL upsert.
            if at > entry.last_seen_at {
                entry.last_seen_at = at;
            }
        }
    }

    fn lookup(&self, tenant_id: Uuid, user_id: Uuid, fp_hash: &str) -> DeviceFingerprintSignal {
        let key = Self::key(tenant_id, user_id, fp_hash);
        if let Some(row) = self.rows.get(&key) {
            let status = if row.revoked {
                DeviceFingerprintStatus::Revoked
            } else {
                DeviceFingerprintStatus::Known
            };
            DeviceFingerprintSignal {
                fp_hash: fp_hash.to_owned(),
                last_seen_at: Some(row.last_seen_at),
                status,
            }
        } else {
            DeviceFingerprintSignal::unknown(fp_hash)
        }
    }

    fn revoke(&self, tenant_id: Uuid, user_id: Uuid, fp_hash: &str) {
        let key = Self::key(tenant_id, user_id, fp_hash);
        self.rows
            .entry(key)
            .and_modify(|e| e.revoked = true)
            .or_insert(LedgerEntry {
                last_seen_at: OffsetDateTime::UNIX_EPOCH,
                revoked: true,
            });
    }

    fn list_for_user(&self, tenant_id: Uuid, user_id: Uuid) -> Vec<DeviceFingerprintRow> {
        let prefix = format!("{tenant_id}|{user_id}|");
        self.rows
            .iter()
            .filter_map(|kv| {
                let key = kv.key();
                if !key.starts_with(&prefix) {
                    return None;
                }
                let fp_hash = key[prefix.len()..].to_owned();
                let row = kv.value();
                Some(DeviceFingerprintRow {
                    fp_hash,
                    last_seen_at: row.last_seen_at,
                    status: if row.revoked {
                        DeviceFingerprintStatus::Revoked
                    } else {
                        DeviceFingerprintStatus::Known
                    },
                })
            })
            .collect()
    }
}

/// Back-compat alias for the in-memory ledger.
///
/// Pre-LOW-004 callers (one round of admin + dashboard adapters) named
/// the concrete type `DeviceFingerprintLedger`. LOW-004 extracted the
/// [`DeviceFingerprintStore`] trait and renamed the in-memory impl to
/// [`MemDeviceFingerprintLedger`]; this alias preserves the old name so
/// downstream tests / adapter code keeps compiling without churn.
pub type DeviceFingerprintLedger = MemDeviceFingerprintLedger;

/// Score a fingerprint signal by its status.
#[must_use]
pub fn score(signal: &DeviceFingerprintSignal) -> i32 {
    match signal.status {
        DeviceFingerprintStatus::Known => SCORE_KNOWN,
        DeviceFingerprintStatus::Unknown => SCORE_UNKNOWN,
        DeviceFingerprintStatus::Revoked => SCORE_REVOKED,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use time::macros::datetime;

    fn ts() -> OffsetDateTime {
        datetime!(2026-06-12 10:00:00 UTC)
    }

    #[test]
    fn scores_match_acceptance_criteria() {
        assert_eq!(
            score(&DeviceFingerprintSignal {
                fp_hash: "h".into(),
                last_seen_at: Some(ts()),
                status: DeviceFingerprintStatus::Known,
            }),
            0
        );
        assert_eq!(score(&DeviceFingerprintSignal::unknown("h")), 30);
        assert_eq!(
            score(&DeviceFingerprintSignal {
                fp_hash: "h".into(),
                last_seen_at: Some(ts()),
                status: DeviceFingerprintStatus::Revoked,
            }),
            100
        );
    }

    #[test]
    fn first_login_is_unknown_then_known() {
        let ledger = MemDeviceFingerprintLedger::new();
        let tenant = Uuid::new_v4();
        let user = Uuid::new_v4();
        let s = ledger.lookup(tenant, user, "abc");
        assert_eq!(s.status, DeviceFingerprintStatus::Unknown);
        ledger.record(tenant, user, "abc", ts());
        let s2 = ledger.lookup(tenant, user, "abc");
        assert_eq!(s2.status, DeviceFingerprintStatus::Known);
        assert_eq!(s2.last_seen_at, Some(ts()));
    }

    #[test]
    fn revoked_fingerprint_does_not_silently_recover() {
        let ledger = MemDeviceFingerprintLedger::new();
        let tenant = Uuid::new_v4();
        let user = Uuid::new_v4();
        ledger.record(tenant, user, "abc", ts());
        ledger.revoke(tenant, user, "abc");
        let s = ledger.lookup(tenant, user, "abc");
        assert_eq!(s.status, DeviceFingerprintStatus::Revoked);
        // Subsequent record() must NOT re-arm the device.
        ledger.record(tenant, user, "abc", ts());
        let s2 = ledger.lookup(tenant, user, "abc");
        assert_eq!(s2.status, DeviceFingerprintStatus::Revoked);
    }

    #[test]
    fn revoking_a_never_seen_fingerprint_creates_revoked_row() {
        let ledger = MemDeviceFingerprintLedger::new();
        let tenant = Uuid::new_v4();
        let user = Uuid::new_v4();
        ledger.revoke(tenant, user, "abc");
        assert_eq!(
            ledger.lookup(tenant, user, "abc").status,
            DeviceFingerprintStatus::Revoked
        );
    }

    #[test]
    fn ledger_is_tenant_and_user_scoped() {
        let ledger = MemDeviceFingerprintLedger::new();
        let t1 = Uuid::new_v4();
        let t2 = Uuid::new_v4();
        let u = Uuid::new_v4();
        ledger.record(t1, u, "abc", ts());
        assert_eq!(
            ledger.lookup(t2, u, "abc").status,
            DeviceFingerprintStatus::Unknown
        );
    }

    #[test]
    fn status_strings_are_stable() {
        assert_eq!(DeviceFingerprintStatus::Known.as_str(), "known");
        assert_eq!(DeviceFingerprintStatus::Unknown.as_str(), "unknown");
        assert_eq!(DeviceFingerprintStatus::Revoked.as_str(), "revoked");
    }

    #[test]
    fn list_for_user_scopes_to_tenant_and_user_and_includes_revoked() {
        let ledger = MemDeviceFingerprintLedger::new();
        let t = Uuid::new_v4();
        let u = Uuid::new_v4();
        let other_user = Uuid::new_v4();
        let other_tenant = Uuid::new_v4();

        ledger.record(t, u, "fp_a", ts());
        ledger.record(t, u, "fp_b", ts());
        ledger.revoke(t, u, "fp_b");
        // Same fp_hash for a different user — must NOT leak into our list.
        ledger.record(t, other_user, "fp_a", ts());
        // Same (user, fp) for a different tenant — must NOT leak.
        ledger.record(other_tenant, u, "fp_a", ts());

        let rows = ledger.list_for_user(t, u);
        assert_eq!(rows.len(), 2, "exactly our two fingerprints");
        let mut hashes: Vec<_> = rows.iter().map(|r| r.fp_hash.clone()).collect();
        hashes.sort();
        assert_eq!(hashes, vec!["fp_a".to_owned(), "fp_b".to_owned()]);
        let revoked = rows
            .iter()
            .find(|r| r.fp_hash == "fp_b")
            .expect("fp_b row present");
        assert_eq!(revoked.status, DeviceFingerprintStatus::Revoked);
    }

    #[test]
    fn list_for_user_returns_empty_when_no_devices_enrolled() {
        let ledger = MemDeviceFingerprintLedger::new();
        let t = Uuid::new_v4();
        let u = Uuid::new_v4();
        assert!(ledger.list_for_user(t, u).is_empty());
    }

    #[test]
    fn record_uses_greatest_semantics_on_out_of_order_replay() {
        // The Postgres implementor uses `GREATEST(last_seen, EXCLUDED.last_seen)`
        // — the in-memory ledger mirrors that so the trait contract is
        // identical across implementors. Replay an earlier timestamp
        // and assert it does NOT clobber the latest known sighting.
        let ledger = MemDeviceFingerprintLedger::new();
        let t = Uuid::new_v4();
        let u = Uuid::new_v4();
        let later = ts();
        let earlier = ts() - time::Duration::hours(1);
        ledger.record(t, u, "abc", later);
        ledger.record(t, u, "abc", earlier);
        assert_eq!(ledger.lookup(t, u, "abc").last_seen_at, Some(later));
    }
}
