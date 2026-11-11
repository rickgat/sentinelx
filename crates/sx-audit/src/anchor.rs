//! HMAC audit-chain anchor publisher.
//!
//! Periodically snapshots each tenant's HMAC chain head and writes a
//! tamper-evident manifest to an S3-compatible store with **Object Lock**
//! retention (`COMPLIANCE` semantics — the caller's bucket configuration
//! is expected to enforce the retention mode; this crate supplies the
//! `RetainUntil` timestamp).
//!
//! # Why a separate anchor?
//!
//! The per-tenant [`crate::chain::HashChain`] is a strong tamper-evidence
//! primitive on its own, but an attacker with write access to the
//! primary store could rewrite the *entire* chain. Anchoring the chain
//! head into write-once object storage means any post-hoc rewrite can
//! be detected by comparing the stored manifest against the live chain.
//!
//! # Module layout
//!
//! - [`S3Like`] — minimal S3 surface (`put_object` + `get_object` with
//!   `RetainUntil`). Implementing this against `aws-sdk-s3` is deferred
//!   to a separate adapter file outside this crate.
//! - [`MockS3`] — in-memory implementation for tests.
//! - [`ChainHeadSource`] — port for enumerating tenant chain heads.
//! - [`AnchorManifest`] — the JSON body written per tenant per snapshot.
//! - [`AnchorPublisher`] — the orchestrator with [`AnchorPublisher::publish_once`].
//! - [`spawn`] — runs the publisher on an interval until shutdown.
//!
//! # Security
//!
//! - The signing key is held in a [`secrecy::SecretString`] and is
//!   **never** rendered through `tracing`. Manifests log only the
//!   tenant id, key, and a 16-char HMAC prefix.
//! - Manifest bodies are written with deterministic, sorted-key JSON so
//!   external verifiers can reproduce them byte-for-byte.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Duration as StdDuration;

use async_trait::async_trait;
use hmac::{Hmac, Mac};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use thiserror::Error;
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};
use tokio::sync::Mutex;
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tracing::{debug, info, instrument, warn};

use sx_core::value_object::ids::TenantId;

pub mod sdk;

/// Tracing target for anchor-publisher logs.
const TRACING_TARGET: &str = "sx_audit::anchor";

/// Prefix under which manifests are stored within the bucket.
pub const ANCHOR_KEY_PREFIX: &str = "audit-anchors";

type HmacSha256 = Hmac<Sha256>;

/// Errors produced by the anchor publisher.
#[derive(Debug, Error)]
pub enum AnchorError {
    /// The signing key was empty — refusing to publish unsigned anchors.
    #[error("signing key must be non-empty")]
    EmptySigningKey,

    /// HMAC initialisation rejected the key (extremely unlikely; modelled
    /// for completeness).
    #[error("invalid signing key for HMAC-SHA256: {0}")]
    InvalidKey(String),

    /// Manifest JSON serialisation failed.
    #[error("serialization: {0}")]
    Serialization(String),

    /// Timestamp formatting (RFC 3339 / object key) failed.
    #[error("time format: {0}")]
    TimeFormat(String),

    /// `retain_days` was negative or otherwise out of range.
    #[error("invalid retain_days: {0}")]
    InvalidRetainDays(i64),

    /// The underlying chain-head source returned an error.
    #[error("chain head source: {0}")]
    Source(String),

    /// The underlying S3 implementation returned an error.
    #[error("s3: {0}")]
    S3(String),

    /// The requested object was not found in the bucket.
    #[error("s3 object not found: bucket={bucket} key={key}")]
    NotFound {
        /// Bucket the lookup targeted.
        bucket: String,
        /// Key that was missing.
        key: String,
    },
}

/// Snapshot of one tenant's HMAC chain head at a particular moment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainHead {
    /// Tenant the head belongs to.
    pub tenant_id: TenantId,
    /// Sequence number of the latest entry (`0` is reserved for "no
    /// entries yet" and is filtered out by the publisher).
    pub head_seq: u64,
    /// Hex-encoded HMAC-SHA256 chain hash of the latest entry. Empty
    /// when the tenant has no entries yet.
    pub head_hash: String,
}

/// Source of per-tenant chain heads.
///
/// Implementations typically live in `sx-storage` (a SQL adapter that
/// runs `SELECT tenant_id, MAX(seq), chain_hash FROM audit_entries
/// GROUP BY tenant_id`). Tests can supply an in-memory stub.
#[async_trait]
pub trait ChainHeadSource: Send + Sync + std::fmt::Debug {
    /// Return the chain head for every tenant that has at least one
    /// entry. The order is implementation-defined; the publisher sorts
    /// internally so callers should not rely on it.
    async fn list_chain_heads(&self) -> Result<Vec<ChainHead>, AnchorError>;
}

/// Minimal S3 surface required by the anchor publisher.
///
/// This trait deliberately omits everything the publisher does not
/// need (multi-part uploads, ACLs, tagging, etc.). A real adapter
/// backed by `aws-sdk-s3` is **deferred** to a separate file outside
/// this crate so that `sx-audit` stays free of AWS SDK dependencies.
///
/// # Object Lock semantics
///
/// `put_object` is expected to write the object with an Object Lock
/// retention of `retain_until` (the caller's bucket configuration is
/// expected to enforce `COMPLIANCE` mode so neither the publisher nor
/// any later actor can shorten the retention).
#[async_trait]
pub trait S3Like: Send + Sync + std::fmt::Debug {
    /// Upload `body` to `s3://<bucket>/<key>` with an Object Lock
    /// `RetainUntil` of `retain_until`.
    async fn put_object(
        &self,
        bucket: &str,
        key: &str,
        body: Vec<u8>,
        retain_until: OffsetDateTime,
    ) -> Result<(), AnchorError>;

    /// Fetch the body of `s3://<bucket>/<key>`.
    async fn get_object(&self, bucket: &str, key: &str) -> Result<Vec<u8>, AnchorError>;
}

/// JSON body written for each tenant per snapshot.
///
/// The struct is serialised in **sorted-key JSON** order via
/// [`AnchorManifest::to_canonical_bytes`]; do not rely on the field
/// order in the source code matching the on-disk order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnchorManifest {
    /// Tenant whose chain is being anchored.
    pub tenant_id: TenantId,
    /// Time at which the snapshot was taken (RFC 3339, UTC).
    #[serde(with = "time::serde::rfc3339")]
    pub snapshot_ts: OffsetDateTime,
    /// Sequence number of the head entry.
    pub head_seq: u64,
    /// Hex-encoded HMAC-SHA256 chain hash of the head entry.
    pub head_hash: String,
    /// Hex-encoded HMAC-SHA256 anchor of this manifest itself
    /// (`HMAC(key, tenant_id || snapshot_ts || head_seq || head_hash)`).
    pub hmac: String,
}

impl AnchorManifest {
    /// Serialise this manifest to deterministic, sorted-key JSON bytes
    /// (no extraneous whitespace).
    ///
    /// External verifiers reproduce this exact byte sequence to confirm
    /// an anchor object has not been re-keyed in storage.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, AnchorError> {
        let ts_str = self
            .snapshot_ts
            .format(&Rfc3339)
            .map_err(|e| AnchorError::TimeFormat(e.to_string()))?;
        let mut map: BTreeMap<&'static str, serde_json::Value> = BTreeMap::new();
        map.insert(
            "head_hash",
            serde_json::Value::String(self.head_hash.clone()),
        );
        map.insert("head_seq", serde_json::Value::Number(self.head_seq.into()));
        map.insert("hmac", serde_json::Value::String(self.hmac.clone()));
        map.insert("snapshot_ts", serde_json::Value::String(ts_str));
        map.insert(
            "tenant_id",
            serde_json::Value::String(self.tenant_id.to_string()),
        );
        serde_json::to_vec(&map).map_err(|e| AnchorError::Serialization(e.to_string()))
    }
}

/// Periodic publisher that snapshots tenant chain heads to S3 with
/// Object Lock retention.
///
/// The generic parameter `S` is the [`ChainHeadSource`] (typically the
/// storage-layer audit sink). The S3 surface is type-erased behind an
/// `Arc<dyn S3Like>` so multiple publishers can share one client.
pub struct AnchorPublisher<S> {
    sink: S,
    s3: Arc<dyn S3Like>,
    bucket: String,
    retain_days: i64,
    signing_key: SecretString,
}

impl<S: std::fmt::Debug> std::fmt::Debug for AnchorPublisher<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AnchorPublisher")
            .field("sink", &self.sink)
            .field("s3", &self.s3)
            .field("bucket", &self.bucket)
            .field("retain_days", &self.retain_days)
            .field("signing_key", &"<redacted>")
            .finish()
    }
}

impl<S> AnchorPublisher<S>
where
    S: ChainHeadSource,
{
    /// Construct a new publisher.
    ///
    /// # Errors
    ///
    /// - [`AnchorError::EmptySigningKey`] if `signing_key` is empty.
    /// - [`AnchorError::InvalidRetainDays`] if `retain_days` is negative.
    pub fn new(
        sink: S,
        s3: Arc<dyn S3Like>,
        bucket: impl Into<String>,
        retain_days: i64,
        signing_key: SecretString,
    ) -> Result<Self, AnchorError> {
        if signing_key.expose_secret().is_empty() {
            return Err(AnchorError::EmptySigningKey);
        }
        if retain_days < 0 {
            return Err(AnchorError::InvalidRetainDays(retain_days));
        }
        Ok(Self {
            sink,
            s3,
            bucket: bucket.into(),
            retain_days,
            signing_key,
        })
    }

    /// Bucket the publisher writes into.
    #[must_use]
    pub fn bucket(&self) -> &str {
        &self.bucket
    }

    /// Retention horizon in days.
    #[must_use]
    pub const fn retain_days(&self) -> i64 {
        self.retain_days
    }

    /// Run a single snapshot pass.
    ///
    /// Returns the number of tenant manifests successfully written.
    /// Failing to write a manifest for one tenant does not abort the
    /// whole pass — the error is logged at WARN and the publisher
    /// moves on to the next tenant. The returned count reflects only
    /// successful writes.
    ///
    /// # Errors
    ///
    /// Returns [`AnchorError::Source`] if the underlying chain-head
    /// source fails. Per-tenant write failures are *not* propagated.
    #[instrument(skip(self), fields(bucket = %self.bucket))]
    pub async fn publish_once(&self) -> Result<u32, AnchorError> {
        let heads = self.sink.list_chain_heads().await?;
        let now = OffsetDateTime::now_utc();
        self.publish_at(heads, now).await
    }

    /// Internal helper: publish a known list of heads at a known
    /// `snapshot_ts`. Exposed via `pub(crate)` purely so the test
    /// suite can drive a deterministic timestamp.
    #[allow(clippy::cognitive_complexity)] // linear gate: filter → canonicalise → sign → upload per tenant
    pub(crate) async fn publish_at(
        &self,
        heads: Vec<ChainHead>,
        snapshot_ts: OffsetDateTime,
    ) -> Result<u32, AnchorError> {
        let retain_until = snapshot_ts
            .checked_add(Duration::days(self.retain_days))
            .ok_or_else(|| {
                AnchorError::TimeFormat(format!(
                    "retain_until overflow: now + {} days",
                    self.retain_days
                ))
            })?;

        let mut written: u32 = 0;
        for head in heads {
            if head.head_seq == 0 || head.head_hash.is_empty() {
                debug!(
                    target: TRACING_TARGET,
                    tenant = %head.tenant_id,
                    "skipping tenant with empty chain",
                );
                continue;
            }
            match self.publish_one(&head, snapshot_ts, retain_until).await {
                Ok(()) => {
                    written = written.saturating_add(1);
                }
                Err(e) => {
                    warn!(
                        target: TRACING_TARGET,
                        tenant = %head.tenant_id,
                        error = %e,
                        "anchor publish failed for tenant",
                    );
                }
            }
        }
        info!(
            target: TRACING_TARGET,
            written,
            "anchor publish pass complete",
        );
        Ok(written)
    }

    async fn publish_one(
        &self,
        head: &ChainHead,
        snapshot_ts: OffsetDateTime,
        retain_until: OffsetDateTime,
    ) -> Result<(), AnchorError> {
        let hmac = self.compute_manifest_hmac(head, snapshot_ts)?;
        let manifest = AnchorManifest {
            tenant_id: head.tenant_id,
            snapshot_ts,
            head_seq: head.head_seq,
            head_hash: head.head_hash.clone(),
            hmac,
        };
        let body = manifest.to_canonical_bytes()?;
        let key = object_key(head.tenant_id, snapshot_ts);
        debug!(
            target: TRACING_TARGET,
            tenant = %head.tenant_id,
            key = %key,
            bytes = body.len(),
            "writing anchor manifest",
        );
        self.s3
            .put_object(&self.bucket, &key, body, retain_until)
            .await
    }

    /// Compute the manifest-level HMAC over
    /// `tenant_id || RFC3339(snapshot_ts) || head_seq.to_be_bytes() || head_hash`.
    fn compute_manifest_hmac(
        &self,
        head: &ChainHead,
        snapshot_ts: OffsetDateTime,
    ) -> Result<String, AnchorError> {
        let ts_str = snapshot_ts
            .format(&Rfc3339)
            .map_err(|e| AnchorError::TimeFormat(e.to_string()))?;
        let mut mac = HmacSha256::new_from_slice(self.signing_key.expose_secret().as_bytes())
            .map_err(|e| AnchorError::InvalidKey(e.to_string()))?;
        mac.update(head.tenant_id.to_string().as_bytes());
        mac.update(b"|");
        mac.update(ts_str.as_bytes());
        mac.update(b"|");
        mac.update(&head.head_seq.to_be_bytes());
        mac.update(b"|");
        mac.update(head.head_hash.as_bytes());
        Ok(hex::encode(mac.finalize().into_bytes()))
    }
}

/// Format the object key for a given tenant + snapshot timestamp:
/// `audit-anchors/<tenant_id>/<yyyymmddTHHMMSSZ>.json`.
fn object_key(tenant_id: TenantId, snapshot_ts: OffsetDateTime) -> String {
    let utc = snapshot_ts.to_offset(time::UtcOffset::UTC);
    let stamp = format!(
        "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
        utc.year(),
        u8::from(utc.month()),
        utc.day(),
        utc.hour(),
        utc.minute(),
        utc.second(),
    );
    format!("{ANCHOR_KEY_PREFIX}/{tenant_id}/{stamp}.json")
}

/// Spawn a background task that calls [`AnchorPublisher::publish_once`]
/// every `interval` until `shutdown` is notified.
///
/// The first tick fires one `interval` after spawn (matching
/// [`tokio::time::interval`] semantics with the immediate tick consumed).
#[must_use]
pub fn spawn<S>(
    publisher: AnchorPublisher<S>,
    interval: StdDuration,
    shutdown: Arc<Notify>,
) -> JoinHandle<()>
where
    S: ChainHeadSource + 'static,
{
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        // Consume the immediate-fire tick so the first real pass is at
        // `+interval`, not at `t=0`.
        ticker.tick().await;
        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    match publisher.publish_once().await {
                        Ok(n) => debug!(
                            target: TRACING_TARGET,
                            written = n,
                            "anchor publish tick",
                        ),
                        Err(e) => warn!(
                            target: TRACING_TARGET,
                            error = %e,
                            "anchor publish tick failed",
                        ),
                    }
                }
                () = shutdown.notified() => {
                    debug!(
                        target: TRACING_TARGET,
                        "anchor publisher shutting down",
                    );
                    break;
                }
            }
        }
    })
}

/// In-memory [`S3Like`] for tests. **Not** for production use; there is
/// no real Object Lock — the `retain_until` value is stored alongside
/// the body so tests can assert on it.
#[derive(Debug, Default)]
pub struct MockS3 {
    inner: Mutex<HashMap<(String, String), MockObject>>,
}

/// A single object held in [`MockS3`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MockObject {
    /// Body bytes as written.
    pub body: Vec<u8>,
    /// `RetainUntil` value the publisher requested at write time.
    pub retain_until: OffsetDateTime,
}

impl MockS3 {
    /// New, empty mock.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of objects currently stored.
    pub async fn len(&self) -> usize {
        self.inner.lock().await.len()
    }

    /// Convenience: `len() == 0`.
    pub async fn is_empty(&self) -> bool {
        self.inner.lock().await.is_empty()
    }

    /// Read the raw [`MockObject`] (body + `retain_until`) for a key.
    pub async fn get(&self, bucket: &str, key: &str) -> Option<MockObject> {
        self.inner
            .lock()
            .await
            .get(&(bucket.to_owned(), key.to_owned()))
            .cloned()
    }

    /// Snapshot all keys present in the mock, sorted ascending.
    pub async fn keys(&self) -> Vec<(String, String)> {
        let mut v: Vec<_> = {
            let g = self.inner.lock().await;
            g.keys().cloned().collect()
        };
        v.sort();
        v
    }
}

#[async_trait]
impl S3Like for MockS3 {
    async fn put_object(
        &self,
        bucket: &str,
        key: &str,
        body: Vec<u8>,
        retain_until: OffsetDateTime,
    ) -> Result<(), AnchorError> {
        {
            let mut g = self.inner.lock().await;
            g.insert(
                (bucket.to_owned(), key.to_owned()),
                MockObject { body, retain_until },
            );
        }
        Ok(())
    }

    async fn get_object(&self, bucket: &str, key: &str) -> Result<Vec<u8>, AnchorError> {
        let result = {
            let g = self.inner.lock().await;
            g.get(&(bucket.to_owned(), key.to_owned()))
                .map(|o| o.body.clone())
        };
        result.ok_or_else(|| AnchorError::NotFound {
            bucket: bucket.to_owned(),
            key: key.to_owned(),
        })
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_lossless,
    clippy::similar_names
)]
mod tests {
    use super::*;

    use std::sync::Mutex as StdMutex;

    use uuid::Uuid;

    fn key() -> SecretString {
        SecretString::from("anchor-test-key-must-be-at-least-16b".to_owned())
    }

    fn tenant(n: u128) -> TenantId {
        let mut bytes = [0u8; 16];
        bytes[0..16].copy_from_slice(&n.to_be_bytes());
        // Set v7-ish bits so the Uuid parses as a sane TenantId.
        bytes[6] = (bytes[6] & 0x0F) | 0x70;
        bytes[8] = (bytes[8] & 0x3F) | 0x80;
        Uuid::from_bytes(bytes).into()
    }

    fn fixed_ts() -> OffsetDateTime {
        // 2025-01-02T03:04:05Z — chosen for an unambiguous key string.
        OffsetDateTime::from_unix_timestamp(1_735_787_045).unwrap()
    }

    /// Test stub source — returns whatever it was constructed with.
    #[derive(Debug)]
    struct StubSource {
        heads: StdMutex<Vec<ChainHead>>,
    }

    impl StubSource {
        fn new(heads: Vec<ChainHead>) -> Self {
            Self {
                heads: StdMutex::new(heads),
            }
        }
    }

    #[async_trait]
    impl ChainHeadSource for StubSource {
        async fn list_chain_heads(&self) -> Result<Vec<ChainHead>, AnchorError> {
            Ok(self.heads.lock().unwrap().clone())
        }
    }

    fn head(t: TenantId, seq: u64, hash_byte: u8) -> ChainHead {
        ChainHead {
            tenant_id: t,
            head_seq: seq,
            head_hash: hex::encode([hash_byte; 32]),
        }
    }

    #[tokio::test]
    async fn publish_once_writes_one_object_per_tenant() {
        let t1 = tenant(1);
        let t2 = tenant(2);
        let t3 = tenant(3);
        let source = StubSource::new(vec![
            head(t1, 10, 0xAA),
            head(t2, 20, 0xBB),
            head(t3, 30, 0xCC),
        ]);
        let s3 = Arc::new(MockS3::new());
        let pub_ = AnchorPublisher::new(
            source,
            s3.clone() as Arc<dyn S3Like>,
            "audit-bucket",
            7,
            key(),
        )
        .unwrap();

        let n = pub_.publish_once().await.unwrap();
        assert_eq!(n, 3);
        assert_eq!(s3.len().await, 3);

        let keys = s3.keys().await;
        assert!(keys.iter().any(|(_, k)| k.contains(&t1.to_string())));
        assert!(keys.iter().any(|(_, k)| k.contains(&t2.to_string())));
        assert!(keys.iter().any(|(_, k)| k.contains(&t3.to_string())));
    }

    #[tokio::test]
    async fn manifest_body_is_sorted_key_json() {
        let t = tenant(42);
        let source = StubSource::new(vec![head(t, 99, 0x11)]);
        let s3 = Arc::new(MockS3::new());
        let pub_ = AnchorPublisher::new(
            source,
            s3.clone() as Arc<dyn S3Like>,
            "audit-bucket",
            7,
            key(),
        )
        .unwrap();
        let ts = fixed_ts();
        let n = pub_.publish_at(vec![head(t, 99, 0x11)], ts).await.unwrap();
        assert_eq!(n, 1);

        let key_ = object_key(t, ts);
        let obj = s3.get("audit-bucket", &key_).await.unwrap();
        let body_str = std::str::from_utf8(&obj.body).unwrap();
        // Keys must appear in lexicographic order:
        // head_hash < head_seq < hmac < snapshot_ts < tenant_id.
        let positions: Vec<usize> = [
            "\"head_hash\"",
            "\"head_seq\"",
            "\"hmac\"",
            "\"snapshot_ts\"",
            "\"tenant_id\"",
        ]
        .iter()
        .map(|k| body_str.find(k).unwrap_or_else(|| panic!("missing {k}")))
        .collect();
        for w in positions.windows(2) {
            assert!(w[0] < w[1], "manifest keys not lexicographically sorted");
        }
        // And the body round-trips through the public deserializer.
        let parsed: AnchorManifest = serde_json::from_slice(&obj.body).unwrap();
        assert_eq!(parsed.tenant_id, t);
        assert_eq!(parsed.head_seq, 99);
        assert_eq!(parsed.head_hash, hex::encode([0x11u8; 32]));
        assert_eq!(parsed.snapshot_ts, ts);
        assert_eq!(parsed.hmac.len(), 64);
    }

    #[tokio::test]
    async fn retain_until_is_now_plus_retain_days() {
        let t = tenant(7);
        let source = StubSource::new(vec![head(t, 1, 0xEE)]);
        let s3 = Arc::new(MockS3::new());
        let pub_ = AnchorPublisher::new(
            source,
            s3.clone() as Arc<dyn S3Like>,
            "audit-bucket",
            90,
            key(),
        )
        .unwrap();
        let ts = fixed_ts();
        pub_.publish_at(vec![head(t, 1, 0xEE)], ts).await.unwrap();
        let key_ = object_key(t, ts);
        let obj = s3.get("audit-bucket", &key_).await.unwrap();
        let expected = ts.checked_add(Duration::days(90)).unwrap();
        assert_eq!(obj.retain_until, expected);
        // Sanity: retain_until is strictly in the future relative to ts.
        assert!(obj.retain_until > ts);
        // And it equals ts + 90*86400s exactly.
        assert_eq!((obj.retain_until - ts), Duration::days(90));
    }

    #[tokio::test(start_paused = true)]
    async fn spawn_runs_and_cancels_cleanly() {
        let t = tenant(123);
        let source = StubSource::new(vec![head(t, 5, 0x55)]);
        let s3 = Arc::new(MockS3::new());
        let pub_ = AnchorPublisher::new(
            source,
            s3.clone() as Arc<dyn S3Like>,
            "audit-bucket",
            1,
            key(),
        )
        .unwrap();

        let shutdown = Arc::new(Notify::new());
        let handle = spawn(pub_, StdDuration::from_millis(50), shutdown.clone());

        tokio::task::yield_now().await;
        tokio::time::advance(StdDuration::from_millis(200)).await;
        for _ in 0..5 {
            tokio::task::yield_now().await;
        }
        // At least one tick should have written.
        assert!(s3.len().await >= 1, "expected at least one tick to write");

        shutdown.notify_waiters();
        tokio::time::timeout(StdDuration::from_secs(1), handle)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn hmac_includes_head_hash_and_snapshot_ts() {
        let t = tenant(31);
        let source = StubSource::new(vec![]); // unused for direct hmac compute
        let s3 = Arc::new(MockS3::new()) as Arc<dyn S3Like>;
        let pub_ = AnchorPublisher::new(source, s3, "audit-bucket", 7, key()).unwrap();

        let h1 = head(t, 1, 0xAA);
        let h2 = head(t, 1, 0xBB); // different head_hash
        let ts1 = fixed_ts();
        let ts2 = ts1.checked_add(Duration::seconds(1)).unwrap();

        let m_h1_ts1 = pub_.compute_manifest_hmac(&h1, ts1).unwrap();
        let m_h2_ts1 = pub_.compute_manifest_hmac(&h2, ts1).unwrap();
        let m_h1_ts2 = pub_.compute_manifest_hmac(&h1, ts2).unwrap();

        // Different head_hash => different HMAC.
        assert_ne!(m_h1_ts1, m_h2_ts1);
        // Different snapshot_ts => different HMAC.
        assert_ne!(m_h1_ts1, m_h1_ts2);
        // Same inputs => same HMAC (determinism).
        assert_eq!(m_h1_ts1, pub_.compute_manifest_hmac(&h1, ts1).unwrap());
        // 32-byte HMAC => 64 hex chars.
        assert_eq!(m_h1_ts1.len(), 64);
    }

    #[tokio::test]
    async fn mock_s3_put_get_round_trip() {
        let s3 = MockS3::new();
        assert!(s3.is_empty().await);
        let until = fixed_ts().checked_add(Duration::days(30)).unwrap();
        s3.put_object("b1", "k1", b"hello".to_vec(), until)
            .await
            .unwrap();
        let got = s3.get_object("b1", "k1").await.unwrap();
        assert_eq!(got, b"hello");
        assert_eq!(s3.len().await, 1);

        // Missing key surfaces NotFound.
        let err = s3.get_object("b1", "missing").await.unwrap_err();
        match err {
            AnchorError::NotFound { bucket, key } => {
                assert_eq!(bucket, "b1");
                assert_eq!(key, "missing");
            }
            other => panic!("expected NotFound, got {other:?}"),
        }

        // And put overwrites cleanly.
        let until2 = fixed_ts().checked_add(Duration::days(60)).unwrap();
        s3.put_object("b1", "k1", b"world".to_vec(), until2)
            .await
            .unwrap();
        let obj = s3.get("b1", "k1").await.unwrap();
        assert_eq!(obj.body, b"world");
        assert_eq!(obj.retain_until, until2);
    }

    #[tokio::test]
    async fn skips_tenants_with_empty_chain() {
        let t1 = tenant(1);
        let t2 = tenant(2);
        // t2 has no entries yet (head_seq=0, empty hash) — should be skipped.
        let source = StubSource::new(vec![
            head(t1, 7, 0x42),
            ChainHead {
                tenant_id: t2,
                head_seq: 0,
                head_hash: String::new(),
            },
        ]);
        let s3 = Arc::new(MockS3::new());
        let pub_ = AnchorPublisher::new(
            source,
            s3.clone() as Arc<dyn S3Like>,
            "audit-bucket",
            7,
            key(),
        )
        .unwrap();
        let n = pub_.publish_once().await.unwrap();
        assert_eq!(n, 1);
        assert_eq!(s3.len().await, 1);
    }

    #[test]
    fn object_key_format() {
        let t = tenant(99);
        let ts = OffsetDateTime::from_unix_timestamp(1_735_787_045).unwrap();
        let k = object_key(t, ts);
        // Prefix and tenant segment.
        assert!(k.starts_with(&format!("{ANCHOR_KEY_PREFIX}/{t}/")));
        assert!(std::path::Path::new(&k)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("json")));
        // The timestamp segment is exactly yyyymmddTHHMMSSZ.
        let stamp = k.rsplit('/').next().unwrap().trim_end_matches(".json");
        assert_eq!(stamp.len(), 16);
        assert!(stamp.ends_with('Z'));
        assert!(stamp.contains('T'));
    }

    #[test]
    fn new_rejects_empty_key() {
        let s3 = Arc::new(MockS3::new()) as Arc<dyn S3Like>;
        let err = AnchorPublisher::new(
            StubSource::new(vec![]),
            s3,
            "b",
            7,
            SecretString::from(String::new()),
        )
        .unwrap_err();
        assert!(matches!(err, AnchorError::EmptySigningKey));
    }

    #[test]
    fn new_rejects_negative_retain_days() {
        let s3 = Arc::new(MockS3::new()) as Arc<dyn S3Like>;
        let err = AnchorPublisher::new(StubSource::new(vec![]), s3, "b", -1, key()).unwrap_err();
        assert!(matches!(err, AnchorError::InvalidRetainDays(-1)));
    }

    #[test]
    fn debug_for_publisher_redacts_signing_key() {
        let s3 = Arc::new(MockS3::new()) as Arc<dyn S3Like>;
        let pub_ = AnchorPublisher::new(StubSource::new(vec![]), s3, "b", 7, key()).unwrap();
        let dbg = format!("{pub_:?}");
        assert!(dbg.contains("<redacted>"));
        assert!(!dbg.contains("anchor-test-key"));
    }
}
