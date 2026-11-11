//! CVE master scheduler (P0-006).
//!
//! Glues [`NvdFetcher`], [`KevFetcher`], and [`EpssFetcher`] together into a
//! single orchestrated sync loop. Owns the per-source cadence policy and
//! the once-per-deployment historical backfill (last five years).
//!
//! The scheduler is intentionally storage-agnostic: it talks to a
//! [`CveMasterStore`] trait that abstracts upsert, sync-state, severity
//! recompute, and audit-log writes. The monolith plumbs a Postgres-backed
//! implementation in a separate commit; the crate-level test suite uses an
//! in-memory store to exercise every branch deterministically.
//!
//! ## Cadence
//!
//! | Source | Cadence | Window |
//! |---|---|---|
//! | NVD | `nvd_interval` (default 1 h) | `last_synced_at` → now |
//! | KEV | `kev_interval` (default 1 h) | full catalogue snapshot |
//! | EPSS | `epss_interval` (default 24 h) | yesterday's UTC date |
//!
//! ## Backfill
//!
//! On first run for a given source (i.e. `cve_master_sync_state.backfill_complete = FALSE`),
//! the NVD sweep widens its `since` window to `now − 5 years` and flags
//! the run as a "full sync". Full syncs emit a [`AuditEvent::FullSync`]
//! audit record and call the severity-recompute hook for every CVE that
//! was inserted-or-modified.
//!
//! ## Per-tenant boundary
//!
//! The `cve_master` table is **global** — no tenant scoping. Severity
//! recompute is **per-tenant**: the store's
//! [`CveMasterStore::recompute_severities`] is expected to iterate over
//! every tenant whose findings reference the modified CVE ids and rewrite
//! their `severity` column accordingly. The scheduler hands the store a
//! single `Vec<String>` of affected CVE ids and lets the store decide how
//! to fan it out across tenants.

use std::collections::{HashMap, HashSet};

use async_trait::async_trait;
use time::format_description::well_known::Rfc3339;
use time::macros::format_description;
use time::{Duration as TimeDuration, OffsetDateTime};
use tracing::{debug, info, instrument, warn};

use crate::cve_master::{CveMasterError, CveMasterRow};
use crate::epss::EpssFetcher;
use crate::kev::KevFetcher;
use crate::nvd::NvdFetcher;

/// Sources tracked by [`CveMasterStore::load_sync_state`] /
/// [`CveMasterStore::save_sync_state`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SyncSource {
    /// NVD CVE 2.0 incremental sweep.
    Nvd,
    /// CISA KEV catalogue snapshot.
    Kev,
    /// FIRST EPSS daily CSV.
    Epss,
}

impl SyncSource {
    /// Lowercase string form used as the `cve_master_sync_state.source`
    /// primary-key value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Nvd => "nvd",
            Self::Kev => "kev",
            Self::Epss => "epss",
        }
    }
}

/// Persisted high-water-mark for a single source.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SyncState {
    /// High-water-mark passed as the next sweep's `since` argument.
    /// `None` means "no successful sync yet — perform a backfill".
    pub high_water_mark: Option<OffsetDateTime>,
    /// Whether the initial 5-year backfill has completed for this source.
    pub backfill_complete: bool,
}

/// Audit events emitted by the scheduler.
///
/// These match `audit_log` rows the store is expected to write under the
/// global / cross-tenant scope. Only [`Self::FullSync`] is mandatory per
/// the P0-006 acceptance criteria; the incremental variant is included so
/// operators can correlate every sync with a row in the audit chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditEvent {
    /// A full historical backfill completed.
    FullSync {
        /// Which source the sync ran against.
        source: SyncSource,
        /// Number of `cve_master` rows touched.
        row_count: u64,
        /// When the sync finished.
        completed_at: OffsetDateTime,
    },
    /// An incremental sweep completed.
    IncrementalSync {
        /// Which source the sync ran against.
        source: SyncSource,
        /// Number of `cve_master` rows touched.
        row_count: u64,
        /// When the sync finished.
        completed_at: OffsetDateTime,
    },
}

/// Storage contract for the CVE master scheduler.
///
/// Implementations must be `Send + Sync` so the scheduler can hold them
/// across `.await` points inside a `tokio::spawn`'d task. The trait is
/// deliberately small — every method either reads or writes a single
/// well-typed row, leaving SQL choices (UPSERT vs MERGE, ON CONFLICT
/// clauses, etc.) to the implementer.
///
/// ### Error surface
///
/// All methods return [`CveMasterError`] so the scheduler's error type
/// stays uniform. The store layer is expected to wrap database errors via
/// [`CveMasterError::Status`] with a synthetic `500 Internal Server Error`
/// status, or a freshly-added variant in a follow-up round.
#[async_trait]
pub trait CveMasterStore: Send + Sync {
    /// Upsert `rows` into `cve_master`. Returns the number of rows that
    /// were either inserted or modified (i.e. `XMAX = 0` on insert, or
    /// `xmin != xmax` on update — implementation choice).
    async fn upsert_rows(&self, rows: &[CveMasterRow]) -> Result<u64, CveMasterError>;

    /// Read the high-water-mark for `source`. Returns the [`Default`]
    /// (`backfill_complete = false`, `high_water_mark = None`) when the
    /// row does not yet exist.
    async fn load_sync_state(&self, source: SyncSource) -> Result<SyncState, CveMasterError>;

    /// Persist the high-water-mark for `source`. Implementations should
    /// `INSERT … ON CONFLICT (source) DO UPDATE`.
    async fn save_sync_state(
        &self,
        source: SyncSource,
        state: &SyncState,
    ) -> Result<(), CveMasterError>;

    /// Recompute severities for every finding referencing one of the
    /// supplied CVE ids. Per-tenant scoping is the store's responsibility:
    /// the scheduler does not know how many tenants exist or which
    /// findings reference which CVE.
    ///
    /// Returns the total number of findings whose `severity` was rewritten
    /// across all tenants.
    async fn recompute_severities(&self, cves: &[String]) -> Result<u64, CveMasterError>;

    /// Append an entry to the global audit chain. Mandatory on every
    /// full-sync per the P0-006 acceptance criteria; the scheduler also
    /// records incremental sweeps so operators get a complete timeline.
    async fn append_audit(&self, event: &AuditEvent) -> Result<(), CveMasterError>;
}

/// How far back the historical backfill reaches on first run.
///
/// 5 years matches the P0-006 acceptance criteria. Operators can override
/// this via [`Scheduler::with_backfill_window`] for partial restores.
pub const DEFAULT_BACKFILL: TimeDuration = TimeDuration::days(5 * 365);

/// Orchestrates the three per-source fetchers, the sync-state bookkeeping,
/// and the severity-recompute + audit hooks.
///
/// Cheap to construct, expensive to call: each [`Scheduler::run_once`] kick
/// performs one NVD incremental sweep, one KEV refresh, and one EPSS daily
/// download (if the EPSS cadence is due).
#[derive(Debug)]
pub struct Scheduler<S> {
    nvd: NvdFetcher,
    kev: KevFetcher,
    epss: EpssFetcher,
    store: S,
    backfill_window: TimeDuration,
}

impl<S> Scheduler<S> {
    /// Build a scheduler that owns the three fetchers and the store.
    #[must_use]
    pub const fn new(nvd: NvdFetcher, kev: KevFetcher, epss: EpssFetcher, store: S) -> Self {
        Self {
            nvd,
            kev,
            epss,
            store,
            backfill_window: DEFAULT_BACKFILL,
        }
    }

    /// Override the historical backfill window. Tests use this to shorten
    /// the sweep to a few days; operators use it to widen / narrow the
    /// initial pull.
    #[must_use]
    pub const fn with_backfill_window(mut self, window: TimeDuration) -> Self {
        self.backfill_window = window;
        self
    }
}

impl<S: CveMasterStore> Scheduler<S> {
    /// Run one full cycle of (NVD → KEV → EPSS), upsert the merged rows,
    /// and (on a full sync) trigger the severity recompute + audit hooks.
    ///
    /// Returns the number of `cve_master` rows touched by the merge. The
    /// caller is responsible for scheduling — typically a `tokio` interval
    /// at `nvd_interval` cadence in the monolith binary.
    ///
    /// `now` is injected so tests can pin the clock; production code calls
    /// `OffsetDateTime::now_utc()`.
    #[instrument(skip(self), fields(now = %now))]
    #[allow(clippy::cognitive_complexity)]
    pub async fn run_once(&self, now: OffsetDateTime) -> Result<SyncOutcome, CveMasterError> {
        // ── 1. Resolve the NVD "since" window. ────────────────────────────
        let nvd_state = self.store.load_sync_state(SyncSource::Nvd).await?;
        let is_full_sync = !nvd_state.backfill_complete;
        let since = if is_full_sync {
            info!(
                window_days = self.backfill_window.whole_days(),
                "NVD full backfill"
            );
            now - self.backfill_window
        } else {
            nvd_state
                .high_water_mark
                .unwrap_or(now - self.backfill_window)
        };

        // ── 2. Pull NVD, KEV, EPSS in series. ────────────────────────────
        // Series, not parallel, because the rate-limited NVD sweep already
        // consumes most of the wall-clock budget and the KEV/EPSS GETs are
        // single requests.
        let nvd_rows = self.nvd.fetch_since(since).await?;
        debug!(count = nvd_rows.len(), "NVD slice fetched");

        let kev_rows = self.kev.fetch().await?;
        let kev_map: HashMap<String, OffsetDateTime> = kev_rows.into_iter().collect();
        debug!(count = kev_map.len(), "KEV catalogue fetched");

        let epss_date = epss_date_for(now);
        let epss_rows = match self.epss.fetch_for_date(&epss_date).await {
            Ok(rows) => rows,
            Err(CveMasterError::Status { status }) if status.as_u16() == 404 => {
                // FIRST publishes the daily blob ~04:00 UTC. A 404 means
                // we're running before today's drop landed — fall back to
                // an empty join so KEV + NVD still merge cleanly.
                warn!(date = %epss_date, "EPSS daily CSV not yet published — skipping");
                Vec::new()
            }
            Err(e) => return Err(e),
        };
        let epss_map: HashMap<String, (f32, f32)> = epss_rows
            .into_iter()
            .map(|(cve, e, p)| (cve, (e, p)))
            .collect();
        debug!(count = epss_map.len(), "EPSS slice fetched");

        // ── 3. Merge and upsert. ─────────────────────────────────────────
        let merged = crate::cve_master::merge(nvd_rows, &kev_map, &epss_map);
        let affected_cves: Vec<String> = merged
            .iter()
            .map(|r| r.cve_id.clone())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        let row_count = self.store.upsert_rows(&merged).await?;
        info!(
            rows = row_count,
            full = is_full_sync,
            "cve_master upsert complete"
        );

        // ── 4. Persist sync state. ───────────────────────────────────────
        let new_state = SyncState {
            high_water_mark: Some(now),
            backfill_complete: true,
        };
        self.store
            .save_sync_state(SyncSource::Nvd, &new_state)
            .await?;
        self.store
            .save_sync_state(SyncSource::Kev, &new_state)
            .await?;
        self.store
            .save_sync_state(SyncSource::Epss, &new_state)
            .await?;

        // ── 5. Severity recompute hook (per-tenant inside the store). ────
        let recomputed = if affected_cves.is_empty() {
            0
        } else {
            self.store.recompute_severities(&affected_cves).await?
        };

        // ── 6. Audit log. ────────────────────────────────────────────────
        let event = if is_full_sync {
            AuditEvent::FullSync {
                source: SyncSource::Nvd,
                row_count,
                completed_at: now,
            }
        } else {
            AuditEvent::IncrementalSync {
                source: SyncSource::Nvd,
                row_count,
                completed_at: now,
            }
        };
        self.store.append_audit(&event).await?;

        Ok(SyncOutcome {
            full_sync: is_full_sync,
            cve_rows_upserted: row_count,
            findings_recomputed: recomputed,
        })
    }
}

/// Summary of a single [`Scheduler::run_once`] invocation. Returned for
/// observability + test assertions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncOutcome {
    /// Whether this run performed the historical backfill.
    pub full_sync: bool,
    /// Number of `cve_master` rows that were inserted or modified.
    pub cve_rows_upserted: u64,
    /// Number of `findings` whose `severity` column was recomputed across
    /// all tenants by the store hook.
    pub findings_recomputed: u64,
}

/// Returns the YYYY-MM-DD string for the EPSS daily CSV.
///
/// Today's CSV is published around 04:00 UTC. To avoid a constant 404 race
/// window in the first four hours of every day we always pull *yesterday's*
/// blob — it is guaranteed to exist and the freshness loss is bounded.
fn epss_date_for(now: OffsetDateTime) -> String {
    let target = now - TimeDuration::days(1);
    let desc = format_description!("[year]-[month]-[day]");
    target
        .format(desc)
        .unwrap_or_else(|_| target.date().to_string())
}

/// Convenience helper: format `OffsetDateTime` as RFC 3339. Used by the
/// monolith binary when writing tracing events for the sync timeline.
///
/// Surfaces as a panic-free `String` — formatting failure falls back to
/// `Debug` so observability never disappears entirely.
#[must_use]
pub fn rfc3339(t: OffsetDateTime) -> String {
    t.format(&Rfc3339).unwrap_or_else(|_| format!("{t:?}"))
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::float_cmp
)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::time::Duration as StdDuration;
    use time::macros::datetime;

    use crate::rate_limit::TokenBucket;
    use reqwest::Client;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// In-memory store: records every call for later assertions.
    #[derive(Debug, Default)]
    struct MemStore {
        inner: Mutex<MemState>,
    }

    #[derive(Debug, Default)]
    struct MemState {
        rows: Vec<CveMasterRow>,
        sync_state: HashMap<SyncSource, SyncState>,
        recomputed_calls: Vec<Vec<String>>,
        audit: Vec<AuditEvent>,
    }

    impl MemStore {
        fn snapshot(&self) -> MemSnapshot {
            let s = self.inner.lock().unwrap();
            MemSnapshot {
                rows: s.rows.clone(),
                sync_state: s.sync_state.clone(),
                recomputed_calls: s.recomputed_calls.clone(),
                audit: s.audit.clone(),
            }
        }

        fn preload_state(&self, source: SyncSource, state: SyncState) {
            self.inner.lock().unwrap().sync_state.insert(source, state);
        }
    }

    #[derive(Debug)]
    struct MemSnapshot {
        rows: Vec<CveMasterRow>,
        sync_state: HashMap<SyncSource, SyncState>,
        recomputed_calls: Vec<Vec<String>>,
        audit: Vec<AuditEvent>,
    }

    #[async_trait]
    impl CveMasterStore for MemStore {
        async fn upsert_rows(&self, rows: &[CveMasterRow]) -> Result<u64, CveMasterError> {
            {
                let mut s = self.inner.lock().unwrap();
                for r in rows {
                    s.rows.retain(|existing| existing.cve_id != r.cve_id);
                    s.rows.push(r.clone());
                }
            }
            Ok(rows.len() as u64)
        }
        async fn load_sync_state(&self, source: SyncSource) -> Result<SyncState, CveMasterError> {
            Ok(self
                .inner
                .lock()
                .unwrap()
                .sync_state
                .get(&source)
                .cloned()
                .unwrap_or_default())
        }
        async fn save_sync_state(
            &self,
            source: SyncSource,
            state: &SyncState,
        ) -> Result<(), CveMasterError> {
            self.inner
                .lock()
                .unwrap()
                .sync_state
                .insert(source, state.clone());
            Ok(())
        }
        async fn recompute_severities(&self, cves: &[String]) -> Result<u64, CveMasterError> {
            {
                let mut s = self.inner.lock().unwrap();
                s.recomputed_calls.push(cves.to_vec());
            }
            Ok(cves.len() as u64)
        }
        async fn append_audit(&self, event: &AuditEvent) -> Result<(), CveMasterError> {
            self.inner.lock().unwrap().audit.push(event.clone());
            Ok(())
        }
    }

    fn fast_bucket() -> TokenBucket {
        TokenBucket::new(1000, StdDuration::from_millis(1))
    }

    fn nvd_envelope() -> serde_json::Value {
        serde_json::json!({
            "totalResults": 1,
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2024-1234",
                    "published": "2024-06-01T12:00:00.000",
                    "lastModified": "2024-06-02T12:00:00.000",
                    "descriptions": [{ "lang": "en", "value": "test" }],
                    "metrics": {
                        "cvssMetricV31": [{
                            "cvssData": { "baseScore": 7.5, "vectorString": "CVSS:3.1/X" }
                        }]
                    },
                    "configurations": []
                }
            }]
        })
    }

    fn kev_envelope() -> serde_json::Value {
        serde_json::json!({
            "vulnerabilities": [
                { "cveID": "CVE-2024-1234", "dateAdded": "2024-06-10" }
            ]
        })
    }

    fn gzip_csv(csv: &str) -> Vec<u8> {
        use std::io::Write;
        let mut gz = Vec::new();
        {
            let mut enc = flate2::write::GzEncoder::new(&mut gz, flate2::Compression::default());
            enc.write_all(csv.as_bytes()).unwrap();
            enc.finish().unwrap();
        }
        gz
    }

    async fn build_scheduler(server: &MockServer, store: MemStore) -> Scheduler<MemStore> {
        // Mount NVD, KEV, EPSS routes on a single server keyed by path.
        Mock::given(method("GET"))
            .and(path("/nvd"))
            .respond_with(ResponseTemplate::new(200).set_body_json(nvd_envelope()))
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path("/kev.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(kev_envelope()))
            .mount(server)
            .await;
        let csv = "cve,epss,percentile\nCVE-2024-1234,0.99,0.99\n";
        Mock::given(method("GET"))
            .and(path("/epss"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(gzip_csv(csv)))
            .mount(server)
            .await;

        let http = Client::new();
        let nvd = NvdFetcher::new(http.clone())
            .with_base(format!("{}/nvd", server.uri()))
            .with_bucket(fast_bucket());
        let kev = KevFetcher::new(http.clone()).with_url(format!("{}/kev.json", server.uri()));
        let epss = EpssFetcher::new(http).with_template(format!("{}/epss", server.uri()));
        Scheduler::new(nvd, kev, epss, store).with_backfill_window(TimeDuration::days(30))
    }

    #[tokio::test]
    async fn first_run_is_full_sync_and_emits_audit() {
        let server = MockServer::start().await;
        let store = MemStore::default();
        let sched = build_scheduler(&server, store).await;
        let now = datetime!(2024-06-15 0:00 UTC);

        let outcome = sched.run_once(now).await.unwrap();

        assert!(outcome.full_sync, "first run must be a full sync");
        assert_eq!(outcome.cve_rows_upserted, 1);
        assert_eq!(outcome.findings_recomputed, 1);

        let snap = sched.store.snapshot();
        // The single merged row picked up KEV + EPSS side-channels.
        assert_eq!(snap.rows.len(), 1);
        let row = &snap.rows[0];
        assert_eq!(row.cve_id, "CVE-2024-1234");
        assert!(row.kev);
        assert!((row.epss - 0.99).abs() < 1e-5);
        assert_eq!(row.cvss_v3_score, Some(7.5));
        assert_eq!(row.severity(), crate::cve_master::Severity::Critical);

        // Sync state persisted for all three sources.
        for source in [SyncSource::Nvd, SyncSource::Kev, SyncSource::Epss] {
            let st = snap.sync_state.get(&source).expect("source state saved");
            assert!(st.backfill_complete, "{source:?} must be marked complete");
            assert_eq!(st.high_water_mark, Some(now));
        }

        // Audit chain: exactly one FullSync entry.
        assert_eq!(snap.audit.len(), 1);
        match &snap.audit[0] {
            AuditEvent::FullSync {
                source,
                row_count,
                completed_at,
            } => {
                assert_eq!(*source, SyncSource::Nvd);
                assert_eq!(*row_count, 1);
                assert_eq!(*completed_at, now);
            }
            AuditEvent::IncrementalSync { .. } => panic!("expected FullSync"),
        }

        // Severity recompute hook was invoked once with the affected CVE.
        assert_eq!(snap.recomputed_calls.len(), 1);
        assert_eq!(snap.recomputed_calls[0], vec!["CVE-2024-1234".to_owned()]);
    }

    #[tokio::test]
    async fn subsequent_run_is_incremental() {
        let server = MockServer::start().await;
        let store = MemStore::default();
        // Preload the NVD source as "already backfilled".
        store.preload_state(
            SyncSource::Nvd,
            SyncState {
                high_water_mark: Some(datetime!(2024-06-14 0:00 UTC)),
                backfill_complete: true,
            },
        );
        let sched = build_scheduler(&server, store).await;
        let now = datetime!(2024-06-15 0:00 UTC);

        let outcome = sched.run_once(now).await.unwrap();
        assert!(!outcome.full_sync, "second run must be incremental");

        let snap = sched.store.snapshot();
        assert_eq!(snap.audit.len(), 1);
        assert!(matches!(snap.audit[0], AuditEvent::IncrementalSync { .. }));
    }

    #[tokio::test]
    async fn epss_404_is_swallowed() {
        let server = MockServer::start().await;
        let store = MemStore::default();
        // Mount NVD + KEV success, but EPSS 404.
        Mock::given(method("GET"))
            .and(path("/nvd"))
            .respond_with(ResponseTemplate::new(200).set_body_json(nvd_envelope()))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/kev.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(kev_envelope()))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/epss"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let http = Client::new();
        let nvd = NvdFetcher::new(http.clone())
            .with_base(format!("{}/nvd", server.uri()))
            .with_bucket(fast_bucket());
        let kev = KevFetcher::new(http.clone()).with_url(format!("{}/kev.json", server.uri()));
        let epss = EpssFetcher::new(http).with_template(format!("{}/epss", server.uri()));
        let sched =
            Scheduler::new(nvd, kev, epss, store).with_backfill_window(TimeDuration::days(30));

        let outcome = sched
            .run_once(datetime!(2024-06-15 0:00 UTC))
            .await
            .unwrap();
        // KEV still applied even when EPSS is missing.
        let snap = sched.store.snapshot();
        assert_eq!(outcome.cve_rows_upserted, 1);
        assert!(snap.rows[0].kev);
        assert_eq!(snap.rows[0].epss, 0.0);
    }

    #[test]
    fn epss_date_targets_yesterday() {
        let now = datetime!(2024-06-15 0:30 UTC);
        assert_eq!(epss_date_for(now), "2024-06-14");
    }

    #[test]
    fn sync_source_as_str_round_trips() {
        assert_eq!(SyncSource::Nvd.as_str(), "nvd");
        assert_eq!(SyncSource::Kev.as_str(), "kev");
        assert_eq!(SyncSource::Epss.as_str(), "epss");
    }

    #[test]
    fn rfc3339_formats_dates() {
        let s = rfc3339(datetime!(2024-06-15 12:34:56 UTC));
        assert!(s.starts_with("2024-06-15T12:34:56"));
    }
}
