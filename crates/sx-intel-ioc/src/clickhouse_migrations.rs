//! Idempotent `ClickHouse` schema migration runner.
//!
//! ## Scope
//!
//! [`ClickHouseMigrator`] applies a fixed sequence of SQL migrations against a
//! `ClickHouse` cluster and records which ones have been applied. The runner
//! is idempotent: calling [`ClickHouseMigrator::run`] repeatedly is safe and
//! cheap once the schema is up to date.
//!
//! State tracking lives in a small ledger table on the `ClickHouse` side:
//!
//! ```sql
//! CREATE TABLE IF NOT EXISTS _sx_migrations (
//!     version    String,
//!     applied_at DateTime DEFAULT now()
//! ) ENGINE = MergeTree() ORDER BY version;
//! ```
//!
//! ## Migration sources
//!
//! Two sources are supported, in priority order:
//!
//! 1. **Embedded** (default) — the canonical
//!    `crates/sx-intel-ioc/clickhouse/projections.sql` file is embedded at
//!    compile time via [`include_str!`] and applied as a single migration
//!    with version `projections`. This is what production deploys use, since
//!    no filesystem access is required.
//! 2. **Filesystem** — an explicit `migrations_dir` can be supplied at
//!    construction time. All `*.sql` files in that directory are sorted
//!    lexicographically by file name and applied in that order. The file
//!    stem (without extension) is used as the migration version.
//!
//! ## Multi-statement files
//!
//! `ClickHouse`'s HTTP interface accepts at most one statement per request,
//! so multi-statement files are split on `;` at the SQL-comment-and-string
//! level. The splitter is intentionally simple: it tracks single-line `--`
//! comments and single-quoted string literals so semicolons inside them
//! don't terminate a statement. It does **not** understand `/* ... */`
//! block comments or backslash escapes — `projections.sql` and future
//! migrations should avoid both.
//!
//! ## Non-goals
//!
//! * Down migrations / rollbacks — `ClickHouse` schemas are append-only in
//!   practice; we lean on the deployment process to recover from mistakes.
//! * Per-tenant migrations — the ledger is cluster-global.
//! * Distributed locking — the runner is single-writer by convention.

use std::path::PathBuf;
use std::sync::Arc;

use crate::clickhouse::ClickHouseError;
use crate::clickhouse_http::HttpClickHouseLink;

/// The canonical `projections.sql` embedded at compile time.
///
/// This is what production deploys apply by default. The file lives at
/// `crates/sx-intel-ioc/clickhouse/projections.sql`; if it is ever removed
/// the build will fail loudly here.
const EMBEDDED_PROJECTIONS_SQL: &str = include_str!("../clickhouse/projections.sql");

/// Version assigned to the embedded [`EMBEDDED_PROJECTIONS_SQL`] payload.
const EMBEDDED_PROJECTIONS_VERSION: &str = "projections";

/// Bootstrap DDL: creates the `_sx_migrations` ledger table if absent.
const BOOTSTRAP_DDL: &str = "CREATE TABLE IF NOT EXISTS _sx_migrations (\
    version String, applied_at DateTime DEFAULT now()) \
    ENGINE = MergeTree() ORDER BY version";

/// A single migration to apply.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Migration {
    /// Stable identifier — recorded verbatim in `_sx_migrations`.
    version: String,
    /// Full SQL text. May contain multiple `;`-separated statements.
    sql: String,
}

/// Where to load migrations from.
#[derive(Debug, Clone)]
enum Source {
    /// Apply the embedded [`EMBEDDED_PROJECTIONS_SQL`].
    Embedded,
    /// Scan a filesystem directory for `*.sql` files.
    Directory(PathBuf),
}

/// Errors surfaced by [`ClickHouseMigrator`].
///
/// Wraps [`ClickHouseError`] for HTTP / SQL failures and adds a discovery
/// variant for filesystem scan problems.
#[derive(Debug, thiserror::Error)]
pub enum MigrationError {
    /// A `ClickHouse` HTTP / SQL operation failed.
    #[error("clickhouse error: {0}")]
    ClickHouse(#[from] ClickHouseError),
    /// The configured migrations directory could not be read.
    #[error("migration discovery failed at {path}: {message}")]
    Discovery {
        /// Path that failed to read.
        path: PathBuf,
        /// Human-readable cause.
        message: String,
    },
    /// A migration file could not be read.
    #[error("read migration {path} failed: {message}")]
    Read {
        /// Path that failed to read.
        path: PathBuf,
        /// Human-readable cause.
        message: String,
    },
    /// A migration file had no parseable version (e.g. no stem).
    #[error("migration {path} has no usable version stem")]
    BadVersion {
        /// Path that lacked a stem.
        path: PathBuf,
    },
}

/// Idempotent `ClickHouse` schema migration runner.
///
/// Holds a shared reference to an [`HttpClickHouseLink`] and a source for
/// migration SQL (either the embedded `projections.sql` or a filesystem
/// directory). See the module-level docs for the wire protocol.
#[derive(Debug, Clone)]
pub struct ClickHouseMigrator {
    http: Arc<HttpClickHouseLink>,
    source: Source,
}

impl ClickHouseMigrator {
    /// Build a migrator that applies the embedded `projections.sql`.
    ///
    /// This is the default production wiring — no filesystem access required.
    #[must_use]
    pub const fn with_embedded(http: Arc<HttpClickHouseLink>) -> Self {
        Self {
            http,
            source: Source::Embedded,
        }
    }

    /// Build a migrator that scans `migrations_dir` for `*.sql` files at
    /// run time, applying them in lexicographic order of file name.
    ///
    /// If the directory does not exist at [`Self::run`] time the run is a
    /// no-op (after bootstrap) — this matches the "migrations are optional
    /// in tests" contract documented on the struct.
    #[must_use]
    pub const fn with_directory(http: Arc<HttpClickHouseLink>, migrations_dir: PathBuf) -> Self {
        Self {
            http,
            source: Source::Directory(migrations_dir),
        }
    }

    /// Apply all pending migrations.
    ///
    /// Steps:
    ///
    /// 1. Execute [`BOOTSTRAP_DDL`] to ensure the `_sx_migrations` ledger
    ///    exists (idempotent — uses `IF NOT EXISTS`).
    /// 2. Discover candidate migrations from the configured source.
    /// 3. For each candidate, check the ledger; if absent, execute each
    ///    `;`-separated statement and then insert a ledger row.
    ///
    /// Returns the list of versions that were *newly* applied during this
    /// call. Already-applied migrations are skipped silently and excluded
    /// from the return value.
    pub async fn run(&self) -> Result<Vec<String>, MigrationError> {
        self.http.execute_ddl(BOOTSTRAP_DDL).await?;

        let migrations = self.discover()?;
        let mut applied = Vec::new();
        for migration in migrations {
            if self.is_applied(&migration.version).await? {
                tracing::debug!(
                    target: "sx_intel_ioc::clickhouse_migrations",
                    version = %migration.version,
                    "migration already applied; skipping",
                );
                continue;
            }
            self.apply(&migration).await?;
            applied.push(migration.version);
        }
        Ok(applied)
    }

    /// Discover migrations from the configured source.
    fn discover(&self) -> Result<Vec<Migration>, MigrationError> {
        match &self.source {
            Source::Embedded => Ok(vec![Migration {
                version: EMBEDDED_PROJECTIONS_VERSION.to_string(),
                sql: EMBEDDED_PROJECTIONS_SQL.to_string(),
            }]),
            Source::Directory(dir) => Self::discover_dir(dir),
        }
    }

    /// Filesystem-scan implementation. See the comment in [`Self::discover`]
    /// for the contract.
    fn discover_dir(dir: &PathBuf) -> Result<Vec<Migration>, MigrationError> {
        if !dir.exists() {
            tracing::info!(
                target: "sx_intel_ioc::clickhouse_migrations",
                path = %dir.display(),
                "migrations directory absent; treating as empty",
            );
            return Ok(Vec::new());
        }
        let read_dir = std::fs::read_dir(dir).map_err(|e| MigrationError::Discovery {
            path: dir.clone(),
            message: e.to_string(),
        })?;

        let mut entries: Vec<PathBuf> = Vec::new();
        for entry in read_dir {
            let entry = entry.map_err(|e| MigrationError::Discovery {
                path: dir.clone(),
                message: e.to_string(),
            })?;
            let path = entry.path();
            if path.extension().and_then(std::ffi::OsStr::to_str) == Some("sql") {
                entries.push(path);
            }
        }
        entries.sort();

        let mut migrations = Vec::with_capacity(entries.len());
        for path in entries {
            let version = path
                .file_stem()
                .and_then(std::ffi::OsStr::to_str)
                .map(ToString::to_string)
                .ok_or_else(|| MigrationError::BadVersion { path: path.clone() })?;
            let sql = std::fs::read_to_string(&path).map_err(|e| MigrationError::Read {
                path: path.clone(),
                message: e.to_string(),
            })?;
            migrations.push(Migration { version, sql });
        }
        Ok(migrations)
    }

    /// Existence check against the ledger.
    async fn is_applied(&self, version: &str) -> Result<bool, MigrationError> {
        let escaped = escape_sql_string(version);
        let query = format!("SELECT count() FROM _sx_migrations WHERE version = '{escaped}'");
        let n = self.http.select_one_u64(&query).await?;
        Ok(n > 0)
    }

    /// Apply a single migration: execute each statement, then record it.
    async fn apply(&self, migration: &Migration) -> Result<(), MigrationError> {
        let statements = split_statements(&migration.sql);
        tracing::info!(
            target: "sx_intel_ioc::clickhouse_migrations",
            version = %migration.version,
            statements = statements.len(),
            "applying migration",
        );
        for stmt in &statements {
            self.http.execute_ddl(stmt).await?;
        }
        let escaped = escape_sql_string(&migration.version);
        let record_sql = format!("INSERT INTO _sx_migrations (version) VALUES ('{escaped}')");
        self.http.execute_ddl(&record_sql).await?;
        Ok(())
    }
}

/// Escape a string literal for safe inclusion in a single-quoted SQL value.
///
/// We only ever feed `_sx_migrations.version` values here, which are
/// developer-controlled (file stems or the literal `projections`). The
/// escape is still applied as a defence-in-depth so malformed versions
/// can't break the query.
fn escape_sql_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\'' => out.push_str("\\'"),
            '\\' => out.push_str("\\\\"),
            other => out.push(other),
        }
    }
    out
}

/// Split a SQL blob into individual statements on `;`, ignoring semicolons
/// inside `--` line comments and single-quoted string literals.
///
/// Empty statements (whitespace only) are dropped. The returned strings are
/// trimmed of surrounding whitespace and do not include the trailing `;`.
fn split_statements(sql: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut buf = String::new();
    let mut in_string = false;
    let mut in_line_comment = false;

    for ch in sql.chars() {
        if in_line_comment {
            buf.push(ch);
            if ch == '\n' {
                in_line_comment = false;
            }
            continue;
        }
        if in_string {
            buf.push(ch);
            if ch == '\'' {
                in_string = false;
            }
            continue;
        }
        match ch {
            '\'' => {
                in_string = true;
                buf.push(ch);
            }
            '-' if buf.ends_with('-') => {
                in_line_comment = true;
                buf.push(ch);
            }
            ';' => {
                let stmt = buf.trim().to_string();
                if !stmt.is_empty() && !is_comment_only(&stmt) {
                    out.push(stmt);
                }
                buf.clear();
            }
            _ => buf.push(ch),
        }
    }
    let tail = buf.trim().to_string();
    if !tail.is_empty() && !is_comment_only(&tail) {
        out.push(tail);
    }
    out
}

/// Return `true` if every non-empty line in `s` is a `--` comment.
///
/// Used to drop "comment-only" trailing chunks the splitter would otherwise
/// emit (e.g. the header banner at the top of `projections.sql`).
fn is_comment_only(s: &str) -> bool {
    s.lines().all(|line| {
        let t = line.trim();
        t.is_empty() || t.starts_with("--")
    })
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::expect_used,
    clippy::indexing_slicing
)]
mod tests {
    use super::{
        escape_sql_string, is_comment_only, split_statements, ClickHouseMigrator, MigrationError,
        BOOTSTRAP_DDL, EMBEDDED_PROJECTIONS_SQL, EMBEDDED_PROJECTIONS_VERSION,
    };
    use crate::clickhouse::ClickHouseError;
    use crate::clickhouse_http::{ClickHouseConfig, HttpClickHouseLink};
    use secrecy::SecretString;
    use std::sync::Arc;
    use url::Url;
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, Request, ResponseTemplate};

    fn build_link(server: &MockServer) -> Arc<HttpClickHouseLink> {
        let cfg = ClickHouseConfig {
            endpoint: Url::parse(&server.uri()).unwrap(),
            database: Some("intel".to_string()),
            user: "ch_user".to_string(),
            password: SecretString::from("ch_pass".to_string()),
        };
        Arc::new(HttpClickHouseLink::new(reqwest::Client::new(), cfg).unwrap())
    }

    /// Read the body of a recorded request as UTF-8.
    fn body_of(req: &Request) -> String {
        std::str::from_utf8(&req.body).unwrap().to_string()
    }

    #[test]
    fn split_statements_handles_single_statement() {
        let out = split_statements("CREATE TABLE t (id UInt64) ENGINE = Memory");
        assert_eq!(out.len(), 1);
        assert!(out[0].starts_with("CREATE TABLE"));
    }

    #[test]
    fn split_statements_splits_on_semicolon() {
        let sql = "CREATE TABLE a (x UInt64) ENGINE = Memory;\nCREATE TABLE b (y UInt64) ENGINE = Memory;";
        let out = split_statements(sql);
        assert_eq!(out.len(), 2);
        assert!(out[0].contains("CREATE TABLE a"));
        assert!(out[1].contains("CREATE TABLE b"));
    }

    #[test]
    fn split_statements_ignores_semicolons_in_strings() {
        let sql = "INSERT INTO t VALUES ('a;b'); SELECT 1";
        let out = split_statements(sql);
        assert_eq!(out.len(), 2);
        assert!(out[0].contains("'a;b'"));
        assert_eq!(out[1], "SELECT 1");
    }

    #[test]
    fn split_statements_ignores_semicolons_in_line_comments() {
        let sql = "CREATE TABLE t (x UInt64) ENGINE = Memory; -- trailing; comment\nSELECT 2";
        let out = split_statements(sql);
        // The line comment swallows its trailing ";" so the splitter must
        // NOT cut the chunk inside the comment. The trailing chunk is the
        // comment followed by SELECT 2, both of which we keep intact.
        assert_eq!(out.len(), 2);
        assert!(out[1].contains("SELECT 2"));
        assert!(out[1].contains("trailing; comment"));
    }

    #[test]
    fn split_statements_drops_comment_only_chunks() {
        let sql =
            "-- header\n-- more header\nCREATE TABLE t (x UInt64) ENGINE = Memory;\n-- trailer";
        let out = split_statements(sql);
        assert_eq!(out.len(), 1, "got: {out:?}");
        assert!(out[0].contains("CREATE TABLE t"));
    }

    #[test]
    fn embedded_projections_splits_cleanly() {
        let out = split_statements(EMBEDDED_PROJECTIONS_SQL);
        // projections.sql defines two CREATE TABLEs.
        assert_eq!(out.len(), 2, "got: {out:?}");
        assert!(out[0].contains("findings_projection"));
        assert!(out[1].contains("audit_projection"));
    }

    #[test]
    fn escape_sql_string_quotes_and_backslashes() {
        assert_eq!(escape_sql_string("foo"), "foo");
        assert_eq!(escape_sql_string("a'b"), "a\\'b");
        assert_eq!(escape_sql_string("a\\b"), "a\\\\b");
    }

    #[test]
    fn is_comment_only_recognises_blanks_and_dashes() {
        assert!(is_comment_only(""));
        assert!(is_comment_only("-- one\n-- two"));
        assert!(!is_comment_only("-- one\nSELECT 1"));
        assert!(!is_comment_only("SELECT 1"));
    }

    #[tokio::test]
    async fn bootstrap_and_apply_when_ledger_empty() {
        let server = MockServer::start().await;

        // Bootstrap DDL: the very first POST creates _sx_migrations.
        // Existence check: returns 0 -> migration is pending.
        // Migration DDL: two CREATE TABLEs from projections.sql.
        // Ledger insert: records the version.
        Mock::given(method("POST"))
            .respond_with(move |req: &Request| {
                let body = std::str::from_utf8(&req.body).unwrap_or_default();
                if body.starts_with("SELECT count()") {
                    ResponseTemplate::new(200).set_body_string("0\n")
                } else {
                    ResponseTemplate::new(200)
                }
            })
            .mount(&server)
            .await;

        let link = build_link(&server);
        let migrator = ClickHouseMigrator::with_embedded(link);
        let applied = migrator.run().await.unwrap();
        assert_eq!(applied, vec![EMBEDDED_PROJECTIONS_VERSION.to_string()]);

        let reqs = server.received_requests().await.unwrap();
        // Expected: 1 bootstrap + 1 existence check + 2 DDL + 1 insert.
        assert_eq!(reqs.len(), 5, "got requests: {}", reqs.len());

        let bodies: Vec<String> = reqs.iter().map(body_of).collect();
        assert!(bodies[0].contains("CREATE TABLE IF NOT EXISTS _sx_migrations"));
        assert!(bodies[1].starts_with("SELECT count()"));
        assert!(bodies[2].contains("findings_projection"));
        assert!(bodies[3].contains("audit_projection"));
        assert!(bodies[4].starts_with("INSERT INTO _sx_migrations"));
        assert!(bodies[4].contains("'projections'"));
    }

    #[tokio::test]
    async fn already_applied_migration_is_skipped() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .respond_with(move |req: &Request| {
                let body = std::str::from_utf8(&req.body).unwrap_or_default();
                if body.starts_with("SELECT count()") {
                    ResponseTemplate::new(200).set_body_string("1\n")
                } else {
                    ResponseTemplate::new(200)
                }
            })
            .mount(&server)
            .await;

        let link = build_link(&server);
        let migrator = ClickHouseMigrator::with_embedded(link);
        let applied = migrator.run().await.unwrap();
        assert!(applied.is_empty(), "expected no new migrations");

        let reqs = server.received_requests().await.unwrap();
        // Expected: 1 bootstrap + 1 existence check only — no DDL, no insert.
        assert_eq!(reqs.len(), 2, "got requests: {}", reqs.len());
        let bodies: Vec<String> = reqs.iter().map(body_of).collect();
        assert!(bodies[0].contains("_sx_migrations"));
        assert!(bodies[1].starts_with("SELECT count()"));
    }

    #[tokio::test]
    async fn bootstrap_failure_surfaces_as_clickhouse_error() {
        let server = MockServer::start().await;

        // The bootstrap is the first POST; serve a 500 for everything.
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(500).set_body_string("syntax error near 'foo'"))
            .mount(&server)
            .await;

        let link = build_link(&server);
        let migrator = ClickHouseMigrator::with_embedded(link);
        let err = migrator.run().await.unwrap_err();
        match err {
            MigrationError::ClickHouse(ClickHouseError::HttpStatus { status, body }) => {
                assert_eq!(status, 500);
                assert!(body.contains("syntax error"));
            }
            other => panic!("expected ClickHouse(HttpStatus), got {other:?}"),
        }
    }

    #[tokio::test]
    async fn directory_source_picks_up_sql_files() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .respond_with(move |req: &Request| {
                let body = std::str::from_utf8(&req.body).unwrap_or_default();
                if body.starts_with("SELECT count()") {
                    ResponseTemplate::new(200).set_body_string("0\n")
                } else {
                    ResponseTemplate::new(200)
                }
            })
            .mount(&server)
            .await;

        // Stage two migrations under a tempdir; only `.sql` files are picked up.
        let tmp = std::env::temp_dir().join(format!(
            "sx-intel-ioc-mig-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or_default()
        ));
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(
            tmp.join("20260101_001_a.sql"),
            "CREATE TABLE a (x UInt64) ENGINE = Memory;",
        )
        .unwrap();
        std::fs::write(
            tmp.join("20260102_002_b.sql"),
            "CREATE TABLE b (y UInt64) ENGINE = Memory;",
        )
        .unwrap();
        std::fs::write(tmp.join("not-a-migration.txt"), "ignore me").unwrap();

        let link = build_link(&server);
        let migrator = ClickHouseMigrator::with_directory(link, tmp.clone());
        let applied = migrator.run().await.unwrap();
        assert_eq!(
            applied,
            vec!["20260101_001_a".to_string(), "20260102_002_b".to_string(),]
        );

        // Cleanup.
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[tokio::test]
    async fn missing_directory_is_no_op_after_bootstrap() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let link = build_link(&server);
        let bogus = std::env::temp_dir().join("sx-intel-ioc-does-not-exist-aeb742f7");
        if bogus.exists() {
            std::fs::remove_dir_all(&bogus).ok();
        }
        let migrator = ClickHouseMigrator::with_directory(link, bogus);
        let applied = migrator.run().await.unwrap();
        assert!(applied.is_empty());

        let reqs = server.received_requests().await.unwrap();
        // Just the bootstrap.
        assert_eq!(reqs.len(), 1);
        assert!(body_of(&reqs[0]).contains("_sx_migrations"));
    }

    #[test]
    fn bootstrap_ddl_is_idempotent_create() {
        // Catches accidental edits that drop the IF NOT EXISTS guard.
        assert!(BOOTSTRAP_DDL.contains("CREATE TABLE IF NOT EXISTS _sx_migrations"));
        assert!(BOOTSTRAP_DDL.contains("ORDER BY version"));
    }
}
