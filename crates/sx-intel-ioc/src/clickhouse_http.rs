//! HTTP `ClickHouse` projection link.
//!
//! Production implementation of [`crate::ClickHouseLink`] that speaks to the
//! `ClickHouse` HTTP interface using the `JSONEachRow` row format. Each call
//! issues a single `POST` to
//! `<endpoint>/?database=<db>&query=INSERT%20INTO%20<table>%20FORMAT%20JSONEachRow`
//! with a body composed of newline-delimited serialized rows.
//!
//! ## Scope
//!
//! This module owns the on-the-wire format and authentication only:
//!
//! * Connection setup, TLS, and basic-auth headers.
//! * Single-shot `INSERT` for [`crate::FindingProjection`] and
//!   [`crate::AuditProjection`] using `JSONEachRow`.
//! * Strongly-typed error variants surfaced via [`ClickHouseError`].
//!
//! Higher-level concerns intentionally live elsewhere:
//!
//! * **Batching / back-pressure** — tracked separately (see the TODO in
//!   [`crate::clickhouse`]).
//! * **Retry / circuit breaking** — tracked separately (same).
//! * **Schema management / migrations** — see `clickhouse/projections.sql`;
//!   the deployment layer owns DDL.
//!
//! ## Construction
//!
//! Callers pass in an existing [`reqwest::Client`] so the workspace HTTP
//! connection pool is reused; this crate never builds its own client. TLS is
//! supplied by the caller's client (the workspace pins `rustls-tls`).
//!
//! ## Guardrails
//!
//! * The basic-auth password is held inside a [`secrecy::SecretString`] and
//!   only [`secrecy::ExposeSecret::expose_secret`]-ed at the moment the
//!   `Authorization` header is written. It never appears in [`fmt::Debug`]
//!   output, panic messages, or `tracing` events.
//! * Row contents are not logged. Per-call events carry only the table name,
//!   row count, outcome, and HTTP status.

use std::fmt;

use async_trait::async_trait;
use secrecy::{ExposeSecret, SecretString};
use serde::Serialize;
use url::Url;

use crate::clickhouse::{AuditProjection, ClickHouseError, ClickHouseLink, FindingProjection};

/// `ClickHouse` table receiving [`FindingProjection`] rows.
///
/// Must match the materialised-view name in `clickhouse/projections.sql`.
const FINDINGS_TABLE: &str = "findings_projection";

/// `ClickHouse` table receiving [`AuditProjection`] rows.
///
/// Must match the materialised-view name in `clickhouse/projections.sql`.
const AUDIT_TABLE: &str = "audit_projection";

/// Configuration for [`HttpClickHouseLink`].
///
/// Carries the endpoint, optional database name, and HTTP basic-auth
/// credentials. The `password` field is held in a [`SecretString`] so it
/// cannot leak through [`fmt::Debug`] or `tracing` events.
#[derive(Clone)]
pub struct ClickHouseConfig {
    /// Base endpoint URL — e.g. `https://clickhouse.internal:8443`.
    ///
    /// Must be an absolute URL. TLS is selected by the scheme (`https`); the
    /// caller-supplied [`reqwest::Client`] is responsible for the TLS stack.
    pub endpoint: Url,
    /// Optional `ClickHouse` database name. When `Some`, the value is
    /// rendered into the `database=` query parameter; when `None`, the
    /// server's default database is used.
    pub database: Option<String>,
    /// HTTP basic-auth user — sent in the `Authorization` header.
    pub user: String,
    /// HTTP basic-auth password — never logged, never printed.
    pub password: SecretString,
}

impl fmt::Debug for ClickHouseConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClickHouseConfig")
            .field("endpoint", &self.endpoint.as_str())
            .field("database", &self.database)
            .field("user", &self.user)
            .field("password", &"<redacted>")
            .finish()
    }
}

/// Production HTTP [`ClickHouseLink`] using `JSONEachRow`.
///
/// See module-level docs for scope. This struct does not own retry, batching,
/// or migration concerns — those are tracked separately and will wrap this
/// type rather than re-implement it.
#[derive(Clone)]
pub struct HttpClickHouseLink {
    http: reqwest::Client,
    cfg: ClickHouseConfig,
}

impl fmt::Debug for HttpClickHouseLink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Delegate to `ClickHouseConfig`'s redacting Debug.
        f.debug_struct("HttpClickHouseLink")
            .field("cfg", &self.cfg)
            .finish_non_exhaustive()
    }
}

impl HttpClickHouseLink {
    /// Build a link from an existing [`reqwest::Client`] and config.
    ///
    /// The HTTP client is supplied by the caller so the workspace
    /// connection pool is reused. Validation errors (empty user, empty
    /// password, relative endpoint) surface as
    /// [`ClickHouseError::Config`].
    pub fn new(http: reqwest::Client, cfg: ClickHouseConfig) -> Result<Self, ClickHouseError> {
        Self::validate(&cfg)?;
        Ok(Self { http, cfg })
    }

    fn validate(cfg: &ClickHouseConfig) -> Result<(), ClickHouseError> {
        if cfg.endpoint.cannot_be_a_base() {
            return Err(ClickHouseError::Config(
                "endpoint must be an absolute base URL",
            ));
        }
        if cfg.user.is_empty() {
            return Err(ClickHouseError::Config("user must be non-empty"));
        }
        if cfg.password.expose_secret().is_empty() {
            return Err(ClickHouseError::Config("password must be non-empty"));
        }
        if let Some(db) = &cfg.database {
            if db.is_empty() {
                return Err(ClickHouseError::Config(
                    "database, when set, must be non-empty",
                ));
            }
        }
        Ok(())
    }

    /// Build the per-insert URL for `table`, attaching `database=` (when
    /// configured) and the `query=` parameter that selects `JSONEachRow`.
    fn insert_url(&self, table: &str) -> Url {
        let mut url = self.cfg.endpoint.clone();
        let query_clause = format!("INSERT INTO {table} FORMAT JSONEachRow");
        {
            let mut pairs = url.query_pairs_mut();
            if let Some(db) = &self.cfg.database {
                pairs.append_pair("database", db);
            }
            pairs.append_pair("query", &query_clause);
        }
        url
    }

    /// Serialize `rows` as newline-delimited JSON suitable for the
    /// `JSONEachRow` format.
    fn encode_rows<T: Serialize>(rows: &[T]) -> Result<String, ClickHouseError> {
        let mut buf = String::new();
        for row in rows {
            let line = serde_json::to_string(row)
                .map_err(|e| ClickHouseError::Serialization(e.to_string()))?;
            buf.push_str(&line);
            buf.push('\n');
        }
        Ok(buf)
    }

    /// Send a single `INSERT` for the supplied table + body. Empty bodies
    /// are short-circuited and return `Ok(())` without a network round-trip.
    #[allow(clippy::cognitive_complexity)] // structured logging branches inflate the score
    async fn insert(&self, table: &str, body: String) -> Result<(), ClickHouseError> {
        if body.is_empty() {
            tracing::trace!(
                target: "sx_intel_ioc::clickhouse_http",
                table,
                "skipping empty insert",
            );
            return Ok(());
        }
        let url = self.insert_url(table);
        let row_bytes = body.len();
        let resp = self
            .http
            .post(url)
            .basic_auth(&self.cfg.user, Some(self.cfg.password.expose_secret()))
            .header("content-type", "application/x-ndjson")
            .body(body)
            .send()
            .await
            .map_err(|e| {
                tracing::warn!(
                    target: "sx_intel_ioc::clickhouse_http",
                    table,
                    outcome = "transport",
                    "clickhouse insert failed",
                );
                ClickHouseError::Transport(e.to_string())
            })?;

        let status = resp.status();
        if !status.is_success() {
            let body_text = resp.text().await.unwrap_or_default();
            tracing::warn!(
                target: "sx_intel_ioc::clickhouse_http",
                table,
                status = status.as_u16(),
                outcome = "http_status",
                "clickhouse insert non-success status",
            );
            return Err(ClickHouseError::HttpStatus {
                status: status.as_u16(),
                body: body_text,
            });
        }

        tracing::debug!(
            target: "sx_intel_ioc::clickhouse_http",
            table,
            bytes = row_bytes,
            outcome = "ok",
            "clickhouse insert ok",
        );
        Ok(())
    }

    /// Build the base admin URL with only the optional `database=` query
    /// parameter attached. Used by [`Self::execute_ddl`] and
    /// [`Self::select_one_u64`] which carry their SQL in the request body
    /// instead of the `query=` parameter.
    fn admin_url(&self) -> Url {
        let mut url = self.cfg.endpoint.clone();
        if let Some(db) = &self.cfg.database {
            url.query_pairs_mut().append_pair("database", db);
        }
        url
    }

    /// Execute an arbitrary DDL statement (e.g. `CREATE TABLE`, `ALTER`,
    /// `DROP`) against the configured `ClickHouse` endpoint.
    ///
    /// The SQL is sent verbatim as the request body — no `query=` parameter —
    /// matching the `ClickHouse` HTTP convention for body-carried statements.
    /// Empty bodies are short-circuited and return `Ok(())` without a network
    /// round-trip.
    ///
    /// Non-2xx responses surface as [`ClickHouseError::HttpStatus`]; transport
    /// failures surface as [`ClickHouseError::Transport`]. The response body
    /// is discarded on success (DDL has no useful payload).
    #[allow(clippy::cognitive_complexity)] // structured logging branches inflate the score
    pub async fn execute_ddl(&self, sql: &str) -> Result<(), ClickHouseError> {
        if sql.is_empty() {
            tracing::trace!(
                target: "sx_intel_ioc::clickhouse_http",
                outcome = "skip_empty",
                "skipping empty ddl",
            );
            return Ok(());
        }
        let url = self.admin_url();
        let sql_bytes = sql.len();
        let resp = self
            .http
            .post(url)
            .basic_auth(&self.cfg.user, Some(self.cfg.password.expose_secret()))
            .header("content-type", "text/plain; charset=utf-8")
            .body(sql.to_string())
            .send()
            .await
            .map_err(|e| {
                tracing::warn!(
                    target: "sx_intel_ioc::clickhouse_http",
                    outcome = "transport",
                    "clickhouse ddl failed",
                );
                ClickHouseError::Transport(e.to_string())
            })?;

        let status = resp.status();
        if !status.is_success() {
            let body_text = resp.text().await.unwrap_or_default();
            tracing::warn!(
                target: "sx_intel_ioc::clickhouse_http",
                status = status.as_u16(),
                outcome = "http_status",
                "clickhouse ddl non-success status",
            );
            return Err(ClickHouseError::HttpStatus {
                status: status.as_u16(),
                body: body_text,
            });
        }

        tracing::debug!(
            target: "sx_intel_ioc::clickhouse_http",
            bytes = sql_bytes,
            outcome = "ok",
            "clickhouse ddl ok",
        );
        Ok(())
    }

    /// Execute a `SELECT` statement that returns a single `UInt64` value and
    /// parse the response.
    ///
    /// `ClickHouse`'s default HTTP response format for a scalar `SELECT` is
    /// plain text — typically a single integer followed by a newline (e.g.
    /// `"1\n"`). This helper is intentionally narrow: it powers the
    /// `SELECT count() FROM _sx_migrations WHERE version = '...'` existence
    /// check used by [`crate::clickhouse_migrations::ClickHouseMigrator`].
    ///
    /// Returns [`ClickHouseError::Serialization`] if the body cannot be parsed
    /// as a `u64`, [`ClickHouseError::HttpStatus`] on non-2xx, and
    /// [`ClickHouseError::Transport`] on network failure.
    pub async fn select_one_u64(&self, query: &str) -> Result<u64, ClickHouseError> {
        if query.is_empty() {
            return Err(ClickHouseError::Serialization(
                "select_one_u64 requires a non-empty query".to_string(),
            ));
        }
        let url = self.admin_url();
        let resp = self
            .http
            .post(url)
            .basic_auth(&self.cfg.user, Some(self.cfg.password.expose_secret()))
            .header("content-type", "text/plain; charset=utf-8")
            .body(query.to_string())
            .send()
            .await
            .map_err(|e| {
                tracing::warn!(
                    target: "sx_intel_ioc::clickhouse_http",
                    outcome = "transport",
                    "clickhouse select failed",
                );
                ClickHouseError::Transport(e.to_string())
            })?;

        let status = resp.status();
        if !status.is_success() {
            let body_text = resp.text().await.unwrap_or_default();
            tracing::warn!(
                target: "sx_intel_ioc::clickhouse_http",
                status = status.as_u16(),
                outcome = "http_status",
                "clickhouse select non-success status",
            );
            return Err(ClickHouseError::HttpStatus {
                status: status.as_u16(),
                body: body_text,
            });
        }

        let body_text = resp
            .text()
            .await
            .map_err(|e| ClickHouseError::Transport(format!("body read failed: {e}")))?;
        let trimmed = body_text.trim();
        trimmed.parse::<u64>().map_err(|e| {
            ClickHouseError::Serialization(format!("expected u64 scalar, got {trimmed:?}: {e}"))
        })
    }
}

#[async_trait]
impl ClickHouseLink for HttpClickHouseLink {
    async fn write_findings(&self, rows: &[FindingProjection]) -> Result<(), ClickHouseError> {
        let body = Self::encode_rows(rows)?;
        self.insert(FINDINGS_TABLE, body).await
    }

    async fn write_audit(&self, rows: &[AuditProjection]) -> Result<(), ClickHouseError> {
        let body = Self::encode_rows(rows)?;
        self.insert(AUDIT_TABLE, body).await
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::expect_used
)]
mod tests {
    use super::{ClickHouseConfig, HttpClickHouseLink, AUDIT_TABLE, FINDINGS_TABLE};
    use crate::clickhouse::{AuditProjection, ClickHouseError, ClickHouseLink, FindingProjection};
    use secrecy::SecretString;
    use url::Url;
    use wiremock::matchers::{header, header_exists, method, path, query_param};
    use wiremock::{Mock, MockServer, Request, ResponseTemplate};

    fn cfg_for(server: &MockServer, database: Option<&str>) -> ClickHouseConfig {
        ClickHouseConfig {
            endpoint: Url::parse(&server.uri()).unwrap(),
            database: database.map(ToString::to_string),
            user: "ch_user".to_string(),
            password: SecretString::from("ch_pass".to_string()),
        }
    }

    fn sample_finding() -> FindingProjection {
        FindingProjection {
            id: "11111111-1111-1111-1111-111111111111".to_string(),
            tenant_id: "22222222-2222-2222-2222-222222222222".to_string(),
            severity: "high".to_string(),
            cvss: 8.4,
            ts_epoch_secs: 1_700_000_000,
        }
    }

    fn sample_audit() -> AuditProjection {
        AuditProjection {
            tenant_id: "22222222-2222-2222-2222-222222222222".to_string(),
            seq: 42,
            action: "finding.update".to_string(),
            actor: "system:scanner".to_string(),
            ts_epoch_secs: 1_700_000_000,
        }
    }

    #[tokio::test]
    async fn write_findings_posts_jsoneachrow() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/"))
            .and(query_param("database", "intel"))
            .and(query_param(
                "query",
                format!("INSERT INTO {FINDINGS_TABLE} FORMAT JSONEachRow"),
            ))
            .and(header("content-type", "application/x-ndjson"))
            .and(header_exists("authorization"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let link = HttpClickHouseLink::new(reqwest::Client::new(), cfg_for(&server, Some("intel")))
            .unwrap();
        let rows = vec![sample_finding(), sample_finding()];
        link.write_findings(&rows).await.unwrap();

        let reqs = server.received_requests().await.unwrap();
        assert_eq!(reqs.len(), 1);
        let body = std::str::from_utf8(&reqs[0].body).unwrap();
        // Two rows -> two newline-delimited objects.
        let lines: Vec<&str> = body.lines().collect();
        assert_eq!(lines.len(), 2);
        let first: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(first["id"], "11111111-1111-1111-1111-111111111111");
        assert_eq!(first["severity"], "high");

        // Basic-auth header carries the configured credentials.
        let auth = reqs[0]
            .headers
            .get("authorization")
            .expect("authorization header missing");
        let expected = format!("Basic {}", base64_encode_for_test("ch_user:ch_pass"));
        assert_eq!(auth.to_str().unwrap(), expected);
    }

    #[tokio::test]
    async fn write_audit_uses_audit_table() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/"))
            .and(query_param(
                "query",
                format!("INSERT INTO {AUDIT_TABLE} FORMAT JSONEachRow"),
            ))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let link = HttpClickHouseLink::new(reqwest::Client::new(), cfg_for(&server, None)).unwrap();
        link.write_audit(&[sample_audit()]).await.unwrap();

        let reqs = server.received_requests().await.unwrap();
        assert_eq!(reqs.len(), 1);
        // database= absent when not configured.
        let query = reqs[0].url.query().unwrap_or_default();
        assert!(!query.contains("database="), "query = {query}");
    }

    #[tokio::test]
    async fn empty_batch_skips_request() {
        let server = MockServer::start().await;
        // No mock mounted — any HTTP call would fail.
        let link = HttpClickHouseLink::new(reqwest::Client::new(), cfg_for(&server, None)).unwrap();
        link.write_findings(&[]).await.unwrap();
        link.write_audit(&[]).await.unwrap();
        let reqs = server.received_requests().await.unwrap();
        assert!(reqs.is_empty(), "expected no requests, got {}", reqs.len());
    }

    #[tokio::test]
    async fn non_success_maps_to_http_status() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(500).set_body_string("boom"))
            .mount(&server)
            .await;

        let link = HttpClickHouseLink::new(reqwest::Client::new(), cfg_for(&server, None)).unwrap();
        let err = link.write_findings(&[sample_finding()]).await.unwrap_err();
        match err {
            ClickHouseError::HttpStatus { status, body } => {
                assert_eq!(status, 500);
                assert_eq!(body, "boom");
            }
            other => panic!("expected HttpStatus, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn transport_error_maps_to_transport_variant() {
        // Point the link at a port nothing is listening on — the connect
        // attempt must surface as Transport.
        let cfg = ClickHouseConfig {
            // 127.0.0.1:1 is reserved; connecting will be refused.
            endpoint: Url::parse("http://127.0.0.1:1").unwrap(),
            database: None,
            user: "ch_user".to_string(),
            password: SecretString::from("ch_pass".to_string()),
        };
        let link = HttpClickHouseLink::new(reqwest::Client::new(), cfg).unwrap();
        let err = link.write_findings(&[sample_finding()]).await.unwrap_err();
        match err {
            ClickHouseError::Transport(_) => {}
            other => panic!("expected Transport, got {other:?}"),
        }
    }

    #[test]
    fn debug_redacts_password() {
        let cfg = ClickHouseConfig {
            endpoint: Url::parse("https://example.invalid").unwrap(),
            database: Some("intel".to_string()),
            user: "ch_user".to_string(),
            password: SecretString::from("super-secret".to_string()),
        };
        let link = HttpClickHouseLink::new(reqwest::Client::new(), cfg).unwrap();
        let dbg = format!("{link:?}");
        assert!(
            !dbg.contains("super-secret"),
            "password leaked in Debug: {dbg}"
        );
        assert!(dbg.contains("<redacted>"));
    }

    #[test]
    fn new_rejects_empty_user() {
        let cfg = ClickHouseConfig {
            endpoint: Url::parse("https://example.invalid").unwrap(),
            database: None,
            user: String::new(),
            password: SecretString::from("p".to_string()),
        };
        match HttpClickHouseLink::new(reqwest::Client::new(), cfg) {
            Err(ClickHouseError::Config(_)) => {}
            other => panic!("expected Config error, got {other:?}"),
        }
    }

    #[test]
    fn new_rejects_empty_password() {
        let cfg = ClickHouseConfig {
            endpoint: Url::parse("https://example.invalid").unwrap(),
            database: None,
            user: "ch_user".to_string(),
            password: SecretString::from(String::new()),
        };
        match HttpClickHouseLink::new(reqwest::Client::new(), cfg) {
            Err(ClickHouseError::Config(_)) => {}
            other => panic!("expected Config error, got {other:?}"),
        }
    }

    #[test]
    fn new_rejects_empty_database_when_set() {
        let cfg = ClickHouseConfig {
            endpoint: Url::parse("https://example.invalid").unwrap(),
            database: Some(String::new()),
            user: "ch_user".to_string(),
            password: SecretString::from("p".to_string()),
        };
        match HttpClickHouseLink::new(reqwest::Client::new(), cfg) {
            Err(ClickHouseError::Config(_)) => {}
            other => panic!("expected Config error, got {other:?}"),
        }
    }

    /// Small fixed base64 encoder for the basic-auth assertion. The
    /// production code path uses `reqwest::basic_auth` which already
    /// base64-encodes; tests just need to predict the wire format.
    fn base64_encode_for_test(s: &str) -> String {
        // Use the `base64` crate via reqwest's transitive dep would couple
        // tests to internals; build the value through a tiny standalone
        // encoder. Length is small so allocation cost is irrelevant.
        const TABLE: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let bytes = s.as_bytes();
        let mut out = String::new();
        let chunks = bytes.chunks(3);
        for chunk in chunks {
            let b0 = chunk[0];
            let b1 = chunk.get(1).copied().unwrap_or(0);
            let b2 = chunk.get(2).copied().unwrap_or(0);
            let n: u32 = (u32::from(b0) << 16) | (u32::from(b1) << 8) | u32::from(b2);
            out.push(char::from(TABLE[((n >> 18) & 0x3f) as usize]));
            out.push(char::from(TABLE[((n >> 12) & 0x3f) as usize]));
            if chunk.len() > 1 {
                out.push(char::from(TABLE[((n >> 6) & 0x3f) as usize]));
            } else {
                out.push('=');
            }
            if chunk.len() > 2 {
                out.push(char::from(TABLE[(n & 0x3f) as usize]));
            } else {
                out.push('=');
            }
        }
        out
    }

    /// Silence unused-fn warning from wiremock fixtures when only some tests
    /// are run.
    #[allow(dead_code)]
    fn _coverage(_r: &Request) {}
}
