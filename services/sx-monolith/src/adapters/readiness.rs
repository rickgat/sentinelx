//! Readiness probe backing `GET /readyz` (SELL-P1-05 — observability).
//!
//! Liveness (`/healthz`) only proves the process can serve a request;
//! readiness proves its *critical dependencies* are reachable so an
//! orchestrator holds traffic until the instance can actually do work.
//!
//! In this deployment the one critical external dependency is Postgres
//! (when `database.enabled`). The probe runs a cheap `SELECT 1` with a
//! short timeout and reports the result; in zero-config dev (no database)
//! it reports the in-memory mode as ready. The `process` check is always
//! present so `/readyz` has a non-empty body even with no external deps.

use std::time::Duration;

use async_trait::async_trait;
use sqlx::PgPool;
use sx_api::port::{ReadinessCheck, ReadinessProbe, ReadinessReport};

/// Hard cap on how long a readiness check may block, so `/readyz` stays
/// fast even when a dependency is hung (a hang is reported as not-ready).
const CHECK_TIMEOUT: Duration = Duration::from_secs(2);

/// Composition-root readiness probe.
pub(crate) struct MonolithReadinessProbe {
    /// Postgres pool when `database.enabled`, else `None` (in-memory dev).
    pool: Option<PgPool>,
}

impl std::fmt::Debug for MonolithReadinessProbe {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MonolithReadinessProbe")
            .field("database_enabled", &self.pool.is_some())
            .finish()
    }
}

impl MonolithReadinessProbe {
    /// Build a probe. `pool` is `Some` only when the database is enabled.
    pub(crate) fn new(pool: Option<PgPool>) -> Self {
        Self { pool }
    }

    /// Readiness of the database dependency.
    async fn database_check(&self) -> ReadinessCheck {
        let Some(pool) = self.pool.as_ref() else {
            return ReadinessCheck {
                name: "database".to_owned(),
                ok: true,
                detail: Some("in-memory mode (development); no external database".to_owned()),
            };
        };
        let probe = sqlx::query("SELECT 1").execute(pool);
        match tokio::time::timeout(CHECK_TIMEOUT, probe).await {
            Ok(Ok(_)) => ReadinessCheck {
                name: "database".to_owned(),
                ok: true,
                detail: None,
            },
            Ok(Err(e)) => ReadinessCheck {
                name: "database".to_owned(),
                ok: false,
                detail: Some(format!("query failed: {e}")),
            },
            Err(_) => ReadinessCheck {
                name: "database".to_owned(),
                ok: false,
                detail: Some(format!("timed out after {}s", CHECK_TIMEOUT.as_secs())),
            },
        }
    }
}

#[async_trait]
impl ReadinessProbe for MonolithReadinessProbe {
    async fn check(&self) -> ReadinessReport {
        ReadinessReport::from_checks(vec![
            ReadinessCheck {
                name: "process".to_owned(),
                ok: true,
                detail: None,
            },
            self.database_check().await,
        ])
    }
}
