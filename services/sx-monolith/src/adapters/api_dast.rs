//! API DAST (P2-013) adapter — wires the in-crate Postman replay
//! engine ([`sx_discovery::api_dast::run_dast`]) behind the
//! [`sx_api::port::ApiDastPort`] HTTP trait.
//!
//! Responsibilities:
//!
//! * Parse the uploaded Postman v2.1 collection bytes via
//!   [`PostmanCollection::parse`].
//! * Build a per-scan [`ApiDastConfig`] (base URL + bearer + IDOR
//!   probe ids) and dispatch [`run_dast`] over a shared `reqwest`
//!   client.
//! * Project the resulting [`ApiDastReport`] into the wire-side
//!   [`ApiDastScanResultView`].
//! * Persist scan results per-tenant in an in-memory ring (capped at
//!   `MAX_HISTORY_PER_TENANT`) so the HTTP GET endpoint surfaces them
//!   newest-first.
//!
//! The adapter never logs the raw bearer credential — it is held in a
//! [`secrecy::SecretString`] and exposed only as a `Bearer …` value to
//! the replay engine, which itself redacts the header before any
//! tracing event is emitted.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use secrecy::{ExposeSecret, SecretString};
use sx_api::port::{ApiDastFindingView, ApiDastPort, ApiDastPortError, ApiDastScanResultView};
use sx_discovery::api_dast::{run_dast, ApiDastConfig, ApiDastFinding, PostmanCollection};
use sx_discovery::error::DiscoveryError;
use url::Url;
use uuid::Uuid;

/// Per-tenant cap on the in-memory scan history.
const MAX_HISTORY_PER_TENANT: usize = 100;

/// Bundle of API DAST handles handed to the composition root.
#[derive(Clone)]
pub(crate) struct ApiDastBundle {
    /// HTTP-facing trait object installed onto [`sx_api::AppState`].
    pub api_dast: Arc<dyn ApiDastPort>,
}

/// Build the API DAST bundle. The composition root installs a single
/// long-lived `reqwest::Client` so the per-scan replay does not allocate
/// a new TLS context.
pub(crate) fn build(client: reqwest::Client) -> ApiDastBundle {
    ApiDastBundle {
        api_dast: Arc::new(ApiDastAdapter::new(client)),
    }
}

/// Concrete `ApiDastPort` implementation.
pub(crate) struct ApiDastAdapter {
    client: reqwest::Client,
    history: Mutex<HashMap<String, Vec<ApiDastScanResultView>>>,
}

impl std::fmt::Debug for ApiDastAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiDastAdapter").finish_non_exhaustive()
    }
}

impl ApiDastAdapter {
    fn new(client: reqwest::Client) -> Self {
        Self {
            client,
            history: Mutex::new(HashMap::new()),
        }
    }

    fn record(&self, tenant_id: &str, view: ApiDastScanResultView) {
        let Ok(mut guard) = self.history.lock() else {
            return;
        };
        let entry = guard.entry(tenant_id.to_owned()).or_default();
        entry.insert(0, view);
        if entry.len() > MAX_HISTORY_PER_TENANT {
            entry.truncate(MAX_HISTORY_PER_TENANT);
        }
    }
}

fn map_discovery(err: DiscoveryError) -> ApiDastPortError {
    match err {
        DiscoveryError::Config(m) => ApiDastPortError::Invalid(m),
        DiscoveryError::Io(m) => ApiDastPortError::Dependency(m),
        DiscoveryError::Timeout => {
            ApiDastPortError::Dependency("scan timed out before completion".into())
        }
        DiscoveryError::SafetyGate(m) => ApiDastPortError::Invalid(format!("safety gate: {m}")),
        DiscoveryError::RateLimited => ApiDastPortError::Dependency("rate limited".into()),
        DiscoveryError::KillSwitchTripped => {
            ApiDastPortError::Dependency("kill switch tripped".into())
        }
        DiscoveryError::ScannerNotFound(m) | DiscoveryError::Internal(m) => {
            ApiDastPortError::Internal(m)
        }
    }
}

fn project_finding(f: ApiDastFinding) -> ApiDastFindingView {
    ApiDastFindingView {
        check_id: f.check_id,
        severity: f.severity,
        method: f.method,
        url: f.url,
        message: f.message,
        remediation: f.remediation,
        source_item: f.source_item,
    }
}

fn rfc3339(ts: time::OffsetDateTime) -> String {
    ts.format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| ts.unix_timestamp().to_string())
}

#[async_trait]
impl ApiDastPort for ApiDastAdapter {
    async fn scan(
        &self,
        tenant_id: &str,
        collection: &[u8],
        base_url: &str,
        bearer: Option<SecretString>,
        idor_probe_ids: Vec<String>,
    ) -> Result<ApiDastScanResultView, ApiDastPortError> {
        if tenant_id.is_empty() {
            return Err(ApiDastPortError::Invalid("tenant id is empty".into()));
        }
        if collection.is_empty() {
            return Err(ApiDastPortError::Invalid(
                "postman collection is empty".into(),
            ));
        }
        let parsed = PostmanCollection::parse(collection).map_err(map_discovery)?;
        let base = Url::parse(base_url)
            .map_err(|e| ApiDastPortError::Invalid(format!("base_url parse failed: {e}")))?;
        let mut cfg = ApiDastConfig::new(base.clone()).map_err(map_discovery)?;
        cfg.bearer = bearer.map(|s| s.expose_secret().to_owned());
        cfg.idor_probe_ids = idor_probe_ids;
        cfg.request_timeout = Duration::from_secs(5);

        let report = run_dast(&self.client, &parsed, &cfg)
            .await
            .map_err(map_discovery)?;

        let view = ApiDastScanResultView {
            scan_id: Uuid::now_v7().to_string(),
            tenant_id: tenant_id.to_owned(),
            collection_name: parsed.name().to_owned(),
            base_url: base.to_string(),
            started_at: rfc3339(report.started_at),
            ended_at: rfc3339(report.ended_at),
            requests_sent: report.requests_sent,
            findings: report.findings.into_iter().map(project_finding).collect(),
        };
        self.record(tenant_id, view.clone());
        Ok(view)
    }

    async fn list(
        &self,
        tenant_id: &str,
        limit: usize,
    ) -> Result<Vec<ApiDastScanResultView>, ApiDastPortError> {
        if tenant_id.is_empty() {
            return Err(ApiDastPortError::Invalid("tenant id is empty".into()));
        }
        let Ok(guard) = self.history.lock() else {
            return Err(ApiDastPortError::Internal(
                "api_dast history mutex poisoned".into(),
            ));
        };
        let items = guard
            .get(tenant_id)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .take(limit)
            .collect();
        Ok(items)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn fixture_collection(server: &str) -> String {
        format!(
            r#"{{
"info": {{ "name": "demo", "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json" }},
"variable": [{{ "key": "baseUrl", "value": "{server}" }}],
"item": [
  {{
    "name": "get-user",
    "request": {{
      "method": "GET",
      "url": "{{{{baseUrl}}}}/users/42"
    }}
  }}
]
}}"#
        )
    }

    #[tokio::test]
    async fn scan_returns_projected_result_and_persists_per_tenant() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/users/42"))
            .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
            .mount(&server)
            .await;
        let bundle = build(reqwest::Client::builder().build().unwrap());
        let raw = fixture_collection(&server.uri());
        let result = bundle
            .api_dast
            .scan(
                "tenant-1",
                raw.as_bytes(),
                &server.uri(),
                Some(SecretString::from("test-token")),
                Vec::new(),
            )
            .await
            .unwrap();
        assert_eq!(result.tenant_id, "tenant-1");
        assert_eq!(result.collection_name, "demo");
        // Auth bypass should trigger — the mocked server returns 200
        // regardless of the Authorization header.
        assert!(result.findings.iter().any(|f| f.check_id == "auth-bypass"));

        // Persisted scan list surfaces the entry.
        let list = bundle.api_dast.list("tenant-1", 10).await.unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].scan_id, result.scan_id);

        // Other tenants do not see this scan.
        let other = bundle.api_dast.list("tenant-2", 10).await.unwrap();
        assert!(other.is_empty());
    }

    #[tokio::test]
    async fn scan_rejects_empty_collection() {
        let bundle = build(reqwest::Client::builder().build().unwrap());
        let err = bundle
            .api_dast
            .scan("t", b"", "http://example.com", None, Vec::new())
            .await
            .unwrap_err();
        assert!(matches!(err, ApiDastPortError::Invalid(_)));
    }

    #[tokio::test]
    async fn scan_rejects_bad_base_url() {
        let bundle = build(reqwest::Client::builder().build().unwrap());
        let err = bundle
            .api_dast
            .scan(
                "t",
                br#"{"info":{"name":"x"},"item":[]}"#,
                "not-a-url",
                None,
                Vec::new(),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, ApiDastPortError::Invalid(_)));
    }

    #[tokio::test]
    async fn list_with_empty_tenant_is_invalid() {
        let bundle = build(reqwest::Client::builder().build().unwrap());
        let err = bundle.api_dast.list("", 10).await.unwrap_err();
        assert!(matches!(err, ApiDastPortError::Invalid(_)));
    }
}
