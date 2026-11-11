//! Jira Cloud REST API adapter.
//!
//! Creates Jira issues for `SentinelX` findings. Authentication is the
//! standard Atlassian "email + API token" basic-auth pair, base64-encoded
//! and held inside a [`secrecy::SecretString`] so the `Debug` impl can
//! redact it.
//!
//! ## Severity mapping
//!
//! `SentinelX` uses a five-level severity scale. We map each level to a
//! Jira label `sx-severity-{level}` and to a Jira priority-name stub on
//! the issue payload (under `fields.priority.name`). The label is the
//! durable, queryable hook — priority is a hint that Jira may override
//! depending on per-project scheme configuration.
//!
//! | Severity   | Label                 | Priority hint |
//! |------------|-----------------------|---------------|
//! | `Info`     | `sx-severity-info`    | `Lowest`      |
//! | `Low`      | `sx-severity-low`     | `Low`         |
//! | `Medium`   | `sx-severity-medium`  | `Medium`      |
//! | `High`     | `sx-severity-high`    | `High`        |
//! | `Critical` | `sx-severity-critical`| `Highest`     |

use std::fmt;

use base64::Engine;
use reqwest::{Client, StatusCode, Url};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{debug, warn};

use crate::error::IntegrationError;
use crate::siem::Severity;

/// Issue-creation endpoint, appended to the configured base URL.
const ISSUE_PATH: &str = "rest/api/3/issue";

/// Jira Cloud REST API client.
///
/// The API token is held as a [`SecretString`]; the `Debug` impl below
/// redacts it. The `Authorization: Basic <base64(email:token)>` header
/// is rebuilt on every request so a future rotation of `api_token` (if
/// the field is ever mutated through a wrapper) is observed without
/// extra plumbing.
#[derive(Clone)]
pub struct JiraClient {
    http: Client,
    base_url: Url,
    email: String,
    api_token: SecretString,
}

impl fmt::Debug for JiraClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JiraClient")
            .field("base_url", &self.base_url.as_str())
            .field("email", &self.email)
            .field("api_token", &"<redacted>")
            .finish_non_exhaustive()
    }
}

/// Reference to a created Jira issue.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct JiraIssueRef {
    /// Internal Jira issue id (numeric string).
    pub id: String,
    /// Human-readable key (e.g. `"SEC-1234"`).
    pub key: String,
    /// URL of the issue resource in the REST API.
    #[serde(rename = "self", default, skip_serializing_if = "Option::is_none")]
    pub self_url: Option<String>,
}

impl JiraClient {
    /// Construct a new Jira client.
    ///
    /// `base_url` is the Atlassian Cloud site root, e.g.
    /// `https://acme.atlassian.net/`.
    #[must_use]
    pub const fn new(http: Client, base_url: Url, email: String, api_token: SecretString) -> Self {
        Self {
            http,
            base_url,
            email,
            api_token,
        }
    }

    /// Build the `Authorization: Basic …` header value for the current
    /// credential pair. Returned as a [`SecretString`] so it can be
    /// passed to the HTTP client without ever materialising into a
    /// `Debug`-able owned string elsewhere.
    fn basic_auth_header(&self) -> SecretString {
        let raw = format!("{}:{}", self.email, self.api_token.expose_secret());
        let encoded = base64::engine::general_purpose::STANDARD.encode(raw.as_bytes());
        SecretString::new(format!("Basic {encoded}").into_boxed_str())
    }

    /// Create a Jira issue.
    ///
    /// * `project_key` — Jira project key (e.g. `"SEC"`).
    /// * `summary` — issue title.
    /// * `description` — Atlassian Document Format is the canonical
    ///   payload; we wrap the supplied plain text in a minimal ADF
    ///   paragraph so callers don't have to know about that.
    /// * `severity` — drives the label and priority hint per the table
    ///   in the module docs.
    pub async fn create_issue(
        &self,
        project_key: &str,
        summary: &str,
        description: &str,
        severity: Severity,
    ) -> Result<JiraIssueRef, IntegrationError> {
        let endpoint = self
            .base_url
            .join(ISSUE_PATH)
            .map_err(IntegrationError::format)?;

        let label = severity_label(severity);
        let priority = severity_priority_hint(severity);
        let body = json!({
            "fields": {
                "project": { "key": project_key },
                "summary": summary,
                "issuetype": { "name": "Task" },
                "labels": [label],
                "priority": { "name": priority },
                "description": {
                    "type": "doc",
                    "version": 1,
                    "content": [{
                        "type": "paragraph",
                        "content": [{
                            "type": "text",
                            "text": description
                        }]
                    }]
                }
            }
        });

        debug!(
            target: "sx_integrations::jira",
            %project_key,
            severity = severity.label(),
            "creating jira issue"
        );

        let auth = self.basic_auth_header();
        let resp = self
            .http
            .post(endpoint)
            .header(reqwest::header::AUTHORIZATION, auth.expose_secret())
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header(reqwest::header::ACCEPT, "application/json")
            .json(&body)
            .send()
            .await?;

        let status = resp.status();
        if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
            warn!(
                target: "sx_integrations::jira",
                %status,
                "jira rejected create-issue request"
            );
            return Err(IntegrationError::Unauthorized);
        }
        if status == StatusCode::TOO_MANY_REQUESTS {
            let retry_after_secs = resp
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.trim().parse::<u64>().ok());
            return Err(IntegrationError::RateLimited { retry_after_secs });
        }
        if !status.is_success() {
            // 400 (bad project, missing field, ...) collapses into Format
            // — the caller's payload was wrong, not their credentials.
            let body_text = resp.text().await.unwrap_or_default();
            return Err(IntegrationError::Format(format!(
                "jira returned {status}: {body_text}"
            )));
        }

        let issue: JiraIssueRef = resp.json().await?;
        Ok(issue)
    }
}

/// Map a [`Severity`] to its Jira label.
#[must_use]
pub fn severity_label(sev: Severity) -> String {
    format!("sx-severity-{}", sev.label())
}

/// Map a [`Severity`] to a Jira priority name hint.
#[must_use]
pub const fn severity_priority_hint(sev: Severity) -> &'static str {
    match sev {
        Severity::Info => "Lowest",
        Severity::Low => "Low",
        Severity::Medium => "Medium",
        Severity::High => "High",
        Severity::Critical => "Highest",
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::expect_used,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;
    use serde_json::json;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn token() -> SecretString {
        SecretString::new("jira-api-token-shhh".to_owned().into_boxed_str())
    }

    fn client_for(server: &MockServer) -> JiraClient {
        let url = Url::parse(&format!("{}/", server.uri())).unwrap();
        JiraClient::new(
            reqwest::Client::new(),
            url,
            "ops@example.com".to_owned(),
            token(),
        )
    }

    fn expected_basic_auth_header() -> String {
        let raw = "ops@example.com:jira-api-token-shhh";
        let encoded = base64::engine::general_purpose::STANDARD.encode(raw.as_bytes());
        format!("Basic {encoded}")
    }

    #[tokio::test]
    async fn create_issue_success_returns_ref() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/rest/api/3/issue"))
            .and(header(
                "authorization",
                expected_basic_auth_header().as_str(),
            ))
            .and(header("content-type", "application/json"))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "id": "10042",
                "key": "SEC-7",
                "self": "https://acme.atlassian.net/rest/api/3/issue/10042"
            })))
            .expect(1)
            .mount(&server)
            .await;

        let c = client_for(&server);
        let issue = c
            .create_issue(
                "SEC",
                "Finding: SQLi",
                "Detected SQLi at /login",
                Severity::High,
            )
            .await
            .unwrap();
        assert_eq!(issue.id, "10042");
        assert_eq!(issue.key, "SEC-7");
        assert_eq!(
            issue.self_url.as_deref(),
            Some("https://acme.atlassian.net/rest/api/3/issue/10042")
        );
    }

    #[tokio::test]
    async fn create_issue_401_maps_to_unauthorized() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/rest/api/3/issue"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&server)
            .await;

        let c = client_for(&server);
        let err = c
            .create_issue("SEC", "x", "y", Severity::Low)
            .await
            .unwrap_err();
        assert!(matches!(err, IntegrationError::Unauthorized));
    }

    #[tokio::test]
    async fn create_issue_400_bad_project_maps_to_format() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/rest/api/3/issue"))
            .respond_with(ResponseTemplate::new(400).set_body_json(json!({
                "errorMessages": ["project key NOPE is invalid"],
                "errors": {}
            })))
            .mount(&server)
            .await;

        let c = client_for(&server);
        let err = c
            .create_issue("NOPE", "x", "y", Severity::Medium)
            .await
            .unwrap_err();
        match err {
            IntegrationError::Format(msg) => {
                assert!(msg.contains("400"), "msg: {msg}");
            }
            other => panic!("expected Format, got {other:?}"),
        }
    }

    #[test]
    fn debug_impl_redacts_basic_auth_and_token() {
        let c = JiraClient::new(
            reqwest::Client::new(),
            Url::parse("https://acme.atlassian.net/").unwrap(),
            "ops@example.com".to_owned(),
            SecretString::new("super-secret-token".to_owned().into_boxed_str()),
        );
        let dbg = format!("{c:?}");
        assert!(dbg.contains("ops@example.com"));
        assert!(!dbg.contains("super-secret-token"), "token leaked: {dbg}");
        // The base64 of "ops@example.com:super-secret-token" must not appear either.
        let raw = "ops@example.com:super-secret-token";
        let encoded = base64::engine::general_purpose::STANDARD.encode(raw.as_bytes());
        assert!(
            !dbg.contains(&encoded),
            "basic-auth header leaked in debug: {dbg}"
        );
        // The redaction marker must be there for the token field.
        assert!(dbg.contains("<redacted>"));
    }

    #[test]
    fn severity_label_mapping_is_stable() {
        assert_eq!(severity_label(Severity::Info), "sx-severity-info");
        assert_eq!(severity_label(Severity::Low), "sx-severity-low");
        assert_eq!(severity_label(Severity::Medium), "sx-severity-medium");
        assert_eq!(severity_label(Severity::High), "sx-severity-high");
        assert_eq!(severity_label(Severity::Critical), "sx-severity-critical");
    }
}
