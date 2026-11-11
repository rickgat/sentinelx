//! Outbound ticketing + alerting integrations (TOP5-#5).
//!
//! Configures the optional sinks that the monolith fans an
//! `IncidentEvent` out to when a `Critical` finding lands, a SOC playbook
//! triggers, or an audit-chain break is detected. Both vendor sub-configs
//! ship **disabled by default** — a freshly cloned checkout never reaches
//! Atlassian, `PagerDuty`, or any other outbound third party.
//!
//! ## Vendor coverage
//!
//! * [`JiraIntegrationConfig`] — Jira Cloud REST API v3 (`POST
//!   /rest/api/3/issue`). Authentication is either `email + api_token`
//!   (basic auth, standard Atlassian Cloud flow) or a bearer access token
//!   when the operator has wired up a 3LO OAuth flow externally and is
//!   feeding the resulting token in.
//! * [`PagerDutyIntegrationConfig`] — `PagerDuty` Events API v2 (`POST
//!   https://events.pagerduty.com/v2/enqueue`). Authentication is the
//!   integration's routing key (a per-service shared secret).
//! * [`LinearIntegrationConfig`] — Linear GraphQL (`POST
//!   https://api.linear.app/graphql`, `IssueCreate` mutation). Auth is a
//!   raw API key passed verbatim in the `Authorization` header (no
//!   `Bearer ` prefix). OAuth 2.0 is out of scope for the MVP.
//! * [`OpsgenieIntegrationConfig`] — Atlassian Opsgenie Alerts API v2
//!   (`POST {api_url}/v2/alerts`). Authentication is the per-team
//!   integration API key, sent as `Authorization: GenieKey <key>`.
//!
//! One vendor remains tracked as a follow-up (`TOP5-#5-FU1` `ServiceNow`);
//! see `docs/SPRINT_HARDENING_HANDOFF.md`.
//!
//! ## Secret handling
//!
//! Every credential field is wrapped in [`secrecy::SecretString`] so the
//! value never appears in `Debug` output, panic messages, or `tracing`
//! events. Adapters expose the secret only at the moment they construct
//! the outbound `Authorization` / `routing_key` payload.

use secrecy::SecretString;
use serde::Deserialize;
use validator::Validate;

/// Jira authentication mode.
///
/// Atlassian Cloud accepts two stable credential shapes for REST API v3:
///
/// * **`basic_auth`** — `email + api_token`, base64-encoded into a
///   `Authorization: Basic ...` header. This is the documented "API
///   token" path operators get from `id.atlassian.com/manage-profile/
///   security/api-tokens`.
/// * **`bearer`** — an OAuth 2.0 (3LO) access token. The token exchange
///   itself lives outside `SentinelX` (typically a one-time consent flow
///   driven by the operator's identity provider); we accept the resulting
///   bearer and replay it on every outbound issue-create call.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum JiraAuthKind {
    /// `email + api_token`, encoded as HTTP Basic. The default — it's
    /// what Atlassian's "I want to script Jira from a CLI" docs walk
    /// every new operator through.
    #[default]
    BasicAuth,
    /// OAuth 2.0 (3LO) bearer access token. The token exchange happens
    /// out-of-band; we replay the bearer on every outbound call.
    Bearer,
}

/// Jira integration configuration.
///
/// Disabled by default. When `enabled` is `true`:
///   * `base_url` MUST be non-empty (e.g. `https://acme.atlassian.net/`),
///   * `project_key` MUST be non-empty (e.g. `SEC`),
///   * either the basic-auth pair (`email` + `api_token`) OR the bearer
///     token MUST be supplied — picked by [`Self::auth_kind`].
///
/// Mismatched combinations (e.g. `auth_kind: bearer` with an empty
/// `bearer_token`) surface a [`crate::ConfigError::MissingValue`]
/// pointing at the first missing key.
#[derive(Debug, Clone, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
pub struct JiraIntegrationConfig {
    /// Whether the Jira adapter should be wired into the monolith's
    /// incident-sink fan-out at boot.
    pub enabled: bool,

    /// Atlassian Cloud site root, e.g. `https://acme.atlassian.net/`.
    /// Mandatory iff `enabled`.
    #[serde(default)]
    pub base_url: String,

    /// Jira project key the adapter files issues against (e.g. `SEC`).
    /// Mandatory iff `enabled`.
    #[serde(default)]
    pub project_key: String,

    /// Issue type to file under. Defaults to `Task` so a project without
    /// custom types still accepts our payload.
    #[serde(default = "default_issue_type")]
    pub issue_type: String,

    /// Authentication strategy. See [`JiraAuthKind`].
    #[serde(default)]
    pub auth_kind: JiraAuthKind,

    /// Atlassian Cloud account email. Mandatory iff `enabled` and
    /// `auth_kind = basic_auth`.
    #[serde(default)]
    pub email: String,

    /// Atlassian Cloud API token (paired with `email` for basic auth).
    /// Mandatory iff `enabled` and `auth_kind = basic_auth`.
    #[serde(default)]
    pub api_token: SecretString,

    /// OAuth 2.0 (3LO) bearer access token. Mandatory iff `enabled`
    /// and `auth_kind = bearer`.
    #[serde(default)]
    pub bearer_token: SecretString,

    /// Optional custom-field id used to stamp the finding's stable
    /// `SentinelX` id on the issue, enabling idempotent retries. When
    /// `None` we rely on Jira's natural dedup, which is none — the
    /// caller is responsible for not double-emitting.
    ///
    /// Atlassian custom field ids look like `customfield_10042`.
    #[serde(default)]
    pub external_id_custom_field: Option<String>,
}

/// Default issue type when none is supplied. `Task` is the standard
/// out-of-the-box Atlassian type that every project accepts.
fn default_issue_type() -> String {
    "Task".to_owned()
}

impl Default for JiraIntegrationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            base_url: String::new(),
            project_key: String::new(),
            issue_type: default_issue_type(),
            auth_kind: JiraAuthKind::default(),
            email: String::new(),
            api_token: SecretString::from(String::new()),
            bearer_token: SecretString::from(String::new()),
            external_id_custom_field: None,
        }
    }
}

impl JiraIntegrationConfig {
    /// Cross-field invariants. Disabled configs always pass; enabled
    /// configs must supply the endpoint, project key, and a complete
    /// credential set matching `auth_kind`.
    pub(crate) fn check_invariants(&self) -> Result<(), crate::ConfigError> {
        if !self.enabled {
            return Ok(());
        }
        if self.base_url.trim().is_empty() {
            return Err(crate::ConfigError::missing("integrations.jira.base_url"));
        }
        if self.project_key.trim().is_empty() {
            return Err(crate::ConfigError::missing("integrations.jira.project_key"));
        }
        match self.auth_kind {
            JiraAuthKind::BasicAuth => {
                if self.email.trim().is_empty() {
                    return Err(crate::ConfigError::missing("integrations.jira.email"));
                }
                if crate::secret::is_empty(&self.api_token) {
                    return Err(crate::ConfigError::missing("integrations.jira.api_token"));
                }
            }
            JiraAuthKind::Bearer => {
                if crate::secret::is_empty(&self.bearer_token) {
                    return Err(crate::ConfigError::missing(
                        "integrations.jira.bearer_token",
                    ));
                }
            }
        }
        Ok(())
    }
}

/// `PagerDuty` integration configuration.
///
/// Disabled by default. When `enabled` is `true`:
///   * `routing_key` MUST be non-empty.
///   * `events_url` defaults to the public Events API v2 endpoint when
///     omitted; operators can override it for testing or for the EU
///     residency endpoint (`https://events.eu.pagerduty.com/v2/enqueue`).
#[derive(Debug, Clone, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
pub struct PagerDutyIntegrationConfig {
    /// Whether the `PagerDuty` adapter should be wired into the monolith's
    /// incident-sink fan-out at boot.
    pub enabled: bool,

    /// `PagerDuty` Events API v2 endpoint. Defaults to the public US
    /// endpoint (`https://events.pagerduty.com/v2/enqueue`). Override
    /// for EU residency or for a local wiremock fixture in tests.
    #[serde(default = "default_pagerduty_events_url")]
    pub events_url: String,

    /// Per-service integration key ("routing key"). `PagerDuty` mints one
    /// of these per Events API v2 integration on a service. Mandatory
    /// iff `enabled`.
    #[serde(default)]
    pub routing_key: SecretString,

    /// Optional override of `payload.source` on every event. Defaults
    /// to the emitting tenant's slug at dispatch time when `None`.
    #[serde(default)]
    pub source_override: Option<String>,
}

/// Default Events API v2 endpoint. Public US datacentre — operators on
/// the EU residency plan override `events_url` to
/// `https://events.eu.pagerduty.com/v2/enqueue`.
fn default_pagerduty_events_url() -> String {
    "https://events.pagerduty.com/v2/enqueue".to_owned()
}

impl Default for PagerDutyIntegrationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            events_url: default_pagerduty_events_url(),
            routing_key: SecretString::from(String::new()),
            source_override: None,
        }
    }
}

impl PagerDutyIntegrationConfig {
    /// Cross-field invariants. Disabled configs always pass; enabled
    /// configs must supply a non-empty routing key.
    pub(crate) fn check_invariants(&self) -> Result<(), crate::ConfigError> {
        if !self.enabled {
            return Ok(());
        }
        if self.events_url.trim().is_empty() {
            return Err(crate::ConfigError::missing(
                "integrations.pagerduty.events_url",
            ));
        }
        if crate::secret::is_empty(&self.routing_key) {
            return Err(crate::ConfigError::missing(
                "integrations.pagerduty.routing_key",
            ));
        }
        Ok(())
    }
}

/// Linear integration configuration.
///
/// Disabled by default. When `enabled` is `true`:
///   * `api_url` MUST be a parsable URL (defaults to
///     `https://api.linear.app/graphql`),
///   * `api_key` MUST be non-empty,
///   * `team_id` MUST be non-empty — Linear's `IssueCreate` mutation
///     requires the target team.
///
/// `label_ids` is optional; when supplied every issue the adapter files
/// is tagged with the listed Linear label UUIDs.
#[derive(Debug, Clone, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
pub struct LinearIntegrationConfig {
    /// Whether the Linear adapter should be wired into the monolith's
    /// incident-sink fan-out at boot.
    pub enabled: bool,

    /// Linear GraphQL endpoint. Defaults to the public production
    /// endpoint (`https://api.linear.app/graphql`). Override for a
    /// wiremock fixture in tests; Linear does not currently expose a
    /// regional endpoint variant.
    #[serde(default = "default_linear_api_url")]
    pub api_url: String,

    /// Raw Linear API key. Travels verbatim in the `Authorization`
    /// header — Linear's API docs do NOT use the `Bearer ` prefix.
    /// Mandatory iff `enabled`.
    #[serde(default)]
    pub api_key: SecretString,

    /// Linear team UUID — the target team's id from `team.id` in the
    /// Linear GraphQL schema. Mandatory iff `enabled`.
    #[serde(default)]
    pub team_id: String,

    /// Optional list of Linear label UUIDs to attach to every filed
    /// issue. Empty by default.
    #[serde(default)]
    pub label_ids: Vec<String>,
}

/// Default Linear GraphQL endpoint. Operators override `api_url` only
/// for tests or for a local mock fixture.
fn default_linear_api_url() -> String {
    "https://api.linear.app/graphql".to_owned()
}

impl Default for LinearIntegrationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            api_url: default_linear_api_url(),
            api_key: SecretString::from(String::new()),
            team_id: String::new(),
            label_ids: Vec::new(),
        }
    }
}

/// Opsgenie integration configuration.
///
/// Disabled by default. When `enabled` is `true`:
///   * `api_key` MUST be non-empty.
///   * `api_url` defaults to the public US datacentre when omitted;
///     operators on the EU residency plan override it to
///     `https://api.eu.opsgenie.com`, and tests can target a wiremock
///     fixture.
#[derive(Debug, Clone, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
pub struct OpsgenieIntegrationConfig {
    /// Whether the Opsgenie adapter should be wired into the monolith's
    /// incident-sink fan-out at boot.
    pub enabled: bool,

    /// Opsgenie API host root. Defaults to the public US datacentre
    /// (`https://api.opsgenie.com`). Override for EU residency
    /// (`https://api.eu.opsgenie.com`) or for a local wiremock fixture.
    /// The adapter appends `/v2/alerts` at construction time.
    #[serde(default = "default_opsgenie_api_url")]
    pub api_url: String,

    /// Per-team integration API key. Opsgenie mints one of these per
    /// API-integration on a team. Mandatory iff `enabled`. Sent as
    /// `Authorization: GenieKey <api_key>` on every outbound call.
    #[serde(default)]
    pub api_key: SecretString,

    /// Optional override of `source` on every alert payload. Defaults
    /// to the emitting tenant's slug at dispatch time when `None`.
    #[serde(default)]
    pub source_override: Option<String>,
}

/// Default Opsgenie API host. Public US datacentre — operators on the
/// EU residency plan override `api_url` to `https://api.eu.opsgenie.com`.
fn default_opsgenie_api_url() -> String {
    "https://api.opsgenie.com".to_owned()
}

impl Default for OpsgenieIntegrationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            api_url: default_opsgenie_api_url(),
            api_key: SecretString::from(String::new()),
            source_override: None,
        }
    }
}

impl LinearIntegrationConfig {
    /// Cross-field invariants. Disabled configs always pass; enabled
    /// configs must supply a non-empty endpoint, API key, and team id.
    pub(crate) fn check_invariants(&self) -> Result<(), crate::ConfigError> {
        if !self.enabled {
            return Ok(());
        }
        if self.api_url.trim().is_empty() {
            return Err(crate::ConfigError::missing("integrations.linear.api_url"));
        }
        if crate::secret::is_empty(&self.api_key) {
            return Err(crate::ConfigError::missing("integrations.linear.api_key"));
        }
        if self.team_id.trim().is_empty() {
            return Err(crate::ConfigError::missing("integrations.linear.team_id"));
        }
        Ok(())
    }
}

impl OpsgenieIntegrationConfig {
    /// Cross-field invariants. Disabled configs always pass; enabled
    /// configs must supply a non-empty API key + a non-empty API host.
    pub(crate) fn check_invariants(&self) -> Result<(), crate::ConfigError> {
        if !self.enabled {
            return Ok(());
        }
        if self.api_url.trim().is_empty() {
            return Err(crate::ConfigError::missing("integrations.opsgenie.api_url"));
        }
        if crate::secret::is_empty(&self.api_key) {
            return Err(crate::ConfigError::missing("integrations.opsgenie.api_key"));
        }
        Ok(())
    }
}

/// `ServiceNow` Table API integration configuration (TOP5-#5-FU1).
///
/// Disabled by default. When `enabled` is `true`:
///   * `base_url` MUST be non-empty (e.g.
///     `https://acme.service-now.com/`).
///   * `user` MUST be non-empty (typically a dedicated integration user
///     with the `itil` role).
///   * `password` MUST be non-empty.
///
/// The MVP exposes basic auth only — OAuth tracked as a future
/// enhancement. The optional `assignment_group` is a `sys_id`
/// pass-through; `ServiceNow` resolves it server-side and the adapter
/// does not validate the value beyond presence.
#[derive(Debug, Clone, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
pub struct ServiceNowIntegrationConfig {
    /// Whether the `ServiceNow` adapter should be wired into the monolith's
    /// incident-sink fan-out at boot.
    pub enabled: bool,

    /// `ServiceNow` instance root, e.g. `https://acme.service-now.com/`.
    /// Mandatory iff `enabled`.
    #[serde(default)]
    pub base_url: String,

    /// Basic-auth user name. Mandatory iff `enabled`.
    #[serde(default)]
    pub user: String,

    /// Basic-auth password. Mandatory iff `enabled`. Wrapped in
    /// [`SecretString`] so it never leaks via `Debug` / `tracing`.
    /// Override at runtime with
    /// `SENTINELX__INTEGRATIONS__SERVICENOW__PASSWORD`.
    #[serde(default)]
    pub password: SecretString,

    /// Optional `sys_id` of the `ServiceNow` group that should receive
    /// every incident. When `None` the platform's default assignment
    /// rules run.
    #[serde(default)]
    pub assignment_group: Option<String>,
}

impl Default for ServiceNowIntegrationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            base_url: String::new(),
            user: String::new(),
            password: SecretString::from(String::new()),
            assignment_group: None,
        }
    }
}

impl ServiceNowIntegrationConfig {
    /// Cross-field invariants. Disabled configs always pass; enabled
    /// configs must supply the endpoint + basic-auth credential pair.
    pub(crate) fn check_invariants(&self) -> Result<(), crate::ConfigError> {
        if !self.enabled {
            return Ok(());
        }
        if self.base_url.trim().is_empty() {
            return Err(crate::ConfigError::missing(
                "integrations.servicenow.base_url",
            ));
        }
        if self.user.trim().is_empty() {
            return Err(crate::ConfigError::missing("integrations.servicenow.user"));
        }
        if crate::secret::is_empty(&self.password) {
            return Err(crate::ConfigError::missing(
                "integrations.servicenow.password",
            ));
        }
        Ok(())
    }
}

/// Aggregate ticketing + alerting integrations block.
///
/// Mirrors the per-vendor sub-config pattern other multi-vendor blocks
/// use (`cloud.aws / cloud.gcp / cloud.azure`). All four vendors ship
/// disabled by default.
#[derive(Debug, Clone, Default, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
pub struct IntegrationsConfig {
    /// Jira Cloud ticketing adapter. Disabled by default.
    #[serde(default)]
    #[validate(nested)]
    pub jira: JiraIntegrationConfig,

    /// `PagerDuty` alerting adapter. Disabled by default.
    #[serde(default)]
    #[validate(nested)]
    pub pagerduty: PagerDutyIntegrationConfig,

    /// Linear ticketing adapter. Disabled by default.
    #[serde(default)]
    #[validate(nested)]
    pub linear: LinearIntegrationConfig,

    /// Opsgenie alerting adapter. Disabled by default.
    #[serde(default)]
    #[validate(nested)]
    pub opsgenie: OpsgenieIntegrationConfig,

    /// `ServiceNow` ticketing adapter. Disabled by default.
    #[serde(default)]
    #[validate(nested)]
    pub servicenow: ServiceNowIntegrationConfig,
}

impl IntegrationsConfig {
    /// Cross-field invariants for every sub-vendor.
    pub(crate) fn check_invariants(&self) -> Result<(), crate::ConfigError> {
        self.jira.check_invariants()?;
        self.pagerduty.check_invariants()?;
        self.linear.check_invariants()?;
        self.opsgenie.check_invariants()?;
        self.servicenow.check_invariants()?;
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::secret;

    fn disabled_jira() -> JiraIntegrationConfig {
        JiraIntegrationConfig::default()
    }

    fn disabled_pd() -> PagerDutyIntegrationConfig {
        PagerDutyIntegrationConfig::default()
    }

    fn disabled_linear() -> LinearIntegrationConfig {
        LinearIntegrationConfig::default()
    }

    fn disabled_og() -> OpsgenieIntegrationConfig {
        OpsgenieIntegrationConfig::default()
    }

    #[test]
    fn defaults_are_all_disabled() {
        let cfg = IntegrationsConfig::default();
        assert!(!cfg.jira.enabled);
        assert!(!cfg.pagerduty.enabled);
        assert!(!cfg.linear.enabled);
        assert!(!cfg.opsgenie.enabled);
        cfg.check_invariants()
            .expect("disabled integrations block must always pass");
    }

    #[test]
    fn jira_disabled_skips_validation() {
        let cfg = disabled_jira();
        cfg.check_invariants()
            .expect("disabled jira config must always pass");
    }

    #[test]
    fn jira_enabled_basic_auth_happy() {
        let mut cfg = disabled_jira();
        cfg.enabled = true;
        cfg.base_url = "https://acme.atlassian.net/".to_owned();
        cfg.project_key = "SEC".to_owned();
        cfg.email = "ops@example.com".to_owned();
        cfg.api_token = secret::wrap("jira-api-token");
        cfg.check_invariants()
            .expect("complete basic-auth jira config must pass");
    }

    #[test]
    fn jira_enabled_bearer_happy() {
        let mut cfg = disabled_jira();
        cfg.enabled = true;
        cfg.base_url = "https://acme.atlassian.net/".to_owned();
        cfg.project_key = "SEC".to_owned();
        cfg.auth_kind = JiraAuthKind::Bearer;
        cfg.bearer_token = secret::wrap("bearer-token");
        cfg.check_invariants()
            .expect("complete bearer jira config must pass");
    }

    #[test]
    fn jira_enabled_missing_base_url() {
        let mut cfg = disabled_jira();
        cfg.enabled = true;
        cfg.project_key = "SEC".to_owned();
        cfg.email = "ops@example.com".to_owned();
        cfg.api_token = secret::wrap("jira-api-token");
        let err = cfg
            .check_invariants()
            .expect_err("missing base_url must surface MissingValue");
        match err {
            crate::ConfigError::MissingValue { key } => {
                assert_eq!(key, "integrations.jira.base_url");
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn jira_enabled_missing_project_key() {
        let mut cfg = disabled_jira();
        cfg.enabled = true;
        cfg.base_url = "https://acme.atlassian.net/".to_owned();
        cfg.email = "ops@example.com".to_owned();
        cfg.api_token = secret::wrap("jira-api-token");
        let err = cfg.check_invariants().unwrap_err();
        match err {
            crate::ConfigError::MissingValue { key } => {
                assert_eq!(key, "integrations.jira.project_key");
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn jira_enabled_basic_auth_missing_token() {
        let mut cfg = disabled_jira();
        cfg.enabled = true;
        cfg.base_url = "https://acme.atlassian.net/".to_owned();
        cfg.project_key = "SEC".to_owned();
        cfg.email = "ops@example.com".to_owned();
        let err = cfg.check_invariants().unwrap_err();
        match err {
            crate::ConfigError::MissingValue { key } => {
                assert_eq!(key, "integrations.jira.api_token");
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn jira_enabled_bearer_missing_token() {
        let mut cfg = disabled_jira();
        cfg.enabled = true;
        cfg.base_url = "https://acme.atlassian.net/".to_owned();
        cfg.project_key = "SEC".to_owned();
        cfg.auth_kind = JiraAuthKind::Bearer;
        let err = cfg.check_invariants().unwrap_err();
        match err {
            crate::ConfigError::MissingValue { key } => {
                assert_eq!(key, "integrations.jira.bearer_token");
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn pd_disabled_skips_validation() {
        let cfg = disabled_pd();
        cfg.check_invariants()
            .expect("disabled pagerduty config must always pass");
    }

    #[test]
    fn pd_enabled_happy() {
        let mut cfg = disabled_pd();
        cfg.enabled = true;
        cfg.routing_key = secret::wrap("pd-routing-key");
        cfg.check_invariants()
            .expect("complete pagerduty config must pass");
    }

    #[test]
    fn pd_enabled_missing_routing_key() {
        let mut cfg = disabled_pd();
        cfg.enabled = true;
        let err = cfg.check_invariants().unwrap_err();
        match err {
            crate::ConfigError::MissingValue { key } => {
                assert_eq!(key, "integrations.pagerduty.routing_key");
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn pd_default_url_is_pagerduty_events_v2() {
        let cfg = disabled_pd();
        assert_eq!(cfg.events_url, "https://events.pagerduty.com/v2/enqueue");
    }

    #[test]
    fn debug_does_not_leak_jira_token() {
        let mut cfg = disabled_jira();
        cfg.api_token = secret::wrap("jira-secret-token");
        let dbg = format!("{cfg:?}");
        assert!(
            !dbg.contains("jira-secret-token"),
            "token leaked in Debug: {dbg}"
        );
    }

    #[test]
    fn debug_does_not_leak_jira_bearer() {
        let mut cfg = disabled_jira();
        cfg.bearer_token = secret::wrap("bearer-leak-canary");
        let dbg = format!("{cfg:?}");
        assert!(
            !dbg.contains("bearer-leak-canary"),
            "bearer leaked in Debug: {dbg}"
        );
    }

    #[test]
    fn debug_does_not_leak_pd_routing_key() {
        let mut cfg = disabled_pd();
        cfg.routing_key = secret::wrap("pd-secret-routing-key");
        let dbg = format!("{cfg:?}");
        assert!(
            !dbg.contains("pd-secret-routing-key"),
            "routing key leaked in Debug: {dbg}"
        );
    }

    #[test]
    fn linear_disabled_skips_validation() {
        let cfg = disabled_linear();
        cfg.check_invariants()
            .expect("disabled linear config must always pass");
    }

    #[test]
    fn linear_enabled_happy() {
        let mut cfg = disabled_linear();
        cfg.enabled = true;
        cfg.api_key = secret::wrap("linear-api-key");
        cfg.team_id = "team-uuid".to_owned();
        cfg.check_invariants()
            .expect("complete linear config must pass");
    }

    #[test]
    fn linear_enabled_missing_api_key() {
        let mut cfg = disabled_linear();
        cfg.enabled = true;
        cfg.team_id = "team-uuid".to_owned();
        let err = cfg.check_invariants().unwrap_err();
        match err {
            crate::ConfigError::MissingValue { key } => {
                assert_eq!(key, "integrations.linear.api_key");
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn og_disabled_skips_validation() {
        let cfg = disabled_og();
        cfg.check_invariants()
            .expect("disabled opsgenie config must always pass");
    }

    #[test]
    fn og_enabled_happy() {
        let mut cfg = disabled_og();
        cfg.enabled = true;
        cfg.api_key = secret::wrap("og-api-key");
        cfg.check_invariants()
            .expect("complete opsgenie config must pass");
    }

    #[test]
    fn og_enabled_missing_api_key() {
        let mut cfg = disabled_og();
        cfg.enabled = true;
        let err = cfg.check_invariants().unwrap_err();
        match err {
            crate::ConfigError::MissingValue { key } => {
                assert_eq!(key, "integrations.opsgenie.api_key");
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn linear_enabled_missing_team_id() {
        let mut cfg = disabled_linear();
        cfg.enabled = true;
        cfg.api_key = secret::wrap("linear-api-key");
        let err = cfg.check_invariants().unwrap_err();
        match err {
            crate::ConfigError::MissingValue { key } => {
                assert_eq!(key, "integrations.linear.team_id");
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn og_enabled_missing_api_url() {
        let mut cfg = disabled_og();
        cfg.enabled = true;
        cfg.api_url = String::new();
        cfg.api_key = secret::wrap("og-api-key");
        let err = cfg.check_invariants().unwrap_err();
        match err {
            crate::ConfigError::MissingValue { key } => {
                assert_eq!(key, "integrations.opsgenie.api_url");
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn linear_default_url_is_public_graphql_endpoint() {
        let cfg = disabled_linear();
        assert_eq!(cfg.api_url, "https://api.linear.app/graphql");
    }

    #[test]
    fn debug_does_not_leak_linear_api_key() {
        let mut cfg = disabled_linear();
        cfg.api_key = secret::wrap("linear-secret-canary");
        let dbg = format!("{cfg:?}");
        assert!(
            !dbg.contains("linear-secret-canary"),
            "api key leaked in Debug: {dbg}"
        );
    }

    #[test]
    fn og_default_url_is_public_us_host() {
        let cfg = disabled_og();
        assert_eq!(cfg.api_url, "https://api.opsgenie.com");
    }

    #[test]
    fn debug_does_not_leak_og_api_key() {
        let mut cfg = disabled_og();
        cfg.api_key = secret::wrap("og-secret-api-key");
        let dbg = format!("{cfg:?}");
        assert!(
            !dbg.contains("og-secret-api-key"),
            "api key leaked in Debug: {dbg}"
        );
    }
}
