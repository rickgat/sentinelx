//! Incident-sink fan-out (TOP5-#5).
//!
//! Glue layer that wires the per-vendor adapters from `sx-integrations`
//! into a single `IncidentSinkFanOut`. The fan-out invokes every
//! configured sink in **parallel**; a single sink's failure never blocks
//! the others.
//!
//! ## What gets registered
//!
//! At boot, [`build`] reads `settings.integrations` and constructs
//! whichever vendor sinks have `enabled = true`. The MVP supports three
//! vendors: Jira Cloud (`integrations.jira`), PagerDuty
//! (`integrations.pagerduty`), and Linear (`integrations.linear`,
//! TOP5-#5-FU2). When every vendor block is disabled the fan-out is still
//! constructed but with an empty sink set; emissions become a
//! structured-trace-only no-op.
//! whichever vendor sinks have `enabled = true`. Three vendors are wired:
//! Jira Cloud (`integrations.jira`), PagerDuty (`integrations.pagerduty`),
//! and Opsgenie (`integrations.opsgenie`). When every vendor block is
//! disabled the fan-out is still constructed but with an empty sink set;
//! emissions become a structured-trace-only no-op.
//!
//! ## Trigger points
//!
//! Three triggers are documented for the MVP:
//!
//! 1. **`Critical` finding lands** — wired via FOUND-001's repository
//!    `insert(...)` path. At dispatch time FOUND-001 had NOT landed on
//!    main; the wiring is therefore staged as the TODO marker on
//!    [`fan_out_finding_emitted`] below. When FOUND-001 lands, that
//!    function gets called from
//!    `sx-api::controller::finding_repository::insert(...)` (or
//!    wherever the canonical insert path materialises).
//! 2. **SOC playbook fires** — call [`IncidentSinkFanOut::emit`]
//!    directly with `IncidentKind::PlaybookTriggered`.
//! 3. **Audit chain break** — call [`IncidentSinkFanOut::emit`] directly
//!    with `IncidentKind::AuditChainBreak` from the chain verifier
//!    handler.

// FOUND-001's `FindingRepositoryPort::insert(...)` slice (not yet on
// `main` at TOP5-#5 dispatch time) is the load-bearing caller that
// instantiates the fan-out via `build` from the composition root and
// invokes `fan_out_finding_emitted` from the insert path. Until that
// slice lands, every helper below is unreferenced. The framework + 3
// adapters (Jira, PagerDuty, Linear) are the current deliverable; the
// wiring is staged so FOUND-001's follow-up is a one-line
// `let fan_out = adapters::incident_sinks::build(http.clone(),
// &settings.integrations.jira, &settings.integrations.pagerduty,
// &settings.integrations.linear)?;` inside `build_app_state`.
#![allow(dead_code)]

use std::sync::Arc;

use anyhow::Result;
use futures::future::join_all;
use reqwest::Client;
use sx_config::schema::integrations::{
    JiraAuthKind, JiraIntegrationConfig, LinearIntegrationConfig, OpsgenieIntegrationConfig,
    PagerDutyIntegrationConfig, ServiceNowIntegrationConfig,
};
use sx_integrations::{
    EmissionReceipt, IncidentEvent, IncidentSinkError, IncidentSinkPort, JiraAuth,
    JiraIncidentSink, LinearIncidentSink, OpsgenieIncidentSink, PagerDutyIncidentSink,
    ServiceNowIncidentSink,
};
use tracing::{info, warn};
use url::Url;

/// Outcome of one sink emission inside a fan-out call.
#[derive(Debug)]
pub(crate) struct SinkOutcome {
    /// Stable adapter name (`"jira"`, `"pagerduty"`, …).
    pub adapter: &'static str,
    /// Result returned by the underlying [`IncidentSinkPort::emit`].
    pub result: Result<EmissionReceipt, IncidentSinkError>,
}

/// Fan-out wrapper over zero or more configured incident sinks.
///
/// `Clone` because the composition root stuffs it inside `Arc` and the
/// per-handler shared-state plumbing wants a value type for downstream
/// `Arc::new(...)` calls. Internally each sink is itself shared via
/// `Arc` so cloning is cheap.
#[derive(Clone)]
pub(crate) struct IncidentSinkFanOut {
    sinks: Vec<Arc<dyn IncidentSinkPort>>,
}

impl std::fmt::Debug for IncidentSinkFanOut {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let names: Vec<&'static str> = self.sinks.iter().map(|s| s.name()).collect();
        f.debug_struct("IncidentSinkFanOut")
            .field("sinks", &names)
            .finish()
    }
}

impl IncidentSinkFanOut {
    /// Construct a fan-out from a pre-built list of sinks (used by tests
    /// + by [`build`]).
    pub(crate) const fn new(sinks: Vec<Arc<dyn IncidentSinkPort>>) -> Self {
        Self { sinks }
    }

    /// Empty fan-out — useful when no vendor is enabled, so the call
    /// sites do not have to special-case an `Option<IncidentSinkFanOut>`.
    pub(crate) fn empty() -> Self {
        Self { sinks: Vec::new() }
    }

    /// Stable adapter names — convenient for boot logging.
    pub(crate) fn names(&self) -> Vec<&'static str> {
        self.sinks.iter().map(|s| s.name()).collect()
    }

    /// Number of registered sinks.
    pub(crate) fn len(&self) -> usize {
        self.sinks.len()
    }

    /// `true` when no sink is registered. Callers can short-circuit and
    /// avoid building an [`IncidentEvent`] when no one would consume it.
    pub(crate) fn is_empty(&self) -> bool {
        self.sinks.is_empty()
    }

    /// Emit `event` to every registered sink in parallel. Returns the
    /// per-sink outcome so callers can audit / log granular results.
    pub(crate) async fn emit(&self, event: &IncidentEvent) -> Vec<SinkOutcome> {
        if self.sinks.is_empty() {
            return Vec::new();
        }
        let futures = self.sinks.iter().map(|sink| {
            let sink = Arc::clone(sink);
            let event = event.clone();
            async move {
                let adapter = sink.name();
                let result = sink.emit(&event).await;
                match &result {
                    Ok(receipt) => {
                        info!(
                            target: "adapters.incident_sinks",
                            adapter,
                            external_id = %receipt.external_id,
                            external_url = %receipt.external_url,
                            "incident-sink emission succeeded",
                        );
                    }
                    Err(err) => {
                        warn!(
                            target: "adapters.incident_sinks",
                            adapter,
                            error = %err,
                            "incident-sink emission failed",
                        );
                    }
                }
                SinkOutcome { adapter, result }
            }
        });
        join_all(futures).await
    }
}

/// Build the fan-out from a [`Settings`](sx_config::Settings) block.
///
/// `http` is the workspace-shared `reqwest::Client` from the
/// composition root. The same client is handed to every sink so the
/// underlying connection pool is shared and TLS-handshake budget stays
/// bounded.
pub(crate) fn build(
    http: Client,
    jira: &JiraIntegrationConfig,
    pagerduty: &PagerDutyIntegrationConfig,
    linear: &LinearIntegrationConfig,
    opsgenie: &OpsgenieIntegrationConfig,
    servicenow: &ServiceNowIntegrationConfig,
) -> Result<IncidentSinkFanOut> {
    let mut sinks: Vec<Arc<dyn IncidentSinkPort>> = Vec::new();

    if jira.enabled {
        sinks.push(Arc::new(build_jira(http.clone(), jira)?));
    }
    if pagerduty.enabled {
        sinks.push(Arc::new(build_pagerduty(http.clone(), pagerduty)?));
    }
    if linear.enabled {
        sinks.push(Arc::new(build_linear(http.clone(), linear)?));
    }
    if opsgenie.enabled {
        sinks.push(Arc::new(build_opsgenie(http.clone(), opsgenie)?));
    }
    if servicenow.enabled {
        sinks.push(Arc::new(build_servicenow(http, servicenow)?));
    }

    let fan_out = IncidentSinkFanOut::new(sinks);
    info!(
        target: "adapters.incident_sinks",
        sinks = ?fan_out.names(),
        count = fan_out.len(),
        "incident-sink fan-out initialised",
    );
    Ok(fan_out)
}

/// Build a [`JiraIncidentSink`] from the on-disk config block.
fn build_jira(http: Client, cfg: &JiraIntegrationConfig) -> Result<JiraIncidentSink> {
    let base_url = Url::parse(&cfg.base_url)
        .map_err(|e| anyhow::anyhow!("integrations.jira.base_url is not a valid URL: {e}"))?;

    let auth = match cfg.auth_kind {
        JiraAuthKind::BasicAuth => JiraAuth::BasicAuth {
            email: cfg.email.clone(),
            api_token: cfg.api_token.clone(),
        },
        JiraAuthKind::Bearer => JiraAuth::Bearer {
            token: cfg.bearer_token.clone(),
        },
    };

    Ok(JiraIncidentSink::new(
        http,
        base_url,
        cfg.project_key.clone(),
        cfg.issue_type.clone(),
        auth,
        cfg.external_id_custom_field.clone(),
    ))
}

/// Build a [`PagerDutyIncidentSink`] from the on-disk config block.
fn build_pagerduty(
    http: Client,
    cfg: &PagerDutyIntegrationConfig,
) -> Result<PagerDutyIncidentSink> {
    let events_url = Url::parse(&cfg.events_url).map_err(|e| {
        anyhow::anyhow!("integrations.pagerduty.events_url is not a valid URL: {e}")
    })?;
    Ok(PagerDutyIncidentSink::new(
        http,
        events_url,
        cfg.routing_key.clone(),
        cfg.source_override.clone(),
    ))
}

/// Build a [`LinearIncidentSink`] from the on-disk config block.
fn build_linear(http: Client, cfg: &LinearIntegrationConfig) -> Result<LinearIncidentSink> {
    let api_url = Url::parse(&cfg.api_url)
        .map_err(|e| anyhow::anyhow!("integrations.linear.api_url is not a valid URL: {e}"))?;
    Ok(LinearIncidentSink::new(
        http,
        api_url,
        cfg.api_key.clone(),
        cfg.team_id.clone(),
        cfg.label_ids.clone(),
    ))
}

/// Build an [`OpsgenieIncidentSink`] from the on-disk config block.
///
/// Appends `/v2/alerts` to the configured `api_url` host root. Operators
/// configure just the host (e.g. `https://api.eu.opsgenie.com`); the
/// path is fixed by the Opsgenie Alerts API v2 contract.
fn build_opsgenie(http: Client, cfg: &OpsgenieIntegrationConfig) -> Result<OpsgenieIncidentSink> {
    let api_url = Url::parse(&cfg.api_url)
        .map_err(|e| anyhow::anyhow!("integrations.opsgenie.api_url is not a valid URL: {e}"))?;
    let alerts_url = api_url.join("/v2/alerts").map_err(|e| {
        anyhow::anyhow!("integrations.opsgenie.api_url cannot be joined with /v2/alerts: {e}")
    })?;
    Ok(OpsgenieIncidentSink::new(
        http,
        alerts_url,
        cfg.api_key.clone(),
        cfg.source_override.clone(),
    ))
}

/// Build a [`ServiceNowIncidentSink`] from the on-disk config block.
fn build_servicenow(
    http: Client,
    cfg: &ServiceNowIntegrationConfig,
) -> Result<ServiceNowIncidentSink> {
    let base_url = Url::parse(&cfg.base_url)
        .map_err(|e| anyhow::anyhow!("integrations.servicenow.base_url is not a valid URL: {e}"))?;
    Ok(ServiceNowIncidentSink::new(
        http,
        base_url,
        cfg.user.clone(),
        cfg.password.clone(),
        cfg.assignment_group.clone(),
    ))
}

// ----------------------------------------------------------------------------
// Trigger-point stubs.
// ----------------------------------------------------------------------------

/// Trigger-point stub for "Critical finding emitted" (TOP5-#5 +
/// FOUND-001).
///
/// **NOTE**: at TOP5-#5 dispatch time, FOUND-001's
/// `FindingRepositoryPort::insert(...)` method had **NOT** landed on
/// `main`. When FOUND-001 lands, the insert call site (in
/// `sx-api::controller::finding_repository` or equivalent) calls this
/// helper to fan out a `IncidentKind::FindingEmitted` event for every
/// `Severity::Critical` finding. Until then this helper is here as a
/// load-bearing call site marker — the framework + 2 adapters are the
/// MVP deliverable, the wiring just shows intent.
///
/// Concretely, the integration point is:
///
/// ```ignore
/// // Inside `FindingRepositoryPort::insert` adapter, after the row is
/// // persisted:
/// if finding.severity == "critical" {
///     let event = adapters::incident_sinks::build_finding_event(&finding, &tenant_id);
///     adapters::incident_sinks::fan_out_finding_emitted(&fan_out, &event).await;
/// }
/// ```
///
/// The fan-out instance lives on `AppState` (the composition root
/// stores it inside `Arc<IncidentSinkFanOut>`); FOUND-001's wiring slice
/// will plumb the `AppState` handle into the adapter struct so the
/// closure above resolves to a real type.
#[allow(dead_code)] // Wired up by FOUND-001's `insert(...)` slice.
pub(crate) async fn fan_out_finding_emitted(
    fan_out: &IncidentSinkFanOut,
    event: &IncidentEvent,
) -> Vec<SinkOutcome> {
    fan_out.emit(event).await
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use sx_core::value_object::compliance::ComplianceTags;
    use sx_core::value_object::severity::Severity;
    use sx_integrations::{FindingDigest, IncidentKind};

    /// In-memory sink that records every emission for assertions.
    struct CountingSink {
        adapter: &'static str,
        count: Arc<AtomicUsize>,
        result: Result<EmissionReceipt, IncidentSinkErrorKind>,
    }

    /// Cloneable error variants so the test can specify the outcome
    /// without re-creating the non-Clone underlying error type.
    #[derive(Clone)]
    enum IncidentSinkErrorKind {
        Unauthenticated,
    }

    impl IncidentSinkErrorKind {
        fn realise(&self) -> IncidentSinkError {
            match self {
                Self::Unauthenticated => IncidentSinkError::Unauthenticated,
            }
        }
    }

    #[async_trait]
    impl IncidentSinkPort for CountingSink {
        async fn emit(&self, _event: &IncidentEvent) -> Result<EmissionReceipt, IncidentSinkError> {
            self.count.fetch_add(1, Ordering::SeqCst);
            self.result
                .as_ref()
                .map_or_else(|e| Err(e.realise()), |r| Ok(r.clone()))
        }

        fn name(&self) -> &'static str {
            self.adapter
        }
    }

    fn ok_sink(adapter: &'static str) -> (Arc<dyn IncidentSinkPort>, Arc<AtomicUsize>) {
        let count = Arc::new(AtomicUsize::new(0));
        let sink = Arc::new(CountingSink {
            adapter,
            count: Arc::clone(&count),
            result: Ok(EmissionReceipt {
                external_id: format!("{adapter}-id-1"),
                external_url: format!("https://example.invalid/{adapter}/1"),
            }),
        });
        (sink, count)
    }

    fn err_sink(adapter: &'static str) -> (Arc<dyn IncidentSinkPort>, Arc<AtomicUsize>) {
        let count = Arc::new(AtomicUsize::new(0));
        let sink = Arc::new(CountingSink {
            adapter,
            count: Arc::clone(&count),
            result: Err(IncidentSinkErrorKind::Unauthenticated),
        });
        (sink, count)
    }

    fn fake_event() -> IncidentEvent {
        IncidentEvent {
            kind: IncidentKind::FindingEmitted,
            severity: Severity::Critical,
            tenant_id: "t-1".to_owned(),
            title: "test".to_owned(),
            description: "test".to_owned(),
            finding: Some(FindingDigest {
                id: "f-1".to_owned(),
                asset_id: "a-1".to_owned(),
                status: "open".to_owned(),
                cve_id: None,
            }),
            cvss: None,
            cwe: Vec::new(),
            mitre_attack: Vec::new(),
            compliance: ComplianceTags::default(),
            source_url: None,
        }
    }

    #[tokio::test]
    async fn empty_fanout_returns_empty_vector() {
        let fan = IncidentSinkFanOut::empty();
        assert!(fan.is_empty());
        let outcomes = fan.emit(&fake_event()).await;
        assert!(outcomes.is_empty());
    }

    #[tokio::test]
    async fn fanout_dispatches_to_every_registered_sink_in_parallel() {
        let (jira, jira_count) = ok_sink("jira");
        let (pd, pd_count) = ok_sink("pagerduty");
        let fan = IncidentSinkFanOut::new(vec![jira, pd]);
        assert_eq!(fan.len(), 2);

        let outcomes = fan.emit(&fake_event()).await;
        assert_eq!(outcomes.len(), 2);
        assert_eq!(jira_count.load(Ordering::SeqCst), 1);
        assert_eq!(pd_count.load(Ordering::SeqCst), 1);
        // Both succeeded.
        assert!(outcomes.iter().all(|o| o.result.is_ok()));
    }

    #[tokio::test]
    async fn one_sink_failure_does_not_block_the_others() {
        let (jira_ok, jira_count) = ok_sink("jira");
        let (pd_err, pd_count) = err_sink("pagerduty");
        let fan = IncidentSinkFanOut::new(vec![jira_ok, pd_err]);

        let outcomes = fan.emit(&fake_event()).await;
        assert_eq!(outcomes.len(), 2);
        assert_eq!(jira_count.load(Ordering::SeqCst), 1);
        assert_eq!(pd_count.load(Ordering::SeqCst), 1);
        // Exactly one ok, exactly one err.
        let oks = outcomes.iter().filter(|o| o.result.is_ok()).count();
        let errs = outcomes.iter().filter(|o| o.result.is_err()).count();
        assert_eq!(oks, 1);
        assert_eq!(errs, 1);
    }

    #[test]
    fn build_with_all_disabled_returns_empty_fanout() {
        let jira = JiraIntegrationConfig::default();
        let pd = PagerDutyIntegrationConfig::default();
        let linear = LinearIntegrationConfig::default();
        let og = OpsgenieIntegrationConfig::default();
        let sn = ServiceNowIntegrationConfig::default();
        let fan = build(Client::new(), &jira, &pd, &linear, &og, &sn).unwrap();
        assert!(fan.is_empty());
    }

    fn enabled_jira_config() -> JiraIntegrationConfig {
        JiraIntegrationConfig {
            enabled: true,
            base_url: "https://acme.atlassian.net/".to_owned(),
            project_key: "SEC".to_owned(),
            email: "ops@example.com".to_owned(),
            api_token: secrecy::SecretString::from("token".to_owned()),
            ..JiraIntegrationConfig::default()
        }
    }

    fn enabled_pd_config() -> PagerDutyIntegrationConfig {
        PagerDutyIntegrationConfig {
            enabled: true,
            routing_key: secrecy::SecretString::from("routing-key".to_owned()),
            ..PagerDutyIntegrationConfig::default()
        }
    }

    fn enabled_linear_config() -> LinearIntegrationConfig {
        LinearIntegrationConfig {
            enabled: true,
            api_key: secrecy::SecretString::from("linear-key".to_owned()),
            team_id: "team-uuid".to_owned(),
            ..LinearIntegrationConfig::default()
        }
    }

    fn enabled_og_config() -> OpsgenieIntegrationConfig {
        OpsgenieIntegrationConfig {
            enabled: true,
            api_key: secrecy::SecretString::from("og-api-key".to_owned()),
            ..OpsgenieIntegrationConfig::default()
        }
    }

    #[test]
    fn build_with_jira_enabled_registers_one_sink() {
        let jira = enabled_jira_config();
        let pd = PagerDutyIntegrationConfig::default();
        let linear = LinearIntegrationConfig::default();
        let og = OpsgenieIntegrationConfig::default();
        let sn = ServiceNowIntegrationConfig::default();
        let fan = build(Client::new(), &jira, &pd, &linear, &og, &sn).unwrap();
        assert_eq!(fan.len(), 1);
        assert_eq!(fan.names(), vec!["jira"]);
    }

    #[test]
    fn build_with_pagerduty_enabled_registers_one_sink() {
        let jira = JiraIntegrationConfig::default();
        let pd = enabled_pd_config();
        let linear = LinearIntegrationConfig::default();
        let og = OpsgenieIntegrationConfig::default();
        let sn = ServiceNowIntegrationConfig::default();
        let fan = build(Client::new(), &jira, &pd, &linear, &og, &sn).unwrap();
        assert_eq!(fan.len(), 1);
        assert_eq!(fan.names(), vec!["pagerduty"]);
    }

    #[test]
    fn build_with_linear_enabled_registers_one_sink() {
        let jira = JiraIntegrationConfig::default();
        let pd = PagerDutyIntegrationConfig::default();
        let linear = enabled_linear_config();
        let og = OpsgenieIntegrationConfig::default();
        let sn = ServiceNowIntegrationConfig::default();
        let fan = build(Client::new(), &jira, &pd, &linear, &og, &sn).unwrap();
        assert_eq!(fan.len(), 1);
        assert_eq!(fan.names(), vec!["linear"]);
    }

    #[test]
    fn build_with_opsgenie_enabled_registers_one_sink() {
        let jira = JiraIntegrationConfig::default();
        let pd = PagerDutyIntegrationConfig::default();
        let linear = LinearIntegrationConfig::default();
        let og = enabled_og_config();
        let sn = ServiceNowIntegrationConfig::default();
        let fan = build(Client::new(), &jira, &pd, &linear, &og, &sn).unwrap();
        assert_eq!(fan.len(), 1);
        assert_eq!(fan.names(), vec!["opsgenie"]);
    }

    #[test]
    fn build_with_all_enabled_registers_all_sinks() {
        let jira = enabled_jira_config();
        let pd = enabled_pd_config();
        let linear = enabled_linear_config();
        let og = enabled_og_config();
        let sn = ServiceNowIntegrationConfig::default();
        let fan = build(Client::new(), &jira, &pd, &linear, &og, &sn).unwrap();
        assert!(fan.len() >= 4);
        let names = fan.names();
        assert!(names.contains(&"jira"));
        assert!(names.contains(&"pagerduty"));
        assert!(names.contains(&"linear"));
        assert!(names.contains(&"opsgenie"));
    }
}
