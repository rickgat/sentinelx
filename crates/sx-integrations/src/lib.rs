//! # `sx-integrations`
//!
//! Outbound integrations for `SentinelX`. Five adapter families live
//! here:
//!
//! * [`siem`] — forwarders that ship audit events to external SIEM
//!   platforms. Today: Splunk HEC over HTTP and a generic Syslog/CEF
//!   UDP sink.
//! * [`jira`] — a thin HTTP client for the Jira Cloud REST API capable of
//!   filing issues for `SentinelX` findings.
//! * [`chat`] — Slack (Block Kit) and Microsoft Teams (Adaptive Card)
//!   webhook notifiers behind a common [`chat::ChatNotifier`] trait.
//! * [`grc`] — Governance / Risk / Compliance connectors (Vanta, Drata,
//!   `ServiceNow`) for pushing compliance evidence and finding state into
//!   external GRC platforms.
//! * [`bugbounty`] — HackerOne + Bugcrowd bridge. Outbound: push triaged
//!   SentinelX findings (severity ≥ HIGH) as draft *internal* program
//!   notes (never public reports). Inbound: ingest researcher reports
//!   posted to `POST /v1/integrations/bugbounty/inbound/{platform}`,
//!   verify HMAC-SHA256 signature (constant-time), map to a canonical
//!   finding tagged `bugbounty.<platform>.researcher_<id>`, and dedupe
//!   against existing findings via TF-IDF cosine ≥ 0.85.
//! * [`incident_sink`] — TOP5-#5 ticketing + alerting framework. Declares
//!   the [`IncidentSinkPort`] trait and the shared event / receipt /
//!   error taxonomy consumed by every incident sink. Two reference
//!   adapters land alongside it: [`jira_incident`] (Jira Cloud REST v3)
//!   and [`pagerduty`] (Events API v2). [`opsgenie`] (Alerts API v2)
//!   ships as `TOP5-#5-FU3`. Two follow-up vendors (ServiceNow, Linear)
//!   remain tracked as `TOP5-#5-FU1` / `FU2`.
//!
//! Every SIEM/Jira adapter shares the [`error::IntegrationError`] surface
//! in [`error`]. Chat notifiers carry their own [`chat::ChatError`]
//! because the chat surface needs `InvalidConfig` for malformed webhook
//! URLs.
//!
//! ## Quality & safety
//!
//! * `#![forbid(unsafe_code)]`.
//! * All bearer/token credentials *and webhook URLs* are wrapped in
//!   [`secrecy::SecretString`] and the per-type `Debug` impls redact
//!   them.
//! * Tracing emits structured events for *what happened* and *how long it
//!   took* — never the token, the basic-auth header, the webhook URL,
//!   or any other secret value.
//!
//! ## Wiring
//!
//! This crate is intentionally *standalone*: it is not yet plumbed into
//! `sx-monolith`. Consumers construct the adapters directly and call them
//! from whichever pipeline (audit shipping, finding triage, chat
//! alerting, ...) needs the outbound integration.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
// Vendor / product names (`HackerOne`, `Bugcrowd`, `SentinelX`, …) appear
// in many doc strings; backticking every occurrence pollutes prose without
// adding precision, and the platform docs treat the bare names as the
// canonical spelling. Other adapter crates (`sx-twin`, `sx-scim`,
// `sx-cloud`, `sx-bas`, `sx-log-ingest`) already disable the lint at the
// crate root for the same reason.
#![allow(clippy::doc_markdown)]

pub mod bugbounty;
pub mod chat;
pub mod error;
pub mod grc;
pub mod incident_sink;
pub mod jira;
pub mod jira_incident;
pub mod linear;
pub mod opsgenie;
pub mod pagerduty;
pub mod servicenow;
pub mod siem;

pub use crate::chat::slack::{SlackWebhookConfig, SlackWebhookNotifier};
pub use crate::chat::teams::{TeamsAdaptiveCardNotifier, TeamsWebhookConfig};
pub use crate::chat::{
    compute_slack_signature_hex, load_signing_secret, load_webhook_url, parse_slash_command,
    verify_slack_signature, ChatAlert, ChatAuditDirection, ChatAuditEvent, ChatAuditOutcome,
    ChatAuditProvider, ChatAuditSink, ChatChannelConfig, ChatConfigError, ChatConfigStore,
    ChatDispatcher, ChatError, ChatNotifier, ChatSeverity, DispatchOutcome, DispatcherConfig,
    InMemoryChatConfigStore, InboundError, NoopChatAuditSink, NoopNotifier, RecordingChatAuditSink,
    RecordingNotifier, SlackCommand,
};
pub use crate::error::IntegrationError;
pub use crate::grc::{
    load_secret, Clock, ComplianceEvidence, ConfigError, ConnectorError, DeadLetter,
    DrataConnector, FindingState, FixedClock, GrcAuditEvent, GrcAuditOutcome, GrcAuditResource,
    GrcAuditSink, GrcConfigStore, GrcConnectionConfig, GrcConnector, GrcConnectorRegistry,
    GrcDeadLetterQueue, GrcDispatcher, GrcKind, InMemoryGrcConfigStore, NoopAuditSink, PushOutcome,
    RecordingAuditSink, RetryConfig, ServiceNowConnector, ServiceNowCredentials, Sleeper,
    SystemClock, TokioSleeper, VantaConnector, VantaCredentials,
};
pub use crate::incident_sink::{
    parse_retry_after_secs, EmissionReceipt, FindingDigest, IncidentEvent, IncidentKind,
    IncidentSinkError, IncidentSinkPort,
};
pub use crate::jira_incident::{
    severity_label as jira_incident_severity_label,
    severity_priority_hint as jira_incident_severity_priority_hint, JiraAuth, JiraIncidentSink,
};
pub use crate::linear::{
    severity_priority as linear_severity_priority, LinearIncidentSink, ISSUE_CREATE_MUTATION,
};
pub use crate::opsgenie::{OpsgenieIncidentSink, OpsgeniePriority};
pub use crate::pagerduty::{PagerDutyIncidentSink, PagerDutySeverity};
pub use crate::servicenow::{
    severity_impact_urgency as servicenow_severity_impact_urgency, ServiceNowIncidentSink,
};
