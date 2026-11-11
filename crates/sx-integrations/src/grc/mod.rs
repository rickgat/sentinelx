//! GRC (Governance / Risk / Compliance) outbound integrations.
//!
//! This module hosts the connector surface for pushing compliance
//! evidence and finding state into external GRC platforms.
//!
//! ## Layout
//!
//! * [`connector`] — the [`connector::GrcConnector`] trait every concrete
//!   connector implements, together with the connector identity enum
//!   ([`connector::GrcKind`]), the wire-shape projections of
//!   [`connector::ComplianceEvidence`] / [`connector::FindingState`], and
//!   the connector-specific error type
//!   ([`connector::ConnectorError`]).
//! * [`vanta`] — concrete Vanta REST connector calling
//!   `https://api.vanta.com` with a bearer API key.
//! * [`drata`] — placeholder connector — every method returns
//!   [`connector::ConnectorError::Unimplemented`] for now.
//! * [`servicenow`] — concrete `ServiceNow` connector hitting
//!   `/api/now/table/incident` with HTTP Basic auth.
//! * [`registry`] — maps a tenant's configured [`connector::GrcKind`] onto
//!   a concrete connector instance held inside the monolith.
//! * [`config`] — per-tenant connection rows + token resolution against
//!   an [`sx_secrets::SecretsProvider`] so API keys / passwords stay
//!   encrypted at rest.
//! * [`dispatcher`] — tenant-scoped dispatcher with exponential-backoff
//!   retry, in-memory dead-letter queue, and per-push audit emission.
//! * [`audit`] — [`audit::GrcAuditSink`] trait + recording / no-op
//!   implementations the dispatcher writes to on every push attempt.
//!
//! ## MVP scope
//!
//! * One GRC connection per tenant (enforced higher up — see the
//!   `grc_connections` table in `sx-storage`).
//! * Vanta is the production-shaped MVP connector; `ServiceNow` uses the
//!   same client wiring; Drata is intentionally a stub.
//! * Credentials handed to a connector are wrapped in
//!   [`secrecy::SecretString`] / [`secrecy::SecretBox`] so the `Debug`
//!   surface and tracing emissions never include them.
//!
//! ## Wiring
//!
//! Like the rest of [`crate`], this module stays *standalone* — the
//! monolith adapter is responsible for materialising connectors from
//! tenant credentials and dispatching evidence + finding pushes through
//! the trait surface.

pub mod audit;
pub mod config;
pub mod connector;
pub mod dispatcher;
pub mod drata;
pub mod registry;
pub mod servicenow;
pub mod vanta;

pub use audit::{
    GrcAuditEvent, GrcAuditOutcome, GrcAuditResource, GrcAuditSink, NoopAuditSink,
    RecordingAuditSink,
};
pub use config::{
    load_secret, ConfigError, GrcConfigStore, GrcConnectionConfig, InMemoryGrcConfigStore,
};
pub use connector::{
    ComplianceEvidence, ConnectorError, FindingState, GrcConnector, GrcKind, PushOutcome,
    ServiceNowCredentials, VantaCredentials,
};
pub use dispatcher::{
    Clock, DeadLetter, FixedClock, GrcDeadLetterQueue, GrcDispatcher, RetryConfig, Sleeper,
    SystemClock, TokioSleeper,
};
pub use drata::DrataConnector;
pub use registry::GrcConnectorRegistry;
pub use servicenow::ServiceNowConnector;
pub use vanta::VantaConnector;
