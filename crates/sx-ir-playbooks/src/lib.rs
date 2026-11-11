//! # sx-ir-playbooks — In-app Incident Response playbooks (P3-004 MVP).
//!
//! Implements the IR side of the security-gap remediation plan: a small
//! state-machine on top of the NIST SP 800-61 Rev 2 incident-response
//! lifecycle plus a JSON-driven catalog of pre-canned playbooks
//! (`ransomware`, `data_exfiltration`, `credential_compromise`,
//! `insider_threat`).
//!
//! ## Status — MVP complete (P3-004)
//!
//! * Crate scaffolded, NIST SP 800-61 Rev 2 phase enum, per-step and
//!   per-incident state machines with legal/illegal transition tests.
//! * Four pre-canned playbooks (ransomware, data-exfil, credential
//!   compromise, insider threat); each covers every NIST phase.
//! * `IrPlaybookService` trait + `InMemoryIrPlaybookService` adapter.
//! * `/v1/ir/playbooks`, `POST /v1/ir/incidents`,
//!   `GET /v1/ir/incidents/{id}`,
//!   `PATCH /v1/ir/incidents/{id}/steps/{step}` HTTP surface wired into
//!   `sx-api` and the `sx-monolith` composition root.
//! * `ir_incidents` + `ir_step_audit` tables shipped via timestamped
//!   migration with RLS scoped on `app_current_tenant()`.
//! * Multi-tenant isolation + audit-on-every-state-change covered by
//!   the in-crate and adapter test suites.
//!
//! ## Lifecycle phases ([`IrPhase`])
//!
//! 1. `preparation`               — readiness, comms tree, on-call.
//! 2. `detection_analysis`        — triage, scoping, evidence pulls.
//! 3. `containment_eradication_recovery` — short / long-term containment,
//!    root-cause removal, service restoration.
//! 4. `post_incident_activity`    — lessons learned, gap close-out.
//!
//! ## Domain model
//!
//! * A [`Playbook`] is an immutable template with ordered
//!   [`PlaybookStep`]s grouped per [`IrPhase`].
//! * An [`Incident`] is a *cloned* execution of a playbook — every step
//!   gets a mutable [`IncidentStep`] with an [`StepStatus`] and an
//!   optional owner.
//! * The [`incident::IncidentState`] enum models the open / in-progress /
//!   contained / closed lifecycle of an incident.
//! * Every step transition is audited via [`audit::StepAuditEntry`].
//!
//! ## Service surface
//!
//! [`service::IrPlaybookService`] is the trait the API + monolith layers
//! depend on. The in-memory implementation
//! [`service::InMemoryIrPlaybookService`] backs dev / standalone monolith
//! mode and is exercised by the integration tests.
//!
//! ## Security posture
//!
//! * `#![forbid(unsafe_code)]`.
//! * No `.unwrap()` / `.expect()` / `panic!` in non-test code.
//! * All catalog content is embedded JSON parsed at construction —
//!   tampered tenant data cannot mutate the template store.
//! * Service methods are tenant-scoped; cross-tenant reads are rejected
//!   with [`error::IrPlaybookError::NotFound`].

#![forbid(unsafe_code)]
#![deny(missing_docs)]
// Pedantic / nursery lints we deliberately tolerate inside this crate:
//
// * `module_name_repetitions` — `StepAuditEntry`, `IncidentStep` repeat
//   their parent module name and that is the established naming style.
// * `missing_const_for_fn` — domain helpers carry `String` parameters
//   (move semantics) that nightly rustc still flags as non-const eligible.
// * `too_long_first_doc_paragraph` — phase doc paragraph is intentionally
//   one prose block so it renders as a single paragraph in rustdoc.
#![allow(
    clippy::module_name_repetitions,
    clippy::missing_const_for_fn,
    clippy::too_long_first_doc_paragraph
)]
// Tests use `expect`, `expect_err`, indexing into known-non-empty
// fixtures, and `panic!` for the wrong-variant match assertions — these
// are explicitly idiomatic in this crate's unit tests but the workspace
// lints deny them in production code.
#![cfg_attr(
    test,
    allow(
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic,
        clippy::similar_names,
        clippy::unwrap_used,
        clippy::missing_panics_doc,
        clippy::missing_assert_message
    )
)]

pub mod audit;
pub mod catalog;
pub mod error;
pub mod incident;
pub mod phase;
pub mod playbook;
pub mod service;
pub mod state;

pub use crate::audit::{StepAuditEntry, StepAuditKind};
pub use crate::catalog::{
    builtin_catalog, AUDIT_CHAIN_COMPROMISE_PLAYBOOK_ID, BUILTIN_PLAYBOOK_IDS,
};
pub use crate::error::IrPlaybookError;
pub use crate::incident::{Incident, IncidentState, IncidentStep, StepStatus};
pub use crate::phase::IrPhase;
pub use crate::playbook::{Playbook, PlaybookStep};
pub use crate::service::{
    AuditChainBrokenEvent, AutoFireOutcome, InMemoryIrPlaybookService, IrPlaybookService,
    AUTO_FIRE_ACTOR, AUTO_FIRE_SEVERITY,
};
pub use crate::state::{is_legal_incident_transition, is_legal_step_transition};
