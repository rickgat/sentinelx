//! `sx-soar` — low-code Security Orchestration, Automation & Response
//! workflow builder.
//!
//! A SOAR [`Workflow`](workflow::Workflow) wraps a directed acyclic
//! [`WorkflowGraph`](graph::WorkflowGraph) of four node kinds:
//!
//! * [`Node::Trigger`](graph::Node::Trigger)   — entry point.
//! * [`Node::Action`](graph::Node::Action)     — invokes an
//!   [`Action`](action::Action) via the [`ActionRegistry`](action::ActionRegistry).
//! * [`Node::Condition`](graph::Node::Condition) — JSON-pointer predicate
//!   that branches the DAG.
//! * [`Node::Parallel`](graph::Node::Parallel)  — fans out to N branches
//!   and waits for the full set.
//!
//! The [`DagExecutor`](executor::DagExecutor) walks the graph in
//! topological order, evaluates branches and records a
//! [`WorkflowRun`](executor::WorkflowRun) for the operator-facing
//! execution log.
//!
//! ## MVP scope
//!
//! * Node kinds: trigger / action / condition / parallel.
//! * Action kinds: `http_request`, `run_remediation_play`, `emit_webhook`,
//!   `noop`.
//! * Sub-graph branches MUST stay shallow (no nested parallels in the
//!   MVP); validation caps node count at
//!   [`graph::MAX_NODES`].
//! * Cycle detection at validation time (Kahn topological sort).
//!
//! ## Security posture
//!
//! * `#![forbid(unsafe_code)]` is enforced crate-wide.
//! * No `unwrap`, `expect`, or `panic!` in production paths; tests opt-in
//!   via the standard workspace `#[cfg(test)]` allow-block.

#![forbid(unsafe_code)]
#![allow(
    clippy::module_name_repetitions,
    clippy::missing_errors_doc,
    clippy::missing_const_for_fn,
    clippy::option_if_let_else,
    clippy::doc_markdown,
    clippy::significant_drop_tightening,
    clippy::cognitive_complexity,
    clippy::too_many_lines,
    clippy::case_sensitive_file_extension_comparisons
)]
#![cfg_attr(
    test,
    allow(
        clippy::indexing_slicing,
        clippy::unwrap_used,
        clippy::panic,
        clippy::expect_used,
        clippy::redundant_clone,
        clippy::missing_panics_doc,
        clippy::missing_assert_message
    )
)]

pub mod action;
pub mod error;
pub mod executor;
pub mod graph;
pub mod service;
pub mod trigger;
pub mod workflow;

pub use crate::action::{Action, ActionExecutor, ActionRegistry, ActionResult, ActionStatus};
pub use crate::error::SoarError;
pub use crate::executor::{DagExecutor, WorkflowRun, WorkflowRunStatus};
pub use crate::graph::{ConditionExpr, Edge, Node, WorkflowGraph};
pub use crate::service::{AuditHook, InMemorySoarService, SoarService, WorkflowDraft};
pub use crate::trigger::{Severity, Trigger, TriggerEvent};
pub use crate::workflow::Workflow;
