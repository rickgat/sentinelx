//! Use-case (application) layer.
//!
//! Each submodule exposes a thin, framework-free wrapper around one of
//! the domain services. The wrappers exist so that wiring code (HTTP
//! handlers, CLI commands, schedulers) only ever needs to depend on a
//! single struct per capability rather than reaching into the service
//! module's internals.

pub mod propose_pr;
pub mod share_with_network;
pub mod start_validation;
