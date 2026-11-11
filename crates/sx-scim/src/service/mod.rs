//! Service layer: the [`provisioner::ScimProvisioner`] trait and the
//! in-memory implementation used by both unit tests and the monolith
//! adapter in dev / standalone mode.

pub mod provisioner;

pub use provisioner::{
    InMemoryScimProvisioner, ListGroupsResult, ListUsersQuery, ListUsersResult, ScimProvisioner,
};
