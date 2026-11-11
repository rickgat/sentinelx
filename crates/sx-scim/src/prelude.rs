//! Convenience re-exports for downstream callers.

pub use crate::error::ScimError;
pub use crate::filter::{Filter, FilterOp};
pub use crate::schema::group::{GroupMember, ScimGroup};
pub use crate::schema::meta::Meta;
pub use crate::schema::user::{Email, Name, ScimUser};
pub use crate::scope::{
    parse_scopes, scopes_cover, ScimRotationPolicy, ScimScope, ScopeParseError,
};
pub use crate::service::provisioner::{
    InMemoryScimProvisioner, ListUsersQuery, ListUsersResult, ScimProvisioner,
};
