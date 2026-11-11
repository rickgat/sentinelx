//! [`Actor`] — the principal responsible for an audited action.

use serde::{Deserialize, Serialize};

use sx_core::value_object::ids::UserId;

/// Kind of principal that performed an action.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorKind {
    /// A human user, authenticated via the IAM subsystem.
    User,
    /// A non-human service principal (e.g. a worker, an integration).
    Service,
    /// The platform itself (e.g. an internal scheduler).
    System,
}

/// Principal that performed an audited action.
///
/// The [`Actor`] is captured as part of every [`crate::model::entry::AuditEntry`]
/// and is included in the hashed canonical bytes, so tampering with the
/// recorded actor is detectable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Actor {
    /// Kind of principal (user / service / system).
    pub kind: ActorKind,
    /// Identifier — for [`ActorKind::User`] this is the [`UserId`] string,
    /// for service / system principals this is an opaque tag (e.g. the
    /// service name or `"system"`).
    pub id: String,
    /// Source IP address as observed by the request boundary, if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    /// User-agent string as observed by the request boundary, if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
}

impl Actor {
    /// Construct an [`Actor`] of [`ActorKind::User`] from a [`UserId`].
    #[must_use]
    pub fn user(id: UserId) -> Self {
        Self {
            kind: ActorKind::User,
            id: id.to_string(),
            ip: None,
            user_agent: None,
        }
    }

    /// Construct an [`Actor`] of [`ActorKind::Service`] with an opaque tag.
    #[must_use]
    pub fn service(name: impl Into<String>) -> Self {
        Self {
            kind: ActorKind::Service,
            id: name.into(),
            ip: None,
            user_agent: None,
        }
    }

    /// Construct an [`Actor`] of [`ActorKind::System`].
    #[must_use]
    pub fn system() -> Self {
        Self {
            kind: ActorKind::System,
            id: "system".to_owned(),
            ip: None,
            user_agent: None,
        }
    }

    /// Attach a source IP to the actor.
    #[must_use]
    pub fn with_ip(mut self, ip: impl Into<String>) -> Self {
        self.ip = Some(ip.into());
        self
    }

    /// Attach a user-agent string to the actor.
    #[must_use]
    pub fn with_user_agent(mut self, ua: impl Into<String>) -> Self {
        self.user_agent = Some(ua.into());
        self
    }
}
