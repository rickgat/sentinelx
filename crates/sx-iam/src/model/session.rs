//! Server-side session record.
//!
//! A session is created on successful authentication; its id is embedded
//! into the token as `sid` so revoking the session immediately invalidates
//! every token derived from it.

use std::fmt;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::domain::{TenantId, UserId};

/// Strongly-typed session identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SessionId(Uuid);

impl SessionId {
    /// Generate a new time-ordered (v7) session id.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }

    /// Wrap an existing [`Uuid`] (used by refresh-token rotation, which
    /// preserves the session id across token rotations).
    #[must_use]
    pub fn from_uuid(id: Uuid) -> Self {
        Self(id)
    }

    /// Borrow the underlying [`Uuid`].
    #[must_use]
    pub fn as_uuid(&self) -> &Uuid {
        &self.0
    }
}

impl Default for SessionId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

/// A user's active session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Session {
    /// Session identifier (also embedded into the JWT as `sid`).
    pub id: SessionId,
    /// User who owns the session.
    pub user_id: UserId,
    /// Tenant scope.
    pub tenant_id: TenantId,
    /// When the session was created.
    pub issued_at: OffsetDateTime,
    /// When the session expires (matches `JwtConfig.refresh_ttl`).
    pub expires_at: OffsetDateTime,
    /// Client IP address (string form — accepts v4 or v6).
    pub ip: Option<String>,
    /// Browser / client user-agent string.
    pub user_agent: Option<String>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn default_session_id_is_unique() {
        assert_ne!(SessionId::default(), SessionId::default());
    }

    #[test]
    fn session_id_round_trips_json() {
        let id = SessionId::new();
        let s = serde_json::to_string(&id).unwrap();
        let back: SessionId = serde_json::from_str(&s).unwrap();
        assert_eq!(id, back);
    }
}
