//! SCIM token scoping + rotation policy (MED-005).
//!
//! SCIM bearer tokens are long-lived service-account credentials —
//! Okta / Azure AD / Google Workspace hold them for months at a time.
//! Without scoping they are *root* over a tenant's SCIM surface:
//! whoever holds the token can list, mutate, and delete every user
//! and every group. MED-005 closes that gap by giving every token an
//! explicit list of [`ScimScope`] grants. The HTTP layer enforces the
//! grants on every request (default-deny on missing scope) and the
//! adapter rejects mint requests that try to issue an empty grant.
//!
//! ## Scope grammar
//!
//! Scopes follow the OAuth-flavoured shape `scim:<resource>:<action>`:
//!
//! | Wire string           | Variant                   | Required for                                                 |
//! |-----------------------|---------------------------|--------------------------------------------------------------|
//! | `scim:users:read`     | [`ScimScope::UsersRead`]  | `GET /scim/v2/Users`, `GET /scim/v2/Users/:id`               |
//! | `scim:users:write`    | [`ScimScope::UsersWrite`] | `POST` / `PUT` / `DELETE` on `/scim/v2/Users[...]`           |
//! | `scim:groups:read`    | [`ScimScope::GroupsRead`] | `GET /scim/v2/Groups`, `GET /scim/v2/Groups/:id`             |
//! | `scim:groups:write`   | [`ScimScope::GroupsWrite`]| `POST` on `/scim/v2/Groups`                                  |
//!
//! ## Rotation policy
//!
//! Mirrors `sx_secrets::rotation::RotationPolicy` so the dashboard +
//! scheduler can share the same mental model across SCIM, threat-intel,
//! and webhook signing-key rotation. Default cadence 90 days, default
//! grace window 7 days (RFC 7644 deliberately does not standardise this
//! — we pick the same handover window every commercial SCIM client
//! defaults to).
//!
//! The grace window is **wall-clock**, not "next request": within the
//! grace both old and new tokens authenticate successfully. After the
//! grace the old token returns 401.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::Duration;
use thiserror::Error;

/// Scopes a SCIM bearer token may carry.
///
/// Scopes are bound to the token at mint time and immutable thereafter
/// — to change them the operator must rotate (or revoke + re-mint).
/// All four wire strings appear verbatim in the SCIM provisioning audit
/// row so SOC queries can pattern-match on individual permissions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScimScope {
    /// `scim:users:read` — list + fetch users.
    UsersRead,
    /// `scim:users:write` — create, replace, delete users.
    UsersWrite,
    /// `scim:groups:read` — list + fetch groups.
    GroupsRead,
    /// `scim:groups:write` — create groups (PUT/DELETE on groups not in
    /// scope for MVP per RFC 7644).
    GroupsWrite,
}

impl ScimScope {
    /// All scope variants — handy for iterating in tests + admin UIs.
    pub const ALL: &'static [Self] = &[
        Self::UsersRead,
        Self::UsersWrite,
        Self::GroupsRead,
        Self::GroupsWrite,
    ];

    /// Canonical wire string (matches OAuth-flavoured scope grammar).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UsersRead => "scim:users:read",
            Self::UsersWrite => "scim:users:write",
            Self::GroupsRead => "scim:groups:read",
            Self::GroupsWrite => "scim:groups:write",
        }
    }

    /// Parse a wire string into a [`ScimScope`]. Unknown strings yield
    /// [`ScopeParseError::Unknown`] so the mint endpoint surfaces a
    /// clear error instead of silently dropping unrecognised entries.
    ///
    /// # Errors
    ///
    /// Returns [`ScopeParseError::Unknown`] when `raw` does not match
    /// any documented scope.
    pub fn parse(raw: &str) -> Result<Self, ScopeParseError> {
        match raw {
            "scim:users:read" => Ok(Self::UsersRead),
            "scim:users:write" => Ok(Self::UsersWrite),
            "scim:groups:read" => Ok(Self::GroupsRead),
            "scim:groups:write" => Ok(Self::GroupsWrite),
            other => Err(ScopeParseError::Unknown(other.to_owned())),
        }
    }

    /// `users:write` implies `users:read`. Likewise `groups:write`
    /// implies `groups:read`. The implication is enforced at *check*
    /// time, not stored on the token — a `users:write`-only grant
    /// authorises a `GET /scim/v2/Users` call.
    #[must_use]
    pub const fn implies(self, required: Self) -> bool {
        match (self, required) {
            // Identity.
            (a, b)
                if matches!(
                    (a, b),
                    (Self::UsersRead, Self::UsersRead)
                        | (Self::UsersWrite, Self::UsersWrite)
                        | (Self::GroupsRead, Self::GroupsRead)
                        | (Self::GroupsWrite, Self::GroupsWrite)
                ) =>
            {
                true
            }
            // write ⇒ read on same resource.
            (Self::UsersWrite, Self::UsersRead) | (Self::GroupsWrite, Self::GroupsRead) => true,
            _ => false,
        }
    }
}

impl fmt::Display for ScimScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Parse error returned by [`ScimScope::parse`].
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum ScopeParseError {
    /// The string did not match any documented scope.
    #[error("unknown scope: {0}")]
    Unknown(String),
    /// The mint request supplied an empty scope list.
    #[error("at least one scope is required")]
    Empty,
}

/// Parse a list of wire scope strings into a normalised, deduplicated
/// list of [`ScimScope`].
///
/// Empty input is rejected so callers cannot accidentally mint a token
/// that authenticates but authorises nothing (default-deny is enforced
/// at check time, but minting an empty grant is almost always a bug).
///
/// # Errors
///
/// Returns [`ScopeParseError::Empty`] when `raw` is empty, and
/// [`ScopeParseError::Unknown`] on any unrecognised entry.
pub fn parse_scopes(raw: &[String]) -> Result<Vec<ScimScope>, ScopeParseError> {
    if raw.is_empty() {
        return Err(ScopeParseError::Empty);
    }
    let mut out = Vec::with_capacity(raw.len());
    for s in raw {
        let scope = ScimScope::parse(s.trim())?;
        if !out.contains(&scope) {
            out.push(scope);
        }
    }
    out.sort();
    Ok(out)
}

/// Check that `granted` contains a scope that `implies(required)`.
///
/// Walks the list (typical token has 1–4 scopes — linear scan is
/// faster than a HashSet at this size).
#[must_use]
pub fn scopes_cover(granted: &[ScimScope], required: ScimScope) -> bool {
    granted.iter().any(|s| s.implies(required))
}

/// Rotation policy for SCIM bearer tokens.
///
/// Mirrors [`sx_secrets::rotation::RotationPolicy`] in shape so the
/// scheduler can lift one rotation strategy across both subsystems.
/// `cadence` is the *issue → must-rotate-by* gap; `grace_window` is
/// the window after rotation during which the OLD token continues to
/// authenticate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScimRotationPolicy {
    /// How long a freshly-minted token is valid before it must be
    /// rotated.
    pub cadence: Duration,
    /// Window after rotation during which the previous token remains
    /// valid. Lets external SCIM agents (Okta, AAD) swap atomically.
    pub grace_window: Duration,
}

impl ScimRotationPolicy {
    /// Default cadence — 90 days. Matches CRIT-005.
    pub const DEFAULT_CADENCE: Duration = Duration::from_secs(60 * 60 * 24 * 90);

    /// Default grace window — 7 days. Aligned with Okta + AAD
    /// rotation guidance.
    pub const DEFAULT_GRACE: Duration = Duration::from_secs(60 * 60 * 24 * 7);

    /// Build the standard policy (90-day cadence, 7-day grace).
    #[must_use]
    pub const fn standard() -> Self {
        Self {
            cadence: Self::DEFAULT_CADENCE,
            grace_window: Self::DEFAULT_GRACE,
        }
    }

    /// Build an explicit policy from a TTL specified in days. Used by
    /// the admin mint endpoint when the operator overrides the default.
    #[must_use]
    pub const fn with_ttl_days(days: u32) -> Self {
        let cadence = Duration::from_secs((days as u64) * 60 * 60 * 24);
        Self {
            cadence,
            grace_window: Self::DEFAULT_GRACE,
        }
    }
}

impl Default for ScimRotationPolicy {
    fn default() -> Self {
        Self::standard()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn scope_wire_strings_are_stable() {
        assert_eq!(ScimScope::UsersRead.as_str(), "scim:users:read");
        assert_eq!(ScimScope::UsersWrite.as_str(), "scim:users:write");
        assert_eq!(ScimScope::GroupsRead.as_str(), "scim:groups:read");
        assert_eq!(ScimScope::GroupsWrite.as_str(), "scim:groups:write");
    }

    #[test]
    fn parse_roundtrips_every_variant() {
        for s in ScimScope::ALL {
            assert_eq!(ScimScope::parse(s.as_str()).unwrap(), *s);
        }
    }

    #[test]
    fn parse_rejects_unknown_scope() {
        assert!(matches!(
            ScimScope::parse("scim:secrets:write"),
            Err(ScopeParseError::Unknown(_))
        ));
    }

    #[test]
    fn parse_scopes_dedupes_and_sorts() {
        let raw = vec![
            "scim:users:write".to_owned(),
            "scim:users:read".to_owned(),
            "scim:users:write".to_owned(),
        ];
        let parsed = parse_scopes(&raw).unwrap();
        assert_eq!(parsed, vec![ScimScope::UsersRead, ScimScope::UsersWrite]);
    }

    #[test]
    fn parse_scopes_rejects_empty() {
        let raw: Vec<String> = vec![];
        assert!(matches!(parse_scopes(&raw), Err(ScopeParseError::Empty)));
    }

    #[test]
    fn parse_scopes_trims_whitespace() {
        let raw = vec!["  scim:users:read  ".to_owned()];
        assert_eq!(parse_scopes(&raw).unwrap(), vec![ScimScope::UsersRead]);
    }

    #[test]
    fn write_implies_read_same_resource() {
        assert!(ScimScope::UsersWrite.implies(ScimScope::UsersRead));
        assert!(ScimScope::GroupsWrite.implies(ScimScope::GroupsRead));
    }

    #[test]
    fn read_does_not_imply_write() {
        assert!(!ScimScope::UsersRead.implies(ScimScope::UsersWrite));
        assert!(!ScimScope::GroupsRead.implies(ScimScope::GroupsWrite));
    }

    #[test]
    fn users_scope_does_not_imply_groups() {
        assert!(!ScimScope::UsersWrite.implies(ScimScope::GroupsRead));
        assert!(!ScimScope::UsersRead.implies(ScimScope::GroupsRead));
    }

    #[test]
    fn scopes_cover_walks_granted_list() {
        let granted = vec![ScimScope::UsersWrite, ScimScope::GroupsRead];
        assert!(scopes_cover(&granted, ScimScope::UsersRead)); // via implies
        assert!(scopes_cover(&granted, ScimScope::UsersWrite));
        assert!(scopes_cover(&granted, ScimScope::GroupsRead));
        assert!(!scopes_cover(&granted, ScimScope::GroupsWrite));
    }

    #[test]
    fn scopes_cover_empty_list_denies() {
        assert!(!scopes_cover(&[], ScimScope::UsersRead));
    }

    #[test]
    fn rotation_policy_defaults_align_with_crit_005() {
        let p = ScimRotationPolicy::standard();
        assert_eq!(p.cadence.as_secs(), 90 * 24 * 60 * 60);
        assert_eq!(p.grace_window.as_secs(), 7 * 24 * 60 * 60);
        assert_eq!(ScimRotationPolicy::default(), p);
    }

    #[test]
    fn rotation_policy_with_ttl_days_scales_cadence() {
        let p = ScimRotationPolicy::with_ttl_days(30);
        assert_eq!(p.cadence.as_secs(), 30 * 24 * 60 * 60);
        // Grace window stays at the default.
        assert_eq!(p.grace_window.as_secs(), 7 * 24 * 60 * 60);
    }

    #[test]
    fn scope_serde_uses_wire_string_via_explicit_serialiser() {
        // We serialise using `as_str()` in the adapter, not serde
        // (the snake_case `serde(rename_all = "snake_case")` rename
        // would yield `users_read`, not `scim:users:read`). This test
        // pins the canonical wire string we actually emit.
        let s = ScimScope::UsersRead.to_string();
        assert_eq!(s, "scim:users:read");
    }

    #[test]
    fn scope_ordering_is_deterministic() {
        let mut all = ScimScope::ALL.to_vec();
        all.sort();
        // Variant declaration order is the canonical sort order.
        assert_eq!(
            all,
            vec![
                ScimScope::UsersRead,
                ScimScope::UsersWrite,
                ScimScope::GroupsRead,
                ScimScope::GroupsWrite,
            ]
        );
    }
}
