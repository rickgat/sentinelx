//! `IssueTokenUseCase` — given an authenticated user + session, mint a
//! token pair.

use std::sync::Arc;
use std::time::Duration;

use time::OffsetDateTime;

use crate::domain::User;
use crate::model::{Session, SessionId, Token};
use crate::service::token_issuer::IssueInput;
use crate::service::{Clock, TokenIssuer};
use crate::IamError;

/// Inputs to [`IssueTokenUseCase::execute`].
#[derive(Debug)]
pub struct IssueTokenInput {
    /// The authenticated user.
    pub user: User,
    /// Client IP (optional).
    pub ip: Option<String>,
    /// Client user-agent (optional).
    pub user_agent: Option<String>,
    /// Optional credential binding (P1-002 / `WebAuthn`). When `Some`, the
    /// minted access + refresh tokens carry the `cred_id` claim so
    /// downstream services can verify the session is bound to a
    /// hardware-backed passkey. Always `None` for password / OIDC flows.
    #[allow(clippy::struct_field_names)]
    pub cred_id: Option<String>,
}

/// Output bundles the session alongside the token pair so the caller
/// can persist the session record.
#[derive(Debug)]
pub struct IssueTokenOutput {
    /// The newly-created session.
    pub session: Session,
    /// Signed (access, refresh) token pair.
    pub token: Token,
}

/// Use case: issue a token pair for an already-authenticated user.
pub struct IssueTokenUseCase<I, C>
where
    I: TokenIssuer,
    C: Clock,
{
    issuer: Arc<I>,
    clock: Arc<C>,
    session_ttl: Duration,
}

impl<I, C> std::fmt::Debug for IssueTokenUseCase<I, C>
where
    I: TokenIssuer,
    C: Clock,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IssueTokenUseCase")
            .field("session_ttl", &self.session_ttl)
            .finish()
    }
}

impl<I, C> IssueTokenUseCase<I, C>
where
    I: TokenIssuer,
    C: Clock,
{
    /// Build the use case.
    pub fn new(issuer: Arc<I>, clock: Arc<C>, session_ttl: Duration) -> Self {
        Self {
            issuer,
            clock,
            session_ttl,
        }
    }

    /// Run the use case — mint session + tokens.
    pub fn execute(&self, input: IssueTokenInput) -> Result<IssueTokenOutput, IamError> {
        let now: OffsetDateTime = self.clock.now();
        let user_id_str = input.user.id.to_string();
        let tenant_id_str = input.user.tenant_id.to_string();
        let roles: Vec<String> = input.user.roles.iter().map(|r| r.name.clone()).collect();
        let permissions = input.user.permissions();
        let session = Session {
            id: SessionId::new(),
            user_id: input.user.id,
            tenant_id: input.user.tenant_id,
            issued_at: now,
            expires_at: now + self.session_ttl,
            ip: input.ip,
            user_agent: input.user_agent,
        };
        let issue_input = IssueInput {
            user_id: user_id_str,
            tenant_id: tenant_id_str,
            session: session.clone(),
            roles,
            permissions,
            cred_id: input.cred_id,
        };
        let token = self.issuer.issue(&issue_input)?;
        Ok(IssueTokenOutput { session, token })
    }
}
