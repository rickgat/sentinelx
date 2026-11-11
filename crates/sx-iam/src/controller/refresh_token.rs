//! `RefreshTokenUseCase` — rotate a refresh token into a fresh pair.
//!
//! Requires the presented token to be of type `Refresh`. The session id
//! is preserved; a fresh `jti` is implicit (the issuer mints a new one).
//! Callers may also bind the refresh token to its session record and
//! reject reuse — that is `sx-storage`'s responsibility.

use std::sync::Arc;
use std::time::Duration;

use time::OffsetDateTime;

use crate::domain::{TenantId, UserId};
use crate::model::claims::TokenType;
use crate::model::{AccessClaims, Session, SessionId, Token};
use crate::port::UserRepository;
use crate::service::token_issuer::IssueInput;
use crate::service::{Clock, TokenIssuer, TokenValidator};
use crate::IamError;

/// Inputs to [`RefreshTokenUseCase::execute`].
#[derive(Debug)]
pub struct RefreshTokenInput {
    /// The raw refresh JWT (no `Bearer` prefix — the caller is
    /// expected to strip the framing).
    pub refresh_token: String,
}

/// Use case: rotate a refresh token into a fresh `(access, refresh)`
/// pair.
pub struct RefreshTokenUseCase<R, V, I, C>
where
    R: UserRepository,
    V: TokenValidator,
    I: TokenIssuer,
    C: Clock,
{
    users: Arc<R>,
    validator: Arc<V>,
    issuer: Arc<I>,
    clock: Arc<C>,
    session_ttl: Duration,
}

impl<R, V, I, C> std::fmt::Debug for RefreshTokenUseCase<R, V, I, C>
where
    R: UserRepository,
    V: TokenValidator,
    I: TokenIssuer,
    C: Clock,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RefreshTokenUseCase")
            .field("session_ttl", &self.session_ttl)
            .finish()
    }
}

impl<R, V, I, C> RefreshTokenUseCase<R, V, I, C>
where
    R: UserRepository,
    V: TokenValidator,
    I: TokenIssuer,
    C: Clock,
{
    /// Build the use case.
    pub fn new(
        users: Arc<R>,
        validator: Arc<V>,
        issuer: Arc<I>,
        clock: Arc<C>,
        session_ttl: Duration,
    ) -> Self {
        Self {
            users,
            validator,
            issuer,
            clock,
            session_ttl,
        }
    }

    /// Run the use case.
    pub async fn execute(&self, input: RefreshTokenInput) -> Result<Token, IamError> {
        // Step 1: validate the refresh JWT — signature, exp, aud, iss,
        // etc. Returns AccessClaims on success.
        let claims: AccessClaims = self.validator.validate(&input.refresh_token)?;
        // Step 2: require the typ claim be Refresh (and not Access).
        if claims.token_type != TokenType::Refresh {
            tracing::warn!(sub = %claims.sub, "iam.refresh.wrong_type");
            return Err(IamError::InvalidToken);
        }
        // Step 3: re-load the user so the new token reflects the
        // current roles / permissions. The tenant lives on the claim;
        // pass it through so RLS-protected stores (e.g. Postgres) can
        // apply the tenant context before issuing the lookup.
        let user_id = parse_user_id(&claims.sub)?;
        let tenant_id = parse_tenant_id(&claims.tenant_id)?;
        let user = self
            .users
            .find_by_id_with_tenant(tenant_id, user_id)
            .await?
            .filter(|u| u.is_active)
            .ok_or(IamError::InvalidToken)?;
        // Step 4: extend the session window. We reuse the session id so
        // downstream stores can mark the old refresh as revoked under
        // the same `sid`.
        let sid = claims
            .sid
            .parse::<uuid::Uuid>()
            .map(SessionId::from_uuid)
            .map_err(|_| IamError::InvalidToken)?;
        let now: OffsetDateTime = self.clock.now();
        let session = Session {
            id: sid,
            user_id: user.id,
            tenant_id: user.tenant_id,
            issued_at: now,
            expires_at: now + self.session_ttl,
            ip: None,
            user_agent: None,
        };
        let roles: Vec<String> = user.roles.iter().map(|r| r.name.clone()).collect();
        let permissions = user.permissions();
        let issue_input = IssueInput {
            user_id: user.id.to_string(),
            tenant_id: user.tenant_id.to_string(),
            session,
            roles,
            permissions,
            cred_id: None,
        };
        let token = self.issuer.issue(&issue_input)?;
        tracing::info!(
            user_id = %user.id,
            tenant_id = %user.tenant_id,
            sid = %claims.sid,
            "iam.refresh.rotated",
        );
        Ok(token)
    }
}

fn parse_user_id(sub: &str) -> Result<UserId, IamError> {
    let u = sub
        .parse::<uuid::Uuid>()
        .map_err(|_| IamError::InvalidToken)?;
    Ok(UserId::from_uuid(u))
}

fn parse_tenant_id(tid: &str) -> Result<TenantId, IamError> {
    let u = tid
        .parse::<uuid::Uuid>()
        .map_err(|_| IamError::InvalidToken)?;
    Ok(TenantId::from_uuid(u))
}
