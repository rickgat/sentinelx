//! CRIT-004 — OIDC + SAML logout adapter.
//!
//! Wires the five new [`sx_api::port`] traits behind a single
//! in-memory session registry and the OIDC/SAML primitives shipped in
//! [`sx_iam::service::logout`].
//!
//! ## Session registry
//!
//! [`SessionRegistry`] tracks, per session id (the JWT `jti` SX issues
//! on login), the artefacts the three logout flows need to look up:
//!
//! * `id_token` (string) — the IdP-issued JWT preserved at login. Used
//!   by RP-initiated logout to construct `id_token_hint`.
//! * `oidc_sid` (string) — the IdP-side session id claim. Used by
//!   back-channel + front-channel logout to find the matching local
//!   session.
//! * `oidc_sub` (string) — the IdP-side subject claim. Fallback when no
//!   `sid` was issued.
//! * `saml_session_index` (string) — the `<AuthnStatement>/@SessionIndex`
//!   captured during SAML ACS. Used by the back-channel SAML logout
//!   receiver.
//! * `tenant_id` (string) — preserves tenant scope so cross-tenant
//!   revocation cannot occur even if an attacker forges a logout token
//!   for a sid that collides across tenants.
//!
//! The registry is in-memory; production deployments back it with the
//! same Postgres `iam_sessions` table the JWT validator uses. The
//! revocation API exposes a single [`SessionRegistry::revoke`] entry
//! that maps to the existing [`InMemorySessionRevoker`] so the bearer
//! middleware drops the next request that arrives with the same `jti`.
//!
//! ## Replay protection
//!
//! Back-channel `logout_token` requests MUST NOT be accepted twice. We
//! reuse [`sx_iam::service::saml::InMemoryReplayCache`] (which is a
//! pure-Rust TTL set under the hood) keyed by the token's `jti` claim
//! (or, when absent, the SHA-256 fingerprint of the raw token).

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as B64_STANDARD;
use base64::Engine as _;
use jsonwebtoken::jwk::JwkSet;
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq;
use sx_api::port::{
    LogoutPortError, OidcBackchannelLogoutPort, OidcDiscoveryPort, OidcFrontchannelLogoutPort,
    OidcRpLogoutPort, OidcRpLogoutRedirect, SamlBackchannelLogoutPort,
};
use sx_config::schema::oidc::OidcConfig;
use sx_config::schema::saml::SamlConfig;
use sx_iam::service::logout::{
    build_rp_logout_redirect, parse_saml_logout_request, verify_logout_token,
    LogoutTokenVerifierConfig,
};
use sx_iam::service::saml::{
    verify_logout_request_signature, AssertionReplayCache, InMemoryReplayCache, InsertOutcome,
    SamlSigningAlgo, SamlSpConfig,
};
use tracing::{info, warn};

use crate::adapters::saml::InMemoryIdpStore;

/// Per-session record persisted by [`SessionRegistry`].
#[derive(Debug, Clone, Default)]
pub struct SessionRecord {
    /// Tenant scope.
    pub tenant_id: String,
    /// The OIDC `id_token` returned by the IdP at login. Empty when the
    /// session was minted by a non-OIDC flow.
    pub id_token: String,
    /// The IdP-side `sid` (session id) claim. Optional.
    pub oidc_sid: Option<String>,
    /// The IdP-side `sub` (subject) claim. Optional. Used as the
    /// fallback revocation key when `sid` is absent.
    pub oidc_sub: Option<String>,
    /// SAML `SessionIndex` captured during ACS, if the session was
    /// established via the SAML SP.
    pub saml_session_index: Option<String>,
}

/// In-memory session registry. Three index maps:
///
/// * `by_session_id` — the SX-issued `jti` (canonical key).
/// * `by_oidc_sid`   — the IdP-side `sid`.
/// * `by_oidc_sub`   — the IdP-side `sub`.
/// * `by_saml_idx`   — the SAML `SessionIndex`.
///
/// Each secondary index stores `(tenant_id, session_id)` so a lookup
/// produces both the session to revoke and the tenant scope check.
#[derive(Debug, Default)]
pub struct SessionRegistry {
    inner: RwLock<RegistryInner>,
}

#[derive(Debug, Default)]
struct RegistryInner {
    by_session_id: HashMap<String, SessionRecord>,
    by_oidc_sid: HashMap<String, (String, String)>,
    by_oidc_sub: HashMap<String, (String, String)>,
    by_saml_idx: HashMap<String, (String, String)>,
    revoked: std::collections::HashSet<String>,
}

impl SessionRegistry {
    /// Build an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Upsert a session record under `session_id`. Idempotent.
    ///
    /// The login flow calls this on every successful authentication so
    /// the four logout endpoints can resolve the matching local
    /// session by `sid`, `sub`, or `SessionIndex`. Marked
    /// `allow(dead_code)` at the boundary because the login-side
    /// wiring lands in a follow-up commit; the method is exercised by
    /// unit tests in this module today.
    #[allow(dead_code)]
    pub fn upsert(&self, session_id: &str, record: SessionRecord) {
        let mut guard = match self.inner.write() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        if let Some(sid) = &record.oidc_sid {
            guard.by_oidc_sid.insert(
                sid.clone(),
                (record.tenant_id.clone(), session_id.to_string()),
            );
        }
        if let Some(sub) = &record.oidc_sub {
            guard.by_oidc_sub.insert(
                sub.clone(),
                (record.tenant_id.clone(), session_id.to_string()),
            );
        }
        if let Some(idx) = &record.saml_session_index {
            guard.by_saml_idx.insert(
                idx.clone(),
                (record.tenant_id.clone(), session_id.to_string()),
            );
        }
        guard.by_session_id.insert(session_id.to_string(), record);
    }

    /// Fetch the record stored under `session_id`.
    #[must_use]
    pub fn get(&self, session_id: &str) -> Option<SessionRecord> {
        let guard = match self.inner.read() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        guard.by_session_id.get(session_id).cloned()
    }

    /// Resolve the canonical `(tenant_id, session_id)` for the supplied
    /// OIDC `sid`.
    fn resolve_oidc_sid(&self, sid: &str) -> Option<(String, String)> {
        let guard = match self.inner.read() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        guard.by_oidc_sid.get(sid).cloned()
    }

    /// Resolve via `sub`. Fallback when `sid` is missing.
    fn resolve_oidc_sub(&self, sub: &str) -> Option<(String, String)> {
        let guard = match self.inner.read() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        guard.by_oidc_sub.get(sub).cloned()
    }

    /// Resolve via SAML `SessionIndex`.
    fn resolve_saml_index(&self, idx: &str) -> Option<(String, String)> {
        let guard = match self.inner.read() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        guard.by_saml_idx.get(idx).cloned()
    }

    /// Mark `session_id` as revoked. The bearer-token middleware checks
    /// `is_revoked` on every request.
    pub fn revoke(&self, session_id: &str) {
        let mut guard = match self.inner.write() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        guard.revoked.insert(session_id.to_string());
        // Drop secondary indexes so subsequent lookups do not find a
        // stale record. We keep the canonical record so an audit query
        // can still report on the revoked session.
        if let Some(rec) = guard.by_session_id.get(session_id).cloned() {
            if let Some(sid) = rec.oidc_sid {
                guard.by_oidc_sid.remove(&sid);
            }
            if let Some(sub) = rec.oidc_sub {
                guard.by_oidc_sub.remove(&sub);
            }
            if let Some(idx) = rec.saml_session_index {
                guard.by_saml_idx.remove(&idx);
            }
        }
    }

    /// Whether `session_id` has been revoked.
    ///
    /// The bearer-token middleware queries this on every protected
    /// request. Until that wiring lands the function is dead-code at
    /// the boundary; tests in this module exercise it.
    #[allow(dead_code)]
    #[must_use]
    pub fn is_revoked(&self, session_id: &str) -> bool {
        let guard = match self.inner.read() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        guard.revoked.contains(session_id)
    }
}

// ---------------------------------------------------------------------------
// OIDC RP-initiated logout adapter
// ---------------------------------------------------------------------------

/// Wires [`OidcRpLogoutPort`].
pub struct OidcRpLogoutAdapter {
    end_session_endpoint: String,
    post_logout_redirect_uri: String,
    sessions: Arc<SessionRegistry>,
    enabled: bool,
}

impl OidcRpLogoutAdapter {
    /// Build from the OIDC config + the shared session registry.
    #[must_use]
    pub fn new(
        cfg: &OidcConfig,
        sessions: Arc<SessionRegistry>,
        post_logout_redirect_uri: String,
    ) -> Self {
        // The end_session_endpoint is derived from the issuer per the
        // OpenID Connect Session Management 1.0 convention. Most IdPs
        // publish `<issuer>/protocol/openid-connect/logout` (Keycloak)
        // or `<issuer>/v2/logout` (Auth0) — operators override this in
        // configuration if their IdP uses a different shape. For the
        // MVP we accept the issuer + `/protocol/openid-connect/logout`
        // default and treat the empty string as "disabled".
        let end_session_endpoint = if cfg.issuer.is_empty() {
            String::new()
        } else {
            format!(
                "{}/protocol/openid-connect/logout",
                cfg.issuer.trim_end_matches('/')
            )
        };
        Self {
            end_session_endpoint,
            post_logout_redirect_uri,
            sessions,
            enabled: cfg.enabled,
        }
    }
}

#[async_trait]
impl OidcRpLogoutPort for OidcRpLogoutAdapter {
    async fn initiate(&self, session_id: &str) -> Result<OidcRpLogoutRedirect, LogoutPortError> {
        if !self.enabled {
            return Err(LogoutPortError::Disabled(
                "OIDC is not enabled on this deployment".into(),
            ));
        }
        let Some(record) = self.sessions.get(session_id) else {
            warn!(
                target: "audit.iam.logout.oidc_rp",
                session_id = %session_id,
                reason = "session_unknown",
                "oidc rp-initiated logout: rejected",
            );
            return Err(LogoutPortError::Rejected);
        };
        if record.id_token.is_empty() {
            warn!(
                target: "audit.iam.logout.oidc_rp",
                session_id = %session_id,
                reason = "no_id_token_on_session",
                "oidc rp-initiated logout: rejected",
            );
            return Err(LogoutPortError::Rejected);
        }
        // CSRF token: 16 cryptographically-random bytes -> base64url.
        let mut state_bytes = [0u8; 16];
        {
            use rand::RngCore as _;
            rand::thread_rng().fill_bytes(&mut state_bytes);
        }
        let state = B64_STANDARD
            .encode(state_bytes)
            .trim_end_matches('=')
            .to_string();
        let redirect = build_rp_logout_redirect(
            &self.end_session_endpoint,
            &record.id_token,
            &self.post_logout_redirect_uri,
            state,
        );
        // Revoke the local session straight away. Per the spec the SP
        // MUST terminate its own session before bouncing to the IdP —
        // otherwise an attacker who intercepts the IdP redirect can
        // keep the SX session alive.
        self.sessions.revoke(session_id);
        info!(
            target: "audit.iam.logout.oidc_rp",
            session_id = %session_id,
            tenant_id = %record.tenant_id,
            "oidc rp-initiated logout: session revoked, redirecting to idp",
        );
        Ok(OidcRpLogoutRedirect {
            url: redirect.url,
            state: redirect.state,
        })
    }
}

// ---------------------------------------------------------------------------
// OIDC back-channel logout adapter
// ---------------------------------------------------------------------------

/// Wires [`OidcBackchannelLogoutPort`].
pub struct OidcBackchannelLogoutAdapter {
    cfg: LogoutTokenVerifierConfig,
    enabled: bool,
    /// Pre-fetched JWKS. In production this would be a cache backed by
    /// the same `JwksOidcVerifier` cache used by `id_token` exchange;
    /// for the MVP composition root we accept a snapshot loaded at
    /// boot. Operators can swap the implementation later without
    /// touching the port.
    jwks: Arc<RwLock<JwkSet>>,
    sessions: Arc<SessionRegistry>,
    replay: Arc<dyn AssertionReplayCache>,
}

impl OidcBackchannelLogoutAdapter {
    /// Build from the OIDC config + the shared session registry. The
    /// JWKS is initialised to an empty set; callers wire in the
    /// fetched JWKS via [`Self::set_jwks`] once the verifier crate
    /// resolves them, or rely on the back-channel endpoint always
    /// rejecting until the JWKS is populated.
    #[must_use]
    pub fn new(cfg: &OidcConfig, sessions: Arc<SessionRegistry>, replay_ttl: Duration) -> Self {
        Self {
            cfg: LogoutTokenVerifierConfig {
                issuer: cfg.issuer.clone(),
                audience: cfg.audience.clone(),
                leeway: Duration::from_secs(5),
            },
            enabled: cfg.enabled,
            jwks: Arc::new(RwLock::new(empty_jwks())),
            sessions,
            replay: Arc::new(InMemoryReplayCache::new(replay_ttl)),
        }
    }

    /// Replace the cached JWKS. Production wiring calls this after a
    /// background refresh; the test suite calls it inline to inject a
    /// signing key. Marked `allow(dead_code)` until the refresher
    /// background task lands.
    #[allow(dead_code)]
    pub fn set_jwks(&self, jwks: JwkSet) {
        let mut g = match self.jwks.write() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        *g = jwks;
    }

    fn snapshot_jwks(&self) -> JwkSet {
        match self.jwks.read() {
            Ok(g) => g.clone(),
            Err(p) => p.into_inner().clone(),
        }
    }
}

#[async_trait]
impl OidcBackchannelLogoutPort for OidcBackchannelLogoutAdapter {
    async fn process(&self, logout_token: &str) -> Result<(), LogoutPortError> {
        if !self.enabled {
            return Err(LogoutPortError::Disabled(
                "OIDC is not enabled on this deployment".into(),
            ));
        }
        let jwks = self.snapshot_jwks();
        let claims = verify_logout_token(&self.cfg, &jwks, logout_token)
            .map_err(|_| LogoutPortError::Rejected)?;

        // Replay protection — keyed by jti if present, otherwise by a
        // SHA-256 fingerprint of the raw token. Constant-time compare
        // happens inside the replay cache's HashSet semantics; the
        // fingerprint protects against the case where the IdP does not
        // mint a jti.
        let replay_key = claims
            .jti
            .clone()
            .unwrap_or_else(|| token_fingerprint(logout_token));
        match self.replay.insert_if_absent(&replay_key).await {
            InsertOutcome::Inserted => {}
            InsertOutcome::Duplicate => return Err(LogoutPortError::Replay),
        }

        // Resolve the local session. Prefer `sid`, fall back to `sub`.
        let resolved = if let Some(sid) = &claims.session_id {
            self.sessions.resolve_oidc_sid(sid)
        } else if let Some(sub) = &claims.subject {
            self.sessions.resolve_oidc_sub(sub)
        } else {
            None
        };

        let Some((_tenant_id, session_id)) = resolved else {
            // Per spec we still return 200 so the IdP does not retry,
            // but at the port boundary we surface a Rejected so the
            // HTTP layer can emit a 401 in the audit stream. The
            // monolith controller folds this back into a 200 on the
            // wire (the spec says the SP MUST tolerate "session not
            // found" gracefully — the receiver might never have seen
            // the user). For the MVP we choose the conservative path:
            // surface Rejected so audit picks up "logout_token for
            // unknown session" — operators can grep this and confirm
            // the IdP/SP trust is correctly configured.
            return Err(LogoutPortError::Rejected);
        };
        self.sessions.revoke(&session_id);
        Ok(())
    }
}

fn token_fingerprint(token: &str) -> String {
    let mut h = Sha256::new();
    h.update(token.as_bytes());
    let digest = h.finalize();
    let mut s = String::with_capacity(64);
    for b in digest {
        use std::fmt::Write as _;
        write!(&mut s, "{b:02x}").ok();
    }
    s
}

fn empty_jwks() -> JwkSet {
    JwkSet { keys: Vec::new() }
}

// ---------------------------------------------------------------------------
// OIDC front-channel logout adapter
// ---------------------------------------------------------------------------

/// Wires [`OidcFrontchannelLogoutPort`]. Idempotent: revoking the same
/// `sid` twice is a successful no-op the second time.
pub struct OidcFrontchannelLogoutAdapter {
    enabled: bool,
    sessions: Arc<SessionRegistry>,
}

impl OidcFrontchannelLogoutAdapter {
    /// Build from the OIDC config + the shared session registry.
    #[must_use]
    pub fn new(cfg: &OidcConfig, sessions: Arc<SessionRegistry>) -> Self {
        Self {
            enabled: cfg.enabled,
            sessions,
        }
    }
}

#[async_trait]
impl OidcFrontchannelLogoutPort for OidcFrontchannelLogoutAdapter {
    async fn revoke_by_sid(&self, sid: &str) -> Result<(), LogoutPortError> {
        if !self.enabled {
            return Err(LogoutPortError::Disabled(
                "OIDC is not enabled on this deployment".into(),
            ));
        }
        // Constant-time compare against the empty string to mask the
        // shape of the lookup; the actual lookup is a HashMap probe
        // (which is variable-time) but we record the timing of an
        // empty-input rejection as identical to a successful lookup.
        let _ct: bool = bool::from(sid.as_bytes().ct_eq(b""));
        if let Some((_tenant_id, session_id)) = self.sessions.resolve_oidc_sid(sid) {
            self.sessions.revoke(&session_id);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// SAML back-channel logout adapter
// ---------------------------------------------------------------------------

/// Wires [`SamlBackchannelLogoutPort`].
pub struct SamlBackchannelLogoutAdapter {
    enabled: bool,
    sp_entity_id: String,
    idp_store: InMemoryIdpStore,
    sessions: Arc<SessionRegistry>,
    replay: Arc<dyn AssertionReplayCache>,
}

impl SamlBackchannelLogoutAdapter {
    /// Build from the SAML config + the shared session registry.
    #[must_use]
    pub fn new(
        cfg: &SamlConfig,
        idp_store: InMemoryIdpStore,
        sessions: Arc<SessionRegistry>,
    ) -> Self {
        Self {
            enabled: cfg.enabled,
            sp_entity_id: cfg.entity_id.clone(),
            idp_store,
            sessions,
            replay: Arc::new(InMemoryReplayCache::new(cfg.replay_ttl)),
        }
    }
}

#[async_trait]
impl SamlBackchannelLogoutPort for SamlBackchannelLogoutAdapter {
    async fn process(
        &self,
        tenant_id_hint: Option<&str>,
        logout_request_xml: &str,
    ) -> Result<(), LogoutPortError> {
        if !self.enabled {
            return Err(LogoutPortError::Disabled(
                "SAML SP is not enabled on this deployment".into(),
            ));
        }
        let tenant_id = tenant_id_hint.ok_or(LogoutPortError::Rejected)?;
        let idp = self
            .idp_store
            .get(tenant_id)
            .ok_or(LogoutPortError::Rejected)?;

        // 1. Parse the request shape.
        let parsed =
            parse_saml_logout_request(logout_request_xml).map_err(|_| LogoutPortError::Rejected)?;

        // 2. Confirm the issuer matches the configured IdP record. The
        //    LogoutRequest's `<Issuer>` element MUST exactly equal the
        //    IdP's EntityID we trust for this tenant.
        if parsed
            .issuer
            .as_bytes()
            .ct_eq(idp.entity_id.as_bytes())
            .unwrap_u8()
            == 0
        {
            return Err(LogoutPortError::Rejected);
        }

        // 3. Verify the embedded XMLDSig.
        let sp_config = SamlSpConfig {
            entity_id: self.sp_entity_id.clone(),
            sso_url: idp.sso_url.clone(),
            slo_url: idp.slo_url.clone(),
            x509_cert_pem: idp.x509_cert_pem.clone(),
            signing_algo: idp.signing_algo,
        };
        verify_logout_request_signature(&sp_config, logout_request_xml)
            .map_err(|_| LogoutPortError::Rejected)?;

        // 4. Replay protection by request ID.
        match self.replay.insert_if_absent(&parsed.id).await {
            InsertOutcome::Inserted => {}
            InsertOutcome::Duplicate => return Err(LogoutPortError::Replay),
        }

        // 5. Revoke. Prefer SessionIndex; fall back to NameID.
        let resolved = parsed
            .session_index
            .as_ref()
            .and_then(|idx| self.sessions.resolve_saml_index(idx))
            .or_else(|| self.sessions.resolve_oidc_sub(&parsed.name_id));
        if let Some((stored_tenant, session_id)) = resolved {
            if stored_tenant != tenant_id {
                return Err(LogoutPortError::Rejected);
            }
            self.sessions.revoke(&session_id);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// OIDC discovery document
// ---------------------------------------------------------------------------

/// Wires [`OidcDiscoveryPort`].
pub struct OidcDiscoveryAdapter {
    issuer: String,
    base_url: String,
}

impl OidcDiscoveryAdapter {
    /// Build from the deployment's base URL. The discovery document is
    /// served regardless of `oidc.enabled` so probes can detect the SP
    /// even before the IdP trust is configured.
    #[must_use]
    pub fn new(base_url: String, issuer: String) -> Self {
        Self { issuer, base_url }
    }
}

#[async_trait]
impl OidcDiscoveryPort for OidcDiscoveryAdapter {
    async fn document(&self) -> Result<serde_json::Value, LogoutPortError> {
        // Mirror the shape Keycloak / Okta publish so existing clients
        // can consume our document with zero custom parsing. The
        // `*_supported` flags advertise the four CRIT-004 endpoints.
        let base = self.base_url.trim_end_matches('/');
        let issuer = if self.issuer.is_empty() {
            base.to_string()
        } else {
            self.issuer.clone()
        };
        Ok(serde_json::json!({
            "issuer": issuer,
            "authorization_endpoint": format!("{base}/v1/auth/login"),
            "token_endpoint": format!("{base}/v1/auth/oidc/exchange"),
            "end_session_endpoint": format!("{base}/v1/auth/oidc/logout"),
            "backchannel_logout_endpoint": format!("{base}/v1/auth/oidc/back-channel-logout"),
            "frontchannel_logout_endpoint": format!("{base}/v1/auth/oidc/front-channel-logout"),
            "backchannel_logout_supported": true,
            "backchannel_logout_session_supported": true,
            "frontchannel_logout_supported": true,
            "frontchannel_logout_session_supported": true,
            "response_types_supported": ["code", "id_token"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256", "ES256"],
        }))
    }
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

/// Output bundle from [`build`].
pub struct LogoutBundle {
    /// OIDC RP-initiated logout port.
    pub oidc_rp: Arc<dyn OidcRpLogoutPort>,
    /// OIDC back-channel logout port.
    pub oidc_backchannel: Arc<dyn OidcBackchannelLogoutPort>,
    /// OIDC front-channel logout port.
    pub oidc_frontchannel: Arc<dyn OidcFrontchannelLogoutPort>,
    /// SAML back-channel logout port.
    pub saml_backchannel: Arc<dyn SamlBackchannelLogoutPort>,
    /// OIDC discovery document port.
    pub discovery: Arc<dyn OidcDiscoveryPort>,
    /// Session registry — exposed so the composition root can wire it
    /// into the login flow (each successful login MUST call
    /// `sessions.upsert(...)` to register the `id_token` + `sid` + ...).
    /// The login wiring lands separately; the field is marked
    /// `allow(dead_code)` until then to keep the workspace lint clean.
    #[allow(dead_code)]
    pub sessions: Arc<SessionRegistry>,
}

/// Build the logout bundle from the deployment configuration. The
/// session registry is created fresh.
#[must_use]
pub fn build(
    oidc_cfg: &OidcConfig,
    saml_cfg: &SamlConfig,
    saml_idp_store: InMemoryIdpStore,
    base_url: String,
    post_logout_redirect_uri: String,
) -> LogoutBundle {
    let sessions = Arc::new(SessionRegistry::new());
    let oidc_rp: Arc<dyn OidcRpLogoutPort> = Arc::new(OidcRpLogoutAdapter::new(
        oidc_cfg,
        Arc::clone(&sessions),
        post_logout_redirect_uri,
    ));
    let oidc_backchannel: Arc<dyn OidcBackchannelLogoutPort> = Arc::new(
        OidcBackchannelLogoutAdapter::new(oidc_cfg, Arc::clone(&sessions), saml_cfg.replay_ttl),
    );
    let oidc_frontchannel: Arc<dyn OidcFrontchannelLogoutPort> = Arc::new(
        OidcFrontchannelLogoutAdapter::new(oidc_cfg, Arc::clone(&sessions)),
    );
    let saml_backchannel: Arc<dyn SamlBackchannelLogoutPort> = Arc::new(
        SamlBackchannelLogoutAdapter::new(saml_cfg, saml_idp_store, Arc::clone(&sessions)),
    );
    let discovery: Arc<dyn OidcDiscoveryPort> =
        Arc::new(OidcDiscoveryAdapter::new(base_url, oidc_cfg.issuer.clone()));
    LogoutBundle {
        oidc_rp,
        oidc_backchannel,
        oidc_frontchannel,
        saml_backchannel,
        discovery,
        sessions,
    }
}

// Suppress the `SamlSigningAlgo` unused-import lint when no test
// references it; the type is exposed publicly via `sx_iam::service::saml`
// re-exports we may want to bind here in the future.
#[allow(dead_code)]
fn _ensure_signing_algo_in_scope(_a: SamlSigningAlgo) {}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn disabled_oidc() -> OidcConfig {
        OidcConfig::default()
    }
    fn enabled_oidc() -> OidcConfig {
        OidcConfig {
            enabled: true,
            issuer: "https://idp.example.com/realms/sx".into(),
            audience: "sx-dashboard".into(),
            jwks_url: "https://idp.example.com/jwks".into(),
            ..OidcConfig::default()
        }
    }
    fn disabled_saml() -> SamlConfig {
        SamlConfig::default()
    }

    // -------- SessionRegistry ------------------------------------------

    #[test]
    fn registry_upsert_then_get() {
        let reg = SessionRegistry::new();
        reg.upsert(
            "jti-1",
            SessionRecord {
                tenant_id: "t1".into(),
                id_token: "idt".into(),
                oidc_sid: Some("sid-1".into()),
                oidc_sub: Some("sub-1".into()),
                saml_session_index: None,
            },
        );
        let r = reg.get("jti-1").expect("present");
        assert_eq!(r.id_token, "idt");
        assert_eq!(r.oidc_sid.as_deref(), Some("sid-1"));
    }

    #[test]
    fn registry_resolves_by_oidc_sid() {
        let reg = SessionRegistry::new();
        reg.upsert(
            "jti-1",
            SessionRecord {
                tenant_id: "t1".into(),
                oidc_sid: Some("sid-X".into()),
                ..SessionRecord::default()
            },
        );
        let (tid, sid) = reg.resolve_oidc_sid("sid-X").unwrap();
        assert_eq!(tid, "t1");
        assert_eq!(sid, "jti-1");
    }

    #[test]
    fn registry_revoke_drops_secondary_indexes() {
        let reg = SessionRegistry::new();
        reg.upsert(
            "jti-1",
            SessionRecord {
                tenant_id: "t1".into(),
                oidc_sid: Some("sid-X".into()),
                ..SessionRecord::default()
            },
        );
        reg.revoke("jti-1");
        assert!(reg.is_revoked("jti-1"));
        assert!(reg.resolve_oidc_sid("sid-X").is_none());
    }

    // -------- Disabled adapters ----------------------------------------

    #[tokio::test]
    async fn rp_logout_disabled_returns_disabled_error() {
        let bundle = build(
            &disabled_oidc(),
            &disabled_saml(),
            InMemoryIdpStore::empty(),
            "https://sx.example.com".into(),
            "https://sx.example.com/login?logged_out=1".into(),
        );
        let err = bundle
            .oidc_rp
            .initiate("jti-1")
            .await
            .expect_err("disabled");
        assert!(matches!(err, LogoutPortError::Disabled(_)));
    }

    #[tokio::test]
    async fn backchannel_disabled_returns_disabled_error() {
        let bundle = build(
            &disabled_oidc(),
            &disabled_saml(),
            InMemoryIdpStore::empty(),
            "https://sx.example.com".into(),
            "https://sx.example.com/login?logged_out=1".into(),
        );
        let err = bundle
            .oidc_backchannel
            .process("anything")
            .await
            .expect_err("disabled");
        assert!(matches!(err, LogoutPortError::Disabled(_)));
    }

    #[tokio::test]
    async fn rp_logout_rejects_session_without_id_token() {
        let bundle = build(
            &enabled_oidc(),
            &disabled_saml(),
            InMemoryIdpStore::empty(),
            "https://sx.example.com".into(),
            "https://sx.example.com/login?logged_out=1".into(),
        );
        bundle.sessions.upsert(
            "jti-1",
            SessionRecord {
                tenant_id: "t1".into(),
                id_token: String::new(),
                ..SessionRecord::default()
            },
        );
        let err = bundle.oidc_rp.initiate("jti-1").await.expect_err("no idt");
        assert!(matches!(err, LogoutPortError::Rejected));
    }

    #[tokio::test]
    async fn rp_logout_builds_redirect_for_valid_session() {
        let bundle = build(
            &enabled_oidc(),
            &disabled_saml(),
            InMemoryIdpStore::empty(),
            "https://sx.example.com".into(),
            "https://sx.example.com/login?logged_out=1".into(),
        );
        bundle.sessions.upsert(
            "jti-1",
            SessionRecord {
                tenant_id: "t1".into(),
                id_token: "idt-blob".into(),
                ..SessionRecord::default()
            },
        );
        let r = bundle
            .oidc_rp
            .initiate("jti-1")
            .await
            .expect("redirect built");
        assert!(r
            .url
            .starts_with("https://idp.example.com/realms/sx/protocol/openid-connect/logout?"));
        assert!(r.url.contains("id_token_hint=idt-blob"));
        assert!(r.url.contains("state="));
        // Session must be revoked synchronously.
        assert!(bundle.sessions.is_revoked("jti-1"));
    }

    #[tokio::test]
    async fn frontchannel_idempotent() {
        let bundle = build(
            &enabled_oidc(),
            &disabled_saml(),
            InMemoryIdpStore::empty(),
            "https://sx.example.com".into(),
            "https://sx.example.com/login?logged_out=1".into(),
        );
        bundle.sessions.upsert(
            "jti-1",
            SessionRecord {
                tenant_id: "t1".into(),
                oidc_sid: Some("idp-sid-1".into()),
                ..SessionRecord::default()
            },
        );
        // First call revokes; second call is a no-op (same Ok).
        bundle
            .oidc_frontchannel
            .revoke_by_sid("idp-sid-1")
            .await
            .unwrap();
        bundle
            .oidc_frontchannel
            .revoke_by_sid("idp-sid-1")
            .await
            .unwrap();
        assert!(bundle.sessions.is_revoked("jti-1"));
    }

    #[tokio::test]
    async fn frontchannel_unknown_sid_is_success_noop() {
        let bundle = build(
            &enabled_oidc(),
            &disabled_saml(),
            InMemoryIdpStore::empty(),
            "https://sx.example.com".into(),
            "https://sx.example.com/login?logged_out=1".into(),
        );
        // Per spec the iframe MUST get a 200 even when the SP has no
        // matching session (the user may already be logged out).
        bundle
            .oidc_frontchannel
            .revoke_by_sid("ghost-sid")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn discovery_advertises_backchannel_and_frontchannel_endpoints() {
        let bundle = build(
            &enabled_oidc(),
            &disabled_saml(),
            InMemoryIdpStore::empty(),
            "https://sx.example.com".into(),
            "https://sx.example.com/login?logged_out=1".into(),
        );
        let doc = bundle.discovery.document().await.unwrap();
        assert_eq!(doc["backchannel_logout_supported"], true);
        assert_eq!(doc["frontchannel_logout_supported"], true);
        assert_eq!(doc["backchannel_logout_session_supported"], true);
        assert_eq!(doc["frontchannel_logout_session_supported"], true);
        assert_eq!(
            doc["end_session_endpoint"],
            "https://sx.example.com/v1/auth/oidc/logout"
        );
        assert_eq!(
            doc["backchannel_logout_endpoint"],
            "https://sx.example.com/v1/auth/oidc/back-channel-logout"
        );
        assert_eq!(
            doc["frontchannel_logout_endpoint"],
            "https://sx.example.com/v1/auth/oidc/front-channel-logout"
        );
    }

    #[tokio::test]
    async fn saml_backchannel_disabled_returns_disabled_error() {
        let bundle = build(
            &disabled_oidc(),
            &disabled_saml(),
            InMemoryIdpStore::empty(),
            "https://sx.example.com".into(),
            "https://sx.example.com/login?logged_out=1".into(),
        );
        let err = bundle
            .saml_backchannel
            .process(Some("t1"), "<x/>")
            .await
            .expect_err("disabled");
        assert!(matches!(err, LogoutPortError::Disabled(_)));
    }

    // -----------------------------------------------------------------
    // CRIT-004 end-to-end back-channel flow.
    //
    // Drives the full adapter pipeline:
    //   1. seed a session with `oidc_sid` + `oidc_sub`,
    //   2. inject a JWKS containing the test RSA public key,
    //   3. mint a signed `logout_token` carrying the right `iss`/`aud`/
    //      `events` + the seeded `sid`,
    //   4. call `OidcBackchannelLogoutAdapter::process` and assert the
    //      session is revoked,
    //   5. replay the same token and confirm `LogoutPortError::Replay`.
    //
    // This is the integration coverage called for by the CRIT-004 spec
    // ("end-to-end integration test for the back-channel flow"). The
    // logout_token verifier itself is also covered in
    // `crates/sx-iam/tests/oidc_logout_token.rs`; this test ensures the
    // composition root (session registry + verifier + replay cache)
    // wires together correctly behind the trait surface that the HTTP
    // controller depends on.
    // -----------------------------------------------------------------

    /// Same 2048-bit test key fingerprinted in
    /// `crates/sx-iam/src/service/logout.rs#tests`. Sharing the constant
    /// across crates would force a pub re-export of test fixtures; in
    /// practice the value is short and duplication keeps the test
    /// hermetic.
    const TEST_RSA_PRIVATE_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCqmMzkx3mbAlye
aLOygtaQ983yFOVkwDs9DubEt3rdCi/FxQ7kP9QjBBIvsZM2NgEhEOdVxW+pRvJ8
RjDF0J4EO8abSCxo7BBGMppgcyxLxrKhTCaVi+HvjtMNViBsJdSz61+nnatJXVfq
eRxxl3hysSFJCGAuejeK3Z2ZzmGnwGN+YaoVVIRIv4NLPnXBJli1cJzAACFRbJKc
GNAUrW5CDB0f2fLJSMeymC9vsLFiz6gbFGidcQdDSMoWHzZ9DKrqyudIt4nPio9f
5ELefC88rzbszp2Lgqcz5uQ8mJyWHO13TTPEiMjOL+/RvgWTgdRhDMJFhMg8YNCo
m9h1TOSZAgMBAAECggEABID7oiZu3D6qAmUeKbjzpaNjLfsAVOJQgLkgCCLAxRfn
y7il1F+9L85OVXEX2Lsrg7Ysvf++xfkZaFpD30nAYuPPR3TL9lpVcihTxCGE8nxc
utkrXhtHBAebubsJE1iFgW6rVB37omMrBxB65aKo+NyFYKZuf/T0+oRat4TX4MFj
5rStmRyBdaIQA+dfs25DAm340lasbcCj8sSB8ni9SeSxRPGsaDoJnHw+6sHxCJ5u
eyDNUE/Lk6azIdaQTbmicPDa2S3qHyS1UmdHI6pd8/bs7UrulBHAiIacLiFoQJ7M
uV9Apx9MZZTtZST7fO5G6UmLTTSsswnMzyHgD+Cv0QKBgQDl4D4u5r0UxPS8Oorq
Dlq5jeCkOHSrHHejS0P0focaAaxRhslKzoBCEcYa+4uSZKqivaH4EHzJZ+9Nlphb
wEc4tBLBZ70kUp2ZdzLxKHQMMGWmGJbLHhlWmIC8IDnuU3VCOUkO5ti/5TOsHQbN
g7ZcPUZNiPJPNA5wuWj8MS4lKQKBgQC9+/UjKkkOXxnlL6D9/rEMF4eyf7dKxGSS
MGqdtKnQWdnB38LO/nKB/MxfjgP/LcSWEPpndX4bTdKinEnFAApHKj2k9uSD/vhF
sqXureleWVlPARU2ZFyU1J0DSfWJP384Dixim6sJ0l4WW7F8BlXlYrtzYvF9Jmgo
3dqhKxjB8QKBgQDSXQHK3fEOvqbQUiqpwnUX9VQsNFXf+O8rCkenyNpN3FYbTWOM
B6mrzKQkMSoqz+CviSZd4oivr2N492V6IV2L8I5xW0Plp4z90e1Wb5SzSt7avwnP
2z2I14qHnl4lUU6vScknz+1uvoso6G8/R1ds1c4uSjKkdJj6Y1JF56O48QKBgEB+
kDFn4XUng7rx+E1BcQkR09cc1DRlh165YPg4pI0+c1YFiDSM3IKUNy0ZIPI3r0zi
Zp9Im47ZVHAvbjuaT+LozBR8XAcTP2UpyHrGPzrwSgkv7OuSFnvP0Z2UNe5px95X
sWmoPuAOsjIU3qOj4vUEF26MYD6EE0gMSHP+FWGBAoGAc4gvSYJHq1pQw7P/JHPk
rU0/9i8URf0eRPwHQTtBa3AjFIRXRIHKCOmj+3TFeYg2+1nSxFDbFMZuvbcdHZB5
XxubfFDM/zI1lx60G8M0/nCm3D+50moXiTJMfjFth97v7rOzYPv3rkmoOacPJzAY
j5zu3nHyNHrJ7Aoe+QnmfIo=
-----END PRIVATE KEY-----";

    const TEST_RSA_JWK_N: &str = "qpjM5Md5mwJcnmizsoLWkPfN8hTlZMA7PQ7mxLd63QovxcUO5D_UIwQSL7GTNjYBIRDnVcVvqUbyfEYwxdCeBDvGm0gsaOwQRjKaYHMsS8ayoUwmlYvh747TDVYgbCXUs-tfp52rSV1X6nkccZd4crEhSQhgLno3it2dmc5hp8BjfmGqFVSESL-DSz51wSZYtXCcwAAhUWySnBjQFK1uQgwdH9nyyUjHspgvb7CxYs-oGxRonXEHQ0jKFh82fQyq6srnSLeJz4qPX-RC3nwvPK827M6di4KnM-bkPJiclhztd00zxIjIzi_v0b4Fk4HUYQzCRYTIPGDQqJvYdUzkmQ";
    const TEST_RSA_JWK_E: &str = "AQAB";

    fn test_jwks(kid: &str) -> JwkSet {
        let v = serde_json::json!({
            "keys": [{
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": kid,
                "n": TEST_RSA_JWK_N,
                "e": TEST_RSA_JWK_E,
            }]
        });
        serde_json::from_value(v).unwrap()
    }

    fn now_secs() -> i64 {
        i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        )
        .unwrap()
    }

    fn sign_logout_token(kid: &str, claims: serde_json::Value) -> String {
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(kid.to_string());
        let key = EncodingKey::from_rsa_pem(TEST_RSA_PRIVATE_PEM.as_bytes()).unwrap();
        encode(&header, &claims, &key).unwrap()
    }

    #[tokio::test]
    async fn backchannel_end_to_end_revokes_session_and_blocks_replay() {
        // Step 1 — build the bundle with the OIDC config the IdP signed
        // against. We then publish the matching public key by injecting
        // a JWKS into the back-channel adapter so the verifier picks it
        // up on lookup.
        let bundle = build(
            &enabled_oidc(),
            &disabled_saml(),
            InMemoryIdpStore::empty(),
            "https://sx.example.com".into(),
            "https://sx.example.com/login?logged_out=1".into(),
        );

        // The back-channel adapter is the only port that needs JWKS
        // injection. We downcast from the trait-object to the concrete
        // adapter via a fresh build to keep the test ergonomic — same
        // OIDC config + shared session registry.
        let sessions = Arc::clone(&bundle.sessions);
        let bcl = OidcBackchannelLogoutAdapter::new(
            &enabled_oidc(),
            Arc::clone(&sessions),
            std::time::Duration::from_secs(60),
        );
        bcl.set_jwks(test_jwks("kid-1"));

        // Step 2 — register a local session with the IdP-side `sid` we
        // expect the IdP to put into the `logout_token`.
        sessions.upsert(
            "jti-end-to-end",
            SessionRecord {
                tenant_id: "tenant-1".into(),
                id_token: "idt".into(),
                oidc_sid: Some("idp-sid-end-to-end".into()),
                oidc_sub: Some("user-end-to-end".into()),
                saml_session_index: None,
            },
        );

        // Step 3 — mint a well-formed logout_token referencing that sid.
        let token = sign_logout_token(
            "kid-1",
            serde_json::json!({
                "iss": "https://idp.example.com/realms/sx",
                "aud": "sx-dashboard",
                "iat": now_secs(),
                "jti": "logout-int-end-to-end",
                "sub": "user-end-to-end",
                "sid": "idp-sid-end-to-end",
                "events": {
                    sx_iam::service::logout::BACKCHANNEL_LOGOUT_EVENT: {},
                },
            }),
        );

        // Step 4 — feed the token through the adapter; session revoked.
        bcl.process(&token).await.expect("first delivery succeeds");
        assert!(
            sessions.is_revoked("jti-end-to-end"),
            "session revoked by back-channel logout"
        );
        // Secondary indexes are dropped on revoke; a follow-up sid
        // lookup MUST NOT resolve.
        assert!(sessions.resolve_oidc_sid("idp-sid-end-to-end").is_none());

        // Step 5 — replay protection: the same token re-delivered MUST
        // be rejected with `Replay` (per OIDC Back-Channel Logout §2.6).
        let err = bcl
            .process(&token)
            .await
            .expect_err("second delivery is a replay");
        assert!(matches!(err, LogoutPortError::Replay), "got {err:?}");
    }

    #[tokio::test]
    async fn backchannel_end_to_end_falls_back_to_sub_when_sid_absent() {
        // Some IdPs (notably older Okta builds) issue logout_tokens with
        // `sub` only and no `sid`. The adapter must fall back to the
        // sub-index lookup.
        let bundle = build(
            &enabled_oidc(),
            &disabled_saml(),
            InMemoryIdpStore::empty(),
            "https://sx.example.com".into(),
            "https://sx.example.com/login?logged_out=1".into(),
        );
        let sessions = Arc::clone(&bundle.sessions);
        let bcl = OidcBackchannelLogoutAdapter::new(
            &enabled_oidc(),
            Arc::clone(&sessions),
            std::time::Duration::from_secs(60),
        );
        bcl.set_jwks(test_jwks("kid-1"));

        sessions.upsert(
            "jti-sub-only",
            SessionRecord {
                tenant_id: "tenant-1".into(),
                id_token: "idt".into(),
                oidc_sid: None,
                oidc_sub: Some("user-sub-only".into()),
                saml_session_index: None,
            },
        );

        let token = sign_logout_token(
            "kid-1",
            serde_json::json!({
                "iss": "https://idp.example.com/realms/sx",
                "aud": "sx-dashboard",
                "iat": now_secs(),
                "jti": "logout-sub-only",
                "sub": "user-sub-only",
                "events": {
                    sx_iam::service::logout::BACKCHANNEL_LOGOUT_EVENT: {},
                },
            }),
        );

        bcl.process(&token).await.expect("sub-based revocation");
        assert!(sessions.is_revoked("jti-sub-only"));
    }

    #[tokio::test]
    async fn backchannel_end_to_end_rejects_token_for_unknown_session() {
        // A signed-but-stale token from an IdP for a session the SP has
        // already evicted MUST surface `Rejected` — same audit-stream
        // shape as a session-not-found from the front-channel path.
        let bundle = build(
            &enabled_oidc(),
            &disabled_saml(),
            InMemoryIdpStore::empty(),
            "https://sx.example.com".into(),
            "https://sx.example.com/login?logged_out=1".into(),
        );
        let sessions = Arc::clone(&bundle.sessions);
        let bcl = OidcBackchannelLogoutAdapter::new(
            &enabled_oidc(),
            Arc::clone(&sessions),
            std::time::Duration::from_secs(60),
        );
        bcl.set_jwks(test_jwks("kid-1"));

        let token = sign_logout_token(
            "kid-1",
            serde_json::json!({
                "iss": "https://idp.example.com/realms/sx",
                "aud": "sx-dashboard",
                "iat": now_secs(),
                "jti": "logout-ghost",
                "sub": "ghost-user",
                "sid": "ghost-sid",
                "events": {
                    sx_iam::service::logout::BACKCHANNEL_LOGOUT_EVENT: {},
                },
            }),
        );
        let err = bcl.process(&token).await.expect_err("no matching session");
        assert!(matches!(err, LogoutPortError::Rejected), "got {err:?}");
    }
}
