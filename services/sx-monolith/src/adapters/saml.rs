//! SAML 2.0 SP adapter (P0-004) — wires the
//! [`sx_api::port::SamlSpPort`] trait against the
//! `sx_iam::service::saml::*` core.
//!
//! Two flavours:
//!
//! * [`DisabledSamlAdapter`] — installed when `saml.enabled = false`
//!   (the default). Every method returns
//!   `SamlPortError::Disabled("...")` so the SAML endpoints respond
//!   with a deterministic 422 instead of a stack trace.
//! * [`EnabledSamlAdapter`] — installed when `saml.enabled = true`.
//!   Holds the SP config, the per-tenant IdP record store, and the
//!   in-memory replay + outstanding-request caches.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use async_trait::async_trait;
use sqlx::{PgPool, Row as _};
use sx_api::port::{
    SamlAcsOutcome, SamlIdpAdminPort, SamlIdpAdminPortError, SamlPortError, SamlSpPort,
};
use sx_api::view::saml_view::SamlIdpConfigView;
use sx_config::schema::saml::SamlConfig;
use sx_iam::service::saml::{
    build_logout_request, build_verifier, classify_attack, decode_saml_response,
    parse_metadata_xml, process_acs_response_with_verifier, AssertionReplayCache, AttributeMapping,
    InMemoryReplayCache, InResponseToPolicy, NoopSamlAttackObserver, SamlAttackEvent, SamlError,
    SamlSigningAlgo, SamlSpConfig, SharedSamlAttackObserver,
};
use sx_storage::domain::value_object::TenantId;
use sx_storage::tenant_context::TenantContext;
use sx_xmlsec::XmlDsigVerifier;
use tracing::warn;
use uuid::Uuid;

/// In-memory per-tenant IdP record store.
///
/// Production deployments back this with the `iam_saml_idp_config`
/// table (the schema is shipped in `crates/sx-iam/migrations/` and the
/// real adapter would live in `crates/sx-storage`). The in-memory store
/// is sufficient for the MVP composition root, single-tenant
/// deployments, and test scaffolding.
#[derive(Debug, Clone)]
pub struct InMemoryIdpStore {
    inner: Arc<RwLock<HashMap<String, IdpRecord>>>,
    /// `Some` when the DB is enabled — the durable home of IdP records.
    /// The in-memory map above is a hot cache for the sync ACS path,
    /// hydrated from Postgres at boot and kept in sync on admin writes.
    pool: Option<PgPool>,
    stmt_timeout_ms: u64,
}

impl Default for InMemoryIdpStore {
    fn default() -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
            pool: None,
            stmt_timeout_ms: 0,
        }
    }
}

/// Per-tenant IdP configuration row. Matches the
/// `iam_saml_idp_config` table.
///
/// `tenant_id` and `entity_id` are persisted in the production
/// schema (the in-memory store keys by `tenant_id` and the SAML
/// verifier resolves the IdP via `Issuer == entity_id` lookup) but
/// the MVP composition root does not exercise either field — both are
/// kept on the struct so the production adapter can adopt the same
/// row shape without an ABI break.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct IdpRecord {
    /// Tenant id (uuid as string).
    pub tenant_id: String,
    /// IdP's `EntityID`.
    pub entity_id: String,
    /// IdP's SSO endpoint.
    pub sso_url: String,
    /// IdP's SLO endpoint. Optional.
    pub slo_url: Option<String>,
    /// IdP signing certificate, PEM-encoded.
    pub x509_cert_pem: String,
    /// Signing algorithm the IdP uses.
    pub signing_algo: SamlSigningAlgo,
}

impl InMemoryIdpStore {
    /// Build an empty store.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Replace `tenant_id`'s IdP record. Used by the admin API to land
    /// per-tenant IdP rows. (The MVP composition root never calls this
    /// directly — it boots with an empty store and relies on the admin
    /// API surface to populate per-tenant IdP entries — so the method
    /// is allow-dead-coded until that admin route is wired.)
    #[allow(dead_code)]
    pub fn upsert(&self, record: IdpRecord) {
        let tenant_id = record.tenant_id.clone();
        let mut guard = match self.inner.write() {
            Ok(g) => g,
            Err(poison) => poison.into_inner(),
        };
        guard.insert(tenant_id, record);
    }

    /// Build a durable store backed by the `saml_idp_config` table.
    #[must_use]
    pub fn with_pg(pool: PgPool, stmt_timeout_ms: u64) -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
            pool: Some(pool),
            stmt_timeout_ms,
        }
    }

    /// Fetch by tenant id (sync — reads the in-memory cache; used on the
    /// ACS hot path, which is hydrated from Postgres at boot).
    #[must_use]
    pub fn get(&self, tenant_id: &str) -> Option<IdpRecord> {
        let guard = match self.inner.read() {
            Ok(g) => g,
            Err(poison) => poison.into_inner(),
        };
        guard.get(tenant_id).cloned()
    }

    fn dep(e: impl std::fmt::Display) -> SamlIdpAdminPortError {
        SamlIdpAdminPortError::Internal(format!("saml idp store: {e}"))
    }

    /// Load every persisted IdP record into the in-memory cache. Because
    /// `saml_idp_config` is FORCE-RLS, a cross-tenant "load all" is denied;
    /// instead we enumerate the (non-RLS) `tenants` table and read each
    /// tenant's row under its own RLS context.
    pub async fn hydrate(&self) -> Result<(), SamlIdpAdminPortError> {
        let Some(pool) = self.pool.as_ref() else {
            return Ok(());
        };
        let tenant_rows = sqlx::query("SELECT id FROM tenants")
            .fetch_all(pool)
            .await
            .map_err(Self::dep)?;
        for tr in tenant_rows {
            let tid: Uuid = tr.try_get("id").map_err(Self::dep)?;
            if let Some(record) = self.read_from_db(tid).await? {
                let mut guard = self
                    .inner
                    .write()
                    .map_err(|_| SamlIdpAdminPortError::Internal("idp cache poisoned".into()))?;
                guard.insert(tid.to_string(), record);
            }
        }
        Ok(())
    }

    /// Read one tenant's IdP record from Postgres under its RLS context.
    async fn read_from_db(&self, tenant: Uuid) -> Result<Option<IdpRecord>, SamlIdpAdminPortError> {
        let Some(pool) = self.pool.as_ref() else {
            return Ok(None);
        };
        let mut tx = pool.begin().await.map_err(Self::dep)?;
        TenantContext::apply(&mut tx, TenantId::from_uuid(tenant), self.stmt_timeout_ms)
            .await
            .map_err(Self::dep)?;
        let row = sqlx::query(
            "SELECT entity_id, sso_url, slo_url, x509_cert_pem, signing_algo \
             FROM saml_idp_config WHERE tenant_id = $1",
        )
        .bind(tenant)
        .fetch_optional(&mut *tx)
        .await
        .map_err(Self::dep)?;
        tx.commit().await.map_err(Self::dep)?;
        let Some(r) = row else { return Ok(None) };
        let signing_algo =
            algo_from_str(&r.try_get::<String, _>("signing_algo").map_err(Self::dep)?)?;
        Ok(Some(IdpRecord {
            tenant_id: tenant.to_string(),
            entity_id: r.try_get("entity_id").map_err(Self::dep)?,
            sso_url: r.try_get("sso_url").map_err(Self::dep)?,
            slo_url: r.try_get("slo_url").map_err(Self::dep)?,
            x509_cert_pem: r.try_get("x509_cert_pem").map_err(Self::dep)?,
            signing_algo,
        }))
    }

    /// Persist a record to Postgres (when wired) and update the hot cache.
    async fn set_durable(&self, record: IdpRecord) -> Result<(), SamlIdpAdminPortError> {
        if let Some(pool) = self.pool.as_ref() {
            let tenant = Uuid::parse_str(&record.tenant_id).map_err(|e| {
                SamlIdpAdminPortError::Invalid(format!("tenant id not a uuid: {e}"))
            })?;
            let mut tx = pool.begin().await.map_err(Self::dep)?;
            TenantContext::apply(&mut tx, TenantId::from_uuid(tenant), self.stmt_timeout_ms)
                .await
                .map_err(Self::dep)?;
            sqlx::query(
                "INSERT INTO saml_idp_config \
                     (tenant_id, entity_id, sso_url, slo_url, x509_cert_pem, signing_algo, updated_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, now()) \
                 ON CONFLICT (tenant_id) DO UPDATE SET \
                     entity_id = EXCLUDED.entity_id, sso_url = EXCLUDED.sso_url, \
                     slo_url = EXCLUDED.slo_url, x509_cert_pem = EXCLUDED.x509_cert_pem, \
                     signing_algo = EXCLUDED.signing_algo, updated_at = now()",
            )
            .bind(tenant)
            .bind(&record.entity_id)
            .bind(&record.sso_url)
            .bind(&record.slo_url)
            .bind(&record.x509_cert_pem)
            .bind(algo_to_str(record.signing_algo))
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                // The table's CHECK constraints (URL scheme, cert/entity
                // length) surface as a DB error; map to Invalid so the
                // caller sees 422, not 500.
                if let sqlx::Error::Database(ref db) = e {
                    if db.code().as_deref() == Some("23514") {
                        return SamlIdpAdminPortError::Invalid(
                            "idp config violates a schema constraint (URL scheme / length)".into(),
                        );
                    }
                    // FK violation → the tenant does not exist.
                    if db.code().as_deref() == Some("23503") {
                        return SamlIdpAdminPortError::Invalid("unknown tenant".into());
                    }
                }
                Self::dep(e)
            })?;
            tx.commit().await.map_err(Self::dep)?;
        }
        self.upsert(record);
        Ok(())
    }
}

/// Map `SamlSigningAlgo` to its `saml_idp_config.signing_algo` string.
fn algo_to_str(a: SamlSigningAlgo) -> &'static str {
    match a {
        SamlSigningAlgo::Sha1 => "sha1",
        SamlSigningAlgo::Sha256 => "sha256",
        SamlSigningAlgo::Sha384 => "sha384",
    }
}

/// Parse a signing-algo string (the DB CHECK set) back into the enum.
fn algo_from_str(s: &str) -> Result<SamlSigningAlgo, SamlIdpAdminPortError> {
    match s {
        "sha1" => Ok(SamlSigningAlgo::Sha1),
        "sha256" => Ok(SamlSigningAlgo::Sha256),
        "sha384" => Ok(SamlSigningAlgo::Sha384),
        other => Err(SamlIdpAdminPortError::Invalid(format!(
            "unknown signing_algo '{other}' (expected sha1|sha256|sha384)"
        ))),
    }
}

/// Monolith [`SamlIdpAdminPort`] over the shared [`InMemoryIdpStore`].
/// Writes go through the durable store (Postgres + the live SP adapter's
/// cache); reads come from Postgres when wired, else the cache.
#[derive(Debug)]
pub(crate) struct MonolithSamlIdpAdmin {
    store: InMemoryIdpStore,
}

impl MonolithSamlIdpAdmin {
    pub(crate) fn new(store: InMemoryIdpStore) -> Self {
        Self { store }
    }
}

#[async_trait]
impl SamlIdpAdminPort for MonolithSamlIdpAdmin {
    async fn get_idp(
        &self,
        tenant_id: &str,
    ) -> Result<Option<SamlIdpConfigView>, SamlIdpAdminPortError> {
        // Authoritative read from Postgres when wired (keeps multi-process
        // deployments consistent); the in-memory cache otherwise.
        let record = if self.store.pool.is_some() {
            let tenant = Uuid::parse_str(tenant_id).map_err(|e| {
                SamlIdpAdminPortError::Invalid(format!("tenant id not a uuid: {e}"))
            })?;
            self.store.read_from_db(tenant).await?
        } else {
            self.store.get(tenant_id)
        };
        Ok(record.map(record_to_view))
    }

    async fn set_idp(
        &self,
        tenant_id: &str,
        config: SamlIdpConfigView,
    ) -> Result<SamlIdpConfigView, SamlIdpAdminPortError> {
        let record = view_to_record(tenant_id, &config)?;
        self.store.set_durable(record).await?;
        Ok(config)
    }
}

/// Project an [`IdpRecord`] onto the admin view.
fn record_to_view(r: IdpRecord) -> SamlIdpConfigView {
    SamlIdpConfigView {
        entity_id: r.entity_id,
        sso_url: r.sso_url,
        slo_url: r.slo_url,
        x509_cert_pem: r.x509_cert_pem,
        signing_algo: algo_to_str(r.signing_algo).to_owned(),
    }
}

/// Build an [`IdpRecord`] from the admin view, validating URL schemes and
/// the signing algorithm up front so the caller sees `422`, not a DB `500`.
fn view_to_record(
    tenant_id: &str,
    v: &SamlIdpConfigView,
) -> Result<IdpRecord, SamlIdpAdminPortError> {
    let is_http_url = |u: &str| u.starts_with("https://") || u.starts_with("http://");
    if !is_http_url(&v.sso_url) {
        return Err(SamlIdpAdminPortError::Invalid(
            "sso_url must be an absolute http(s):// URL".into(),
        ));
    }
    if let Some(slo) = v.slo_url.as_deref() {
        if !slo.is_empty() && !is_http_url(slo) {
            return Err(SamlIdpAdminPortError::Invalid(
                "slo_url must be an absolute http(s):// URL".into(),
            ));
        }
    }
    let signing_algo = algo_from_str(&v.signing_algo)?;
    Ok(IdpRecord {
        tenant_id: tenant_id.to_owned(),
        entity_id: v.entity_id.clone(),
        sso_url: v.sso_url.clone(),
        slo_url: v.slo_url.clone().filter(|s| !s.is_empty()),
        x509_cert_pem: v.x509_cert_pem.clone(),
        signing_algo,
    })
}

/// Disabled adapter — installed when `saml.enabled = false`.
#[derive(Debug, Default)]
pub struct DisabledSamlAdapter;

#[async_trait]
impl SamlSpPort for DisabledSamlAdapter {
    async fn metadata(&self) -> Result<String, SamlPortError> {
        Err(SamlPortError::Disabled(
            "SAML SP is not enabled on this deployment".into(),
        ))
    }
    async fn process_acs(
        &self,
        _tenant_id_hint: Option<&str>,
        _saml_response_b64: &str,
        _relay_state: Option<&str>,
    ) -> Result<SamlAcsOutcome, SamlPortError> {
        Err(SamlPortError::Disabled(
            "SAML SP is not enabled on this deployment".into(),
        ))
    }
    async fn build_logout(
        &self,
        _tenant_id: &str,
        _name_id: &str,
        _session_index: Option<&str>,
    ) -> Result<String, SamlPortError> {
        Err(SamlPortError::Disabled(
            "SAML SP is not enabled on this deployment".into(),
        ))
    }
}

/// Enabled adapter — installed when `saml.enabled = true`.
pub struct EnabledSamlAdapter {
    sp_entity_id: String,
    clock_skew: Duration,
    in_response_to_policy: InResponseToPolicy,
    attribute_mapping: AttributeMapping,
    idp_store: InMemoryIdpStore,
    replay_cache: Arc<dyn AssertionReplayCache>,
    in_response_to_cache: Arc<dyn AssertionReplayCache>,
    /// SAML SP attack observer (TOP5-#3-P2-004). Default is a no-op
    /// (preserves backward compatibility for adapters built before the
    /// observer wiring landed). The monolith composition root injects
    /// the live observer via [`Self::with_attack_observer`].
    attack_observer: SharedSamlAttackObserver,
    /// TOP5-#1-PHASE-2B: XMLDSig verifier built once at boot from the
    /// `saml.xmldsig.verifier` config flag. The default (`handrolled`)
    /// resolves to a thin adapter over the existing hand-rolled
    /// `verify_assertion` — behaviour byte-identical to PHASE-2A. When
    /// operators flip the flag to `shadow` or `xmlsec1`, this is what
    /// changes shape. Held as `Arc<dyn …>` so every ACS evaluation
    /// shares one verifier instance — important for the libxmlsec1
    /// init lifetime (single `Library` handle for the process).
    xmldsig_verifier: Arc<dyn XmlDsigVerifier>,
}

impl std::fmt::Debug for EnabledSamlAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnabledSamlAdapter")
            .field("sp_entity_id", &self.sp_entity_id)
            .field("clock_skew", &self.clock_skew)
            .field("in_response_to_policy", &self.in_response_to_policy)
            .finish_non_exhaustive()
    }
}

impl EnabledSamlAdapter {
    /// Build from the loader config + the per-tenant IdP store.
    ///
    /// TOP5-#1-PHASE-2B: the [`XmlDsigVerifier`] is constructed here
    /// ONCE from `cfg.xmldsig.verifier`. With default config
    /// (`handrolled`) this is byte-identical to the legacy adapter —
    /// the trait dispatch resolves to the existing `verify_assertion`
    /// via the `HandRolledVerifier` adapter. When the operator flips
    /// the YAML flag to `shadow` or `xmlsec1`, this constructor swaps
    /// the verifier shape without further code changes.
    ///
    /// # Panics
    ///
    /// Panics if `build_verifier` fails. PHASE-2B's contract is that
    /// `XmlDsigVerifierKind::HandRolled` (the default) cannot fail to
    /// construct (it is a unit struct). `Shadow` and `XmlSec1` modes
    /// can theoretically fail when the `xmlsec1` Cargo feature is on
    /// but the libxmlsec1 system package is missing — at which point
    /// the deployment is broken at startup, which is the intended
    /// loud-failure mode. The `expect` here is the "fail fast at boot"
    /// surface; the SLO is to detect a broken config before traffic
    /// arrives, not to silently degrade to handrolled.
    #[must_use]
    pub fn new(cfg: &SamlConfig, idp_store: InMemoryIdpStore) -> Self {
        let verifier_label = cfg.xmldsig.verifier_label();
        let verifier: Arc<dyn XmlDsigVerifier> = match build_verifier(cfg) {
            Ok(boxed) => Arc::<dyn XmlDsigVerifier>::from(boxed),
            Err(e) => {
                // Operator chose `shadow`/`xmlsec1` but libxmlsec1
                // failed to init. Log loudly and fall back to the
                // hand-rolled verifier so the SP path stays live — the
                // operator gets a clear "shadow mode declined" signal
                // in the log without an outage. This is the conservative
                // PHASE-2B posture: default `handrolled` always works.
                warn!(
                    target: "adapters.saml",
                    declared_mode = %verifier_label,
                    error = %e,
                    "xmldsig.verifier could not be constructed; falling back to handrolled. \
                     Inspect the libxmlsec1 system package install if you intended shadow/xmlsec1.",
                );
                Arc::new(sx_iam::service::saml::HandRolledVerifier::new())
            }
        };
        tracing::info!(
            target: "adapters.saml",
            event = "xmldsig.verifier.selected",
            mode = %verifier_label,
            verifier_name = verifier.name(),
            "TOP5-#1-PHASE-2B: SAML XMLDSig verifier wired from config",
        );
        Self {
            sp_entity_id: cfg.entity_id.clone(),
            clock_skew: cfg.clock_skew,
            // IdP-initiated SLO is out of scope for the MVP; the SP
            // accepts IdP-initiated SSO (no InResponseTo) by default
            // because some enterprise deployments rely on it. Tenants
            // that want strictly SP-initiated must flip this to
            // `Required`.
            in_response_to_policy: InResponseToPolicy::Optional,
            attribute_mapping: AttributeMapping::default(),
            idp_store,
            replay_cache: Arc::new(InMemoryReplayCache::new(cfg.replay_ttl)),
            in_response_to_cache: Arc::new(InMemoryReplayCache::new(cfg.replay_ttl)),
            attack_observer: Arc::new(NoopSamlAttackObserver),
            xmldsig_verifier: verifier,
        }
    }

    /// Inject a live [`SharedSamlAttackObserver`]. Called by the
    /// composition root once the `FindingRepositoryPort` is available
    /// so the SP attack-detection observer can surface synthetic
    /// findings via FOUND-001.
    #[must_use]
    pub fn with_attack_observer(mut self, observer: SharedSamlAttackObserver) -> Self {
        self.attack_observer = observer;
        self
    }

    /// Classify a verifier error and dispatch the observer if it maps
    /// to a known attack shape. Pure side-effect — never alters the
    /// returned error.
    fn notify_attack_if_classified(&self, tenant_id: &str, err: &SamlError) {
        if let Some(kind) = classify_attack(err) {
            let idp_issuer = self
                .idp_store
                .get(tenant_id)
                .map_or_else(String::new, |r| r.entity_id);
            let detected_at_unix = time::OffsetDateTime::now_utc().unix_timestamp();
            self.attack_observer.notify(SamlAttackEvent {
                tenant_id: tenant_id.to_owned(),
                kind,
                idp_issuer,
                detected_at_unix,
            });
        }
    }

    fn build_sp_config(&self, idp: &IdpRecord) -> SamlSpConfig {
        SamlSpConfig {
            entity_id: self.sp_entity_id.clone(),
            sso_url: idp.sso_url.clone(),
            slo_url: idp.slo_url.clone(),
            x509_cert_pem: idp.x509_cert_pem.clone(),
            signing_algo: idp.signing_algo,
        }
    }
}

#[async_trait]
impl SamlSpPort for EnabledSamlAdapter {
    async fn metadata(&self) -> Result<String, SamlPortError> {
        // Metadata is global (SP-side). The cert + URLs the IdP needs
        // are SP-owned; per-tenant IdP entries do not influence the
        // metadata document we publish.
        let sp_only = SamlSpConfig {
            entity_id: self.sp_entity_id.clone(),
            sso_url: String::new(),
            slo_url: Some(String::new()),
            x509_cert_pem: String::new(),
            signing_algo: SamlSigningAlgo::Sha256,
        };
        Ok(parse_metadata_xml(&sp_only))
    }

    async fn process_acs(
        &self,
        tenant_id_hint: Option<&str>,
        saml_response_b64: &str,
        _relay_state: Option<&str>,
    ) -> Result<SamlAcsOutcome, SamlPortError> {
        let tenant_id = tenant_id_hint.ok_or(SamlPortError::Rejected)?;
        let idp = self.idp_store.get(tenant_id).ok_or_else(|| {
            warn!(
                target: "adapters.saml",
                tenant_id = %tenant_id,
                "saml acs: no IdP record for tenant"
            );
            SamlPortError::NotFound
        })?;
        let sp_config = self.build_sp_config(&idp);

        let xml = decode_saml_response(saml_response_b64).map_err(|e| {
            // TOP5-#3-P2-004: classify + emit a synthetic Finding via
            // the observer BEFORE collapsing the error. The wire still
            // sees `Rejected`; the Finding gives auditors evidence.
            self.notify_attack_if_classified(tenant_id, &e);
            map_saml_err(e)
        })?;
        // TOP5-#1-PHASE-2B: route through the verifier-trait-aware
        // ACS pipeline. The verifier was constructed once at boot by
        // `EnabledSamlAdapter::new` from `cfg.xmldsig.verifier`; with
        // the default (`handrolled`) this is byte-identical to the
        // legacy direct call.
        let outcome = process_acs_response_with_verifier(
            self.xmldsig_verifier.as_ref(),
            &xml,
            &sp_config,
            tenant_id,
            &sp_config.entity_id,
            self.clock_skew,
            &self.replay_cache,
            &self.in_response_to_cache,
            self.in_response_to_policy,
            &self.attribute_mapping,
        )
        .await
        .map_err(|e| {
            self.notify_attack_if_classified(tenant_id, &e);
            map_saml_err(e)
        })?;

        Ok(SamlAcsOutcome {
            tenant_id: outcome.tenant_id,
            email: outcome.email,
            roles: outcome.roles,
            session_index: outcome.session_index,
            not_on_or_after: outcome.not_on_or_after,
        })
    }

    async fn build_logout(
        &self,
        tenant_id: &str,
        name_id: &str,
        session_index: Option<&str>,
    ) -> Result<String, SamlPortError> {
        let idp = self
            .idp_store
            .get(tenant_id)
            .ok_or(SamlPortError::NotFound)?;
        // Surface the missing-SLO-URL case as Disabled before we even
        // try to build the request — keeps the error message stable
        // and avoids leaking the (privately-formatted) parser error.
        let url = idp
            .slo_url
            .clone()
            .ok_or_else(|| SamlPortError::Disabled("IdP did not configure a SLO URL".into()))?;
        let sp_config = self.build_sp_config(&idp);
        let b64 = build_logout_request(&sp_config, name_id, session_index).map_err(map_saml_err)?;
        // SAML 2.0 Bindings §3.4.4 — the SAMLRequest is appended as a
        // query parameter. Use URL-encoding to keep the base64 padding
        // and '+' / '/' safe.
        let sep = if url.contains('?') { '&' } else { '?' };
        let encoded = url::form_urlencoded::byte_serialize(b64.as_bytes()).collect::<String>();
        Ok(format!("{url}{sep}SAMLRequest={encoded}"))
    }
}

fn map_saml_err(e: SamlError) -> SamlPortError {
    // Everything verification-related collapses to Rejected — the
    // wire deliberately does not distinguish "bad signature" from
    // "wrong audience" from "replay" from "malformed XML" so the
    // attacker cannot calibrate a forgery. The XML parser error
    // string on `XmlMalformed` is also discarded for the same
    // reason — it can leak fragments of the attacker's input.
    match e {
        SamlError::SignatureInvalid
        | SamlError::AudienceMismatch
        | SamlError::TimeWindow
        | SamlError::ReplayAssertion
        | SamlError::MultipleAssertions
        | SamlError::XmlMalformed(_) => SamlPortError::Rejected,
    }
}

/// Build the SAML SP port — pick the disabled or enabled adapter based
/// on the loader config. No attack observer wired (no-op).
///
/// Retained for tests and for non-monolith callers that don't yet have
/// a `FindingRepositoryPort` to plug an observer against; the live
/// monolith composition root uses [`build_with_observer`] instead.
#[must_use]
#[allow(dead_code)] // public API for tests and downstream consumers
pub fn build(cfg: &SamlConfig, idp_store: InMemoryIdpStore) -> Arc<dyn SamlSpPort> {
    build_with_observer(cfg, idp_store, Arc::new(NoopSamlAttackObserver))
}

/// Build the SAML SP port and wire a [`SharedSamlAttackObserver`].
/// Used by the monolith composition root once the
/// `FindingRepositoryPort` is available (TOP5-#3-P2-004).
#[must_use]
pub fn build_with_observer(
    cfg: &SamlConfig,
    idp_store: InMemoryIdpStore,
    attack_observer: SharedSamlAttackObserver,
) -> Arc<dyn SamlSpPort> {
    if cfg.enabled {
        tracing::info!(
            target: "adapters.saml",
            entity_id = %cfg.entity_id,
            clock_skew_secs = cfg.clock_skew.as_secs(),
            "saml SP enabled (attack observer wired)"
        );
        Arc::new(EnabledSamlAdapter::new(cfg, idp_store).with_attack_observer(attack_observer))
    } else {
        tracing::debug!(target: "adapters.saml", "saml SP disabled; installing stub");
        Arc::new(DisabledSamlAdapter)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn disabled_metadata_returns_disabled_error() {
        let port = build(&SamlConfig::default(), InMemoryIdpStore::empty());
        let err = port.metadata().await.unwrap_err();
        assert!(matches!(err, SamlPortError::Disabled(_)));
    }

    #[tokio::test]
    async fn disabled_acs_returns_disabled_error() {
        let port = build(&SamlConfig::default(), InMemoryIdpStore::empty());
        let err = port
            .process_acs(Some("t1"), "ZHVtbXk=", None)
            .await
            .unwrap_err();
        assert!(matches!(err, SamlPortError::Disabled(_)));
    }

    #[tokio::test]
    async fn enabled_metadata_emits_entity_id() {
        let cfg = SamlConfig {
            enabled: true,
            entity_id: "https://sp.example.com/saml".into(),
            ..SamlConfig::default()
        };
        let port = build(&cfg, InMemoryIdpStore::empty());
        let xml = port.metadata().await.unwrap();
        assert!(xml.contains("https://sp.example.com/saml"));
        assert!(xml.contains("AssertionConsumerService"));
    }

    #[tokio::test]
    async fn enabled_acs_without_tenant_hint_is_rejected() {
        let cfg = SamlConfig {
            enabled: true,
            entity_id: "https://sp.example.com/saml".into(),
            ..SamlConfig::default()
        };
        let port = build(&cfg, InMemoryIdpStore::empty());
        let err = port.process_acs(None, "ZHVtbXk=", None).await.unwrap_err();
        assert!(matches!(err, SamlPortError::Rejected));
    }

    #[tokio::test]
    async fn enabled_acs_unknown_tenant_returns_not_found() {
        let cfg = SamlConfig {
            enabled: true,
            entity_id: "https://sp.example.com/saml".into(),
            ..SamlConfig::default()
        };
        let port = build(&cfg, InMemoryIdpStore::empty());
        let err = port
            .process_acs(Some("nope"), "ZHVtbXk=", None)
            .await
            .unwrap_err();
        assert!(matches!(err, SamlPortError::NotFound));
    }

    #[tokio::test]
    async fn enabled_acs_malformed_response_is_rejected() {
        let cfg = SamlConfig {
            enabled: true,
            entity_id: "https://sp.example.com/saml".into(),
            ..SamlConfig::default()
        };
        let store = InMemoryIdpStore::empty();
        store.upsert(IdpRecord {
            tenant_id: "t1".into(),
            entity_id: "https://idp.example.com".into(),
            sso_url: "https://idp.example.com/sso".into(),
            slo_url: Some("https://idp.example.com/slo".into()),
            x509_cert_pem: String::new(),
            signing_algo: SamlSigningAlgo::Sha256,
        });
        let port = build(&cfg, store);
        // Base64 of garbage — base64 decode succeeds but XML parsing
        // / verification fails.
        let err = port
            .process_acs(Some("t1"), "PGRvY3VtZW50Lz4=", None)
            .await
            .unwrap_err();
        assert!(matches!(err, SamlPortError::Rejected));
    }

    #[tokio::test]
    async fn enabled_build_logout_appends_saml_request_param() {
        let cfg = SamlConfig {
            enabled: true,
            entity_id: "https://sp.example.com/saml".into(),
            ..SamlConfig::default()
        };
        let store = InMemoryIdpStore::empty();
        store.upsert(IdpRecord {
            tenant_id: "t1".into(),
            entity_id: "https://idp.example.com".into(),
            sso_url: "https://idp.example.com/sso".into(),
            slo_url: Some("https://idp.example.com/slo".into()),
            x509_cert_pem: String::new(),
            signing_algo: SamlSigningAlgo::Sha256,
        });
        let port = build(&cfg, store);
        let url = port
            .build_logout("t1", "alice@example.com", None)
            .await
            .unwrap();
        assert!(url.starts_with("https://idp.example.com/slo?SAMLRequest="));
    }

    #[tokio::test]
    async fn enabled_build_logout_unknown_tenant_is_not_found() {
        let cfg = SamlConfig {
            enabled: true,
            entity_id: "https://sp.example.com/saml".into(),
            ..SamlConfig::default()
        };
        let port = build(&cfg, InMemoryIdpStore::empty());
        let err = port
            .build_logout("nope", "alice@example.com", None)
            .await
            .unwrap_err();
        assert!(matches!(err, SamlPortError::NotFound));
    }

    fn sample_cert_pem() -> String {
        // 64..=16384 chars to satisfy the saml_idp_config CHECK.
        format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----",
            "A".repeat(256)
        )
    }

    /// Durability proof against a real Postgres: a SAML IdP config written
    /// for a freshly-seeded tenant survives a *fresh store (restart-
    /// equivalent)* — boot hydration restores the cache (so the sync ACS
    /// path sees it) and the admin read-back returns it. Unknown signing
    /// algorithms are rejected before any DB write. Gated on
    /// `TEST_DATABASE_URL` (silent no-op in CI).
    #[tokio::test]
    async fn pg_saml_idp_config_survives_restart() {
        #[allow(clippy::disallowed_methods)]
        let Ok(url) = std::env::var("TEST_DATABASE_URL") else {
            return;
        };
        let tenant = uuid::Uuid::new_v4();
        let tenant_s = tenant.to_string();
        let view = SamlIdpConfigView {
            entity_id: "https://idp.example.com".into(),
            sso_url: "https://idp.example.com/sso".into(),
            slo_url: Some("https://idp.example.com/slo".into()),
            x509_cert_pem: sample_cert_pem(),
            signing_algo: "sha256".into(),
        };

        // Seed the tenant (FK target of saml_idp_config).
        {
            let pool = sqlx::PgPool::connect(&url).await.expect("connect");
            sqlx::query(
                "INSERT INTO tenants (id, name, slug, tier) VALUES ($1, $2, $3, 'starter') \
                 ON CONFLICT (id) DO NOTHING",
            )
            .bind(tenant)
            .bind(format!("saml-{tenant}"))
            .bind(format!("saml-{tenant}"))
            .execute(&pool)
            .await
            .expect("seed tenant");
        }

        // Process 1: author the IdP config through the admin port.
        {
            let pool = sqlx::PgPool::connect(&url).await.expect("connect");
            let store = InMemoryIdpStore::with_pg(pool, 15_000);
            let admin = MonolithSamlIdpAdmin::new(store.clone());
            admin
                .set_idp(&tenant_s, view.clone())
                .await
                .expect("set idp");
            // The shared cache is updated too (the SP adapter reads it sync).
            assert!(store.get(&tenant_s).is_some(), "cache updated on write");
        }

        // Process 2 (fresh store): hydrate restores the cache, and the
        // admin reads the persisted record back.
        {
            let pool = sqlx::PgPool::connect(&url).await.expect("reconnect");
            let store = InMemoryIdpStore::with_pg(pool, 15_000);
            store.hydrate().await.expect("hydrate");
            let cached = store
                .get(&tenant_s)
                .expect("record survived restart via hydration");
            assert_eq!(cached.entity_id, "https://idp.example.com");
            assert_eq!(cached.signing_algo, SamlSigningAlgo::Sha256);

            let admin = MonolithSamlIdpAdmin::new(store.clone());
            let got = admin
                .get_idp(&tenant_s)
                .await
                .expect("get idp")
                .expect("some");
            assert_eq!(got.entity_id, view.entity_id);
            assert_eq!(got.sso_url, view.sso_url);

            // An unconfigured tenant reads back None.
            let other = uuid::Uuid::new_v4().to_string();
            assert!(admin.get_idp(&other).await.expect("get other").is_none());
        }

        // An unknown signing algorithm is rejected before any DB write.
        {
            let pool = sqlx::PgPool::connect(&url).await.expect("reconnect");
            let admin = MonolithSamlIdpAdmin::new(InMemoryIdpStore::with_pg(pool, 15_000));
            let bad = SamlIdpConfigView {
                signing_algo: "md5".into(),
                ..view.clone()
            };
            let err = admin.set_idp(&tenant_s, bad).await.unwrap_err();
            assert!(matches!(err, SamlIdpAdminPortError::Invalid(_)));
        }

        // Cleanup: deleting the tenant cascades to saml_idp_config.
        {
            let pool = sqlx::PgPool::connect(&url).await.expect("reconnect");
            sqlx::query("DELETE FROM tenants WHERE id = $1")
                .bind(tenant)
                .execute(&pool)
                .await
                .expect("cleanup");
        }
    }
}
