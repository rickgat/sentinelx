//! Risk-Based Authentication adapter — wires `sx_rba::RbaService`
//! behind the [`sx_api::port::RbaPort`] trait.
//!
//! The adapter holds a single shared [`RbaService`] (the engine is
//! internally `Arc`-clone-cheap) and translates between:
//!
//! * the wire-shape `Rba*View` DTOs consumed by the HTTP controllers,
//! * the in-process `sx_rba::LoginContext` / `RbaConfig` types the
//!   engine works with.
//!
//! The adapter is also wired into the IAM `AuthnAdapter` (see
//! `iam.rs::AuthnAdapter::set_rba`) so every successful credential
//! match consults the engine BEFORE a JWT is issued. Failures from the
//! engine are logged and translated to fail-open in the login path —
//! a transient engine fault must never lock every user out.
//!
//! ## IP parsing
//!
//! The login flow hands us an IP as a string (best-effort, may be
//! empty or IPv6). The MVP geo table covers IPv4 only; anything that
//! does not parse falls back to the `0.0.0.0` sentinel which the geo
//! table resolves to `??` (unknown), pushing the IP signal towards the
//! step-up bucket — exactly what we want when the platform cannot
//! identify the caller.

use std::net::Ipv4Addr;
use std::sync::Arc;

use async_trait::async_trait;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use sx_api::port::{
    FindingRepositoryPort, RbaActionWire, RbaEvaluateInput, RbaEvaluateOutput, RbaPort,
    RbaPortError,
};
use sx_api::view::finding_view::FindingView;
use sx_api::view::rba_view::{
    KnownDeviceView, KnownDevicesResponse, RbaConfigView, RbaDecisionView, RbaFeatureFlagsView,
    RbaWeightsView, SignalContributionView,
};
use sx_config::schema::RbaFindingEmissionConfig;
use sx_rba::config::RbaWeights;
use sx_rba::finding::{block_decision_description, RBA_HIGH_RISK_BLOCK_DOTTED};
use sx_rba::scorer::rule_based::RuleBasedScorer;
use sx_rba::service::{LoginContext, RbaAction, RbaDecision, RbaService};
use sx_rba::signals::business_hours::BusinessHours;
use sx_rba::signals::device_fp::{DeviceFingerprintStore, MemDeviceFingerprintLedger};
use sx_rba::signals::device_fp_pg::PgDeviceFingerprintLedger;
use sx_rba::signals::impossible_travel::{MemTravelStore, TravelStore};
use sx_rba::signals::travel_pg::PgTravelStore;
use sx_rba::{RbaConfig, SignalContribution};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use uuid::Uuid;

/// Concrete adapter holding the shared [`RbaService`].
///
/// TOP5-#3-P2-005 adds the optional `findings` + `finding_emission`
/// wiring: when emission is enabled in `sx-config` AND a `Block`
/// decision's composite score breaches the operator-set threshold, the
/// adapter projects the decision onto a synthetic [`FindingView`] and
/// calls [`FindingRepositoryPort::insert`]. Allow/StepUpMfa decisions
/// stay decision-only. Both fields are `Option` so callers that don't
/// care about emission (the existing tests, the `build()` ctor) get
/// back-compatible "emission disabled" semantics for free.
#[derive(Clone)]
pub(crate) struct RbaAdapter {
    svc: RbaService,
    /// Sink for synthetic findings. `None` when emission is disabled or
    /// the adapter is constructed via the back-compat `new()` ctor.
    findings: Option<Arc<dyn FindingRepositoryPort>>,
    /// Resolved emission settings. Defaults to "disabled" when emission
    /// wiring is absent; constructors that take a config pin this to
    /// the operator-supplied value.
    emission: RbaFindingEmissionConfig,
}

impl std::fmt::Debug for RbaAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RbaAdapter").finish_non_exhaustive()
    }
}

impl RbaAdapter {
    /// Build an adapter wrapping a fresh [`RbaService`] backed by the
    /// default rule-based scorer + embedded geo table + in-memory
    /// device fingerprint ledger + in-memory travel-last-sighting
    /// ledger.
    ///
    /// Used by tests (and by the composition root when Postgres is not
    /// configured). Production composition with a live `PgPool` calls
    /// [`Self::new_with_pg`] instead so both persistent ledgers survive
    /// process restarts.
    pub(crate) fn new() -> Self {
        Self::with_travel_store(Arc::new(MemTravelStore::new()))
    }

    /// Build an adapter with an explicit [`TravelStore`]. The
    /// composition root passes a [`PgTravelStore`] in production so
    /// the last-sighting ledger survives a restart of `sx-monolith`
    /// (LOW-005). Device-fingerprint store defaults to in-memory.
    pub(crate) fn with_travel_store(travel: Arc<dyn TravelStore>) -> Self {
        Self {
            svc: RbaService::with_travel_store(travel),
            findings: None,
            emission: RbaFindingEmissionConfig::default(),
        }
    }

    /// Install the synthetic-finding emission wiring (TOP5-#3-P2-005).
    ///
    /// Hands the adapter a sink for [`FindingRepositoryPort::insert`] and
    /// the operator-supplied emission settings. Calling this method
    /// without `emission.enabled = true` is harmless: the gating check
    /// in [`Self::maybe_emit_block_finding`] short-circuits.
    pub(crate) fn with_finding_emission(
        mut self,
        findings: Arc<dyn FindingRepositoryPort>,
        emission: RbaFindingEmissionConfig,
    ) -> Self {
        self.findings = Some(findings);
        self.emission = emission;
        self
    }

    /// Build an adapter whose device-fingerprint store is the
    /// Postgres-backed [`PgDeviceFingerprintLedger`] (LOW-004) and
    /// whose travel-last-sighting store remains in-memory. Kept for
    /// callers that only need the LOW-004 wiring; production code
    /// should prefer [`Self::new_with_pg`].
    #[allow(dead_code)]
    pub(crate) fn new_with_pg_ledger(pool: PgPool) -> Self {
        let store: Arc<dyn DeviceFingerprintStore> = Arc::new(PgDeviceFingerprintLedger::new(pool));
        Self {
            svc: RbaService::with_scorer_and_fingerprints(Arc::new(RuleBasedScorer), store),
            findings: None,
            emission: RbaFindingEmissionConfig::default(),
        }
    }

    /// Build the full production adapter: both the device-fingerprint
    /// ledger (LOW-004) AND the impossible-travel last-sighting ledger
    /// (LOW-005) backed by Postgres. This is the production composition
    /// root entry point — both ledgers survive `sx-monolith` restarts.
    pub(crate) fn new_with_pg(pool: PgPool) -> Self {
        let fingerprints: Arc<dyn DeviceFingerprintStore> =
            Arc::new(PgDeviceFingerprintLedger::new(pool.clone()));
        let travel: Arc<dyn TravelStore> = Arc::new(PgTravelStore::new(pool));
        Self {
            svc: RbaService::with_scorer_and_stores(
                Arc::new(RuleBasedScorer),
                fingerprints,
                travel,
            ),
            findings: None,
            emission: RbaFindingEmissionConfig::default(),
        }
    }

    /// Build an adapter with a caller-supplied device fingerprint store.
    /// Used both by tests that want an in-memory ledger via the trait
    /// surface, and by any future production wiring that needs a
    /// non-default scorer alongside the Pg ledger.
    #[allow(dead_code)]
    pub(crate) fn new_with_store(store: Arc<dyn DeviceFingerprintStore>) -> Self {
        Self {
            svc: RbaService::with_scorer_and_fingerprints(Arc::new(RuleBasedScorer), store),
            findings: None,
            emission: RbaFindingEmissionConfig::default(),
        }
    }

    /// Borrow the inner service — used by integration tests.
    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn service(&self) -> &RbaService {
        &self.svc
    }

    /// TOP5-#3-P2-005 post-process hook: surface a high-risk `Block`
    /// decision as a synthetic Finding.
    ///
    /// Emission gating (all must hold; any miss returns silently):
    ///
    /// 1. `self.findings` is wired (composition root opted in).
    /// 2. `self.emission.enabled = true`.
    /// 3. `decision.action == RbaAction::Block`.
    /// 4. `decision.score >= self.emission.block_threshold_score`.
    ///
    /// Idempotency: the synthetic finding id is the SHA-256 hash of
    /// `(tenant_id, user_id_or_email, day_bucket)` truncated to 16
    /// bytes and projected onto a UUID. A user repeatedly tripping the
    /// threshold within one UTC day produces exactly one Finding
    /// because the in-memory [`super::repository::InMemoryFindings`]
    /// last-write-wins on key collision and the Postgres adapter does
    /// `ON CONFLICT (id) DO NOTHING RETURNING …`.
    ///
    /// Failures from the finding sink are logged at WARN level but never
    /// propagated — an RBA decision MUST NOT fail because the SOC
    /// pipeline is back-pressured (fail-open mirrors the existing
    /// engine-fault discipline in this adapter's preamble).
    async fn maybe_emit_block_finding(&self, decision: &RbaDecision, identity_key: &str) {
        // Cheap fail-fast checks first so the hot path is one
        // pointer-deref + two compares for the disabled case.
        if !self.emission.enabled {
            return;
        }
        if decision.action != RbaAction::Block {
            return;
        }
        let threshold_score = i32::from(self.emission.block_threshold_score);
        if decision.score < threshold_score {
            return;
        }
        let Some(sink) = self.findings.as_ref() else {
            return;
        };

        let finding_id = synthetic_finding_id(decision, identity_key);
        let detected_at_str = decision
            .decided_at
            .format(&Rfc3339)
            .unwrap_or_else(|_| String::new());
        let description = block_decision_description(decision, self.emission.block_threshold_score);
        let confidence = f64::from(decision.score) / 100.0;
        // TOP5-#3 Phase 3: emit dotted-form ids everywhere; the alias
        // map on the receive side keeps external consumers who pinned
        // the legacy colon-form working.
        let metadata = serde_json::json!({
            "engagement_id": self.emission.system_engagement_id,
            "rule_id": RBA_HIGH_RISK_BLOCK_DOTTED,
            "check_id": RBA_HIGH_RISK_BLOCK_DOTTED,
            "confidence": confidence,
            "rba": {
                "score": decision.score,
                "threshold": self.emission.block_threshold_score,
                "tenant_id": decision.tenant_id.to_string(),
                "user_id": decision.user_id.map(|u| u.to_string()),
                "ip": decision.ip.to_string(),
                "reason": decision.reason.clone(),
            },
        });
        let view = FindingView {
            id: finding_id.to_string(),
            tenant_id: decision.tenant_id.to_string(),
            asset_id: self.emission.system_asset_id.clone(),
            severity: "critical".to_owned(),
            status: "open".to_owned(),
            title: "Risk-based authentication blocked sign-in".to_owned(),
            description,
            cvss: None,
            cve_id: None,
            first_seen: detected_at_str.clone(),
            last_seen: detected_at_str,
            metadata: Some(metadata),
        };
        match sink.insert(view).await {
            Ok(persisted) => {
                tracing::info!(
                    target: "sx_rba.finding_emission",
                    finding_id = %persisted.id,
                    tenant_id = %decision.tenant_id,
                    score = decision.score,
                    threshold = self.emission.block_threshold_score,
                    "rba block surfaced as synthetic finding",
                );
            }
            Err(e) => {
                // Fail-open: the decision still returns to the caller.
                tracing::warn!(
                    target: "sx_rba.finding_emission",
                    error = %e,
                    tenant_id = %decision.tenant_id,
                    score = decision.score,
                    "rba block finding emission failed",
                );
            }
        }
    }
}

/// Compute the idempotency-keyed synthetic finding id.
///
/// Inputs hashed in order: tenant uuid bytes, identity key (user uuid as
/// string when known, else lowercased email), and the UTC day bucket
/// (`yyyy-mm-dd` from `decision.decided_at`). SHA-256, first 16 bytes
/// becomes the UUID. We mask in v4 + RFC 4122 variant bits so the
/// resulting UUID is well-formed regardless of what bytes the digest
/// produces — the Postgres `findings.id PRIMARY KEY` only requires a
/// valid UUID, not a specific version, but a well-formed v4 keeps the
/// row indistinguishable from any other finding for casual readers.
fn synthetic_finding_id(decision: &RbaDecision, identity_key: &str) -> Uuid {
    let day = decision.decided_at.date().to_string(); // ISO `yyyy-mm-dd`
    let mut hasher = Sha256::new();
    hasher.update(decision.tenant_id.as_bytes());
    hasher.update(b"|");
    hasher.update(identity_key.as_bytes());
    hasher.update(b"|");
    hasher.update(day.as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0u8; 16];
    // SAFETY: SHA-256 always produces 32 bytes, so [..16] never panics.
    #[allow(clippy::indexing_slicing)]
    bytes.copy_from_slice(&digest[..16]);
    // RFC 4122 v4 + variant 10. The high nibble of byte 6 carries the
    // version; the high nibble of byte 8 carries the variant.
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

// Compile-time witness that `MemDeviceFingerprintLedger` still
// implements the trait we depend on. Belt-and-braces guard against a
// future trait-surface drift that would otherwise only surface in the
// integration test suite.
#[allow(dead_code)]
fn _assert_mem_store_impls_trait(s: MemDeviceFingerprintLedger) -> Box<dyn DeviceFingerprintStore> {
    Box::new(s)
}

#[async_trait]
impl RbaPort for RbaAdapter {
    async fn evaluate(&self, input: RbaEvaluateInput) -> Result<RbaEvaluateOutput, RbaPortError> {
        let tenant = parse_tenant(&input.tenant_id)?;
        let user_id = input
            .user_id
            .as_deref()
            .and_then(|s| Uuid::parse_str(s).ok());
        let ip = parse_ipv4_or_sentinel(&input.ip);
        let email_lower = input.email.to_ascii_lowercase();
        let ctx = LoginContext {
            tenant_id: tenant,
            user_id,
            email: email_lower.clone(),
            ip,
            device_fingerprint: input.device_fingerprint,
            observed_at: OffsetDateTime::now_utc(),
        };
        let decision = self.svc.evaluate(ctx);
        let action = match decision.action {
            RbaAction::Allow => RbaActionWire::Allow,
            RbaAction::StepUpMfa => RbaActionWire::StepUpMfa,
            RbaAction::Block => RbaActionWire::Block,
        };
        // TOP5-#3-P2-005: surface high-risk Block decisions as synthetic
        // findings for SOC visibility. Identity key is the user uuid
        // when known, else the lowercased email — so the per-day
        // idempotency bucket still collapses repeat hits against the
        // same unauthenticated identity. The hook is fail-open: any
        // error is logged at WARN and the wire response still goes
        // back unchanged.
        let identity_key = decision
            .user_id
            .map_or_else(|| email_lower, |u| u.to_string());
        self.maybe_emit_block_finding(&decision, &identity_key)
            .await;
        Ok(RbaEvaluateOutput {
            score: decision.score,
            action,
            reason: decision.reason,
        })
    }

    async fn list_decisions(
        &self,
        tenant_id: &str,
        limit: u32,
        include_signals: bool,
    ) -> Result<Vec<RbaDecisionView>, RbaPortError> {
        let tenant = parse_tenant(tenant_id)?;
        let n = usize::try_from(limit).unwrap_or(100);
        let rows = self.svc.recent_decisions(tenant, n);
        Ok(rows
            .into_iter()
            .map(|d| {
                // LOW-007: only project the per-signal breakdown when
                // the caller is allowed to see it. The engine's
                // [`sx_rba::DecisionAudit`] is always fully populated;
                // the projection here is the single gate that decides
                // whether the field reaches the wire.
                let signals = if include_signals {
                    Some(
                        d.signal_contributions
                            .iter()
                            .map(contribution_to_view)
                            .collect(),
                    )
                } else {
                    None
                };
                RbaDecisionView {
                    id: d.id.to_string(),
                    tenant_id: d.tenant_id.to_string(),
                    user_id: d.user_id.map(|u| u.to_string()),
                    ip: d.ip.to_string(),
                    score: d.score,
                    action: d.action,
                    reason: d.reason,
                    decided_at: d
                        .decided_at
                        .format(&time::format_description::well_known::Rfc3339)
                        .unwrap_or_else(|_| String::new()),
                    signals,
                }
            })
            .collect())
    }

    async fn get_config(&self, tenant_id: &str) -> Result<RbaConfigView, RbaPortError> {
        let tenant = parse_tenant(tenant_id)?;
        let cfg = self.svc.config_for(tenant);
        Ok(config_to_view(&cfg))
    }

    async fn put_config(
        &self,
        tenant_id: &str,
        view: RbaConfigView,
    ) -> Result<RbaConfigView, RbaPortError> {
        let tenant = parse_tenant(tenant_id)?;
        let cfg = view_to_config(view)?;
        let installed = self
            .svc
            .put_config(tenant, cfg)
            .map_err(|e| RbaPortError::Invalid(e.to_string()))?;
        Ok(config_to_view(&installed))
    }

    async fn list_known_devices(
        &self,
        tenant_id: &str,
        user_id: &str,
    ) -> Result<KnownDevicesResponse, RbaPortError> {
        let tenant = parse_tenant(tenant_id)?;
        let user = parse_user(user_id)?;
        let rows = self.svc.list_user_devices(tenant, user);
        let devices = rows
            .into_iter()
            .map(|r| KnownDeviceView {
                fp_hash: r.fp_hash,
                status: r.status.as_str().to_owned(),
                last_seen_at: r
                    .last_seen_at
                    .format(&time::format_description::well_known::Rfc3339)
                    .unwrap_or_else(|_| String::new()),
            })
            .collect();
        Ok(KnownDevicesResponse { devices })
    }

    async fn revoke_known_device(
        &self,
        tenant_id: &str,
        user_id: &str,
        fp_hash: &str,
    ) -> Result<(), RbaPortError> {
        let tenant = parse_tenant(tenant_id)?;
        let user = parse_user(user_id)?;
        let trimmed = fp_hash.trim();
        // Validate against the same shape the migration's CHECK
        // constraint enforces on the persistent table. We refuse early
        // so the operator gets a 400 rather than the engine silently
        // creating a no-op revocation for a malformed hash.
        if !(16..=128).contains(&trimmed.len()) {
            return Err(RbaPortError::Invalid(
                "fp_hash must be 16..=128 chars".to_owned(),
            ));
        }
        self.svc.revoke_device_fingerprint(tenant, user, trimmed);
        Ok(())
    }
}

/// Project an in-process [`SignalContribution`] onto the wire DTO
/// (LOW-007).
///
/// The wire string for `signal` uses the same `snake_case` form as
/// [`sx_rba::SignalKind::as_str`], matching the keys already used in
/// the `signals` JSONB column. We go through serde rather than calling
/// `as_str` directly so a future renamed variant cannot drift between
/// the two layers — there's one canonical string per signal.
fn contribution_to_view(c: &SignalContribution) -> SignalContributionView {
    // `serde_json::to_value` on a `SignalKind` returns `Value::String`
    // because of the `serde(rename_all = "snake_case")` attribute. We
    // unwrap the value defensively; if serde ever stops producing a
    // string here we fall back to the engine-side `as_str` form so the
    // controller still gets a usable label.
    let signal = serde_json::to_value(c.signal)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_else(|| c.signal.as_str().to_owned());
    SignalContributionView {
        signal,
        sub_score: c.sub_score,
        weight: c.weight,
        weighted: c.weighted,
    }
}

fn parse_user(s: &str) -> Result<Uuid, RbaPortError> {
    Uuid::parse_str(s).map_err(|_| RbaPortError::Invalid("user_id is not a uuid".to_owned()))
}

fn parse_tenant(s: &str) -> Result<Uuid, RbaPortError> {
    Uuid::parse_str(s).map_err(|_| RbaPortError::Invalid("tenant_id is not a uuid".to_owned()))
}

fn parse_ipv4_or_sentinel(s: &str) -> Ipv4Addr {
    s.trim()
        .parse::<Ipv4Addr>()
        .unwrap_or(Ipv4Addr::UNSPECIFIED)
}

fn config_to_view(cfg: &RbaConfig) -> RbaConfigView {
    RbaConfigView {
        allow_threshold: cfg.allow_threshold,
        block_threshold: cfg.block_threshold,
        weights: RbaWeightsView {
            w_ip_geo: cfg.weights.w_ip_geo,
            w_velocity: cfg.weights.w_velocity,
            w_business_hours: cfg.weights.w_business_hours,
            w_device_fp: cfg.weights.w_device_fp,
            w_mfa_recent: cfg.weights.w_mfa_recent,
            w_success_rate: cfg.weights.w_success_rate,
            w_impossible_travel: cfg.weights.w_impossible_travel,
        },
        feature_flags: RbaFeatureFlagsView {
            enable_ip_geo: cfg.feature_flags.enable_ip_geo,
            enable_velocity: cfg.feature_flags.enable_velocity,
            enable_business_hours: cfg.feature_flags.enable_business_hours,
            enable_device_fp: cfg.feature_flags.enable_device_fp,
            enable_mfa_recent: cfg.feature_flags.enable_mfa_recent,
            enable_success_rate: cfg.feature_flags.enable_success_rate,
            enable_impossible_travel: cfg.feature_flags.enable_impossible_travel,
        },
        business_tz: cfg.business_hours.tz.clone(),
        business_hours_start: cfg.business_hours.start_hour,
        business_hours_end: cfg.business_hours.end_hour,
    }
}

fn view_to_config(view: RbaConfigView) -> Result<RbaConfig, RbaPortError> {
    // HIGH-001 dashboard surface: the wire DTO now carries the four
    // HIGH-001 weights (`w_device_fp`, `w_mfa_recent`, `w_success_rate`,
    // `w_impossible_travel`) plus the per-signal feature-flag bundle.
    // Legacy clients posting the pre-HIGH-001 3-weight payload still
    // work because every new field is `#[serde(default)]` on the view
    // (weights default to 0.0, flags default to enabled), preserving
    // the prior implicit "opt-out of new signals" behaviour for
    // legacy callers.
    Ok(RbaConfig {
        allow_threshold: view.allow_threshold,
        block_threshold: view.block_threshold,
        weights: RbaWeights {
            w_ip_geo: view.weights.w_ip_geo,
            w_velocity: view.weights.w_velocity,
            w_business_hours: view.weights.w_business_hours,
            w_device_fp: view.weights.w_device_fp,
            w_mfa_recent: view.weights.w_mfa_recent,
            w_success_rate: view.weights.w_success_rate,
            w_impossible_travel: view.weights.w_impossible_travel,
        },
        feature_flags: sx_rba::RbaFeatureFlags {
            enable_ip_geo: view.feature_flags.enable_ip_geo,
            enable_velocity: view.feature_flags.enable_velocity,
            enable_business_hours: view.feature_flags.enable_business_hours,
            enable_device_fp: view.feature_flags.enable_device_fp,
            enable_mfa_recent: view.feature_flags.enable_mfa_recent,
            enable_success_rate: view.feature_flags.enable_success_rate,
            enable_impossible_travel: view.feature_flags.enable_impossible_travel,
        },
        business_hours: BusinessHours {
            tz: view.business_tz,
            start_hour: view.business_hours_start,
            end_hour: view.business_hours_end,
        },
    })
}

/// Build a shared [`RbaAdapter`] with the in-memory device-fingerprint
/// ledger and the in-memory travel-last-sighting ledger. Used when
/// Postgres is disabled (`database.enabled = false`) or in tests.
#[allow(dead_code)]
pub(crate) fn build() -> Arc<RbaAdapter> {
    Arc::new(RbaAdapter::new())
}

/// TOP5-#3-P2-005 + LOW-004 + LOW-005: production-shaped builder. Wraps
/// either the in-memory or Postgres-backed stores and, when
/// `emission.enabled = true`, plumbs the synthetic-finding emission
/// hook against the supplied [`FindingRepositoryPort`].
///
/// When `emission.enabled = false` (the default) the `findings` handle
/// is still stored — wiring is cheap and harmless — but the post-process
/// hook short-circuits so zero findings are minted, matching the
/// platform's back-compat default.
pub(crate) fn build_with_emission(
    pool: Option<PgPool>,
    findings: Arc<dyn FindingRepositoryPort>,
    emission: RbaFindingEmissionConfig,
) -> Arc<RbaAdapter> {
    let adapter = match pool {
        Some(p) => RbaAdapter::new_with_pg(p),
        None => RbaAdapter::new(),
    };
    Arc::new(adapter.with_finding_emission(findings, emission))
}

/// LOW-004 + LOW-005: build a shared [`RbaAdapter`] with both the
/// device-fingerprint ledger AND the impossible-travel last-sighting
/// ledger backed by Postgres. Used by the composition root when
/// `database.enabled = true` so neither ledger is flushed on restart.
#[allow(dead_code)]
pub(crate) fn build_with_pg(pool: PgPool) -> Arc<RbaAdapter> {
    Arc::new(RbaAdapter::new_with_pg(pool))
}

/// LOW-004-only convenience: build a shared [`RbaAdapter`] backed by
/// the Postgres [`PgDeviceFingerprintLedger`] but with an in-memory
/// travel ledger. Kept for callers that explicitly want the LOW-004
/// wiring without LOW-005; production code should prefer
/// [`build_with_pg`].
#[allow(dead_code)]
pub(crate) fn build_with_pg_ledger(pool: PgPool) -> Arc<RbaAdapter> {
    Arc::new(RbaAdapter::new_with_pg_ledger(pool))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use sx_api::port::RbaEvaluateInput;

    fn input(tenant: &str, email: &str, ip: &str) -> RbaEvaluateInput {
        RbaEvaluateInput {
            tenant_id: tenant.to_owned(),
            user_id: None,
            email: email.to_owned(),
            ip: ip.to_owned(),
            device_fingerprint: None,
        }
    }

    #[tokio::test]
    async fn evaluate_rejects_non_uuid_tenant() {
        let a = RbaAdapter::new();
        let err = a
            .evaluate(input("not-a-uuid", "alice@x.test", "8.8.8.8"))
            .await
            .unwrap_err();
        assert!(matches!(err, RbaPortError::Invalid(_)));
    }

    #[tokio::test]
    async fn evaluate_low_risk_allows() {
        let a = RbaAdapter::new();
        let tenant = Uuid::new_v4();
        let out = a
            .evaluate(input(&tenant.to_string(), "alice@x.test", "8.8.8.8"))
            .await
            .unwrap();
        // Single login from US IP — should be allow, but the
        // observed_at is now() which depends on the wall clock — we
        // only assert it's not blocked.
        assert_ne!(out.action, RbaActionWire::Block);
    }

    #[tokio::test]
    async fn list_decisions_returns_audit_rows() {
        let a = RbaAdapter::new();
        let tenant = Uuid::new_v4();
        let _ = a
            .evaluate(input(&tenant.to_string(), "alice@x.test", "8.8.8.8"))
            .await
            .unwrap();
        let rows = a
            .list_decisions(&tenant.to_string(), 10, false)
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].tenant_id, tenant.to_string());
        // LOW-007 default-deny: when include_signals=false the wire DTO
        // omits the per-signal breakdown — pin the back-compat
        // guarantee on the adapter level too, not just the view layer.
        assert!(
            rows[0].signals.is_none(),
            "non-admin caller must not see the signal breakdown",
        );
    }

    #[tokio::test]
    async fn list_decisions_with_admin_flag_attaches_signal_breakdown() {
        // LOW-007: when the controller passes include_signals=true
        // (admin caller), the adapter must project each
        // SignalContribution onto its wire DTO. Validate every
        // contribution row carries a populated signal label and the
        // sub_score, weight, weighted are passed through verbatim.
        let a = RbaAdapter::new();
        let tenant = Uuid::new_v4();
        let _ = a
            .evaluate(input(&tenant.to_string(), "alice@x.test", "8.8.8.8"))
            .await
            .unwrap();
        let rows = a
            .list_decisions(&tenant.to_string(), 10, true)
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        let signals = rows[0]
            .signals
            .as_ref()
            .expect("admin caller must receive signal breakdown");
        assert!(
            !signals.is_empty(),
            "default config has all signals enabled — breakdown must be non-empty",
        );
        for s in signals {
            assert!(!s.signal.is_empty(), "every contribution carries a label");
            assert!((0..=100).contains(&s.sub_score));
            assert!(s.weight >= 0.0);
            // weighted ≈ sub_score * weight (allow tiny f64 jitter).
            let expected = f64::from(s.sub_score) * s.weight;
            assert!(
                (s.weighted - expected).abs() < 1e-9,
                "weighted ({}) must equal sub_score*weight ({})",
                s.weighted,
                expected,
            );
        }
    }

    #[tokio::test]
    async fn put_config_validates_thresholds() {
        let a = RbaAdapter::new();
        let tenant = Uuid::new_v4();
        let bad = RbaConfigView {
            allow_threshold: 90,
            block_threshold: 30, // inverted
            weights: RbaWeightsView {
                w_ip_geo: 0.4,
                w_velocity: 0.4,
                w_business_hours: 0.2,
                w_device_fp: 0.0,
                w_mfa_recent: 0.0,
                w_success_rate: 0.0,
                w_impossible_travel: 0.0,
            },
            feature_flags: RbaFeatureFlagsView::default(),
            business_tz: "UTC".into(),
            business_hours_start: 9,
            business_hours_end: 18,
        };
        let err = a.put_config(&tenant.to_string(), bad).await.unwrap_err();
        assert!(matches!(err, RbaPortError::Invalid(_)));
    }

    #[tokio::test]
    async fn put_config_then_get_config_round_trips() {
        let a = RbaAdapter::new();
        let tenant = Uuid::new_v4();
        let view = RbaConfigView {
            allow_threshold: 20,
            block_threshold: 80,
            weights: RbaWeightsView {
                w_ip_geo: 0.25,
                w_velocity: 0.20,
                w_business_hours: 0.10,
                w_device_fp: 0.15,
                w_mfa_recent: 0.10,
                w_success_rate: 0.05,
                w_impossible_travel: 0.15,
            },
            feature_flags: RbaFeatureFlagsView {
                enable_ip_geo: true,
                enable_velocity: true,
                enable_business_hours: false,
                enable_device_fp: true,
                enable_mfa_recent: false,
                enable_success_rate: true,
                enable_impossible_travel: true,
            },
            business_tz: "America/Los_Angeles".into(),
            business_hours_start: 8,
            business_hours_end: 17,
        };
        let installed = a
            .put_config(&tenant.to_string(), view.clone())
            .await
            .unwrap();
        assert_eq!(installed, view);
        let back = a.get_config(&tenant.to_string()).await.unwrap();
        assert_eq!(back, view);
    }

    #[tokio::test]
    async fn empty_ip_falls_back_to_sentinel_and_does_not_panic() {
        let a = RbaAdapter::new();
        let tenant = Uuid::new_v4();
        let out = a
            .evaluate(input(&tenant.to_string(), "alice@x.test", ""))
            .await
            .unwrap();
        // 0.0.0.0 is in the embedded table mapped to XX → step-up
        // depending on hour; we only assert no panic + valid range.
        assert!((0..=100).contains(&out.score));
    }

    #[tokio::test]
    async fn high_risk_burst_blocks_login() {
        let a = RbaAdapter::new();
        let tenant = Uuid::new_v4();
        // HIGH-001 added a per-tenant passive-observation phase that
        // forces Allow for the first 30 days. Lock the baseline so the
        // engine actually returns the computed action.
        a.service().lock_baseline(tenant, OffsetDateTime::now_utc());
        let mut last = None;
        for _ in 0..20 {
            // 240.0.0.1 is outside the embedded /8 table → unknown
            // country (sub-score 80). Repeated attempts ramp the
            // velocity signal to 100. The composite must eventually
            // land in the block bucket.
            let out = a
                .evaluate(input(&tenant.to_string(), "alice@x.test", "240.0.0.1"))
                .await
                .unwrap();
            last = Some(out);
        }
        let out = last.unwrap();
        // We can't assert action == Block deterministically because
        // observed_at is now() and the hours signal depends on the
        // current wall clock; but the score must at least cross the
        // step-up threshold.
        assert!(
            matches!(out.action, RbaActionWire::StepUpMfa | RbaActionWire::Block),
            "burst from unknown country must escalate, got score={} action={:?}",
            out.score,
            out.action,
        );
    }

    #[tokio::test]
    async fn list_known_devices_returns_enrolled_rows_newest_first() {
        let a = RbaAdapter::new();
        let tenant = Uuid::new_v4();
        let user = Uuid::new_v4();
        // Enrol two fingerprints at distinct timestamps.
        let early = OffsetDateTime::now_utc() - time::Duration::hours(2);
        let late = OffsetDateTime::now_utc();
        let fp_old = "a".repeat(64);
        let fp_new = "b".repeat(64);
        a.service()
            .enroll_device_fingerprint(tenant, user, &fp_old, early);
        a.service()
            .enroll_device_fingerprint(tenant, user, &fp_new, late);

        let resp = a
            .list_known_devices(&tenant.to_string(), &user.to_string())
            .await
            .unwrap();
        assert_eq!(resp.devices.len(), 2);
        assert_eq!(resp.devices[0].fp_hash, fp_new, "newest first");
        assert_eq!(resp.devices[0].status, "known");
        assert_eq!(resp.devices[1].fp_hash, fp_old);
    }

    #[tokio::test]
    async fn revoke_known_device_then_list_shows_status_revoked() {
        let a = RbaAdapter::new();
        let tenant = Uuid::new_v4();
        let user = Uuid::new_v4();
        let fp = "c".repeat(64);
        a.service()
            .enroll_device_fingerprint(tenant, user, &fp, OffsetDateTime::now_utc());

        a.revoke_known_device(&tenant.to_string(), &user.to_string(), &fp)
            .await
            .unwrap();

        let resp = a
            .list_known_devices(&tenant.to_string(), &user.to_string())
            .await
            .unwrap();
        assert_eq!(resp.devices.len(), 1);
        assert_eq!(resp.devices[0].status, "revoked");
    }

    #[tokio::test]
    async fn revoke_known_device_is_idempotent() {
        let a = RbaAdapter::new();
        let tenant = Uuid::new_v4();
        let user = Uuid::new_v4();
        let fp = "d".repeat(64);
        a.service()
            .enroll_device_fingerprint(tenant, user, &fp, OffsetDateTime::now_utc());

        a.revoke_known_device(&tenant.to_string(), &user.to_string(), &fp)
            .await
            .unwrap();
        // Second revoke succeeds (idempotent — matches AAGUID DELETE behaviour).
        a.revoke_known_device(&tenant.to_string(), &user.to_string(), &fp)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn revoke_rejects_malformed_fp_hash() {
        let a = RbaAdapter::new();
        let tenant = Uuid::new_v4();
        let user = Uuid::new_v4();
        // Too short — table CHECK constraint forbids it.
        let err = a
            .revoke_known_device(&tenant.to_string(), &user.to_string(), "short")
            .await
            .unwrap_err();
        assert!(matches!(err, RbaPortError::Invalid(_)));
    }

    #[tokio::test]
    async fn list_known_devices_rejects_non_uuid_user() {
        let a = RbaAdapter::new();
        let tenant = Uuid::new_v4();
        let err = a
            .list_known_devices(&tenant.to_string(), "not-a-uuid")
            .await
            .unwrap_err();
        assert!(matches!(err, RbaPortError::Invalid(_)));
    }
}
