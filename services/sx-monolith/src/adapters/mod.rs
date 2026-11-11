//! Concrete adapters that implement every trait declared in
//! [`sx_api::port`].
//!
//! Phase 1.5: when `database.enabled` is true the Postgres bundle replaces
//! the in-memory repositories; when `redis.enabled` is true the Redis
//! bundle replaces the in-memory kill switch + login-attempt tracker.
//! Both flags default to `false` in the example config so a developer can
//! still boot the monolith standalone.

use std::sync::Arc;

use sx_api::middleware::rate_limit::{RateLimitConfig, RateLimiterState};
use sx_api::AppState;
use sx_config::Settings;

use crate::config_bridge;

/// Concrete handles to the in-memory repository stores. Hoisted to module
/// scope to satisfy `clippy::items_after_statements` — the type alias is
/// referenced from a destructuring pattern inside `build_app_state`.
type InMemoryHandles = (
    Arc<repository::InMemoryAssets>,
    Arc<repository::InMemoryFindings>,
    Arc<repository::InMemoryTenants>,
);

pub(crate) mod admin;
pub(crate) mod ai_asset_discovery;
pub(crate) mod ai_audit;
pub(crate) mod alerting;
pub(crate) mod api_dast;
pub(crate) mod approvals;
pub(crate) mod asset_bulk;
pub(crate) mod asset_write;
pub(crate) mod audit_anchor;
pub(crate) mod audit_break_observer;
pub(crate) mod audit_query;
pub(crate) mod autonomy;
pub(crate) mod bas;
pub(crate) mod bas_chain;
pub(crate) mod bas_simulator;
pub(crate) mod blast_radius;
pub(crate) mod branding;
pub(crate) mod bugbounty;
pub(crate) mod chain_verifier;
pub(crate) mod cloud;
pub(crate) mod cloud_drift;
pub(crate) mod collab;
pub(crate) mod compliance;
pub(crate) mod compliance_evidence;
pub(crate) mod comprehensive_report;
pub(crate) mod continuous_sim;
pub(crate) mod copilot;
pub(crate) mod copilot_approval;
pub(crate) mod copilot_audit_sink;
pub(crate) mod customer_auth;
pub(crate) mod cve;
pub(crate) mod device_registry;
pub(crate) mod device_trust;
pub(crate) mod discovery;
pub(crate) mod dlp;
pub(crate) mod drift_job;
pub(crate) mod engagement;
pub(crate) mod engagement_clone;
pub(crate) mod engagement_repo;
pub(crate) mod findings_bulk;
pub(crate) mod findings_remediation;
pub(crate) mod github;
pub(crate) mod graph;
pub(crate) mod graphsage_job;
pub(crate) mod graphsage_port;
pub(crate) mod grc;
pub(crate) mod hunt;
pub(crate) mod iam;
/// TOP5-#5 — incident-sink fan-out (Jira + PagerDuty MVP).
pub(crate) mod incident_sinks;
pub(crate) mod intel;
pub(crate) mod intel_check;
pub(crate) mod intel_feed_status;
pub(crate) mod intel_feeds_job;
pub(crate) mod intel_ioc_repo;
pub(crate) mod ir;
pub(crate) mod k8s_admission;
pub(crate) mod log_ingest;
pub(crate) mod logout;
pub(crate) mod mfa;
pub(crate) mod ml;
pub(crate) mod oidc;
/// MED-004 — OAuth2 `client_credentials` + `client_secret_jwt` token
/// endpoint, admin secret rotation, and JWKS publication adapters.
pub(crate) mod oidc_client;
pub(crate) mod pentest;
pub(crate) mod pentest_repo;
pub(crate) mod phase3;
pub(crate) mod plugins;
pub(crate) mod postgres;
pub(crate) mod predictive;
pub(crate) mod prowler_import;
pub(crate) mod rba;
pub(crate) mod readiness;
pub(crate) mod redis;
pub(crate) mod redteam;
pub(crate) mod remediation;
pub(crate) mod remediation_outcomes;
pub(crate) mod report;
pub(crate) mod report_scheduler;
pub(crate) mod repository;
pub(crate) mod risk;
pub(crate) mod risk_tuning;
pub(crate) mod roles;
pub(crate) mod runtime;
pub(crate) mod saml;
pub(crate) mod saml_attack_observer;
pub(crate) mod sca_monitor;
pub(crate) mod scanner_http;
pub(crate) mod scim;
pub(crate) mod secret_cipher;
pub(crate) mod secrets;
pub(crate) mod secrets_admin;
pub(crate) mod seed;
pub(crate) mod soar;
pub(crate) mod soc;
pub(crate) mod tenant_write;
pub(crate) mod twin;
pub(crate) mod ueba;
pub(crate) mod vuln_ingest;
pub(crate) mod webauthn;
pub(crate) mod webhooks_admin;
pub(crate) mod webhooks_rotation_job;

/// Build the [`AppState`] bundle. Async because the Postgres / Redis paths
/// perform network I/O (pool warm-up, ping, migration runner).
#[allow(clippy::cognitive_complexity)] // composition root by design
pub(crate) async fn build_app_state(settings: &Settings) -> anyhow::Result<AppState> {
    let rate_limit_cfg = RateLimitConfig {
        limit_per_minute: settings.server.rate_limit.limit_per_minute,
        burst: settings.server.rate_limit.burst,
        enabled: settings.server.rate_limit.enabled,
    };

    // --- P2-012: chaos engineering registry ------------------------------
    //
    // The registry is built from the process env (`SX_CHAOS_ENABLED=1`
    // plus per-kind fractions). It refuses to enable in production
    // (`APP_ENV=production`). A misconfigured deployment is a HARD
    // failure: we bubble the error rather than silently disabling chaos
    // so operators notice a typo'd env var. The registry is `Send + Sync`
    // and cheap to share via `Arc`.
    let chaos_registry: sx_chaos::SharedChaosRegistry = match sx_chaos::ChaosRegistry::from_env() {
        Ok(r) => Arc::new(r),
        Err(e) => {
            tracing::error!(
                target: "adapters.chaos",
                error = %e,
                "chaos registry refused to initialise; falling back to disabled",
            );
            Arc::new(sx_chaos::ChaosRegistry::disabled())
        }
    };
    let chaos_snapshot = chaos_registry.snapshot();
    tracing::info!(
        target: "adapters.chaos",
        enabled = chaos_snapshot.enabled,
        latency_fraction = chaos_snapshot.latency.fraction,
        error_rate_fraction = chaos_snapshot.error_rate.fraction,
        dependency_fraction = chaos_snapshot.dependency.fraction,
        "chaos engineering registry initialised",
    );

    // --- Redis (optional) ------------------------------------------------
    let redis_bundle = if settings.redis.enabled {
        tracing::info!("redis adapter enabled; connecting");
        Some(redis::build(&settings.redis, settings.iam.lockout.duration).await?)
    } else {
        tracing::debug!("redis adapter disabled; using in-memory kill switch + tracker");
        None
    };

    let external_tracker = redis_bundle.as_ref().map(|b| Arc::clone(&b.login_tracker));
    let external_kill_switch = redis_bundle.as_ref().map(|b| {
        Arc::clone(&b.kill_switch_concrete)
            as Arc<dyn sx_engagement::service::kill_switch::KillSwitch>
    });

    // --- Postgres (optional) ---------------------------------------------
    //
    // Built BEFORE the IAM bundle so the Postgres-backed user repository
    // (when `database.enabled = true`) can be plumbed into the IAM use
    // cases. When disabled, the IAM bundle constructs its own in-memory
    // user repository.
    let postgres_bundle = if settings.database.enabled {
        tracing::info!("postgres adapter enabled; building pool");
        Some(postgres::build(&settings.database, &settings.bootstrap).await?)
    } else {
        tracing::debug!("postgres adapter disabled; using in-memory repositories");
        None
    };

    // --- IAM -------------------------------------------------------------
    let iam_runtime = config_bridge::iam_runtime(&settings.iam, &settings.jwt);
    let session_ttl = config_bridge::session_ttl(&settings.jwt);
    // Choose the active user repository at boot.
    //
    // Postgres path: build a `PgIamUserRepository` over the pool returned
    // by `postgres::build` and wrap it in the unified `MonolithUserRepo`
    // enum so the use case generics stay monomorphised.
    //
    // In-memory path: instantiate an empty `InMemoryUserRepository`.
    //
    // The bootstrap admin seed runs inside `iam::build` against whichever
    // variant was passed in — see [`adapters::iam::seed_bootstrap_admin`].
    let user_repo: Arc<iam::MonolithUserRepo> = if let Some(pg) = postgres_bundle.as_ref() {
        Arc::new(iam::MonolithUserRepo::postgres(
            iam::PgIamUserRepository::new(pg.pool.clone(), settings.database.statement_timeout_ms),
        ))
    } else {
        Arc::new(iam::MonolithUserRepo::in_memory())
    };
    // Session revoker (revoked/logged-out JWT jtis). Redis-backed so
    // revocations survive a monolith restart and are shared across
    // instances; in-memory single-process fallback when redis is disabled.
    // TTL = access-token lifetime (after which the token is expired anyway).
    let session_revoker: Arc<dyn iam::SessionRevoker> = if let Some(rb) = redis_bundle.as_ref() {
        Arc::new(redis::RedisSessionRevoker::new(
            rb.manager.clone(),
            iam_runtime.jwt.access_ttl.as_secs(),
        ))
    } else {
        Arc::new(iam::InMemorySessionRevoker::default())
    };
    let iam_bundle = iam::build(
        &iam_runtime,
        session_ttl,
        external_tracker,
        Some(&settings.bootstrap),
        Arc::clone(&user_repo),
        session_revoker,
    )?;

    // Durable engagement aggregate store when the database is enabled
    // (RoE authorization survives restart + is shared across instances),
    // in-memory otherwise. Shared by the engagement service, transitions,
    // clone, pentest, redteam, and risk adapters.
    // The concrete in-memory handle is retained only on the in-memory path,
    // where the demo-data seeder needs it (seed::run + the empty-store probe
    // operate on the concrete type).
    let (engagement_repo, inmem_engagement_repo): (
        Arc<dyn sx_engagement::port::EngagementRepository>,
        Option<Arc<engagement::InMemoryEngagementRepository>>,
    ) = if let Some(pg) = postgres_bundle.as_ref() {
        (
            Arc::new(engagement_repo::PgEngagementRepository::new(
                pg.pool.clone(),
                settings.database.statement_timeout_ms,
            )),
            None,
        )
    } else {
        let mem = Arc::new(engagement::InMemoryEngagementRepository::default());
        (
            Arc::clone(&mem) as Arc<dyn sx_engagement::port::EngagementRepository>,
            Some(mem),
        )
    };
    let engagement_bundle = engagement::build(external_kill_switch, Arc::clone(&engagement_repo));

    // --- Engagement clone adapter ---------------------------------------
    // Shares the same in-memory engagement repository handle the service
    // + transition adapters drive so the clone-side reads the canonical
    // row and writes the new draft into the same store the read-side
    // iterates.
    let engagement_clone_bundle =
        engagement_clone::EngagementCloneBundle::build(Arc::clone(&engagement_bundle.repo));

    // --- Repositories ----------------------------------------------------
    // Hydrated before the risk adapter so the engagement-aggregate flow
    // can iterate findings through the same trait object the HTTP layer
    // already sees.
    //
    // The third tuple slot keeps a parallel `Option` of concrete in-memory
    // handles so the demo seeder can `seed_one(...)` without trait-object
    // downcasts. Populated only on the in-memory branch. The
    // `InMemoryHandles` type alias is declared at module scope above.
    let (assets, findings, tenants, in_memory_handles): (_, _, _, Option<InMemoryHandles>) =
        if let Some(pg) = postgres_bundle.as_ref() {
            (
                Arc::clone(&pg.assets),
                Arc::clone(&pg.findings),
                Arc::clone(&pg.tenants),
                None,
            )
        } else {
            let in_mem = repository::build();
            let handles: InMemoryHandles = (
                Arc::clone(&in_mem.assets_concrete),
                Arc::clone(&in_mem.findings_concrete),
                Arc::clone(&in_mem.tenants_concrete),
            );
            (
                in_mem.assets,
                in_mem.findings,
                in_mem.tenants,
                Some(handles),
            )
        };

    // --- P1-011: remediation outcomes (MTTR + regression) ---------------
    //
    // Decorate the finding repository *before* any downstream adapter
    // takes a clone so every writer's status transition flows through
    // the outcome observer hook. Reads stay pass-through.
    let outcomes_bundle = remediation_outcomes::build(Arc::clone(&findings));
    let findings: Arc<dyn sx_api::port::FindingRepositoryPort> =
        Arc::clone(&outcomes_bundle.findings_observed);
    let remediation_outcomes_port = Arc::clone(&outcomes_bundle.port);

    // Alerting policy engine: fan every at-or-above-threshold finding out to
    // the configured incident sinks (Jira / PagerDuty / Opsgenie /
    // ServiceNow / Linear). Returns the port unchanged when no sink is
    // configured, so this is zero-cost in the default dev profile.
    let incident_http = reqwest::Client::builder()
        .user_agent("SentinelX-Monolith/0.1")
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| anyhow::anyhow!("incident-sink http client build failed: {e}"))?;
    let incident_fan_out = incident_sinks::build(
        incident_http,
        &settings.integrations.jira,
        &settings.integrations.pagerduty,
        &settings.integrations.linear,
        &settings.integrations.opsgenie,
        &settings.integrations.servicenow,
    )
    .unwrap_or_else(|e| {
        tracing::warn!(
            target: "adapters.alerting",
            error = %e,
            "incident fan-out build failed; finding alerting disabled"
        );
        incident_sinks::IncidentSinkFanOut::empty()
    });
    let findings: Arc<dyn sx_api::port::FindingRepositoryPort> = alerting::wrap(
        findings,
        incident_fan_out,
        sx_core::value_object::severity::Severity::Critical,
    );

    // --- Intel + Risk ----------------------------------------------------
    let http_client = reqwest::Client::builder()
        .user_agent("SentinelX-Monolith/0.1")
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| anyhow::anyhow!("intel http client: {e}"))?;
    let intel_bundle = intel::build(http_client);
    // When Postgres is enabled, plug PgCveLookup as an authoritative CVE
    // source — overriding the NVD-backed CveLookup that ships with the
    // intel bundle. EPSS + KEV still come from the intel bundle.
    let cve_lookup_override: Option<Arc<dyn crate::adapters::intel::CveLookup>> =
        postgres_bundle.as_ref().map(|pg| {
            Arc::new(crate::adapters::cve::PgCveLookup::new(
                pg.pool.clone(),
                settings.database.statement_timeout_ms,
            )) as Arc<dyn crate::adapters::intel::CveLookup>
        });
    let risk_adapter = risk::build(
        &settings.risk,
        Some(intel_bundle),
        Arc::clone(&findings),
        Arc::clone(&assets),
        cve_lookup_override,
    )?;

    // --- P1-014: per-tenant risk-model tuning ---------------------------
    //
    // Sources the platform defaults from the freshly-loaded `settings.risk`
    // (composite weights) and the canonical `RiskThresholdsConfig` factory.
    // Per-tenant risk-model overrides are durable (Postgres) when the DB is
    // enabled — so a tuning override survives a restart — else in-memory
    // (dev quick-start). The recompute queue + audit sink stay in-memory in
    // both modes.
    let risk_tuning_weights =
        sx_config::schema::risk_weights::RiskWeightsConfig::from(settings.risk.weights.clone());
    let risk_tuning_thresholds =
        sx_config::schema::tenant_risk::RiskThresholdsConfig::sentinelx_default();
    let risk_tuning_port = if let Some(pg) = postgres_bundle.as_ref() {
        risk_tuning::build_pg(
            pg.pool.clone(),
            settings.database.statement_timeout_ms,
            risk_tuning_weights,
            risk_tuning_thresholds,
        )
    } else {
        Arc::clone(&risk_tuning::build(risk_tuning_weights, risk_tuning_thresholds).port)
    };

    let discovery_adapter = discovery::build(
        Arc::clone(&engagement_bundle.repo),
        Arc::clone(&engagement_bundle.kill_switch_concrete),
    )?;

    // --- Phase-3 bundles + adapters --------------------------------------
    let phase3_http = reqwest::Client::builder()
        .user_agent("SentinelX-Monolith/0.1")
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| anyhow::anyhow!("phase3 http client: {e}"))?;
    let bas_bundle = bas::build()?;
    // Clone the public BAS use case before the bundle is moved into
    // `phase3::build`; the lateral-movement chain adapter (P2-015) wraps
    // the same use case via `ChainExecutor` so a chain step shares the
    // safety pipeline + technique registry with single-technique runs.
    let bas_chain_use_case = Arc::clone(&bas_bundle.run_use_case);
    let collab_bundle = collab::build(&settings.collab).await?;
    // Pull the two HTTP-facing collaborator ports off the bundle before
    // it is consumed by `phase3::build` (which keeps the bundle alive
    // for its own purposes — DNS/HTTP receiver wiring lands next phase).
    let collab_alloc_port = Arc::clone(&collab_bundle.collab_alloc);
    let collab_lookup_port = Arc::clone(&collab_bundle.collab_lookup);
    let ml_bundle = ml::build(&settings.iam.attempt_email_pepper);
    let cloud_bundle = cloud::build(phase3_http.clone(), &settings.cloud);
    let cloud_inventory_port = Arc::clone(&cloud_bundle.list);
    let cloud_drift_bundle = cloud_drift::build(Arc::clone(&cloud_bundle.use_case));
    let cloud_drift_port = Arc::clone(&cloud_drift_bundle.port);
    let autonomy_bundle = autonomy::build(
        phase3_http.clone(),
        settings.iam.attempt_email_pepper.clone(),
        Arc::clone(&bas_bundle.run_use_case),
        &settings.github,
    )?;
    let autonomy_propose_pr = Arc::clone(&autonomy_bundle.propose_pr);
    let autonomy_submit_threat = Arc::clone(&autonomy_bundle.submit_threat);
    let autonomy_schedule_validation = Arc::clone(&autonomy_bundle.schedule_validation);
    let graph_bundle = graph::build(&settings.graph).await?;

    // --- Envelope-encryption KEK provider (P1-007) ----------------------
    let kek_bundle = secrets::build(&settings.secrets)?;
    let kek_provider_name = kek_bundle.provider_name();
    tracing::info!(
        kek_provider = kek_provider_name,
        kek_provider_attached = kek_bundle.provider.is_some(),
        "secrets adapter wired",
    );

    // Clone the shared graph backend Arc before `graph_bundle` is moved
    // into `phase3::build` — the blast-radius adapter needs to traverse
    // the same backing graph as the attack-paths port.
    let graph_for_blast_radius: Arc<dyn sx_graph::port::KnowledgeGraph> =
        Arc::clone(&graph_bundle.graph);
    let report_bundle = report::build()?;
    // PENTEST-001 — reuse the graph backend + report renderer for the
    // combined pentest orchestrator (built after `phase3` consumes the
    // bundles below, so clone the shared handles now).
    let pentest_report_uc = Arc::clone(&report_bundle.render_use_case);
    let pentest_graph = Arc::clone(&graph_for_blast_radius);
    // PRG-02 durability: a Postgres-backed run repository when the database
    // is enabled (runs + history survive restart), in-memory otherwise
    // (zero-config dev). Both satisfy the same `PentestRepository` trait so
    // the orchestrator and HTTP port are unchanged.
    let pentest_repo: Arc<dyn sx_pentest::port::PentestRepository> =
        if let Some(pg) = postgres_bundle.as_ref() {
            Arc::new(pentest_repo::PgPentestRepository::new(
                pg.pool.clone(),
                settings.database.statement_timeout_ms,
            ))
        } else {
            Arc::new(sx_pentest::testing::InMemoryPentestRepository::new())
        };
    let pentest_bundle = pentest::build(
        pentest_graph,
        pentest_report_uc,
        Arc::clone(&engagement_bundle.repo),
        Arc::clone(&engagement_bundle.kill_switch_concrete),
        &settings.engagement,
        pentest_repo,
    )?;
    let remediation_bundle = remediation::build(phase3_http.clone(), &settings.ai_copilot);
    let compliance_bundle = compliance::build();
    // P2-002 — per-tenant report branding (MSSP white-label). The store is
    // shared with the report adapter so rendered PDFs pick up the same
    // branding the API configures.
    // #1 persistence: Postgres-backed branding store when the database is
    // enabled, in-memory otherwise (zero-config dev). Both satisfy the same
    // async BrandingStore trait so the API + report renderer are unchanged.
    let branding_store: Arc<dyn branding::BrandingStore> =
        if let Some(pg) = postgres_bundle.as_ref() {
            Arc::new(branding::PgBrandingStore::new(
                pg.pool.clone(),
                settings.database.statement_timeout_ms,
            ))
        } else {
            Arc::new(branding::InMemoryBrandingStore::default())
        };
    let branding_bundle = branding::build(Arc::clone(&branding_store));
    let phase3 = phase3::build(
        bas_bundle,
        collab_bundle,
        ml_bundle,
        cloud_bundle,
        autonomy_bundle,
        graph_bundle,
        report_bundle,
        remediation_bundle,
        compliance_bundle,
        Arc::clone(&findings),
        Arc::clone(&tenants),
        Arc::clone(&engagement_bundle.service),
        Arc::clone(&branding_store),
    );

    // P2-001 — scheduled report distribution. Delegates rendering to the
    // phase3 report port; the background tick loop runs due schedules.
    let report_scheduler_bundle = report_scheduler::build(Arc::clone(&phase3.report));
    // #3 — comprehensive cross-module report aggregator (server-side
    // counterpart to the dashboard /dashboard/reporting page).
    let comprehensive_report_bundle = comprehensive_report::build(Arc::clone(&findings));

    // --- Admin user provisioning ----------------------------------------
    // Shares the IAM bundle's in-memory user repo + Argon2id hasher so
    // admin-provisioned users land in the same store the bootstrap admin
    // does and can subsequently authenticate against `/v1/auth/login`.
    let admin_bundle = admin::build(
        Arc::clone(&iam_bundle.users),
        Arc::clone(&iam_bundle.hasher),
    );

    // --- Customer-facing auth (signup / verify / forgot / reset) --------
    // Same shared user repo + hasher as the admin bundle. The in-memory
    // adapter manages two token stores keyed by uuid-v4 verify / reset
    // tokens with a 24h TTL.
    let ca_bundle = customer_auth::build(
        Arc::clone(&iam_bundle.users),
        Arc::clone(&iam_bundle.hasher),
    );

    // --- BAS approvals (two-person rule store) --------------------------
    // Postgres-backed when the bundle is live; falls back to the
    // in-memory store for dev / standalone runs.
    let approvals_port: Arc<dyn sx_api::port::ApprovalPort> =
        if let Some(pg) = postgres_bundle.as_ref() {
            approvals::build_postgres(pg.pool.clone(), settings.database.statement_timeout_ms)
        } else {
            Arc::new(approvals::InMemoryApprovalStore::new())
        };

    // --- IAM roles, asset writes, tenant writes, audit query (built before seed move) --
    let roles_bundle = roles::build();
    let audit_query_bundle = audit_query::build(
        postgres_bundle
            .as_ref()
            .map(|pg| (pg.pool.clone(), settings.database.statement_timeout_ms)),
    );
    // P1-004 — automated compliance-evidence collector adapter (PRG-01).
    // The audit-chain integrity collector verifies the tenant's append-only
    // chain for real via the shared audit sink; the remaining collectors
    // emit honest `not_configured` evidence (never a fabricated pass) until
    // their durable/external sources are wired. In-memory WORM store +
    // reference repository otherwise; production swaps the WORM impl for an
    // `aws-sdk-s3` Object-Lock adapter and the store for a Postgres adapter
    // (`20270601000000__create_compliance_evidence.sql`).
    let compliance_evidence_bundle =
        compliance_evidence::build(Arc::clone(&audit_query_bundle.sink));
    // P1-015 — external audit-chain anchor bundle (in-memory repo +
    // shared AnchorRunner). Periodic scheduler integration is left for
    // a future ticket; the HTTP read endpoints work today.
    let audit_anchor_bundle = audit_anchor::build();
    // --- MFA (TOTP) bundle — in-memory store of `(user_id → secret +
    //                          recovery hashes)`. Composed before the
    //                          AppState assembly below.
    let mfa_bundle = mfa::build(postgres_bundle.as_ref().map(|pg| pg.pool.clone()));
    // --- WebAuthn / FIDO2 bundle (P1-002) — in-memory tenant-RP table,
    //     credential store, and short-TTL state cache. The bundle's
    //     `rp_repo` is seeded with a developer-mode row for the
    //     bootstrap tenant so the dev monolith works out of the box.
    let webauthn_bundle = webauthn::build(
        Arc::clone(&iam_bundle.users),
        Arc::clone(&iam_bundle.issue),
        postgres_bundle
            .as_ref()
            .map(|pg| (pg.pool.clone(), settings.database.statement_timeout_ms)),
    );
    if settings.bootstrap.enabled {
        let bootstrap_tid = settings
            .bootstrap
            .admin_tenant_id
            .and_then(|u| u.to_string().parse::<sx_iam::domain::TenantId>().ok())
            .unwrap_or_default();
        webauthn::seed_dev_tenant_rp(&webauthn_bundle.rp_repo, bootstrap_tid);
    }
    // --- OCSF log-ingest bundle — in-memory ring buffer + per-tenant
    // token-bucket rate limiter (MED-001) seeded from `sx-config`.
    let log_ingest_bundle = log_ingest::build(&settings.log_ingest_rate_limit);
    // --- SCIM 2.0 (P0-005) — in-memory provisioner + durable (Postgres)
    //     SCIM bearer tokens when the DB is enabled.
    let scim_bundle = scim::build(
        postgres_bundle
            .as_ref()
            .map(|pg| (pg.pool.clone(), settings.database.statement_timeout_ms)),
    );
    // --- RBA (risk-based auth) adapter — login-flow hook + `/v1/rba/*`.
    //
    // LOW-004: when Postgres is enabled, install the
    // `PgDeviceFingerprintLedger` so the device-fingerprint ledger
    // survives `sx-monolith` restarts (the in-memory `DashMap` ledger
    // was dropping every enrolled device on every redeploy →
    // step-up-MFA storms for hours/days post-deploy until each user
    // re-enrolled).
    //
    // LOW-005: when Postgres is enabled, also back the
    // impossible-travel last-sighting ledger with `rba_last_sightings`
    // so a restart of sx-monolith does not silently downgrade the
    // travel signal for every user until each one logs in again. When
    // Pg is disabled, both ledgers fall back to in-memory impls.
    // TOP5-#3-P2-005: the RBA adapter takes the shared
    // `FindingRepositoryPort` so high-risk Block decisions can be
    // surfaced as synthetic findings. Emission is gated by
    // `settings.rba.finding_emission.enabled` (default `false`); when
    // disabled the post-process hook short-circuits so zero findings
    // are minted, preserving the back-compat default.
    let rba_adapter = rba::build_with_emission(
        postgres_bundle.as_ref().map(|pg| pg.pool.clone()),
        Arc::clone(&findings),
        settings.rba.finding_emission.clone(),
    );
    iam_bundle
        .authn_concrete
        .set_rba(Arc::clone(&rba_adapter) as Arc<dyn sx_api::port::RbaPort>);
    // --- Device-trust (P2-008) — per-tenant posture policy + snapshot
    //     history. Durable against `device_posture_policy` /
    //     `device_posture_snapshots` (both FORCE-RLS) when the DB is
    //     enabled; falls back to the in-memory policy + snapshot ring in
    //     dev. Without the Pg backing, an admin-set posture policy silently
    //     reverts to the permissive default on every restart.
    let device_trust_bundle = {
        use secrecy::ExposeSecret;
        let secret = settings.jwt.signing_key.expose_secret().as_bytes().to_vec();
        if let Some(pg) = postgres_bundle.as_ref() {
            device_trust::build_pg(
                pg.pool.clone(),
                settings.database.statement_timeout_ms,
                secret,
            )
        } else {
            device_trust::build(secret)
        }
    };
    // --- SAML 2.0 SP (P0-004). The per-tenant IdP record store is backed
    // by the `saml_idp_config` table when the DB is enabled (records
    // survive restart; hydrated into the cache at boot), else in-memory.
    // The admin port (below) authors records durably even while the SP
    // itself stays gated on `saml.enabled` + a configured `entity_id`.
    let saml_idp_store_shared = if let Some(pg) = postgres_bundle.as_ref() {
        let store = saml::InMemoryIdpStore::with_pg(
            pg.pool.clone(),
            settings.database.statement_timeout_ms,
        );
        if let Err(e) = store.hydrate().await {
            tracing::warn!(
                target: "adapters.saml",
                error = %e,
                "failed to hydrate SAML IdP configs from Postgres; starting from an empty cache",
            );
        }
        store
    } else {
        saml::InMemoryIdpStore::empty()
    };
    // P0-004 admin port — authors IdP config durably, independent of the
    // SP enabled flag. Shares the record cache with the SP adapter below.
    let saml_idp_admin: Arc<dyn sx_api::port::SamlIdpAdminPort> = Arc::new(
        saml::MonolithSamlIdpAdmin::new(saml_idp_store_shared.clone()),
    );
    // TOP5-#3-P2-004: wire the SAML attack observer against the
    // canonical FindingRepositoryPort so XSW / XEE / transform-bypass
    // / C14N rejections surface as auditable findings.
    let saml_attack_observer: sx_iam::service::saml::SharedSamlAttackObserver =
        Arc::new(saml_attack_observer::MonolithSamlAttackObserver::new(
            Arc::clone(&findings),
            saml_attack_observer::SamlAttackObserverConfig::default(),
        ));
    let saml_sp_port = saml::build_with_observer(
        &settings.saml,
        saml_idp_store_shared.clone(),
        saml_attack_observer,
    );

    // --- CRIT-004 logout bundle (OIDC RP + back-channel + front-channel
    //     and SAML back-channel receiver). Built up-front so the same
    //     session registry is shared with the login flow that needs to
    //     register every new `(jti, id_token, sid, SessionIndex)` tuple.
    let logout_base_url = settings.server.bind_addr.to_string();
    let logout_bundle = logout::build(
        &settings.oidc,
        &settings.saml,
        saml_idp_store_shared,
        format!("https://{logout_base_url}"),
        format!("https://{logout_base_url}/login?logged_out=1"),
    );
    // --- Plugins (P3-007) — in-memory registry + dispatch history.
    let plugins_bundle = if let Some(pg) = postgres_bundle.as_ref() {
        use secrecy::ExposeSecret;
        // Encrypt the per-plugin webhook secret at rest with the local AEAD
        // cipher (key derived from the deployment signing key), instead of
        // storing it plaintext. A KMS-backed SecretCipher drops in here when
        // one is configured.
        let cipher: Arc<dyn sx_webhooks::signing::secret_cipher::SecretCipher> =
            Arc::new(secret_cipher::LocalSecretCipher::from_signing_key(
                settings.jwt.signing_key.expose_secret().as_bytes(),
            ));
        plugins::build_pg(
            pg.pool.clone(),
            settings.database.statement_timeout_ms,
            cipher,
        )
    } else {
        plugins::build()
    };
    // --- IR playbooks (P3-004) — in-memory incident store + NIST
    //     lifecycle state machine. Persistent storage lands in the
    //     production deploy phase via the timestamped migration
    //     (`ir_incidents` + `ir_step_audit`); the API surface is stable
    //     either way.
    let ir_bundle = ir::build(
        postgres_bundle
            .as_ref()
            .map(|pg| (pg.pool.clone(), settings.database.statement_timeout_ms)),
    );
    let asset_write_bundle = if let Some((ref ca, _, _)) = in_memory_handles {
        asset_write::AssetWriteBundle::build(Arc::clone(ca))
    } else if let Some(pg) = postgres_bundle.as_ref() {
        // Postgres enabled: write to the same `assets` table the read adapter
        // queries (previously this fell back to a detached in-memory store, so
        // POST/PATCH/DELETE /v1/assets were invisible + lost on restart). The
        // bulk-import bundle below reuses this port, so it is durable too.
        asset_write::AssetWriteBundle::from_port(postgres::asset_write_adapter(
            pg.pool.clone(),
            settings.database.statement_timeout_ms,
        ))
    } else {
        asset_write::AssetWriteBundle::build(Arc::new(repository::InMemoryAssets::default()))
    };
    // Bulk-import bundle reuses the same `AssetWritePort` trait object so
    // duplicate detection and tenant scoping share one mutex with the
    // per-row `POST /v1/assets` flow.
    let asset_bulk_bundle =
        asset_bulk::AssetBulkImportBundle::build(Arc::clone(&asset_write_bundle.write));
    // Remediation-link tracking bundle — pure in-memory store keyed by
    // `(TenantId, FindingId)`. The HTTP surface validates request shape;
    // the adapter only mints `linked_at` / `linked_by` and serialises
    // upsert + delete behind a single mutex.
    let remediation_tracking_bundle = if let Some(pg) = postgres_bundle.as_ref() {
        findings_remediation::RemediationTrackingBundle::build_pg(
            pg.pool.clone(),
            settings.database.statement_timeout_ms,
        )
    } else {
        findings_remediation::RemediationTrackingBundle::build()
    };
    // Finding bulk-update + export bundle reuses the shared
    // `FindingRepositoryPort` trait object so the per-id status mutations
    // and the read snapshot used for NDJSON/CSV export share one source
    // of truth with `GET /v1/findings` and `PATCH /v1/findings/{id}/status`.
    let finding_bulk_port = findings_bulk::build(Arc::clone(&findings));
    // Tenant write bundle shares the same `InMemoryTenants` instance as the
    // read-side `TenantRepositoryPort` so a tenant created via
    // `POST /v1/admin/tenants` is immediately observable from
    // `GET /v1/tenants/me`. When Postgres is enabled the in-memory handles
    // are absent — fall back to a standalone in-memory store so the trait
    // object remains satisfied (writes never reach Postgres yet, mirroring
    // the asset-write fallback above).
    let tenant_write_bundle = if let Some((_, _, ref ct)) = in_memory_handles {
        tenant_write::TenantWriteBundle::build(Arc::clone(ct))
    } else if let Some(pg) = postgres_bundle.as_ref() {
        // Postgres enabled: write to the same `tenants` table the read
        // adapter queries (previously this fell back to a detached in-memory
        // store, so admin tenant writes were invisible + lost on restart).
        tenant_write::TenantWriteBundle::from_port(Arc::new(postgres::PgTenantWriteAdapter::new(
            pg.pool.clone(),
            settings.database.statement_timeout_ms,
        )))
    } else {
        tenant_write::TenantWriteBundle::build(Arc::new(repository::InMemoryTenants::default()))
    };

    // --- Demo seed (in-memory + opt-in only) ----------------------------
    //
    // SX-REVIEW-002 / M2 — the seed is gated on `seed_demo_data` but
    // ran unconditionally on every boot before this. For the in-memory
    // path that's harmless (state is lost between boots); for a future
    // Pg-backed dev path it would silently double-write. We probe the
    // engagement repository for emptiness and skip the seed call if
    // anything is already present. Either branch emits a single info
    // line at startup so an operator can tell from the log whether the
    // seed applied or was a no-op.
    if settings.bootstrap.enabled && settings.bootstrap.seed_demo_data {
        if let (Some((concrete_assets, concrete_findings, concrete_tenants)), Some(inmem_eng)) =
            (in_memory_handles, inmem_engagement_repo.as_ref())
        {
            if inmem_eng.is_empty() {
                let tenant_id = settings.bootstrap.admin_tenant_id.map_or_else(
                    || "01010101-0101-0101-0101-010101010101".to_owned(),
                    |u| u.to_string(),
                );
                let inserted = seed::run(
                    &tenant_id,
                    &settings.bootstrap.admin_tenant_name,
                    concrete_tenants,
                    Arc::clone(inmem_eng),
                    concrete_assets,
                    concrete_findings,
                );
                tracing::info!(
                    target: "adapters.seed",
                    records = inserted,
                    "demo data seed: applied {inserted} records",
                );
            } else {
                tracing::info!(
                    target: "adapters.seed",
                    "demo data seed: repository already populated, skipped",
                );
            }
        }

        // SX-REVIEW-002 / M2 (problem 2) — when the operator opted into
        // dev-mode demo data but left Postgres disabled, every
        // Pg-backed RBA path lands LOW-002 / LOW-004 / LOW-005 is
        // silently exercising the in-memory stub. Surface that as a
        // single startup warn line so a "this looks fine in dev"
        // signal can't be misread as "production wiring validated".
        // The dev-mode-with-demo case is the specific concern; the
        // generic `postgres adapter disabled` log at line ~177 stays
        // at debug (M3 demoted it intentionally for prod paths).
        if !settings.database.enabled {
            tracing::warn!(
                target: "adapters.seed.pg_masked",
                "dev seed active with database.enabled=false — \
                 Postgres-backed RBA paths (LOW-002/LOW-004/LOW-005) \
                 are using in-memory stubs; production wiring is not \
                 validated by this run",
            );
        }
    }

    // OIDC exchange — wires `sx_iam::ExchangeOidcUseCase` behind the
    // `OidcExchangePort`. Disabled by default; flip `oidc.enabled = true`
    // in the loader config (plus issuer/audience/jwks_url) to install the
    // real JWKS-backed verifier.
    let oidc_http = reqwest::Client::builder()
        .user_agent("SentinelX-Monolith/0.1")
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| anyhow::anyhow!("oidc http client: {e}"))?;
    let oidc_exchange = oidc::build(
        &settings.oidc,
        Arc::clone(&iam_bundle.users),
        Arc::clone(&iam_bundle.issue),
        oidc_http,
    );

    // MED-004 — OAuth2 token endpoint + admin secret rotation + JWKS
    // publication. Uses the shared IAM JwtConfig so any token we mint
    // here is verifiable via the same code path as user tokens. The
    // signing-key registry is wired empty (HS-only deployment publishes
    // an empty JWKS); RS/EdDSA support lands once the asymmetric-key
    // rollout completes (LOW backlog).
    let oidc_client_bundle = oidc_client::build(oidc_client::BuildConfig {
        expected_audience: format!("https://{logout_base_url}/v1/oauth/token"),
        jwt_cfg: iam_runtime.jwt.clone(),
        registry: sx_iam::service::SigningKeyRegistry::empty(),
    });
    if settings.bootstrap.enabled {
        let tenant_id = settings.bootstrap.admin_tenant_id.map_or_else(
            sx_iam::domain::TenantId::new,
            sx_iam::domain::TenantId::from_uuid,
        );
        let (cid, _secret) =
            oidc_client::seed_dev_client(&oidc_client_bundle, tenant_id, "sx-dev-client");
        tracing::info!(
            target: "adapters.oidc_client",
            tenant_id = %tenant_id,
            client_id = %cid,
            "seeded dev-mode OIDC confidential client"
        );
    }

    // --- UEBA (P2-005) — must be built BEFORE the SOC adapter because
    //     SocAdapter::submit_event calls into the UEBA service on every
    //     event so the per-user behavioural baseline stays in sync with
    //     the SOC ingest pipeline.
    let ueba_bundle = ueba::build();

    // --- Phase-3.5+ adapters (SOC / Twin / Intel / Predictive / Redteam) -
    let soc_bundle = soc::build(ueba_bundle.service.clone());
    let twin_bundle = twin::build(Arc::clone(&assets), Arc::clone(&findings));
    let intel_check_bundle = intel_check::build();
    let pred_bundle = predictive::build(Arc::clone(&findings), Arc::clone(&assets));
    let rt_bundle = redteam::build(Arc::clone(&engagement_bundle.repo));
    // P1-012 — copilot human-in-loop approval queue. The composition
    // root could in principle wire the audit_query sink in here so
    // every transition appends to the existing audit chain; that
    // wiring lands alongside the recorder hookup. For now the
    // adapter runs without an audit sink — the in-crate per-token
    // history still records every transition.
    let copilot_approval_bundle = copilot_approval::build(None);
    // P3-005 — SOAR low-code workflow builder. Audit recorder defaults to
    // `None`; the per-tenant in-crate `InMemorySoarService` still records
    // every workflow CRUD + run transition in tracing so operators have
    // observability while the audit recorder wiring catches up.
    let soar_bundle = soar::build(
        None,
        postgres_bundle
            .as_ref()
            .map(|pg| (pg.pool.clone(), settings.database.statement_timeout_ms)),
    );
    // P2-006 — DLP content inspection. The in-memory service ships with
    // the full inspector set + a permissive default per-tenant config.
    // When the DB is enabled, the per-tenant detector config is persisted
    // so an admin override no longer reverts to permissive-all on restart.
    let dlp_bundle = if let Some(pg) = postgres_bundle.as_ref() {
        dlp::build_pg(pg.pool.clone(), settings.database.statement_timeout_ms)
    } else {
        dlp::build()
    };
    // P2-016 — container-runtime security (Falco) ingest bundle. Wires
    // a per-tenant HMAC-key store (in-memory provider) and, per PRG-04, a
    // durable audit sink forwarding each ingest batch into the shared
    // hash-chained sx-audit trail; the dev-mode admin tenant gets a seeded
    // key so the webhook is reachable from a smoke test out of the box.
    let runtime_audit_recorder = Arc::new(sx_audit::prelude::RecordAuditEventUseCase::new(
        Arc::clone(&audit_query_bundle.sink),
    ));
    let runtime_bundle = runtime::build(runtime_audit_recorder);
    if settings.bootstrap.enabled {
        runtime::seed_dev_tenant_key(&runtime_bundle, &settings.bootstrap).await;
    }
    // HIGH-009 — Kubernetes admission webhook (blocking mode). Wires
    // an in-memory tenant-rule-pack policy (seeded with the
    // `recommended` pack as the default — kube-system opt-out, PSS
    // baseline, no privileged, no host-network, no `:latest` tag) and a
    // tracing-based audit sink. The policy store is kept around so a
    // follow-up admin endpoint can swap per-tenant packs at runtime.
    let k8s_admission_bundle = if let Some(pg) = postgres_bundle.as_ref() {
        k8s_admission::build_pg(pg.pool.clone(), settings.database.statement_timeout_ms).await
    } else {
        k8s_admission::build()
    };
    // P2-013 — API DAST (Postman collection replay). Reuses the
    // long-lived `phase3_http` client so the replay engine does not
    // allocate a new TLS context per scan.
    let api_dast_bundle = api_dast::build(phase3_http.clone());
    // P3-006 — Threat-hunting KQL/SPL-like query surface. The bundle
    // installs a `NullExecutor` until the shared ClickHouse HTTP client
    // is plumbed through; the parser + compiler + audit pipeline is
    // fully wired and the tenant-isolation predicate is non-bypassable.
    let hunt_bundle = hunt::build();
    // AI-SEC-001 — comprehensive AI security audit. In-memory asset source
    // (seeded demo inventory) + in-memory copilot-decision audit sink; the
    // service records every run to the sink (ADR-0004 §7).
    // Shared copilot-decision audit trail (ADR-0004 §7): an in-memory store
    // for read-back, tee'd to the durable sx-audit chain (reusing the same
    // buffer sink the audit-query endpoints read). The SAME sink backs both
    // the AI-audit run path and the live copilot chat path, so every copilot
    // decision lands in one tamper-evident trail.
    let copilot_audit_mem = Arc::new(sx_ai_audit::copilot_audit::InMemoryCopilotAuditSink::new());
    let copilot_audit_recorder = Arc::new(sx_audit::prelude::RecordAuditEventUseCase::new(
        Arc::clone(&audit_query_bundle.sink),
    ));
    let copilot_audit_sink: Arc<dyn sx_ai_audit::copilot_audit::CopilotAuditSink> =
        Arc::new(copilot_audit_sink::AuditChainCopilotSink::new(
            Arc::clone(&copilot_audit_mem),
            copilot_audit_recorder,
        ));
    // #5 — real AI asset discovery: scan the dependency SBOM for AI SDKs /
    // vector DBs / model registries / agent frameworks / MCP, scoped to the
    // admin tenant (falls back to the dev tenant so the demo path shows it).
    let ai_asset_tenant = settings
        .bootstrap
        .admin_tenant_id
        .map_or_else(|| "dev-tenant".to_owned(), |u| u.to_string());
    let detected_ai_assets = ai_asset_discovery::detect_from_file(
        std::path::Path::new("sbom/sentinelx.syft.json"),
        &ai_asset_tenant,
    );
    let ai_audit_bundle = ai_audit::build(
        Arc::clone(&copilot_audit_sink),
        &settings.ai_copilot,
        phase3_http.clone(),
        detected_ai_assets,
        Arc::clone(&engagement_bundle.kill_switch_concrete),
        Arc::clone(&engagement_bundle.repo),
        &settings.engagement.global_denylist,
    );
    // P2-009 — GRC outbound integration. Reuses the long-lived
    // `phase3_http` client so the connector pool is shared with the
    // rest of the outbound adapters.
    let grc_bundle = grc::build(phase3_http.clone());
    // P3-010 — Bug-bounty bridge (HackerOne + Bugcrowd). Shares the
    // same long-lived HTTP client and reads the in-memory finding
    // corpus for inbound dedupe.
    let bugbounty_bundle = bugbounty::build(phase3_http.clone(), Arc::clone(&findings));
    let copilot_bundle = copilot::build(
        &settings.ai_copilot,
        phase3_http.clone(),
        std::sync::Arc::clone(&copilot_approval_bundle.copilot_approval),
        // Share the copilot-decision sink so live `/v1/copilot/chat` calls
        // append prompt/response hashes + model + user id to the same
        // sx-audit-backed trail the ai-audit run path uses (ADR-0004 §7).
        Arc::clone(&copilot_audit_sink),
    );
    // GraphSAGE per-asset risk cache shared between the writer (graphsage_job)
    // and the read port (graphsage_port). Both jobs are spawned but their
    // JoinHandles are dropped — Tokio aborts them on runtime shutdown.
    let graphsage_cache: Arc<std::sync::Mutex<std::collections::HashMap<String, f64>>> =
        Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
    let graphsage_risk_port: Arc<dyn sx_api::port::GraphsageRiskPort> = Arc::new(
        graphsage_port::GraphsageRiskAdapter::new(Arc::clone(&graphsage_cache)),
    );

    // --- Background jobs (spawn-and-forget) ------------------------------
    //
    // Four long-running tasks are spawned here:
    //
    //   * `graphsage_job`     — 15-minute cadence; writes per-asset risk
    //                           scores into the GraphSAGE cache.
    //   * `drift_job`         — 1-hour cadence; emits SOC events via mpsc
    //                           when ML-prediction drift breaches the KL
    //                           threshold.
    //   * `intel_feeds_job`   — TAXII poller cadence; spawned only when
    //                           `intel_feeds.enabled`.
    //   * `continuous_sim`    — 1-minute cadence; polls the autonomy
    //                           continuous simulator over a stub
    //                           catalogue + stub `SimulationPort`. The
    //                           real BAS hookup is deferred.
    //
    // A `CancellationToken` is built so the spawn helpers can cooperate
    // with a future shutdown surface; the current build never trips it
    // and lets Tokio's runtime drop drive cleanup on shutdown. Join
    // handles are kept in a local `Vec` so the tasks aren't detached
    // before `build_app_state` returns — they are then forgotten when
    // the vec drops at the end of the function (Tokio keeps the tasks
    // alive on the runtime until shutdown).
    let shutdown_token = tokio_util::sync::CancellationToken::new();
    let mut job_handles: Vec<tokio::task::JoinHandle<()>> = Vec::with_capacity(5);

    // MED-003 — webhook signing-key rotation, now wired live (replaces the
    // deterministic-422 Disabled adapter). The signing-key store is
    // Postgres-backed when the DB is enabled (keys survive restart), else
    // in-memory for dev. The HMAC secret column rides the SecretCipher
    // seam — PlaintextCipher in the non-KMS build, matching the platform's
    // posture; a KMS-backed cipher drops in without code change. The
    // rotation audit log uses the in-memory sink (rotations themselves are
    // durable; the separate audit log is a noted follow-up). The force-
    // rotate admin route and the background cadence job share one rotator.
    let webhook_key_rotation_admin: Arc<dyn sx_api::port::WebhookKeyRotationAdminPort> = {
        use sx_webhooks::signing::audit::RotationAuditSink;
        use sx_webhooks::signing::secret_cipher::{PlaintextCipher, SecretCipher};
        use sx_webhooks::signing::store::SigningKeyStore;
        use sx_webhooks::{InMemorySigningKeyStore, WebhookKeyRotator};

        let cipher: Arc<dyn SecretCipher> = Arc::new(PlaintextCipher);
        // Durable rotation-audit trail: forward every mint/retire into the
        // shared hash-chained sx-audit log (same sink the audit-query
        // endpoints read), instead of a process-local buffer.
        let rotation_recorder = Arc::new(sx_audit::prelude::RecordAuditEventUseCase::new(
            Arc::clone(&audit_query_bundle.sink),
        ));
        let audit: Arc<dyn RotationAuditSink> = Arc::new(
            webhooks_admin::RotationAuditChainSink::new(rotation_recorder),
        );
        let rotator = if let Some(pg) = postgres_bundle.as_ref() {
            sx_storage::repository::webhook_signing_keys::build_pg_rotator(
                pg.pool.clone(),
                settings.database.statement_timeout_ms,
                Arc::clone(&cipher),
                Arc::clone(&audit),
            )
        } else {
            let store: Arc<dyn SigningKeyStore> = Arc::new(InMemorySigningKeyStore::new());
            WebhookKeyRotator::new(store, Arc::clone(&cipher), Arc::clone(&audit))
        };
        // Background cadence job (spawned when webhook_signing_rotation is
        // enabled — now the default). Shares a clone of the rotator.
        if let Some(handle) =
            webhooks_rotation_job::spawn(&settings.webhook_signing_rotation, rotator.clone())
        {
            job_handles.push(handle);
        }
        webhooks_admin::InProcessWebhookKeyRotationAdmin::new(
            rotator,
            Arc::new(settings.webhook_signing_rotation.clone()),
        )
        .into_arc()
    };

    // GraphSAGE — 15 minutes.
    job_handles.push(graphsage_job::spawn(
        Arc::clone(&findings),
        Arc::clone(&assets),
        Arc::clone(&graphsage_cache),
        graphsage_job::GraphsageJobConfig { interval_secs: 900 },
        shutdown_token.clone(),
    ));

    // Drift detector — 1 hour. Owns the drift→SOC mpsc channel; the
    // receiver end is forwarded into the SOC port by a tiny adapter
    // task so the correlator pipeline observes drift events alongside
    // operator-submitted events.
    let (drift_event_tx, mut drift_event_rx) = tokio::sync::mpsc::channel::<serde_json::Value>(256);
    job_handles.push(drift_job::spawn(
        Arc::clone(&pred_bundle.predict),
        drift_event_tx,
        drift_job::DriftJobConfig {
            interval_secs: 3_600,
            threshold: 0.5,
        },
        shutdown_token.clone(),
    ));
    // Drift → SOC forwarder. The SocPort's `submit_event` is the same
    // entry the HTTP layer uses, so drift events flow through the
    // identical correlator + buffered-sink path. The task exits when
    // the drift_job drops its sender (process shutdown) or the SOC
    // port refuses an event (correlator channel closed).
    let soc_for_forwarder: Arc<dyn sx_api::port::SocPort> = Arc::clone(&soc_bundle.soc);
    let drift_forwarder_shutdown = shutdown_token.clone();
    job_handles.push(tokio::spawn(async move {
        loop {
            tokio::select! {
                () = drift_forwarder_shutdown.cancelled() => {
                    tracing::info!(
                        target: "adapters.drift_forwarder",
                        "drift→soc forwarder received cancellation, exiting",
                    );
                    return;
                }
                event = drift_event_rx.recv() => {
                    let Some(event) = event else {
                        tracing::info!(
                            target: "adapters.drift_forwarder",
                            "drift→soc forwarder channel closed, exiting",
                        );
                        return;
                    };
                    if let Err(err) = soc_for_forwarder.submit_event(event).await {
                        tracing::warn!(
                            target: "adapters.drift_forwarder",
                            error = %err,
                            "drift→soc forwarder dropped event",
                        );
                    }
                }
            }
        }
    }));

    // Intel feeds — only when enabled. We thread the shared bloom from
    // the `intel_check` bundle so freshly-ingested indicators land in the
    // same hot-path filter the `/v1/intel/check` endpoint reads. The
    // per-tenant repository is Postgres-backed (`tenant_iocs` +
    // `intel_feed_status`) when the database is enabled so ingested IOCs
    // and feed health survive a restart (PRG-03); in-memory otherwise.
    let intel_feeds_repo: std::sync::Arc<dyn sx_intel_feeds::TenantIocRepository> =
        if let Some(pg) = postgres_bundle.as_ref() {
            std::sync::Arc::new(intel_ioc_repo::PgTenantIocRepository::new(
                pg.pool.clone(),
                settings.database.statement_timeout_ms,
            ))
        } else {
            std::sync::Arc::new(sx_intel_feeds::InMemoryRepository::new())
        };
    if settings.intel_feeds.enabled {
        if let Some(handle) = intel_feeds_job::spawn_with(
            &settings.intel_feeds,
            std::sync::Arc::clone(&intel_check_bundle.bloom),
            std::sync::Arc::clone(&intel_feeds_repo),
        ) {
            job_handles.push(handle);
        } else {
            tracing::warn!(
                target: "adapters.intel_feeds_job",
                "intel_feeds.enabled = true but spawn returned None; not pushed",
            );
        }
    } else {
        tracing::info!(
            target: "adapters.intel_feeds_job",
            "intel_feeds disabled by config; TAXII poller not spawned",
        );
    }

    // Continuous simulator — 1 minute. Stub catalogue + stub
    // `SimulationPort` returning `Pass` for now; the real BAS hookup
    // lands in a follow-up phase.
    let continuous_simulator = continuous_sim::build_stub_simulator()
        .map_err(|e| anyhow::anyhow!("continuous simulator stub init: {e}"))?;
    job_handles.push(continuous_sim::spawn(
        continuous_simulator,
        shutdown_token.clone(),
    ));

    // --- CRIT-002: audit chain background verifier ----------------------
    //
    // Default cadence: 5 min per tenant (sx_audit::DEFAULT_INTERVAL).
    // Reads the same `InMemoryAuditBufferSink` the recorder appends to,
    // so a tampered hot tail is caught within one tick. On break the
    // verifier fans out to the IR auto-fire subscriber registered by
    // `adapters::ir::build()`. Tenant rotation: when bootstrap is
    // enabled we register the bootstrap tenant up-front; SCIM / tenant
    // provisioning code paths add more via
    // `ChainVerifier::register_tenant`.
    // TOP5-#3-P2-007 — translate every chain-break event into a
    // synthetic `Finding` via the FOUND-001 `FindingRepositoryPort::insert`
    // surface, alongside the IR auto-fire incident. Wired against the
    // *same* shared `findings` trait object the rest of the
    // composition root uses so the remediation-outcomes observer
    // installed earlier still sees status transitions on
    // chain-break findings.
    let audit_break_finding_subscriber: Arc<dyn sx_audit::chain_verifier::BrokenChainSubscriber> =
        Arc::new(audit_break_observer::AuditBreakFindingEmitter::new(
            Arc::clone(&findings),
            settings.audit.system_engagement_id,
        ));
    let audit_chain_subscribers: Vec<Arc<dyn sx_audit::chain_verifier::BrokenChainSubscriber>> = vec![
        Arc::clone(&ir_bundle.chain_broken_subscriber),
        Arc::clone(&audit_break_finding_subscriber),
    ];
    let chain_verifier_bundle = chain_verifier::build(
        Arc::clone(&audit_query_bundle.sink),
        audit_chain_subscribers,
    );
    if settings.bootstrap.enabled {
        if let Some(uuid) = settings.bootstrap.admin_tenant_id {
            let tid: sx_core::value_object::ids::TenantId = uuid.into();
            chain_verifier_bundle.verifier.register_tenant(tid).await;
            tracing::info!(
                target: "monolith.chain_verifier",
                tenant = %tid,
                "bootstrap tenant registered with audit chain verifier"
            );
        }
    }
    job_handles.push(chain_verifier::spawn_loop(
        Arc::clone(&chain_verifier_bundle.verifier),
        shutdown_token.clone(),
    ));
    // P2-001 — scheduled-report distribution tick loop.
    job_handles.push(report_scheduler::spawn(&report_scheduler_bundle));
    // #6 — SCA/SBOM continuous monitor. Parses the checked-in grype report
    // into findings (which auto-alert via the #2 decorator). No-ops unless
    // bootstrap is enabled with a tenant id and the report exists.
    if let Some(handle) = sca_monitor::spawn(
        Arc::clone(&findings),
        settings
            .bootstrap
            .enabled
            .then_some(settings.bootstrap.admin_tenant_id)
            .flatten(),
        // Conventional location of the checked-in grype report (the
        // `sbom-and-grype` CI job writes it here). Operators relocate it by
        // symlinking; the monitor no-ops when the file is absent.
        std::path::PathBuf::from("sbom/sentinelx-vulns.json"),
    ) {
        job_handles.push(handle);
    }

    tracing::info!(
        target: "adapters.background_jobs",
        spawned = job_handles.len(),
        intel_feeds_enabled = settings.intel_feeds.enabled,
        "background jobs spawned",
    );

    // Tasks are intentionally left running. `job_handles` drops at end
    // of scope; Tokio keeps the tasks scheduled on the runtime until
    // process shutdown drives cleanup.
    drop(job_handles);
    drop(shutdown_token);

    Ok(AppState {
        // SELL-P1-05: readiness checks the live Postgres pool (SELECT 1)
        // when the database is enabled, else reports in-memory dev mode.
        readiness: Arc::new(readiness::MonolithReadinessProbe::new(
            postgres_bundle.as_ref().map(|pg| pg.pool.clone()),
        )),
        authn: iam_bundle.authn,
        token_validator: iam_bundle.token_validator,
        refresh: iam_bundle.refresh,
        logout: iam_bundle.logout,
        oidc_exchange,
        oidc_rp_logout: logout_bundle.oidc_rp,
        oidc_backchannel_logout: logout_bundle.oidc_backchannel,
        oidc_frontchannel_logout: logout_bundle.oidc_frontchannel,
        oidc_discovery: logout_bundle.discovery,
        saml_backchannel_logout: logout_bundle.saml_backchannel,
        engagements: engagement_bundle.service,
        kill_switch: engagement_bundle.kill_switch,
        risk: risk_adapter,
        risk_tuning: risk_tuning_port,
        discovery: discovery_adapter,
        assets,
        findings,
        tenants,
        server_cfg: Arc::new(settings.server.clone()),
        rate_limit_cfg: Arc::new(rate_limit_cfg),
        rate_limiter: Arc::new(RateLimiterState::new()),
        release_channel_cfg: Arc::new(settings.release_channel.clone()),
        bas: phase3.bas,
        pentest: pentest_bundle.port,
        graph: phase3.graph,
        blast_radius: Arc::new(blast_radius::BlastRadiusAdapter::new(
            graph_for_blast_radius,
        )),
        report: phase3.report,
        branding: branding_bundle.branding,
        report_schedules: Arc::clone(&report_scheduler_bundle.port),
        comprehensive_report: comprehensive_report_bundle.port,
        report_diff: phase3.report_diff,
        remediation: phase3.remediation,
        compliance: phase3.compliance,
        compliance_evidence: compliance_evidence_bundle.port,
        ml: phase3.ml,
        cloud_inventory: cloud_inventory_port,
        propose_pr: autonomy_propose_pr,
        submit_threat: autonomy_submit_threat,
        schedule_validation: autonomy_schedule_validation,
        collab_alloc: collab_alloc_port,
        collab_lookup: collab_lookup_port,
        create_user: admin_bundle.create_user,
        customer_auth: ca_bundle.auth,
        approvals: approvals_port,
        bas_history: Arc::new(bas::InMemoryBasRunHistory::default()),
        bas_chain: Arc::new(bas_chain::InMemoryBasChainAdapter::new(bas_chain_use_case)),
        http_header_scanner: Arc::new(scanner_http::HttpHeaderScanner::new(phase3_http.clone())),
        soc: soc_bundle.soc,
        twin: twin_bundle.twin,
        intel_check: intel_check_bundle.check,
        predictive: pred_bundle.predict,
        redteam: rt_bundle.redteam,
        copilot: copilot_bundle.copilot,
        copilot_approval: copilot_approval_bundle.copilot_approval,
        graphsage_risk: graphsage_risk_port,
        roles: roles_bundle.roles,
        asset_write: asset_write_bundle.write,
        asset_bulk: asset_bulk_bundle.bulk,
        finding_bulk: finding_bulk_port,
        tenant_write: tenant_write_bundle.write,
        remediation_tracking: remediation_tracking_bundle.tracking,
        audit_query: audit_query_bundle.audit_query,
        audit_replay: audit_query_bundle.audit_replay,
        audit_anchor: audit_anchor_bundle.audit_anchor,
        // CRIT-003 — per-tenant DEK rotation admin port. The default
        // disabled-mode adapter surfaces a deterministic 422 with
        // "dek rotation disabled" until a deployment wires in the
        // production rotation stack (KMS + visitor registry + Postgres
        // progress store). The HTTP routes themselves are reachable
        // immediately so smoke tests / RBAC enforcement can validate
        // the surface without the data plane being live.
        dek_rotation_admin: Arc::new(secrets_admin::DisabledDekRotationAdmin),
        // MED-003 — per-tenant webhook signing-key rotation admin port,
        // wired live above (Postgres-backed signing-key store when the DB
        // is enabled, in-memory in dev; SecretCipher seam for the HMAC
        // secret; shared rotator drives both this route and the cadence
        // job).
        webhook_key_rotation_admin,
        engagement_transitions: engagement_bundle.transitions,
        engagement_clone: engagement_clone_bundle.clone_port,
        mfa: mfa_bundle.mfa,
        webauthn: webauthn_bundle.webauthn,
        log_ingest: log_ingest_bundle.log_ingest,
        log_rate_limit: log_ingest_bundle.log_rate_limit,
        vuln_ingest: if let Some(pg) = postgres_bundle.as_ref() {
            Arc::new(vuln_ingest::VulnIngestAdapter::new_pg(
                pg.pool.clone(),
                settings.database.statement_timeout_ms,
            ))
        } else {
            Arc::new(vuln_ingest::VulnIngestAdapter::new())
        },
        prowler_import: Arc::new(prowler_import::ProwlerImportAdapter::new()),
        scim: scim_bundle.scim,
        rba: rba_adapter,
        remediation_outcomes: remediation_outcomes_port,
        ueba: ueba_bundle.port,
        // HIGH-010 — UEBA freeze-mode admin port.
        ueba_admin: ueba_bundle.admin_port,
        soar: soar_bundle.soar,
        grc: grc_bundle.grc,
        device_trust: device_trust_bundle.device_trust,
        saml_sp: saml_sp_port,
        saml_idp_admin,
        dlp: dlp_bundle.dlp,
        plugins: plugins_bundle.plugins,
        cloud_drift: cloud_drift_port,
        chaos: chaos_registry.clone(),
        chaos_admin: sx_chaos::admin::ChaosAdminService::new(
            chaos_registry,
            Arc::new(sx_chaos::admin::InMemoryChaosAuditSink::new()),
        ),
        ir: ir_bundle.port,
        runtime_falco: runtime_bundle.service,
        k8s_admission: k8s_admission_bundle.port,
        runtime_falco_overrides: runtime_bundle.overrides_port,
        oidc_client_token: oidc_client_bundle.token,
        oidc_client_rotate: oidc_client_bundle.rotate,
        jwks_publish: oidc_client_bundle.jwks,
        api_dast: api_dast_bundle.api_dast,
        bugbounty: bugbounty_bundle.bugbounty,
        hunt: hunt_bundle.hunt,
        ai_audit: ai_audit_bundle.ai_audit,
        admin_user_list: admin_bundle.admin_user_list,
        intel_feed_status: intel_feed_status::InMemoryIntelFeedStatusAdapter::shared(),
        device_registry: Arc::new(device_registry::DeviceRegistryAdapter::in_memory()),
    })
}
