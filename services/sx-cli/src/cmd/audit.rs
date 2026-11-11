//! `sx audit ...` — verify chains and dump audit logs.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use anyhow::{anyhow, Context};
use clap::{Args, Subcommand};
use secrecy::SecretString;
use time::format_description::well_known::Rfc3339;
use tracing::instrument;

use sx_audit::prelude::{verify_entries, AuditEntry, AuditError, ChainError, HashChain};
use sx_core::value_object::ids::TenantId;

use crate::output::{
    print_hmac_verify_failure, print_hmac_verify_report, print_verify_failure, print_verify_report,
    OutputFormat, TenantSummary,
};

/// The `audit` family of sub-commands.
#[derive(Debug, Subcommand)]
pub enum AuditCommand {
    /// Verify a tenant's hash chain from a newline-delimited JSON dump.
    ///
    /// The dump file must contain one [`sx_audit::prelude::AuditEntry`]
    /// per line, in ascending `seq` order. Verification re-derives
    /// every entry's hash and reports the first divergence, if any.
    /// Exit codes: `0` for clean, `1` for any divergence.
    Verify(VerifyArgs),
    /// Dump the audit log for a tenant.
    ///
    /// Phase-1 stub. The Postgres-backed sink is implemented in
    /// `sx-storage` downstream; supplying `--from-redis` returns exit
    /// code 2 with a "not yet implemented (Phase-2)" message.
    Dump(DumpArgs),
    /// CRIT-002 drill simulator: inject a tampered row into a TEST
    /// tenant's exported chain dump, fire the IR `audit_chain_compromise`
    /// playbook against an in-memory IR service, and emit a
    /// post-incident report.
    ///
    /// Refuses to run unless the supplied tenant id matches the test
    /// fixture pattern `00000000-0000-7000-8000-0000000000ff` OR the
    /// `SX_AUDIT_DRILL_ALLOW=1` env var is set in addition. This is the
    /// non-bypassable "real tenant safeguard" called out in CRIT-002
    /// acceptance criterion #5.
    SimulateBreak(SimulateBreakArgs),
}

/// Arguments for `sx audit verify`.
///
/// Two modes are supported:
///
/// 1. **Single-tenant SHA-256 chain** (legacy): pass `--tenant` and
///    `--from <path>` where the file is newline-delimited JSON. The
///    SHA-256 chain is recomputed for the given tenant only.
/// 2. **Multi-tenant HMAC chain** (anchored): pass `--signing-key-env`
///    and `--source <path>`. The source may be either a JSON **array**
///    of entries or newline-delimited JSON. Entries are grouped by
///    `tenant_id` and each group's HMAC chain is verified. The CLI
///    exits non-zero on any tampering and prints a per-tenant summary.
#[derive(Debug, Args)]
pub struct VerifyArgs {
    /// Tenant whose chain is being verified (UUID). Required for the
    /// single-tenant SHA-256 mode; ignored when `--signing-key-env`
    /// is supplied because HMAC verification groups by `tenant_id`
    /// found in each entry.
    #[arg(long)]
    pub tenant: Option<String>,
    /// Path to the newline-delimited JSON dump (single-tenant SHA-256
    /// mode). Either `--from` or `--source` must be supplied.
    #[arg(long)]
    pub from: Option<PathBuf>,
    /// Path to the JSON-array (or NDJSON) audit-event source (HMAC
    /// mode). When supplied alongside `--signing-key-env`, the HMAC
    /// chain is verified per-tenant.
    #[arg(long)]
    pub source: Option<PathBuf>,
    /// Name of the environment variable that holds the per-tenant
    /// signing key (e.g. `SENTINELX__IAM__ATTEMPT_EMAIL_PEPPER`). When
    /// supplied, HMAC chain verification is performed.
    ///
    /// **Production note**: this MVP reuses the IAM attempt-email
    /// pepper as the audit signing key. A separate KMS-managed key
    /// per tenant is a deferred item.
    #[arg(long = "signing-key-env")]
    pub signing_key_env: Option<String>,
    /// Optional output path for the (currently no-op) re-verified
    /// dump — accepted for symmetry with the future `dump` command and
    /// for shell pipelines that pre-allocate destinations.
    #[arg(long)]
    pub to: Option<PathBuf>,
}

/// Arguments for `sx audit dump`.
#[derive(Debug, Args)]
pub struct DumpArgs {
    /// Tenant whose log to dump (UUID).
    #[arg(long)]
    pub tenant: String,
    /// Destination path for the JSON dump.
    #[arg(long)]
    pub to: PathBuf,
    /// Phase-2 hint: pull entries from a Redis stream. Not yet implemented.
    #[arg(long = "from-redis")]
    pub from_redis: Option<String>,
}

/// Arguments for `sx audit simulate-break`.
#[derive(Debug, Args)]
pub struct SimulateBreakArgs {
    /// Test tenant uuid. MUST match the canonical test-tenant pattern
    /// `00000000-0000-7000-8000-0000000000ff` unless
    /// `SX_AUDIT_DRILL_ALLOW=1` is set (e.g. for staging drills).
    #[arg(long)]
    pub tenant: String,
    /// Seq number at which to inject the tampered row. Must be `>= 2`
    /// (genesis must always remain clean so the verifier can find a
    /// last-good baseline). Capped at `100` to keep the drill cheap.
    #[arg(long)]
    pub seq: u64,
    /// Where to write the JSON-array post-incident report. Optional —
    /// the drill report is also rendered to stdout via the regular
    /// `--json` flag.
    #[arg(long = "report-out")]
    pub report_out: Option<PathBuf>,
}

/// Canonical test-tenant UUID. The drill simulator refuses to operate
/// on any other tenant unless `SX_AUDIT_DRILL_ALLOW=1` is set.
pub const DRILL_TEST_TENANT: &str = "00000000-0000-7000-8000-0000000000ff";

/// `SX_AUDIT_DRILL_ALLOW=1` escape hatch — present so staging drills
/// can target a real-but-non-production tenant when the operator has
/// explicitly opted in.
const DRILL_ALLOW_ENV: &str = "SX_AUDIT_DRILL_ALLOW";

/// Entry point for `sx audit`. Returns the process exit code.
#[instrument(skip_all)]
pub fn run(cmd: &AuditCommand, fmt: OutputFormat) -> anyhow::Result<i32> {
    match cmd {
        AuditCommand::Verify(args) => run_verify(args, fmt),
        AuditCommand::Dump(args) => run_dump(args, fmt),
        AuditCommand::SimulateBreak(args) => run_simulate_break(args, fmt),
    }
}

fn run_verify(args: &VerifyArgs, fmt: OutputFormat) -> anyhow::Result<i32> {
    // Dispatch on mode.
    if args.signing_key_env.is_some() || args.source.is_some() {
        return run_verify_hmac(args, fmt);
    }
    run_verify_sha256(args, fmt)
}

fn run_verify_sha256(args: &VerifyArgs, fmt: OutputFormat) -> anyhow::Result<i32> {
    let tenant_str = args
        .tenant
        .as_deref()
        .ok_or_else(|| anyhow!("--tenant is required for the single-tenant SHA-256 chain mode"))?;
    let from = args
        .from
        .as_ref()
        .ok_or_else(|| anyhow!("--from is required for the single-tenant SHA-256 chain mode"))?;
    let tenant = TenantId::from_str(tenant_str)
        .with_context(|| format!("invalid tenant uuid: {tenant_str}"))?;
    let entries = read_ndjson_entries(from)
        .with_context(|| format!("failed to read entries from {}", from.display()))?;

    // Sanity-check tenant ids — every entry must belong to the requested tenant.
    for (i, e) in entries.iter().enumerate() {
        if e.tenant_id != tenant {
            return Err(anyhow!(
                "entry #{i} (seq {}) belongs to tenant {}, expected {}",
                e.seq,
                e.tenant_id,
                tenant
            ));
        }
    }

    let expected_first = entries.first().map_or(1, |e| e.seq);
    match verify_entries(&entries, expected_first) {
        Ok(report) => {
            let first_ts = entries.first().and_then(|e| e.ts.format(&Rfc3339).ok());
            let last_ts = entries.last().and_then(|e| e.ts.format(&Rfc3339).ok());
            print_verify_report(
                &tenant.to_string(),
                report.entries_checked,
                first_ts.as_deref(),
                last_ts.as_deref(),
                fmt,
            )?;
            Ok(0)
        }
        Err(err) => {
            let (seq, msg) = describe_audit_error(&err);
            print_verify_failure(&tenant.to_string(), seq, &msg, fmt);
            Ok(1)
        }
    }
}

fn run_verify_hmac(args: &VerifyArgs, fmt: OutputFormat) -> anyhow::Result<i32> {
    let env_var = args
        .signing_key_env
        .as_deref()
        .ok_or_else(|| anyhow!("--signing-key-env is required for HMAC chain verification"))?;
    let source = args
        .source
        .as_ref()
        .or(args.from.as_ref())
        .ok_or_else(|| anyhow!("--source (or --from) is required"))?;

    let key_value = read_env_var(env_var).map_err(|_| {
        anyhow!(
            "signing key environment variable `{env_var}` is unset \
             or not unicode; expected the audit chain signing key"
        )
    })?;
    let signing_key = SecretString::from(key_value);
    let chain = HashChain::new(signing_key)
        .map_err(|e| anyhow!("invalid signing key from `{env_var}`: {e}"))?;

    let entries = read_audit_source(source)
        .with_context(|| format!("failed to read audit source from {}", source.display()))?;

    // Group by tenant, preserve per-tenant insertion order.
    let mut by_tenant: BTreeMap<TenantId, Vec<AuditEntry>> = BTreeMap::new();
    for entry in entries {
        by_tenant.entry(entry.tenant_id).or_default().push(entry);
    }
    for v in by_tenant.values_mut() {
        v.sort_by_key(|e| e.seq);
    }

    let mut summaries: Vec<TenantSummary> = Vec::with_capacity(by_tenant.len());
    let mut first_failure: Option<(TenantId, ChainError)> = None;
    for (tenant_id, group) in &by_tenant {
        let result = chain.verify(group);
        let (status, message) = match &result {
            Ok(()) => ("ok".to_owned(), None),
            Err(err) => ("fail".to_owned(), Some(describe_chain_error(err))),
        };
        let first_seq = group.first().map_or(0, |e| e.seq);
        let last_seq = group.last().map_or(0, |e| e.seq);
        summaries.push(TenantSummary {
            tenant: tenant_id.to_string(),
            entries: group.len() as u64,
            first_seq,
            last_seq,
            status,
            message,
        });
        if result.is_err() && first_failure.is_none() {
            if let Err(e) = result {
                first_failure = Some((*tenant_id, e));
            }
        }
    }

    match first_failure {
        None => {
            print_hmac_verify_report(&summaries, true, fmt)?;
            Ok(0)
        }
        Some((tenant_id, err)) => {
            let (seq, msg) = (chain_error_seq(&err), describe_chain_error(&err));
            print_hmac_verify_report(&summaries, false, fmt)?;
            print_hmac_verify_failure(&tenant_id.to_string(), seq, &msg, fmt);
            Ok(1)
        }
    }
}

/// Read an audit source that may be either a JSON array of entries or
/// a newline-delimited JSON stream. Empty lines are tolerated.
pub fn read_audit_source(path: &Path) -> anyhow::Result<Vec<AuditEntry>> {
    let mut buf = String::new();
    let mut f = File::open(path).with_context(|| format!("opening {} for read", path.display()))?;
    f.read_to_string(&mut buf)
        .with_context(|| format!("reading {} into memory", path.display()))?;
    let trimmed = buf.trim_start();
    if trimmed.starts_with('[') {
        let entries: Vec<AuditEntry> = serde_json::from_str(trimmed)
            .with_context(|| format!("parsing JSON array from {}", path.display()))?;
        return Ok(entries);
    }
    // Fall back to NDJSON.
    let mut entries = Vec::new();
    for (i, line) in buf.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let entry: AuditEntry = serde_json::from_str(line)
            .with_context(|| format!("parsing line {} of {}", i + 1, path.display()))?;
        entries.push(entry);
    }
    Ok(entries)
}

/// Thin wrapper around `std::env::var` so the clippy disallow can be
/// allowed in exactly one place. The CLI deliberately reads env vars
/// here because the operator selects which variable holds the audit
/// signing key via `--signing-key-env <name>`; the `sx-config` schema
/// is for service-level configuration, not for one-shot CLI flags.
#[allow(clippy::disallowed_methods)]
fn read_env_var(name: &str) -> Result<String, std::env::VarError> {
    std::env::var(name)
}

fn describe_chain_error(err: &ChainError) -> String {
    err.to_string()
}

fn chain_error_seq(err: &ChainError) -> u64 {
    match err {
        ChainError::HashMismatch { at_seq, .. }
        | ChainError::PrevHashMismatch { at_seq, .. }
        | ChainError::SequenceGap { at_seq, .. }
        | ChainError::MalformedHash { at_seq, .. } => *at_seq,
        _ => 0,
    }
}

fn run_dump(args: &DumpArgs, fmt: OutputFormat) -> anyhow::Result<i32> {
    if args.from_redis.is_some() {
        match fmt {
            OutputFormat::Human => {
                eprintln_user("not yet implemented (Phase-2): --from-redis stream dump");
            }
            OutputFormat::Json => {
                eprintln_user(
                    "{\"status\":\"unimplemented\",\"phase\":\"Phase-2\",\"feature\":\"from-redis\"}",
                );
            }
        }
        return Ok(2);
    }
    let _ = TenantId::from_str(&args.tenant)
        .with_context(|| format!("invalid tenant uuid: {}", args.tenant))?;
    Err(anyhow!(
        "audit dump from the Phase-1 in-memory sink is not yet implemented; \
         the Postgres-backed sink ships with `sx-storage` in Phase-2. \
         For now, dumps must be produced by the storage layer directly and \
         then verified with `sx audit verify --from <path>`. Requested target: {}",
        args.to.display()
    ))
}

/// Read a newline-delimited JSON dump into a vector of [`AuditEntry`].
/// Empty lines are tolerated.
///
/// Exposed for testing.
pub fn read_ndjson_entries(path: &Path) -> anyhow::Result<Vec<AuditEntry>> {
    let f = File::open(path).with_context(|| format!("opening {} for read", path.display()))?;
    let mut entries = Vec::new();
    for (i, line) in BufReader::new(f).lines().enumerate() {
        let line =
            line.with_context(|| format!("reading line {} from {}", i + 1, path.display()))?;
        if line.trim().is_empty() {
            continue;
        }
        let entry: AuditEntry = serde_json::from_str(&line)
            .with_context(|| format!("parsing line {} of {}", i + 1, path.display()))?;
        entries.push(entry);
    }
    Ok(entries)
}

fn describe_audit_error(err: &AuditError) -> (u64, String) {
    match err {
        AuditError::ChainDivergence {
            at_seq,
            expected,
            actual,
        } => (
            *at_seq,
            format!("chain divergence at seq {at_seq}: expected {expected}, got {actual}"),
        ),
        AuditError::SequenceGap { at_seq } => (*at_seq, format!("sequence gap at seq {at_seq}")),
        other => (0, other.to_string()),
    }
}

// Intentionally separate from the print_* helpers because stderr is
// disallowed by the workspace clippy config; we route through a single
// local sink that documents the allow. The `audit dump --from-redis`
// Phase-2 stub uses this to surface the not-yet-implemented notice on
// stderr while exit code 2 communicates the result programmatically.
#[allow(clippy::print_stderr, clippy::disallowed_macros)]
fn eprintln_user(msg: &str) {
    eprintln!("{msg}");
}

// ---------------------------------------------------------------------------
// CRIT-002 drill simulator
// ---------------------------------------------------------------------------

/// Thin wrapper around `std::env::var` so the clippy disallow can be
/// allowed in exactly one place; mirrors `read_env_var` above.
#[allow(clippy::disallowed_methods)]
fn read_drill_allow() -> bool {
    std::env::var(DRILL_ALLOW_ENV)
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

#[allow(clippy::print_stdout, clippy::disallowed_macros)]
fn println_user(msg: &str) {
    println!("{msg}");
}

/// Drill report — the JSON shape emitted to `--report-out` (and to
/// stdout when `--json` is set).
#[derive(Debug, serde::Serialize)]
struct DrillReport {
    incident_id: String,
    playbook_id: String,
    final_state: String,
    final_phase: String,
    tampered_seq: u64,
    last_good_seq: Option<u64>,
    detected_at: String,
    deduplicated: bool,
    steps_walked: usize,
}

fn run_simulate_break(args: &SimulateBreakArgs, fmt: OutputFormat) -> anyhow::Result<i32> {
    // ---- Safety gate ---------------------------------------------------
    if args.tenant != DRILL_TEST_TENANT && !read_drill_allow() {
        return Err(anyhow!(
            "refusing to simulate a chain break on tenant {} — drill simulator only \
             targets the canonical test tenant {DRILL_TEST_TENANT}. Set \
             {DRILL_ALLOW_ENV}=1 if you really mean to drill on a non-default tenant.",
            args.tenant
        ));
    }
    if args.seq < 2 {
        return Err(anyhow!(
            "--seq must be >= 2 (genesis must remain clean so the verifier can \
             find a last-good baseline)"
        ));
    }
    if args.seq > 100 {
        return Err(anyhow!("--seq capped at 100 to keep the drill cheap"));
    }
    let tenant_uuid = TenantId::from_str(&args.tenant)
        .with_context(|| format!("invalid tenant uuid: {}", args.tenant))?;

    // The drill runs entirely inside a tokio runtime so we can drive
    // the async chain verifier + IR auto-fire path. We use the basic
    // current-thread runtime — the CLI process is short-lived and the
    // drill is a single tick.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("build tokio runtime for drill")?;
    let report = runtime.block_on(execute_drill(tenant_uuid, args.seq))?;

    if let Some(path) = &args.report_out {
        let s = serde_json::to_string_pretty(&report).context("serialise drill report")?;
        std::fs::write(path, s)
            .with_context(|| format!("write drill report to {}", path.display()))?;
    }
    match fmt {
        OutputFormat::Json => {
            let s = serde_json::to_string(&report).context("serialise drill report")?;
            println_user(&s);
        }
        OutputFormat::Human => {
            println_user(&format!(
                "drill ok: incident={} state={} phase={} steps_walked={} tampered_seq={} last_good_seq={:?}",
                report.incident_id,
                report.final_state,
                report.final_phase,
                report.steps_walked,
                report.tampered_seq,
                report.last_good_seq,
            ));
        }
    }
    Ok(0)
}

/// Drive the drill end-to-end inside the runtime. Pure (returns a
/// `Result`) so the unit tests can exercise it directly.
#[allow(clippy::too_many_lines)]
async fn execute_drill(tenant: TenantId, break_seq: u64) -> anyhow::Result<DrillReport> {
    use std::sync::Arc;

    use sx_audit::chain_verifier::{
        BrokenChainSubscriber, ChainVerifier, RecordingSubscriber, DEFAULT_INTERVAL,
    };
    use sx_audit::prelude::{
        build_entry, build_genesis, Actor, AuditAction, AuditEntry as Entry, AuditSink,
        NewAuditEvent,
    };
    use sx_ir_playbooks::{IrPlaybookService as _, StepStatus};

    // -- 1. Build an in-memory clean chain on a VecSink ----------------
    let sink: Arc<VecSink> = Arc::new(VecSink::default());
    let chain_len = (break_seq + 3).max(5);
    let chain_len_usize = usize::try_from(chain_len)
        .map_err(|_| anyhow!("chain length {chain_len} does not fit in usize"))?;
    let mut entries: Vec<Entry> = Vec::with_capacity(chain_len_usize);
    let payload = |i: u64| NewAuditEvent {
        tenant_id: tenant,
        actor: Actor::system(),
        action: AuditAction::Login,
        resource_kind: "drill".into(),
        resource_id: format!("d-{i}"),
        before: None,
        after: None,
        request_id: format!("drill-{i}"),
        ts: None,
    };
    let g = build_genesis(payload(1)).context("build genesis")?;
    entries.push(g);
    for i in 2..=chain_len {
        let prev = entries.last().ok_or_else(|| anyhow!("no prev entry"))?;
        let e = build_entry(i, prev.hash, payload(i)).context("build entry")?;
        entries.push(e);
    }

    // -- 2. Tamper the target seq --------------------------------------
    let idx = usize::try_from(break_seq - 1)
        .map_err(|_| anyhow!("break_seq {break_seq} does not fit in usize"))?;
    if let Some(target) = entries.get_mut(idx) {
        target.request_id = format!("TAMPERED-DRILL-{break_seq}");
    } else {
        return Err(anyhow!(
            "tamper index {idx} out of bounds for chain length {}",
            entries.len()
        ));
    }

    // -- 3. Persist into the in-memory sink ----------------------------
    for e in &entries {
        sink.append_direct(e.clone()).await;
    }

    // -- 4. Wire the verifier + IR auto-fire subscriber ----------------
    let ir_service: Arc<sx_ir_playbooks::InMemoryIrPlaybookService> =
        Arc::new(sx_ir_playbooks::InMemoryIrPlaybookService::new());
    let ir_subscriber: Arc<dyn BrokenChainSubscriber> = Arc::new(IrAutoFireDrillSubscriber {
        service: Arc::clone(&ir_service) as Arc<dyn sx_ir_playbooks::IrPlaybookService>,
    });
    let recording: Arc<RecordingSubscriber> = Arc::new(RecordingSubscriber::new());

    let verifier = ChainVerifier::new(
        sink.clone() as Arc<dyn AuditSink>,
        vec![
            Arc::clone(&recording) as Arc<dyn BrokenChainSubscriber>,
            Arc::clone(&ir_subscriber),
        ],
        Arc::new(sx_audit::chain_verifier::SystemClock),
        DEFAULT_INTERVAL,
    );
    verifier.register_tenant(tenant).await;

    // -- 5. Drive one tick ---------------------------------------------
    let tick = verifier.run_once().await;
    let detected = recording.events().await.into_iter().next().ok_or_else(|| {
        anyhow!("drill: verifier did not emit audit.chain.broken — synthetic break failed")
    })?;
    if detected.break_seq != break_seq {
        return Err(anyhow!(
            "drill: verifier detected break at seq {} but expected {break_seq}",
            detected.break_seq
        ));
    }
    drop(tick);

    // -- 6. Find the auto-opened incident on the IR service ------------
    let _list = ir_service
        .list_playbooks(&tenant.to_string())
        .await
        .map_err(|e| anyhow!("list playbooks: {e}"))?;

    // The auto-fire opened exactly one incident — fetch the most-recent
    // by walking the in-memory store via get_incident on the id we
    // captured from the subscriber. The recording subscriber doesn't
    // expose the incident id, but the IR service auto-fire logged via
    // tracing; for the drill we walk a small candidate set instead by
    // re-firing on a dedup miss (the second call always returns the
    // existing open incident).
    let outcome = ir_service
        .auto_fire_audit_chain_compromise(sx_ir_playbooks::AuditChainBrokenEvent {
            tenant_id: tenant.to_string(),
            expected_hash: detected.expected_hash.clone(),
            actual_hash: detected.actual_hash.clone(),
            last_good_seq: detected.last_good_seq,
            break_seq: detected.break_seq,
            detected_at: detected.detected_at.clone(),
        })
        .await
        .map_err(|e| anyhow!("ir auto-fire (drill probe): {e}"))?;

    let incident_id = outcome.incident.id.clone();

    // -- 7. Walk every step Todo → InProgress → Done -------------------
    let mut steps_walked = 0usize;
    let step_ids: Vec<String> = outcome
        .incident
        .steps
        .iter()
        .map(|s| s.step_id.clone())
        .collect();
    for step_id in &step_ids {
        let _ = ir_service
            .update_step(
                &tenant.to_string(),
                "system.drill",
                &incident_id,
                step_id,
                sx_ir_playbooks::service::StepUpdate {
                    status: Some(StepStatus::InProgress),
                    ..sx_ir_playbooks::service::StepUpdate::default()
                },
            )
            .await
            .map_err(|e| anyhow!("step {step_id} → in_progress: {e}"))?;
        let _ = ir_service
            .update_step(
                &tenant.to_string(),
                "system.drill",
                &incident_id,
                step_id,
                sx_ir_playbooks::service::StepUpdate {
                    status: Some(StepStatus::Done),
                    ..sx_ir_playbooks::service::StepUpdate::default()
                },
            )
            .await
            .map_err(|e| anyhow!("step {step_id} → done: {e}"))?;
        steps_walked += 1;
    }

    // -- 8. Re-fetch the final incident snapshot ------------------------
    let final_inc = ir_service
        .get_incident(&tenant.to_string(), &incident_id)
        .await
        .map_err(|e| anyhow!("get_incident final: {e}"))?;

    // The acceptance criterion calls for the state machine to "reach
    // recovery phase". Recovery lives inside
    // ContainmentEradicationRecovery; in our rollup that means the
    // incident transitioned at least through `contained` (i.e. every
    // containment step is terminal). We accept `closed` as a strict
    // superset of `contained` since walking every step to Done ends in
    // Closed.
    let final_state = final_inc.state.as_str().to_owned();
    if !matches!(
        final_inc.state,
        sx_ir_playbooks::IncidentState::Contained | sx_ir_playbooks::IncidentState::Closed
    ) {
        return Err(anyhow!(
            "drill: expected state contained|closed after walking every step, got {final_state}"
        ));
    }

    // Identify the latest phase whose steps are all terminal — used in
    // the report so the post-incident reviewer can spot a drill that
    // stopped short of post-incident activity.
    let final_phase = highest_terminal_phase(&final_inc);

    Ok(DrillReport {
        incident_id,
        playbook_id: final_inc.playbook_id,
        final_state,
        final_phase,
        tampered_seq: break_seq,
        last_good_seq: detected.last_good_seq,
        detected_at: detected.detected_at,
        deduplicated: outcome.deduplicated,
        steps_walked,
    })
}

/// In-memory sink used by the drill simulator. Implements [`AuditSink`]
/// and exposes a `append_direct` that bypasses the per-tenant seq
/// monotonicity guard so the drill can seed a pre-baked tampered
/// chain.
#[derive(Debug, Default)]
struct VecSink {
    entries: tokio::sync::Mutex<Vec<sx_audit::prelude::AuditEntry>>,
}

impl VecSink {
    async fn append_direct(&self, entry: sx_audit::prelude::AuditEntry) {
        self.entries.lock().await.push(entry);
    }
}

#[async_trait::async_trait]
impl sx_audit::prelude::AuditSink for VecSink {
    async fn append(
        &self,
        entry: &sx_audit::prelude::AuditEntry,
    ) -> Result<(), sx_audit::prelude::AuditError> {
        self.entries.lock().await.push(entry.clone());
        Ok(())
    }
    async fn last_entry_for_tenant(
        &self,
        tid: TenantId,
    ) -> Result<Option<sx_audit::prelude::AuditEntry>, sx_audit::prelude::AuditError> {
        let g = self.entries.lock().await;
        let last = g
            .iter()
            .filter(|e| e.tenant_id == tid)
            .max_by_key(|e| e.seq)
            .cloned();
        drop(g);
        Ok(last)
    }
    async fn read_range(
        &self,
        tid: TenantId,
        from: u64,
        to: u64,
    ) -> Result<Vec<sx_audit::prelude::AuditEntry>, sx_audit::prelude::AuditError> {
        let g = self.entries.lock().await;
        let mut out: Vec<sx_audit::prelude::AuditEntry> = g
            .iter()
            .filter(|e| e.tenant_id == tid && e.seq >= from && e.seq <= to)
            .cloned()
            .collect();
        drop(g);
        out.sort_by_key(|e| e.seq);
        Ok(out)
    }
}

/// IR auto-fire subscriber used by the drill. Mirrors the monolith's
/// `ChainBrokenAutoFire` adapter but stays inside this binary so the
/// CLI does not pick up a dep on `sx-monolith`.
#[derive(Debug)]
struct IrAutoFireDrillSubscriber {
    service: std::sync::Arc<dyn sx_ir_playbooks::IrPlaybookService>,
}

#[async_trait::async_trait]
impl sx_audit::chain_verifier::BrokenChainSubscriber for IrAutoFireDrillSubscriber {
    async fn on_broken(&self, payload: &sx_audit::chain_verifier::AuditChainBrokenPayload) {
        let _ = self
            .service
            .auto_fire_audit_chain_compromise(sx_ir_playbooks::AuditChainBrokenEvent {
                tenant_id: payload.tenant_id.to_string(),
                expected_hash: payload.expected_hash.clone(),
                actual_hash: payload.actual_hash.clone(),
                last_good_seq: payload.last_good_seq,
                break_seq: payload.break_seq,
                detected_at: payload.detected_at.clone(),
            })
            .await;
    }
}

/// Highest NIST phase whose steps are all terminal (`done` or
/// `skipped`) in the supplied incident. Used by the drill report so a
/// reader can see whether the walk-through stopped short of
/// `post_incident_activity`.
fn highest_terminal_phase(inc: &sx_ir_playbooks::Incident) -> String {
    use sx_ir_playbooks::{IrPhase, StepStatus};
    let mut best: Option<IrPhase> = None;
    for phase in IrPhase::ordered() {
        let steps_in_phase: Vec<&sx_ir_playbooks::IncidentStep> =
            inc.steps.iter().filter(|s| s.phase == phase).collect();
        if steps_in_phase.is_empty() {
            continue;
        }
        if steps_in_phase
            .iter()
            .all(|s| matches!(s.status, StepStatus::Done | StepStatus::Skipped))
        {
            best = Some(phase);
        }
    }
    best.map_or_else(|| "preparation".to_owned(), |p| p.as_str().to_owned())
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use std::env;
    use std::fs::{self, OpenOptions};
    use std::io::Write;
    use std::sync::atomic::{AtomicU64, Ordering};

    use sx_audit::prelude::{build_entry, build_genesis, Actor, AuditAction, NewAuditEvent};
    use sx_core::value_object::ids::TenantId;

    use super::*;

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    /// Tiny RAII temporary file — workspace has no `tempfile` dep so we
    /// roll a minimal substitute. The path lives in `env::temp_dir()`
    /// and is removed on drop on a best-effort basis.
    struct TempFile {
        path: PathBuf,
    }

    impl TempFile {
        fn new() -> Self {
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            let nano = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let path = env::temp_dir().join(format!("sx-cli-test-{nano}-{n}.ndjson"));
            Self { path }
        }
    }

    impl Drop for TempFile {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.path);
        }
    }

    fn make_chain(tenant: TenantId, n: usize) -> Vec<AuditEntry> {
        let mut entries = Vec::with_capacity(n);
        let event = |i: usize| NewAuditEvent {
            tenant_id: tenant,
            actor: Actor::system(),
            action: AuditAction::Login,
            resource_kind: "test".to_owned(),
            resource_id: format!("res-{i}"),
            before: None,
            after: None,
            request_id: format!("req-{i}"),
            ts: None,
        };
        let g = build_genesis(event(0)).unwrap();
        entries.push(g);
        for i in 1..n {
            let prev = &entries[i - 1];
            let e = build_entry(prev.seq + 1, prev.hash, event(i)).unwrap();
            entries.push(e);
        }
        entries
    }

    fn write_ndjson(entries: &[AuditEntry]) -> TempFile {
        let tmp = TempFile::new();
        let mut f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp.path)
            .unwrap();
        for e in entries {
            let line = serde_json::to_string(e).unwrap();
            writeln!(f, "{line}").unwrap();
        }
        f.flush().unwrap();
        tmp
    }

    #[test]
    fn audit_verify_returns_zero_on_clean_chain() {
        let tenant = TenantId::new();
        let entries = make_chain(tenant, 3);
        let f = write_ndjson(&entries);
        let args = VerifyArgs {
            tenant: Some(tenant.to_string()),
            from: Some(f.path.clone()),
            source: None,
            signing_key_env: None,
            to: None,
        };
        let rc = run_verify(&args, OutputFormat::Json).unwrap();
        assert_eq!(rc, 0);
    }

    #[test]
    fn audit_verify_returns_nonzero_on_tampered_chain() {
        let tenant = TenantId::new();
        let mut entries = make_chain(tenant, 3);
        // Tamper: flip a bit in the hash of the middle entry.
        entries[1].hash[0] ^= 0xFF;
        let f = write_ndjson(&entries);
        let args = VerifyArgs {
            tenant: Some(tenant.to_string()),
            from: Some(f.path.clone()),
            source: None,
            signing_key_env: None,
            to: None,
        };
        let rc = run_verify(&args, OutputFormat::Json).unwrap();
        assert_eq!(rc, 1);
    }

    #[test]
    fn audit_verify_rejects_wrong_tenant_entries() {
        let tenant_a = TenantId::new();
        let tenant_b = TenantId::new();
        let entries = make_chain(tenant_a, 2);
        let f = write_ndjson(&entries);
        let args = VerifyArgs {
            tenant: Some(tenant_b.to_string()),
            from: Some(f.path.clone()),
            source: None,
            signing_key_env: None,
            to: None,
        };
        let r = run_verify(&args, OutputFormat::Json);
        assert!(r.is_err());
    }

    #[test]
    fn audit_dump_from_redis_returns_two() {
        let tenant = TenantId::new();
        let args = DumpArgs {
            tenant: tenant.to_string(),
            to: PathBuf::from("/dev/null"),
            from_redis: Some("redis://localhost:6379".into()),
        };
        let rc = run_dump(&args, OutputFormat::Json).unwrap();
        assert_eq!(rc, 2);
    }

    /// Build an HMAC-anchored chain and write it as a JSON array.
    /// Used by the `audit_verify` HMAC integration tests.
    fn make_hmac_chain_json(tenant: TenantId, n: usize, key: &str) -> (TempFile, Vec<AuditEntry>) {
        use sx_audit::prelude::HashChain;
        let chain = HashChain::new(SecretString::from(key.to_owned())).unwrap();
        let mut entries = make_chain(tenant, n);
        let mut prev: Option<String> = None;
        for entry in &mut entries {
            entry.chain_prev_hash = prev.clone();
            let h = chain.step(prev.as_deref(), entry, entry.seq).unwrap();
            entry.chain_hash = h.clone();
            prev = Some(h);
        }
        let tmp = TempFile::new();
        let s = serde_json::to_string(&entries).unwrap();
        std::fs::write(&tmp.path, s).unwrap();
        (tmp, entries)
    }

    #[test]
    fn audit_verify_subcommand_ok_on_well_formed_chain() {
        const KEY_ENV: &str = "SX_TEST_AUDIT_KEY_OK";
        const KEY: &str = "test-pepper-must-be-at-least-16b";
        // Safety: tests run in the same process so we use a unique env
        // var name per-test to avoid cross-test contamination.
        std::env::set_var(KEY_ENV, KEY);
        let tenant = TenantId::new();
        let (f, _entries) = make_hmac_chain_json(tenant, 4, KEY);
        let args = VerifyArgs {
            tenant: None,
            from: None,
            source: Some(f.path.clone()),
            signing_key_env: Some(KEY_ENV.to_owned()),
            to: None,
        };
        let rc = run_verify(&args, OutputFormat::Json).unwrap();
        std::env::remove_var(KEY_ENV);
        assert_eq!(rc, 0);
    }

    #[test]
    fn audit_verify_subcommand_fail_on_tampered() {
        const KEY_ENV: &str = "SX_TEST_AUDIT_KEY_FAIL";
        const KEY: &str = "test-pepper-must-be-at-least-16b";
        std::env::set_var(KEY_ENV, KEY);
        let tenant = TenantId::new();
        let (_old, mut entries) = make_hmac_chain_json(tenant, 4, KEY);
        // Flip a byte in the third entry.
        entries[2].request_id = "TAMPERED".to_owned();
        let tmp = TempFile::new();
        let s = serde_json::to_string(&entries).unwrap();
        std::fs::write(&tmp.path, s).unwrap();
        let args = VerifyArgs {
            tenant: None,
            from: None,
            source: Some(tmp.path.clone()),
            signing_key_env: Some(KEY_ENV.to_owned()),
            to: None,
        };
        let rc = run_verify(&args, OutputFormat::Json).unwrap();
        std::env::remove_var(KEY_ENV);
        assert_eq!(rc, 1, "tampered chain must exit non-zero");
        // The tampered seq is 3 (third entry). We can't easily intercept
        // stdout here, but the run_verify_hmac path constructs an error
        // mentioning that seq; we assert the exit code only here.
    }

    #[test]
    fn audit_verify_hmac_reads_json_array() {
        const KEY_ENV: &str = "SX_TEST_AUDIT_KEY_ARRAY";
        const KEY: &str = "test-pepper-must-be-at-least-16b";
        std::env::set_var(KEY_ENV, KEY);
        let tenant = TenantId::new();
        let (f, _) = make_hmac_chain_json(tenant, 2, KEY);
        // Confirm the test file is a JSON array (first non-whitespace '[').
        let contents = std::fs::read_to_string(&f.path).unwrap();
        assert!(contents.trim_start().starts_with('['));
        let entries = read_audit_source(&f.path).unwrap();
        assert_eq!(entries.len(), 2);
        std::env::remove_var(KEY_ENV);
    }

    #[test]
    fn audit_verify_hmac_requires_env_var() {
        let tenant = TenantId::new();
        let entries = make_chain(tenant, 1);
        let f = write_ndjson(&entries);
        let args = VerifyArgs {
            tenant: None,
            from: None,
            source: Some(f.path.clone()),
            signing_key_env: Some("SX_DEFINITELY_UNSET_VAR_2026".to_owned()),
            to: None,
        };
        let r = run_verify(&args, OutputFormat::Json);
        assert!(r.is_err(), "missing env var must surface as anyhow error");
    }

    #[tokio::test]
    async fn drill_executes_end_to_end_on_test_tenant() {
        let tid = TenantId::from_str(DRILL_TEST_TENANT).unwrap();
        let report = execute_drill(tid, 4).await.expect("drill ok");
        assert_eq!(report.playbook_id, "audit_chain_compromise");
        assert_eq!(report.tampered_seq, 4);
        assert_eq!(report.last_good_seq, Some(3));
        assert!(matches!(
            report.final_state.as_str(),
            "contained" | "closed"
        ));
        // Walking every step terminates in `post_incident_activity`.
        assert_eq!(report.final_phase, "post_incident_activity");
        assert!(
            report.steps_walked >= 5,
            "expected to walk all playbook steps"
        );
    }

    #[test]
    fn drill_refuses_real_tenant_without_env_override() {
        // SX_AUDIT_DRILL_ALLOW unset.
        std::env::remove_var(DRILL_ALLOW_ENV);
        let real_tenant = TenantId::new().to_string();
        let args = SimulateBreakArgs {
            tenant: real_tenant,
            seq: 3,
            report_out: None,
        };
        let err = run_simulate_break(&args, OutputFormat::Json).expect_err("must refuse");
        let msg = err.to_string();
        assert!(msg.contains("refusing to simulate"), "got: {msg}");
    }

    #[test]
    fn drill_rejects_genesis_seq() {
        let args = SimulateBreakArgs {
            tenant: DRILL_TEST_TENANT.to_owned(),
            seq: 1,
            report_out: None,
        };
        let err = run_simulate_break(&args, OutputFormat::Json).expect_err("must reject");
        assert!(err.to_string().contains(">= 2"), "got: {err}");
    }

    #[test]
    fn drill_rejects_oversize_seq() {
        let args = SimulateBreakArgs {
            tenant: DRILL_TEST_TENANT.to_owned(),
            seq: 1_000,
            report_out: None,
        };
        let err = run_simulate_break(&args, OutputFormat::Json).expect_err("must reject");
        assert!(err.to_string().contains("capped at 100"), "got: {err}");
    }
}
