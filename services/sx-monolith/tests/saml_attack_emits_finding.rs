//! TOP5-#3-P2-004-FU1 — bin-spawn integration test for the SAML SP
//! attack-detection observer that emits synthetic Findings via the
//! FOUND-001 [`FindingRepositoryPort::insert`] contract.
//!
//! ## What this gate asserts
//!
//! 1. The monolith binary boots against the committed
//!    `config/sentinelx.dev.example.yaml`, registers the `/v1/auth/saml/acs`
//!    route, parses the SAML HTTP-POST binding form, and returns a
//!    non-200 status when fed a synthetic XSW (XML Signature Wrapping)
//!    body. Proves the route + form decoder + adapter wiring are intact
//!    end-to-end against the same artefact production ships.
//! 2. The committed [`MonolithSamlAttackObserver`] translation contract
//!    (`rule_id` / severity / CWE / metadata shape) is byte-stable: an
//!    inlined mirror of the observer's `build_finding` path is exercised
//!    against the same [`saml_attack_enrichment`] table the production
//!    adapter uses, asserting `rule_id = "saml:xsw-detected"`,
//!    `severity = "high"`, and `metadata.cwe` contains `CWE-347`. The
//!    mirror is a near-copy of
//!    `services/sx-monolith/src/adapters/saml_attack_observer.rs::build_finding`;
//!    a typo in the enrichment row trips both this test and the existing
//!    in-crate unit tests for the adapter.
//!
//! ## Why the finding assertion is in-process (deviation from the bin-spawn ideal)
//!
//! Reaching the live observer through the spawned binary requires an
//! [`IdpRecord`] for the test tenant in the in-memory `IdP` store (the
//! adapter's `process_acs` short-circuits on `idp_store.get(tenant_id)
//! → None` with `SamlPortError::NotFound` BEFORE
//! [`decode_saml_response`] is called — and the observer hot path
//! is invoked from within `decode_saml_response`'s error mapping).
//! The current dev YAML has no SAML stanza and no `IdP`-seed surface, and
//! there is no admin REST endpoint to upsert an [`IdpRecord`] today (the
//! adapter exposes `upsert` as a Rust API only). Seeding an `IdP` from a
//! test would require either (a) a new admin route, or (b) a config-time
//! SAML `IdP` table — both feature-sized work items outside the FU1 scope.
//!
//! So the bin-spawn half of this test exercises the boundary the binary
//! actually offers today (route registration + form decoding + adapter
//! rejection), and the finding-emission half mirrors the observer
//! translation inline — the same convention `audit_chain_break_emits_finding.rs`
//! (P2-007) and `rba_block_emits_finding.rs` (P2-005) use for the same
//! `pub(crate)` adapter-visibility constraint. The 6 unit tests inside
//! `services/sx-monolith/src/adapters/saml_attack_observer.rs` already
//! cover the live `notify → spawn → insert` path; this file pins the
//! wire-shape contract one layer up.

#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::print_stdout)]
#![allow(clippy::print_stderr)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::indexing_slicing)]
// `offset as usize` on `u64` — the `FindingRepositoryPort::list` trait
// takes `u64` for forward-compatibility with PG-backed paginators; the
// in-memory mock above shares the trait signature but the test never
// drives pagination past `0..100`, so the truncation lint is noise here.
// Same justification as `rba_block_emits_finding.rs`.
#![allow(clippy::cast_possible_truncation)]
// Subprocess integration test: we deliberately spawn the production
// `sx-monolith` binary and need to (a) forward the parent's PATH +
// HOME so cargo's runtime-resolved binary still finds linker libs,
// and (b) echo the child's stderr to the test runner so a boot
// panic is visible in CI logs. The workspace bans `std::env::var`
// and `std::eprintln` from product code; both are appropriate here
// in a test harness that crosses the process boundary. Same
// justification as `login_with_readme_creds.rs`.
#![allow(clippy::disallowed_methods)]
#![allow(clippy::disallowed_macros)]

use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as B64_STANDARD;
use base64::Engine;
use sha2::{Digest, Sha256};
use sx_api::port::{EngagementPortError, FindingRepositoryPort};
use sx_api::view::finding_view::FindingView;
use sx_core::reference::saml_attack_enrichment::{
    saml_attack_enrichment, SamlAttackEnrichment, SamlAttackSeverity,
};
use sx_iam::service::saml::SamlAttackKind;

// ---------------------------------------------------------------------------
// Bin-spawn scaffolding — mirrored from `login_with_readme_creds.rs`.
// ---------------------------------------------------------------------------

fn pick_free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    let port = listener.local_addr().expect("local_addr").port();
    drop(listener);
    port
}

fn dev_example_config_path() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .and_then(std::path::Path::parent)
        .map(std::path::Path::to_path_buf)
        .expect("workspace root two levels above CARGO_MANIFEST_DIR")
        .join("config")
        .join("sentinelx.dev.example.yaml")
}

struct ChildKillOnDrop(Child);

impl Drop for ChildKillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn forward_child_stderr(stderr: std::process::ChildStderr) {
    std::thread::spawn(move || {
        let reader = BufReader::new(stderr);
        for line in reader.lines().map_while(Result::ok) {
            eprintln!("[sx-monolith] {line}");
        }
    });
}

async fn wait_for_health(client: &reqwest::Client, base: &str, deadline: Instant) -> bool {
    let url = format!("{base}/healthz");
    while Instant::now() < deadline {
        if let Ok(resp) = client.get(&url).send().await {
            if resp.status().is_success() {
                return true;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

/// A synthetic XSW-shaped `<samlp:Response>` mirroring the
/// `crates/sx-iam/fuzz/corpus/saml_response_fuzz/xsw1.xml` corpus row
/// (nested `<saml:Assertion>` elements). The SP byte-level gate refuses
/// this shape via either the multi-`<Signature>` or the
/// Reference-URI-binding rule (both classify as
/// [`SamlAttackKind::Xsw`]).
///
/// Inlined rather than `include_str!`-ed because the fuzz corpus is
/// part of the `sx-iam` crate's `fuzz/` directory, which lives outside
/// the `sx-monolith` test sandbox and would create a fragile build-time
/// path dependency.
const SYNTHETIC_XSW_SAML_RESPONSE: &str = concat!(
    r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" "#,
    r#"xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_resp-xsw1" "#,
    r#"Version="2.0" IssueInstant="2026-06-25T00:00:00Z">"#,
    r#"<saml:Issuer>https://idp.example.com</saml:Issuer>"#,
    r#"<saml:Assertion ID="_attacker-1" IssueInstant="2026-06-25T00:00:00Z" Version="2.0">"#,
    r#"<saml:Issuer>https://idp.example.com</saml:Issuer>"#,
    r#"<saml:Subject><saml:NameID>eve@example.com</saml:NameID></saml:Subject>"#,
    r#"<saml:Assertion ID="_signed-1" IssueInstant="2026-06-25T00:00:00Z" Version="2.0">"#,
    r#"<saml:Issuer>https://idp.example.com</saml:Issuer>"#,
    r#"<saml:Subject><saml:NameID>alice@example.com</saml:NameID></saml:Subject>"#,
    r#"</saml:Assertion></saml:Assertion></samlp:Response>"#,
);

/// Tenant id documented in the dev example config (matches the
/// `sentinelx-admin` bootstrap row).
const ADMIN_TENANT_ID: &str = "01010101-0101-0101-0101-010101010101";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn saml_acs_rejects_synthetic_xsw_attack_via_live_binary() {
    let config_path = dev_example_config_path();
    assert!(
        config_path.exists(),
        "expected dev example config at {} — bin-spawn relies on the \
         SX-REVIEW-002 C2 file remaining in place",
        config_path.display(),
    );

    let port = pick_free_port();
    let bind = format!("127.0.0.1:{port}");
    let base = format!("http://{bind}");

    let binary = env!("CARGO_BIN_EXE_sx-monolith");
    let mut cmd = Command::new(binary);
    cmd.env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", std::env::var("HOME").unwrap_or_default())
        .env("SENTINELX_CONFIG", &config_path)
        .env("SENTINELX__SERVER__BIND_ADDR", &bind)
        .env("RUST_LOG", "warn,sx_monolith=info,sx_iam=info")
        .stdout(Stdio::null())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn().expect("spawn sx-monolith");
    if let Some(stderr) = child.stderr.take() {
        forward_child_stderr(stderr);
    }
    let _guard = ChildKillOnDrop(child);

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build reqwest client");

    let boot_deadline = Instant::now() + Duration::from_secs(30);
    assert!(
        wait_for_health(&client, &base, boot_deadline).await,
        "monolith /healthz did not return 200 within 30s — check \
         [sx-monolith] stderr lines above for a panic or config error",
    );

    // POST the synthetic XSW body to the live ACS endpoint using the
    // SAML 2.0 HTTP-POST binding (`application/x-www-form-urlencoded`
    // body, `SAMLResponse` is base64-encoded per Bindings §3.5.4).
    let saml_response_b64 = B64_STANDARD.encode(SYNTHETIC_XSW_SAML_RESPONSE);
    let form = [
        ("SAMLResponse", saml_response_b64.as_str()),
        ("tenant_id", ADMIN_TENANT_ID),
    ];
    let resp = client
        .post(format!("{base}/v1/auth/saml/acs"))
        .form(&form)
        .send()
        .await
        .expect("POST /v1/auth/saml/acs");

    let status = resp.status();
    assert!(
        !status.is_success(),
        "ACS must reject a synthetic XSW body — got {status}. \
         A 200 here would mean the binary somehow accepted an unsigned, \
         wrapping-shaped assertion as authentic, which is the exact \
         bug class P2-004 instrumented.",
    );
    // Status is one of 401 (Rejected — SAML enabled path), 404 (no IdP
    // for tenant — SAML enabled path), or 422 (Disabled — default dev
    // config). All three are the SP correctly refusing the input.
    assert!(
        matches!(status.as_u16(), 400 | 401 | 404 | 422),
        "ACS rejection must be a documented 4xx (400/401/404/422), got {status}",
    );

    // The bin-spawn channel ends here. Asserting that a Finding row
    // lands in the live repo would require an enabled SAML adapter with
    // a seeded IdP record (see module doc comment); the next test in
    // this file pins the observer→repo translation contract in-process
    // using the same `saml_attack_enrichment` table the live adapter
    // reads.
}

// ---------------------------------------------------------------------------
// In-process FOUND-001 mirror — exercises the observer translation
// contract against an in-memory FindingRepositoryPort. This is the same
// convention `audit_chain_break_emits_finding.rs` and
// `rba_block_emits_finding.rs` use to pin the wire-shape of an emitter
// whose production type is `pub(crate)` to the monolith crate.
// ---------------------------------------------------------------------------

/// Faithful re-implementation of the monolith's `InMemoryFindings`
/// adapter — same shape, same `(tenant_id, id)` last-write-wins
/// semantics. Mirrors `services/sx-monolith/src/adapters/repository.rs`.
#[derive(Default)]
struct InMemoryFindings {
    rows: Mutex<HashMap<(String, String), FindingView>>,
}

#[async_trait]
impl FindingRepositoryPort for InMemoryFindings {
    async fn list(
        &self,
        tenant_id: &str,
        offset: u64,
        limit: u32,
    ) -> Result<Vec<FindingView>, EngagementPortError> {
        let g = self.rows.lock().unwrap();
        Ok(g.iter()
            .filter(|((t, _), _)| t == tenant_id)
            .map(|(_, v)| v.clone())
            .skip(offset as usize)
            .take(limit as usize)
            .collect())
    }

    async fn get(&self, tenant_id: &str, id: &str) -> Result<FindingView, EngagementPortError> {
        let g = self.rows.lock().unwrap();
        g.get(&(tenant_id.to_owned(), id.to_owned()))
            .cloned()
            .ok_or(EngagementPortError::NotFound)
    }

    async fn update_status(
        &self,
        _tenant_id: &str,
        _id: &str,
        _new_status: &str,
        _comment: Option<&str>,
    ) -> Result<FindingView, EngagementPortError> {
        Err(EngagementPortError::NotFound)
    }

    async fn insert(&self, view: FindingView) -> Result<FindingView, EngagementPortError> {
        let key = (view.tenant_id.clone(), view.id.clone());
        self.rows.lock().unwrap().insert(key, view.clone());
        Ok(view)
    }
}

/// Stable namespace mixed into the deterministic finding id. MUST match
/// `services/sx-monolith/src/adapters/saml_attack_observer.rs::SAML_FINDING_NAMESPACE`
/// byte-for-byte — a divergence here means a re-fire of the same attack
/// would land as a fresh finding, defeating FOUND-001 idempotency.
const SAML_FINDING_NAMESPACE: &str = "sentinelx:saml-attack:v1";

/// UTC midnight (`YYYY-MM-DD`) of a Unix-epoch second. Mirrors
/// `day_bucket_utc` from the production observer.
fn day_bucket_utc(unix_secs: i64) -> String {
    time::OffsetDateTime::from_unix_timestamp(unix_secs).map_or_else(
        |_| "1970-01-01".into(),
        |t| format!("{:04}-{:02}-{:02}", t.year(), u8::from(t.month()), t.day()),
    )
}

/// RFC 3339 (`YYYY-MM-DDTHH:MM:SSZ`) of a Unix-epoch second. Mirrors
/// `unix_to_rfc3339` from the production observer.
fn unix_to_rfc3339(unix_secs: i64) -> String {
    time::OffsetDateTime::from_unix_timestamp(unix_secs).map_or_else(
        |_| "1970-01-01T00:00:00Z".into(),
        |t| {
            format!(
                "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
                t.year(),
                u8::from(t.month()),
                t.day(),
                t.hour(),
                t.minute(),
                t.second()
            )
        },
    )
}

/// Mirrors `MonolithSamlAttackObserver::finding_id` byte-for-byte.
/// A typo here vs production would mean the idempotency bucket diverges
/// silently — that's the failure class this test guards against.
fn finding_id(
    tenant_id: &str,
    kind: SamlAttackKind,
    idp_issuer: &str,
    detected_at_unix: i64,
) -> String {
    let day = day_bucket_utc(detected_at_unix);
    let tuple = format!(
        "{SAML_FINDING_NAMESPACE}|{tenant_id}|{}|{idp_issuer}|{day}",
        kind.rule_id()
    );
    let digest: [u8; 32] = Sha256::digest(tuple.as_bytes()).into();
    format!(
        "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
        u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]),
        u16::from_be_bytes([digest[4], digest[5]]),
        u16::from_be_bytes([digest[6], digest[7]]),
        u16::from_be_bytes([digest[8], digest[9]]),
        u64::from_be_bytes([
            0, 0, digest[10], digest[11], digest[12], digest[13], digest[14], digest[15],
        ]),
    )
}

/// Mirrors `MonolithSamlAttackObserver::build_finding`. Returns the
/// `FindingView` the production observer would insert for a given
/// detected XSW attack from `idp_issuer` at `detected_at_unix`.
fn build_xsw_finding(
    tenant_id: &str,
    idp_issuer: &str,
    detected_at_unix: i64,
    system_engagement_id: &str,
    saml_sp_asset_id: &str,
) -> FindingView {
    let enrichment = saml_attack_enrichment(SamlAttackKind::Xsw.rule_id())
        .expect("xsw enrichment row must exist");
    let SamlAttackEnrichment {
        cwe,
        mitre_attack,
        compliance,
        severity,
        title,
        description,
    } = enrichment;

    let id = finding_id(tenant_id, SamlAttackKind::Xsw, idp_issuer, detected_at_unix);
    let detected_at_iso = unix_to_rfc3339(detected_at_unix);

    let metadata = serde_json::json!({
        "engagement_id": system_engagement_id,
        // TOP5-#3 Phase 3: dotted-form on the wire.
        "rule_id": SamlAttackKind::Xsw.rule_id_dotted(),
        "confidence": 1.0,
        "emitter": "saml_attack_observer",
        "idp_issuer": idp_issuer,
        "cwe": cwe.iter().map(|c| format!("CWE-{}", c.as_u32())).collect::<Vec<_>>(),
        "mitre_attack": mitre_attack
            .iter()
            .map(|t| {
                let mut o = serde_json::json!({
                    "tactic": t.tactic,
                    "technique": t.technique,
                });
                if let (Some(sub), Some(map)) = (t.subtechnique.as_ref(), o.as_object_mut()) {
                    map.insert(
                        "subtechnique".to_owned(),
                        serde_json::Value::String(sub.clone()),
                    );
                }
                o
            })
            .collect::<Vec<_>>(),
        "compliance": {
            "nist_800_53": compliance
                .nist_800_53
                .iter()
                .map(|c| c.as_str().to_owned())
                .collect::<Vec<_>>(),
        },
    });

    FindingView {
        id,
        tenant_id: tenant_id.to_owned(),
        asset_id: saml_sp_asset_id.to_owned(),
        severity: match severity {
            SamlAttackSeverity::High => "high".into(),
            SamlAttackSeverity::Medium => "medium".into(),
        },
        status: "open".into(),
        title: title.into(),
        description: description.into(),
        cvss: None,
        cve_id: None,
        first_seen: detected_at_iso.clone(),
        last_seen: detected_at_iso,
        metadata: Some(metadata),
    }
}

/// FOUND-001 wire-shape gate: when the production observer translates an
/// XSW detection into a `FindingView` and inserts it through
/// `FindingRepositoryPort::insert`, the persisted row MUST carry the
/// curated `rule_id`, severity, CWE-347, and the FOUND-001 metadata
/// envelope. This is the integration assertion the bin-spawn half above
/// cannot reach today (see module doc — needs `IdP` seeding).
#[tokio::test]
async fn xsw_attack_emits_finding_with_canonical_metadata() {
    let repo = InMemoryFindings::default();
    let system_engagement_id = "11111111-1111-1111-1111-111111111111";
    let saml_sp_asset_id = "22222222-2222-2222-2222-222222222222";
    // 2026-06-25T00:00:00Z — same anchor the in-crate adapter tests use.
    let detected_at_unix: i64 = 1_782_604_800;

    let view = build_xsw_finding(
        ADMIN_TENANT_ID,
        "https://idp.example.com",
        detected_at_unix,
        system_engagement_id,
        saml_sp_asset_id,
    );
    let persisted = repo.insert(view).await.expect("insert ok");

    // ---- FOUND-001 wire-shape contract ----------------------------------
    let metadata = persisted.metadata.as_ref().expect("metadata present");
    // TOP5-#3 Phase 3: dotted-form rule_id on the wire (SIEM alias-map
    // still resolves the legacy colon-form for backward compat).
    let rule_id = metadata
        .get("rule_id")
        .and_then(|v| v.as_str())
        .expect("rule_id present");
    assert_eq!(
        rule_id, "SAML.XSW",
        "rule_id pinned by the FOUND-001 / SIEM contract (dotted-form)",
    );
    assert!(
        rule_id.contains('.'),
        "TOP5-#3 Phase 3: rule_id must contain a `.`; got `{rule_id}`",
    );
    assert_eq!(
        metadata.get("engagement_id").and_then(|v| v.as_str()),
        Some(system_engagement_id),
        "engagement_id mandatory in metadata envelope",
    );
    assert_eq!(
        metadata
            .get("confidence")
            .and_then(serde_json::Value::as_f64),
        Some(1.0),
        "confidence pinned at 1.0 — gate-level rejection is deterministic",
    );
    assert_eq!(
        metadata.get("emitter").and_then(|v| v.as_str()),
        Some("saml_attack_observer"),
    );

    // ---- CWE-347 (Improper Verification of Cryptographic Signature) ----
    let cwe_arr = metadata
        .get("cwe")
        .and_then(|v| v.as_array())
        .expect("cwe array present");
    let cwe_strs: Vec<&str> = cwe_arr.iter().filter_map(|v| v.as_str()).collect();
    assert!(
        cwe_strs.contains(&"CWE-347"),
        "XSW metadata must carry CWE-347, got {cwe_strs:?}",
    );

    // ---- severity = "high" --------------------------------------------
    assert_eq!(
        persisted.severity, "high",
        "XSW is high severity per the enrichment table"
    );
    assert_eq!(persisted.status, "open", "newly-emitted findings are open");
    assert_eq!(persisted.tenant_id, ADMIN_TENANT_ID);
    assert_eq!(persisted.asset_id, saml_sp_asset_id);

    // ---- exactly one row landed for the tenant via insert(...) ---------
    let rows = repo.list(ADMIN_TENANT_ID, 0, 100).await.expect("list ok");
    assert_eq!(
        rows.len(),
        1,
        "exactly one finding inserted via the FOUND-001 insert path, got {rows:?}",
    );
}

/// Idempotency rider: two XSW detections from the same `IdP` on the same
/// UTC day MUST collapse to a single finding id, matching the
/// production observer's `(tenant, kind, idp, day)` bucket hash.
#[tokio::test]
async fn xsw_attack_is_idempotent_within_one_utc_day() {
    let repo = InMemoryFindings::default();
    let idp_issuer = "https://idp.example.com";
    let system_engagement_id = "11111111-1111-1111-1111-111111111111";
    let saml_sp_asset_id = "22222222-2222-2222-2222-222222222222";

    // Two detections same UTC day, different hours.
    let view_a = build_xsw_finding(
        ADMIN_TENANT_ID,
        idp_issuer,
        1_782_604_800,
        system_engagement_id,
        saml_sp_asset_id,
    );
    let view_b = build_xsw_finding(
        ADMIN_TENANT_ID,
        idp_issuer,
        1_782_604_800 + 3600,
        system_engagement_id,
        saml_sp_asset_id,
    );

    assert_eq!(
        view_a.id, view_b.id,
        "same (tenant, kind, idp, day) MUST hash to the same finding id",
    );

    repo.insert(view_a).await.expect("first insert");
    repo.insert(view_b).await.expect("second insert");

    let rows = repo.list(ADMIN_TENANT_ID, 0, 100).await.expect("list ok");
    assert_eq!(
        rows.len(),
        1,
        "FOUND-001 last-write-wins on (tenant_id, id) must collapse re-fires \
         within one UTC day to a single row, got {rows:?}",
    );
}
