//! Regression gate for L1-FU1: the analyst e2e fixture credentials
//! documented in `web/dashboard/e2e/README.md` §Seed accounts MUST
//! authenticate against a monolith booted with the committed
//! `config/sentinelx.dev.example.yaml`.
//!
//! Without this gate, the L1 Playwright workflow would fail
//! `auth.spec.ts` + `navigation.spec.ts` on its first CI run because
//! `analyst@sentinelx.dev` is not part of the original SX-REVIEW-002 C2
//! seed (which only created `admin@sentinelx.dev`). L1-FU1 adds an
//! optional analyst-seed path to `BootstrapConfig` + the matching PHC
//! to the dev example YAML; this test is the proof that wiring stays
//! intact across future config tweaks.
//!
//! Mirrors `login_with_readme_creds.rs` — same subprocess pattern, same
//! ephemeral-port discipline, same RAII child cleanup. The only
//! interesting difference is the credentials in the POST body.

#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::print_stdout)]
#![allow(clippy::print_stderr)]
#![allow(clippy::missing_panics_doc)]
// Subprocess integration test — same justification as
// `login_with_readme_creds.rs`: we deliberately spawn the production
// `sx-monolith` binary and need to forward PATH + HOME and echo child
// stderr to the test runner. The workspace bans `std::env::var` /
// `std::eprintln` from product code; both are appropriate here in a
// test harness that crosses the process boundary.
#![allow(clippy::disallowed_methods)]
#![allow(clippy::disallowed_macros)]

use std::io::{BufRead, BufReader};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn analyst_e2e_credentials_authenticate_against_dev_example() {
    let config_path = dev_example_config_path();
    assert!(
        config_path.exists(),
        "expected dev example config at {} — L1-FU1 relies on the SX-REVIEW-002 \
         C2 file remaining in place; if it has gone missing the Playwright \
         workflow is broken upstream of this test",
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

    // The L1 Playwright workflow documents these three values verbatim
    // in `.github/workflows/playwright.yml` and
    // `web/dashboard/e2e/README.md`. The PHC in
    // `config/sentinelx.dev.example.yaml` hashes `Analyst!Password1`,
    // so a successful 200 here is the end-to-end proof that the L1-FU1
    // seed alignment is intact.
    let body = serde_json::json!({
        "tenant_id": "01010101-0101-0101-0101-010101010101",
        "email": "analyst@sentinelx.dev",
        "password": "Analyst!Password1"
    });

    let resp = client
        .post(format!("{base}/v1/auth/login"))
        // Bypass the RBA loopback-block path (mirrors
        // `login_with_readme_creds.rs`).
        .header("x-forwarded-for", "8.8.8.8")
        .json(&body)
        .send()
        .await
        .expect("POST /v1/auth/login");

    let status = resp.status();
    let json: serde_json::Value = resp
        .json()
        .await
        .expect("login response body parses as JSON");

    assert_eq!(
        status.as_u16(),
        200,
        "login with analyst e2e credentials must succeed — \
         got {status} body={json}. If this fails with a 401/422 the \
         dev-example analyst PHC no longer matches the documented \
         `Analyst!Password1`; regenerate per L1-FU1.",
    );

    let access_token = json
        .get("data")
        .and_then(|d| d.get("access_token"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();

    assert!(
        !access_token.is_empty(),
        "login response missing data.access_token: {json}",
    );
}
