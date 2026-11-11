//! Regression gate for SX-REVIEW-002 (C2): the README quick-start
//! credentials MUST authenticate against a monolith booted with the
//! committed `config/sentinelx.dev.example.yaml`.
//!
//! Without this gate, a future tweak to the dev config or to the
//! bootstrap seeder can silently re-break the documented dev path
//! (a fresh-clone developer follows the README, login fails with
//! `iam.auth.bad_password`, days of debugging ensue).
//!
//! The test spawns the actual `sx-monolith` binary as a subprocess
//! against an ephemeral port, polls `/healthz` until ready, and POSTs
//! to `/v1/auth/login` using the README's documented credentials. The
//! response MUST be HTTP 200 with a non-empty `access_token`.

#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::print_stdout)]
#![allow(clippy::print_stderr)]
#![allow(clippy::missing_panics_doc)]
// Subprocess integration test: we deliberately spawn the production
// `sx-monolith` binary and need to (a) forward the parent's PATH +
// HOME so cargo's runtime-resolved binary still finds linker libs,
// and (b) echo the child's stderr to the test runner so a boot
// panic is visible in CI logs. The workspace bans `std::env::var`
// and `std::eprintln` from product code; both are appropriate here
// in a test harness that crosses the process boundary.
#![allow(clippy::disallowed_methods)]
#![allow(clippy::disallowed_macros)]

use std::io::{BufRead, BufReader};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// Bind a fresh ephemeral TCP port and return it. We pick the port
/// up-front and pass it to the subprocess through
/// `SENTINELX__SERVER__BIND_ADDR` rather than relying on the OS to
/// hand us a fresh one — this avoids races between concurrent test
/// threads launching the monolith.
fn pick_free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    let port = listener.local_addr().expect("local_addr").port();
    drop(listener);
    port
}

/// Locate `config/sentinelx.dev.example.yaml` relative to the workspace
/// root. `CARGO_MANIFEST_DIR` here is `services/sx-monolith`, so we
/// walk two levels up to reach the repo root.
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

/// Best-effort kill on `Drop` so a panicking test never leaks a
/// background monolith. Sending SIGKILL is acceptable here because
/// the in-memory configuration has no on-disk state to flush.
struct ChildKillOnDrop(Child);

impl Drop for ChildKillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Drain the child's stderr in a background thread and echo each line
/// to the test runner's stderr. Without it the only signal on a boot
/// panic would be a silent timeout. The thread exits naturally when
/// the pipe closes (child process exits).
fn forward_child_stderr(stderr: std::process::ChildStderr) {
    std::thread::spawn(move || {
        let reader = BufReader::new(stderr);
        for line in reader.lines().map_while(Result::ok) {
            eprintln!("[sx-monolith] {line}");
        }
    });
}

/// Poll `/healthz` until it returns 200 or `deadline` elapses.
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
async fn readme_quick_start_credentials_authenticate_against_dev_example() {
    let config_path = dev_example_config_path();
    assert!(
        config_path.exists(),
        "expected dev example config at {} — the SX-REVIEW-002 fix \
         creates this file; if it has gone missing the README \
         quick-start is broken",
        config_path.display(),
    );

    let port = pick_free_port();
    let bind = format!("127.0.0.1:{port}");
    let base = format!("http://{bind}");

    // Spawn the monolith with the committed dev example config but
    // override the bind address so concurrent test threads cannot
    // collide on the default 8080 port. We clear the env first so a
    // developer's local `SENTINELX__*` shell exports cannot leak in
    // and silently change the bootstrap admin out from under us.
    let binary = env!("CARGO_BIN_EXE_sx-monolith");
    let mut cmd = Command::new(binary);
    cmd.env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", std::env::var("HOME").unwrap_or_default())
        .env("SENTINELX_CONFIG", &config_path)
        .env("SENTINELX__SERVER__BIND_ADDR", &bind)
        // The default config logs at info — crank down to keep the
        // test stderr stream readable when a flake needs investigating.
        .env("RUST_LOG", "warn,sx_monolith=info,sx_iam=info")
        .stdout(Stdio::null())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn().expect("spawn sx-monolith");
    if let Some(stderr) = child.stderr.take() {
        forward_child_stderr(stderr);
    }
    // RAII handle — dropped at the end of the test (or on panic),
    // SIGKILLs the subprocess.
    let _guard = ChildKillOnDrop(child);

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build reqwest client");

    // Release-mode boot on a warm `target/` is ~1-2s; debug-mode boot
    // is ~3-5s. 30s gives a comfortable headroom for cold CI machines
    // without hiding a real wedge.
    let boot_deadline = Instant::now() + Duration::from_secs(30);
    assert!(
        wait_for_health(&client, &base, boot_deadline).await,
        "monolith /healthz did not return 200 within 30s — check \
         [sx-monolith] stderr lines above for a panic or config error",
    );

    // The README quick-start documents these three values verbatim.
    // The PHC embedded in config/sentinelx.dev.example.yaml hashes
    // `sentinelx-admin-pw`, so a successful 200 here is the
    // end-to-end proof that the doc-vs-code drift from SX-REVIEW-002
    // is closed.
    let body = serde_json::json!({
        "tenant_id": "01010101-0101-0101-0101-010101010101",
        "email": "admin@sentinelx.dev",
        "password": "sentinelx-admin-pw"
    });

    let resp = client
        .post(format!("{base}/v1/auth/login"))
        // Bypass the RBA loopback-block path called out in
        // docs/onboarding.md §8.1 — the dashboard proxy injects this
        // header in dev for the same reason.
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
        "login with README quick-start credentials must succeed — \
         got {status} body={json}. If this fails with a 401/422 the \
         dev-example PHC no longer matches the documented password; \
         regenerate per SX-REVIEW-002 C2.",
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
