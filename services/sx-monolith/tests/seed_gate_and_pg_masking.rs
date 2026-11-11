//! Regression gate for SX-REVIEW-002 (M2): the demo data seeder MUST
//! emit a one-line "applied N records" tracing line on first boot, MUST
//! become a no-op on a second invocation, and MUST surface a single
//! `warn` line naming LOW-002 / LOW-004 / LOW-005 whenever the operator
//! booted with `bootstrap.seed_demo_data = true` AND
//! `database.enabled = false` (the dev quick-start configuration).
//!
//! The subprocess path spawns the actual `sx-monolith` binary against
//! `config/sentinelx.dev.example.yaml` (which already satisfies
//! `seed_demo_data=true && database.enabled=false`) with `--diagnose` so
//! the warn-default log filter is overridden to info. Both stdout and
//! stderr are captured into a shared sink — `sx-telemetry::logging`
//! writes records to stdout by default (see the same capture pattern in
//! `tests/diagnose_flag.rs`).
//!
//! The idempotency half of the gate (the in-memory engagement repo's
//! `is_empty()` probe flipping after the first `seed::run`) is covered
//! by the crate-internal unit test
//! `adapters::engagement::tests::is_empty_flips_after_seed_one`. The
//! `InMemoryEngagementRepository` is `pub(crate)` so it is not
//! reachable from an integration target — running the gate against a
//! freshly built `AppState` would require either making the type
//! public or duplicating the wiring. The unit test covers the same
//! contract surface (`is_empty` returns true → false after a seed).

#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::print_stdout)]
#![allow(clippy::print_stderr)]
#![allow(clippy::missing_panics_doc)]
// Subprocess integration test — see the same allow block in
// `login_with_readme_creds.rs` / `diagnose_flag.rs` for the
// workspace-lint rationale.
#![allow(clippy::disallowed_methods)]
#![allow(clippy::disallowed_macros)]

use std::io::{BufRead, BufReader, Read};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Bind a fresh ephemeral TCP port and return it. Pattern lifted from
/// `login_with_readme_creds.rs` / `diagnose_flag.rs` so two concurrent
/// test threads cannot race on the default 8080 port.
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
/// background monolith.
struct ChildKillOnDrop(Child);

impl Drop for ChildKillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Drain a child's output stream into a shared `Vec<String>`. Each line
/// is also echoed to the test runner's stderr so a CI failure surfaces
/// the boot log alongside the assertion. `sx-telemetry::logging`'s
/// fmt layer writes records to stdout by default — capturing both
/// streams is what `tests/diagnose_flag.rs` does for the same reason.
fn capture_child_stream<R>(stream: R, tag: &'static str, sink: Arc<Mutex<Vec<String>>>)
where
    R: Read + Send + 'static,
{
    std::thread::spawn(move || {
        let reader = BufReader::new(stream);
        for line in reader.lines().map_while(Result::ok) {
            eprintln!("[sx-monolith/{tag}] {line}");
            if let Ok(mut guard) = sink.lock() {
                guard.push(line);
            }
        }
    });
}

/// Poll the captured sink for a substring until `deadline` elapses.
fn wait_for_substring(sink: &Arc<Mutex<Vec<String>>>, needle: &str, deadline: Instant) -> bool {
    while Instant::now() < deadline {
        let hit = sink
            .lock()
            .map(|g| g.iter().any(|line| line.contains(needle)))
            .unwrap_or(false);
        if hit {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

/// Spawn the monolith with `--diagnose` (so the warn-default filter is
/// forced to info) against the committed dev example config. Returns
/// the kill-on-drop guard and the shared stdout+stderr sink.
fn spawn_dev_monolith_with_diagnose() -> (ChildKillOnDrop, Arc<Mutex<Vec<String>>>) {
    let config_path = dev_example_config_path();
    assert!(
        config_path.exists(),
        "expected dev example config at {} — the SX-REVIEW-002 / C2 fix \
         creates this file; if it has gone missing the SX-REVIEW-002 / M2 \
         gate cannot run.",
        config_path.display(),
    );

    let port = pick_free_port();
    let bind = format!("127.0.0.1:{port}");
    let binary = env!("CARGO_BIN_EXE_sx-monolith");

    let mut cmd = Command::new(binary);
    cmd.env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", std::env::var("HOME").unwrap_or_default())
        .env("SENTINELX_CONFIG", &config_path)
        .env("SENTINELX__SERVER__BIND_ADDR", &bind)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .arg("--diagnose");

    let mut child = cmd.spawn().expect("spawn sx-monolith");
    let stdout = child
        .stdout
        .take()
        .expect("stdout piped at spawn so .take() must succeed");
    let stderr = child
        .stderr
        .take()
        .expect("stderr piped at spawn so .take() must succeed");
    let sink: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    capture_child_stream(stdout, "stdout", Arc::clone(&sink));
    capture_child_stream(stderr, "stderr", Arc::clone(&sink));
    (ChildKillOnDrop(child), sink)
}

/// SX-REVIEW-002 / M2 — booting the monolith with the committed dev
/// example config (`seed_demo_data=true`, `database.enabled=false`)
/// MUST emit two distinct startup signatures:
///
/// 1. An `adapters.seed` info line `"demo data seed: applied N records"`
///    — proves the gated seed path actually ran and reports the count.
/// 2. An `adapters.seed.pg_masked` warn line naming
///    `LOW-002`, `LOW-004`, `LOW-005` AND `database.enabled=false` —
///    proves the operator sees a single explicit signal that the
///    Pg-backed RBA paths are using in-memory stubs.
#[test]
fn dev_boot_emits_seed_applied_and_pg_masking_warn() {
    let (_guard, sink) = spawn_dev_monolith_with_diagnose();

    // Both lines are emitted during composition-root construction,
    // which finishes well before any HTTP listener accepts a
    // connection. 20s is comfortable headroom for a cold-cache debug
    // boot on CI without hiding a real wedge.
    let deadline = Instant::now() + Duration::from_secs(20);

    assert!(
        wait_for_substring(&sink, "demo data seed: applied", deadline),
        "expected an `adapters.seed` info line matching \
         \"demo data seed: applied N records\" within 20s — none \
         seen. Captured lines:\n{}",
        sink.lock().expect("sink").join("\n"),
    );

    // The warn line MUST name all three LOW-* IDs verbatim plus the
    // exact `database.enabled=false` token so an operator skimming
    // logs can grep straight to the masked paths.
    let pg_warn_deadline = Instant::now() + Duration::from_secs(5);
    let saw_pg_warn = wait_for_substring(&sink, "LOW-002/LOW-004/LOW-005", pg_warn_deadline) && {
        let lines = sink.lock().expect("sink").clone();
        lines.iter().any(|l| {
            l.contains("LOW-002")
                && l.contains("LOW-004")
                && l.contains("LOW-005")
                && l.contains("database.enabled=false")
        })
    };
    assert!(
        saw_pg_warn,
        "expected a warn line naming LOW-002/LOW-004/LOW-005 with \
         `database.enabled=false` — none seen. Captured lines:\n{}",
        sink.lock().expect("sink").join("\n"),
    );
}
