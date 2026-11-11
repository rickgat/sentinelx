//! Container runtime introspection.
//!
//! This module implements two transports:
//!
//! 1. **Docker socket** — when the configured runtime socket path looks like a
//!    Docker engine socket (i.e. `/var/run/docker.sock` or any other path whose
//!    final component mentions `docker`), we open a
//!    [`tokio::net::UnixStream`], speak just enough HTTP/1.1 to issue
//!    `GET /containers/json?all=false`, parse the JSON response, and return one
//!    [`ContainerSummary`] per running container with `runtime = "docker"`.
//!
//! 2. **CRI / containerd socket (detection-only stub)** — when the path
//!    matches the containerd / CRI-O conventions (e.g.
//!    `/run/containerd/containerd.sock`, `/var/run/crio/crio.sock`,
//!    `/var/run/cri-dockerd.sock`), we recognise it but do **not** speak the
//!    gRPC CRI protocol. A real implementation would require pulling in
//!    `tonic` + `prost` and compiling the CRI protobufs, which is heavyweight
//!    for an agent skeleton. Instead we log an `info!` once and return an
//!    empty list. PRs that add a tonic-based CRI client are welcome — see
//!    [`collect_cri_containers`].
//!
//! Anything that is neither Docker nor CRI is logged at `debug!` and yields an
//! empty `Vec`. Every failure path logs and converts to an empty list; the
//! inventory loop must never panic on hosts with a half-broken container
//! runtime.

use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

/// Maximum body we are willing to buffer from the daemon (4 MiB). The Docker
/// API streams JSON, but every realistic container list comfortably fits in a
/// handful of kilobytes even on busy nodes — capping prevents a misbehaving
/// daemon from exhausting agent memory.
const MAX_BODY_BYTES: usize = 4 * 1024 * 1024;

/// Per-request timeout. Two seconds is generous for a local unix socket and
/// keeps the agent's inventory tick responsive even when the daemon is wedged.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(2);

/// One container as seen by the host (best-effort summary).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ContainerSummary {
    pub id: String,
    pub image: String,
    pub runtime: String,
}

/// Internal errors surfaced by the Docker collector. They never escape the
/// public API — the caller always sees a `Vec<ContainerSummary>` — but the
/// typed variants make the unit tests precise.
#[derive(Debug, Error)]
enum DockerError {
    #[error("I/O error talking to docker socket: {0}")]
    Io(#[from] std::io::Error),
    #[error("request to docker socket timed out")]
    Timeout,
    #[error("malformed HTTP response from docker socket: {0}")]
    Protocol(&'static str),
    #[error("docker returned HTTP status {0}")]
    Status(u16),
    #[error("response body exceeded {MAX_BODY_BYTES} bytes")]
    BodyTooLarge,
    #[error("failed to decode docker JSON: {0}")]
    Json(#[from] serde_json::Error),
}

/// Returns a best-effort list of containers.
///
/// Dispatch order:
///
/// * `None` or non-existent path → empty `Vec` (debug / warn log).
/// * Docker socket → full HTTP/1.1 round-trip via [`query_docker`].
/// * CRI / containerd socket → [`collect_cri_containers`] stub (empty `Vec`).
/// * Anything else → empty `Vec` (debug log).
///
/// Any transport, protocol, or parser error on the Docker path is logged and
/// converted to an empty list so the caller's inventory schema remains
/// stable.
#[allow(clippy::cognitive_complexity)] // dispatcher fans out to docker/CRI/missing paths with structured logging
pub async fn collect_containers(socket: Option<&Path>) -> Vec<ContainerSummary> {
    let Some(path) = socket else {
        tracing::debug!("no container runtime socket configured; skipping inventory");
        return Vec::new();
    };
    if !path.exists() {
        tracing::warn!(
            socket = %path.display(),
            "container runtime socket missing; reporting empty container list"
        );
        return Vec::new();
    }
    if is_docker_socket(path) {
        return match query_docker(path).await {
            Ok(containers) => containers,
            Err(err) => {
                tracing::warn!(
                    socket = %path.display(),
                    error = %err,
                    "docker container inventory failed; reporting empty list"
                );
                Vec::new()
            }
        };
    }
    if is_cri_socket(path) {
        return collect_cri_containers(path).await;
    }
    tracing::debug!(
        socket = %path.display(),
        "runtime socket did not match docker or CRI heuristics; reporting empty list"
    );
    Vec::new()
}

/// Heuristic: is this socket path a Docker engine socket?
fn is_docker_socket(path: &Path) -> bool {
    let s = path.to_string_lossy();
    if s == "/var/run/docker.sock" || s == "/run/docker.sock" {
        return true;
    }
    // `cri-dockerd` is the shim that adapts Docker to the CRI protocol; from
    // the agent's perspective it is reached via gRPC, *not* the Docker HTTP
    // API, so we must not treat it as a Docker socket even though the file
    // name contains `docker`.
    if s.contains("cri-dockerd") || s.contains("cri") {
        return false;
    }
    s.contains("docker")
}

/// Heuristic: is this socket path a containerd / CRI-O / cri-dockerd socket?
///
/// We match on substrings rather than exact paths because installers and
/// distributions vary (e.g. `/run/containerd/containerd.sock`,
/// `/var/run/crio/crio.sock`, `/var/run/cri-dockerd.sock`, k3s's
/// `/run/k3s/containerd/containerd.sock`).
fn is_cri_socket(path: &Path) -> bool {
    let s = path.to_string_lossy();
    s.contains("containerd") || s.contains("crio") || s.contains("cri-dockerd") || s.contains("cri")
}

/// CRI / containerd collector — **detection-only stub**.
///
/// A real implementation would speak the CRI gRPC API
/// (`runtime.v1.RuntimeService/ListContainers`) over the unix socket. That
/// requires `tonic` + `prost` + the upstream CRI protobufs, which roughly
/// triples the agent's compiled-binary size and pulls in a non-trivial code
/// generation step. For the skeleton we deliberately stop at detection: we
/// log the socket at `info!` so operators can see CRI was recognised, and we
/// return an empty `Vec` so the inventory schema stays stable.
///
/// PRs that wire up a real tonic-based CRI client are welcome; the signature
/// of this function is intentionally a drop-in replacement target.
#[allow(clippy::unused_async)]
async fn collect_cri_containers(path: &Path) -> Vec<ContainerSummary> {
    tracing::info!(
        socket = %path.display(),
        "CRI/containerd socket detected but full CRI client requires gRPC + protobuf; \
         falling back to runtime detection only and returning empty container list"
    );
    Vec::new()
}

/// Wraps the Docker socket round-trip in a timeout and a body cap.
async fn query_docker(path: &Path) -> Result<Vec<ContainerSummary>, DockerError> {
    let body = tokio::time::timeout(REQUEST_TIMEOUT, fetch_containers_body(path))
        .await
        .map_err(|_| DockerError::Timeout)??;
    parse_containers_json(&body)
}

/// Opens the unix socket, sends a single HTTP/1.1 request, returns the body
/// bytes. Connection is closed after the response by virtue of
/// `Connection: close`.
async fn fetch_containers_body(path: &Path) -> Result<Vec<u8>, DockerError> {
    let mut stream = UnixStream::connect(path).await?;
    let request = b"GET /containers/json?all=false HTTP/1.1\r\n\
                    Host: localhost\r\n\
                    Accept: application/json\r\n\
                    User-Agent: sx-agent\r\n\
                    Connection: close\r\n\
                    \r\n";
    stream.write_all(request).await?;
    stream.flush().await?;

    let mut raw = Vec::with_capacity(8 * 1024);
    let mut buf = [0_u8; 8 * 1024];
    loop {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        if raw.len().saturating_add(n) > MAX_BODY_BYTES.saturating_mul(2) {
            return Err(DockerError::BodyTooLarge);
        }
        let Some(slice) = buf.get(..n) else {
            return Err(DockerError::Protocol("short read"));
        };
        raw.extend_from_slice(slice);
    }
    parse_http_response(&raw)
}

/// Splits a raw HTTP/1.1 response into its decoded body bytes.
///
/// Supports `Content-Length` and `Transfer-Encoding: chunked`. Both are used
/// by the Docker daemon depending on payload size / version. We deliberately
/// roll our own parser rather than pull in `hyper` for the unix-socket path —
/// the surface area is tiny and well-tested.
fn parse_http_response(raw: &[u8]) -> Result<Vec<u8>, DockerError> {
    let split = find_header_end(raw).ok_or(DockerError::Protocol("missing header terminator"))?;
    let header_bytes = raw
        .get(..split)
        .ok_or(DockerError::Protocol("header slice"))?;
    let body_bytes = raw
        .get(split.saturating_add(4)..)
        .ok_or(DockerError::Protocol("body slice"))?;

    let header_str =
        std::str::from_utf8(header_bytes).map_err(|_| DockerError::Protocol("non-utf8 header"))?;
    let mut lines = header_str.split("\r\n");
    let status_line = lines
        .next()
        .ok_or(DockerError::Protocol("no status line"))?;
    let status = parse_status_line(status_line)?;
    if !(200..300).contains(&status) {
        return Err(DockerError::Status(status));
    }

    let mut content_length: Option<usize> = None;
    let mut chunked = false;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim();
        let value = value.trim();
        if name.eq_ignore_ascii_case("content-length") {
            content_length = value.parse::<usize>().ok();
        } else if name.eq_ignore_ascii_case("transfer-encoding")
            && value.eq_ignore_ascii_case("chunked")
        {
            chunked = true;
        }
    }

    let body = if chunked {
        decode_chunked(body_bytes)?
    } else if let Some(len) = content_length {
        if len > MAX_BODY_BYTES {
            return Err(DockerError::BodyTooLarge);
        }
        body_bytes
            .get(..len)
            .ok_or(DockerError::Protocol("body shorter than content-length"))?
            .to_vec()
    } else {
        // No framing header — assume the daemon closed the connection after
        // the body (HTTP/1.0-style). Take what we've got, bounded.
        if body_bytes.len() > MAX_BODY_BYTES {
            return Err(DockerError::BodyTooLarge);
        }
        body_bytes.to_vec()
    };

    if body.len() > MAX_BODY_BYTES {
        return Err(DockerError::BodyTooLarge);
    }
    Ok(body)
}

/// Locates the byte index of the first `\r\n\r\n` separating headers from
/// body. Returns the position of the first `\r`.
fn find_header_end(raw: &[u8]) -> Option<usize> {
    if raw.len() < 4 {
        return None;
    }
    let mut i: usize = 0;
    while i.saturating_add(4) <= raw.len() {
        let window = raw.get(i..i.saturating_add(4))?;
        if window == b"\r\n\r\n" {
            return Some(i);
        }
        i = i.saturating_add(1);
    }
    None
}

fn parse_status_line(line: &str) -> Result<u16, DockerError> {
    // e.g. "HTTP/1.1 200 OK"
    let mut parts = line.split_whitespace();
    let _version = parts
        .next()
        .ok_or(DockerError::Protocol("missing http version"))?;
    let code = parts
        .next()
        .ok_or(DockerError::Protocol("missing status code"))?;
    code.parse::<u16>()
        .map_err(|_| DockerError::Protocol("bad status code"))
}

/// Decodes an HTTP/1.1 chunked body. Each chunk: `<hex-len>\r\n<bytes>\r\n`,
/// terminated by a zero-length chunk. Chunk extensions and trailers are
/// tolerated (and ignored).
fn decode_chunked(mut data: &[u8]) -> Result<Vec<u8>, DockerError> {
    let mut out: Vec<u8> = Vec::new();
    loop {
        let line_end = find_crlf(data).ok_or(DockerError::Protocol("chunk size line"))?;
        let size_line = data
            .get(..line_end)
            .ok_or(DockerError::Protocol("chunk size slice"))?;
        let size_str =
            std::str::from_utf8(size_line).map_err(|_| DockerError::Protocol("chunk size utf8"))?;
        // Strip any chunk extension (everything after `;`).
        let hex = size_str.split(';').next().unwrap_or("").trim();
        let chunk_size =
            usize::from_str_radix(hex, 16).map_err(|_| DockerError::Protocol("chunk size hex"))?;

        data = data
            .get(line_end.saturating_add(2)..)
            .ok_or(DockerError::Protocol("chunk size advance"))?;

        if chunk_size == 0 {
            // Done. Trailers (if any) follow; we ignore them.
            break;
        }
        if out.len().saturating_add(chunk_size) > MAX_BODY_BYTES {
            return Err(DockerError::BodyTooLarge);
        }
        let chunk = data
            .get(..chunk_size)
            .ok_or(DockerError::Protocol("chunk shorter than declared"))?;
        out.extend_from_slice(chunk);
        let after = data
            .get(chunk_size..)
            .ok_or(DockerError::Protocol("chunk trailing crlf missing"))?;
        // Expect trailing CRLF after the chunk data.
        let Some(rest) = after.strip_prefix(b"\r\n") else {
            return Err(DockerError::Protocol("chunk trailing crlf"));
        };
        data = rest;
    }
    Ok(out)
}

fn find_crlf(data: &[u8]) -> Option<usize> {
    let mut i: usize = 0;
    while i.saturating_add(2) <= data.len() {
        let window = data.get(i..i.saturating_add(2))?;
        if window == b"\r\n" {
            return Some(i);
        }
        i = i.saturating_add(1);
    }
    None
}

/// Minimal projection of the Docker `/containers/json` response. We only
/// surface a handful of fields; the daemon returns many more.
#[derive(Debug, Deserialize)]
struct DockerContainerRow {
    #[serde(rename = "Id", default)]
    id: String,
    #[serde(rename = "Image", default)]
    image: String,
}

/// Parses a Docker `/containers/json` body into [`ContainerSummary`] rows.
///
/// Exposed at module scope (not under `#[cfg(test)]`) so the unit tests can
/// exercise the JSON shape without standing up a unix socket; the function is
/// kept `pub(super)`-equivalent (module-private) since it has no callers
/// outside this file.
fn parse_containers_json(body: &[u8]) -> Result<Vec<ContainerSummary>, DockerError> {
    let rows: Vec<DockerContainerRow> = serde_json::from_slice(body)?;
    Ok(rows
        .into_iter()
        .filter(|r| !r.id.is_empty())
        .map(|r| ContainerSummary {
            id: r.id,
            image: r.image,
            runtime: "docker".to_owned(),
        })
        .collect())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tokio::net::UnixListener;

    #[tokio::test]
    async fn collect_containers_returns_empty_when_socket_missing() {
        let result = collect_containers(None).await;
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn collect_containers_returns_empty_for_nonexistent_socket() {
        let result =
            collect_containers(Some(Path::new("/nonexistent/sx-agent/runtime.sock"))).await;
        assert!(result.is_empty());
    }

    #[test]
    fn is_docker_socket_recognises_canonical_paths() {
        assert!(is_docker_socket(Path::new("/var/run/docker.sock")));
        assert!(is_docker_socket(Path::new("/run/docker.sock")));
        assert!(is_docker_socket(Path::new("/var/lib/docker/docker.sock")));
        assert!(is_docker_socket(Path::new("/tmp/some-docker-thing")));
    }

    #[test]
    fn is_docker_socket_rejects_other_runtimes() {
        assert!(!is_docker_socket(Path::new(
            "/run/containerd/containerd.sock"
        )));
        assert!(!is_docker_socket(Path::new("/var/run/crio/crio.sock")));
    }

    #[test]
    fn is_docker_socket_rejects_cri_dockerd_shim() {
        // cri-dockerd is a CRI gRPC shim, not the Docker HTTP API — it must
        // be handled by the CRI path even though the filename mentions docker.
        assert!(!is_docker_socket(Path::new("/var/run/cri-dockerd.sock")));
    }

    #[test]
    fn is_cri_socket_recognises_containerd_paths() {
        assert!(is_cri_socket(Path::new("/run/containerd/containerd.sock")));
        assert!(is_cri_socket(Path::new(
            "/run/k3s/containerd/containerd.sock"
        )));
        assert!(is_cri_socket(Path::new("/var/run/crio/crio.sock")));
        assert!(is_cri_socket(Path::new("/var/run/cri-dockerd.sock")));
    }

    #[test]
    fn is_cri_socket_rejects_docker_paths() {
        assert!(!is_cri_socket(Path::new("/var/run/docker.sock")));
        assert!(!is_cri_socket(Path::new("/run/docker.sock")));
        assert!(!is_cri_socket(Path::new("/tmp/some-docker-thing")));
    }

    #[tokio::test]
    async fn collect_containers_returns_empty_for_cri_socket_stub() {
        // Use a real on-disk file (not a live unix socket) so `path.exists()`
        // is true and the dispatcher reaches the CRI branch. The stub must
        // not attempt any I/O against the path.
        let path = unique_socket_path("cri-stub");
        std::fs::write(&path, b"").unwrap();
        // Sanity: path name itself triggers the CRI heuristic.
        let cri_path = path.with_file_name(format!(
            "containerd-{}.sock",
            path.file_name().and_then(|s| s.to_str()).unwrap_or("x")
        ));
        std::fs::rename(&path, &cri_path).unwrap();
        assert!(is_cri_socket(&cri_path));

        let result = collect_containers(Some(&cri_path)).await;
        let _ = std::fs::remove_file(&cri_path);
        assert!(result.is_empty(), "CRI stub must yield an empty list");
    }

    #[test]
    fn parse_containers_json_handles_empty_array() {
        let out = parse_containers_json(b"[]").unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn parse_containers_json_extracts_id_and_image() {
        let payload = br#"[
            {"Id":"abc123","Image":"nginx:1.27","Names":["/web"]},
            {"Id":"def456","Image":"redis:7","Names":["/cache"]}
        ]"#;
        let out = parse_containers_json(payload).unwrap();
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].id, "abc123");
        assert_eq!(out[0].image, "nginx:1.27");
        assert_eq!(out[0].runtime, "docker");
        assert_eq!(out[1].id, "def456");
    }

    #[test]
    fn parse_containers_json_skips_rows_without_id() {
        let payload = br#"[{"Id":"","Image":"x"},{"Id":"keep","Image":"y"}]"#;
        let out = parse_containers_json(payload).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].id, "keep");
    }

    #[test]
    fn parse_containers_json_rejects_garbage() {
        let err = parse_containers_json(b"not json").unwrap_err();
        assert!(matches!(err, DockerError::Json(_)));
    }

    #[test]
    fn parse_http_response_with_content_length() {
        let body = br#"[{"Id":"a","Image":"x"}]"#;
        let raw = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            std::str::from_utf8(body).unwrap()
        );
        let decoded = parse_http_response(raw.as_bytes()).unwrap();
        assert_eq!(decoded, body);
    }

    #[test]
    fn parse_http_response_with_chunked_encoding() {
        // Body "[]" split into two chunks: "[" and "]".
        let raw = b"HTTP/1.1 200 OK\r\n\
                    Transfer-Encoding: chunked\r\n\
                    Content-Type: application/json\r\n\
                    \r\n\
                    1\r\n[\r\n\
                    1\r\n]\r\n\
                    0\r\n\r\n";
        let decoded = parse_http_response(raw).unwrap();
        assert_eq!(decoded, b"[]");
    }

    #[test]
    fn parse_http_response_chunked_tolerates_extensions() {
        let raw = b"HTTP/1.1 200 OK\r\n\
                    Transfer-Encoding: chunked\r\n\
                    \r\n\
                    2;ext=foo\r\nhi\r\n\
                    0\r\n\r\n";
        let decoded = parse_http_response(raw).unwrap();
        assert_eq!(decoded, b"hi");
    }

    #[test]
    fn parse_http_response_rejects_non_2xx() {
        let raw = b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n";
        let err = parse_http_response(raw).unwrap_err();
        assert!(matches!(err, DockerError::Status(500)));
    }

    #[test]
    fn parse_http_response_rejects_missing_header_terminator() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n";
        let err = parse_http_response(raw).unwrap_err();
        assert!(matches!(err, DockerError::Protocol(_)));
    }

    #[test]
    fn parse_http_response_rejects_oversized_content_length() {
        let raw = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
            MAX_BODY_BYTES + 1
        );
        let err = parse_http_response(raw.as_bytes()).unwrap_err();
        assert!(matches!(err, DockerError::BodyTooLarge));
    }

    fn unique_socket_path(label: &str) -> PathBuf {
        // A process-wide monotonic counter guarantees uniqueness even when
        // two parallel tokio tests reach this on the same nanosecond — the
        // old pid+nanos scheme could collide and make the second
        // `UnixListener::bind` fail with EADDRINUSE (flaky panic).
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        std::env::temp_dir().join(format!("sx-agent-docker-{label}-{pid}-{nanos}-{seq}.sock"))
    }

    fn spawn_mock_docker(response: &'static [u8]) -> (PathBuf, tokio::task::JoinHandle<()>) {
        let path = unique_socket_path("ok");
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).unwrap();
        let handle = tokio::spawn(async move {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            // Drain the request so the client's write completes.
            let mut buf = [0_u8; 1024];
            let _ = sock.read(&mut buf).await;
            let _ = sock.write_all(response).await;
            let _ = sock.shutdown().await;
        });
        (path, handle)
    }

    #[tokio::test]
    async fn collect_containers_over_mock_docker_content_length() {
        let body = br#"[{"Id":"abc","Image":"nginx"}]"#;
        let response_str = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            std::str::from_utf8(body).unwrap()
        );
        // Leak so we can hand a 'static slice to the task.
        let response: &'static [u8] = Box::leak(response_str.into_bytes().into_boxed_slice());
        let (path, handle) = spawn_mock_docker(response);

        let result = collect_containers(Some(&path)).await;
        let _ = handle.await;
        let _ = std::fs::remove_file(&path);

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].id, "abc");
        assert_eq!(result[0].image, "nginx");
        assert_eq!(result[0].runtime, "docker");
    }

    #[tokio::test]
    async fn collect_containers_over_mock_docker_chunked() {
        let response: &'static [u8] = b"HTTP/1.1 200 OK\r\n\
                                       Transfer-Encoding: chunked\r\n\
                                       Content-Type: application/json\r\n\
                                       Connection: close\r\n\
                                       \r\n\
                                       2\r\n[]\r\n\
                                       0\r\n\r\n";
        let (path, handle) = spawn_mock_docker(response);
        let result = collect_containers(Some(&path)).await;
        let _ = handle.await;
        let _ = std::fs::remove_file(&path);
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn collect_containers_returns_empty_on_500() {
        let response: &'static [u8] =
            b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        let (path, handle) = spawn_mock_docker(response);
        let result = collect_containers(Some(&path)).await;
        let _ = handle.await;
        let _ = std::fs::remove_file(&path);
        assert!(result.is_empty());
    }
}
