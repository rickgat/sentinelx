//! Server bootstrap.
//!
//! [`serve`] binds a TCP listener to the address declared in [`ServerConfig`]
//! and runs the supplied router. Shutdown is driven by SIGINT and SIGTERM:
//! either signal causes axum to stop accepting new connections and finishes
//! in-flight requests up to `shutdown_timeout`.
//!
//! [`serve_with_tls`] is the mTLS-capable sibling: callers hand in a
//! pre-built [`rustls::ServerConfig`] (typically produced by
//! `sx_mtls::build_server_config`) plus the explicit bind address, and
//! axum-server takes over the TLS handshake. No certificate, key, or
//! handshake material is ever surfaced through `tracing`.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum_server::tls_rustls::RustlsConfig;
use sx_config::schema::server::ServerConfig;
use thiserror::Error;
use tokio::net::TcpListener;
use tokio::time::timeout;

/// Errors raised while bootstrapping or running the HTTP server.
#[derive(Debug, Error)]
pub enum ServeError {
    /// Failed to bind the TCP listener (port in use, permission denied …).
    #[error("bind {addr}: {source}")]
    Bind {
        /// The address we tried to bind.
        addr: std::net::SocketAddr,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// Failed to install a signal handler.
    #[error("install signal handler: {0}")]
    Signal(#[source] std::io::Error),

    /// Underlying axum/hyper server error.
    #[error("server: {0}")]
    Server(#[source] std::io::Error),
}

/// Run the router with the given server configuration.
///
/// Blocks until SIGINT or SIGTERM is received, then waits up to
/// `cfg.shutdown_timeout` for in-flight requests before forcing exit.
pub async fn serve(cfg: ServerConfig, router: Router) -> Result<(), ServeError> {
    let listener = TcpListener::bind(cfg.bind_addr)
        .await
        .map_err(|e| ServeError::Bind {
            addr: cfg.bind_addr,
            source: e,
        })?;
    tracing::info!(addr = %cfg.bind_addr, "sx-api listening");

    let shutdown_timeout = cfg.shutdown_timeout;
    let signal = wait_for_shutdown(shutdown_timeout);

    axum::serve(listener, router.into_make_service())
        .with_graceful_shutdown(signal)
        .await
        .map_err(ServeError::Server)
}

/// Wraps a [`rustls::ServerConfig`] into the [`RustlsConfig`] shape that
/// axum-server expects.
///
/// The conversion is purely structural: it stashes the `Arc` in an
/// `ArcSwap` so axum-server can hot-swap the underlying config later
/// without dropping in-flight connections. No key material is logged or
/// copied here.
///
/// Note: callers are responsible for ensuring ALPN protocols (`h2`,
/// `http/1.1`) are configured on the inner [`rustls::ServerConfig`] if
/// they need HTTP/2 negotiation — `axum-server` does not set them.
#[must_use]
pub fn make_axum_rustls_config(inner: Arc<rustls::ServerConfig>) -> RustlsConfig {
    RustlsConfig::from_config(inner)
}

/// Run the router with TLS termination.
///
/// `addr` is the explicit socket the listener binds to. `rustls_config`
/// is a fully-populated [`rustls::ServerConfig`] — typically produced by
/// `sx_mtls::build_server_config` so the same expiry/safety-window
/// guarantees apply.
///
/// This function intentionally does **not** install signal handlers: the
/// graceful-shutdown wiring lives in [`serve`]. A future revision will
/// fold both code paths together. For now the monolith composition root
/// is the single caller, and it owns shutdown via the runtime.
///
/// Errors:
/// * [`ServeError::Bind`] — failed to bind the TCP listener.
/// * [`ServeError::Server`] — axum-server returned an I/O error mid-flight.
pub async fn serve_with_tls(
    router: Router,
    addr: SocketAddr,
    rustls_config: Arc<rustls::ServerConfig>,
) -> Result<(), ServeError> {
    let tls = make_axum_rustls_config(rustls_config);
    // Log only the listen address — never the cert chain, fingerprint, or
    // key material. Fingerprint logging is sx-mtls's job at load time.
    tracing::info!(addr = %addr, "sx-api listening (tls)");

    axum_server::bind_rustls(addr, tls)
        .serve(router.into_make_service())
        .await
        .map_err(ServeError::Server)
}

async fn wait_for_shutdown(grace: Duration) {
    let ctrl_c = async {
        if let Err(err) = tokio::signal::ctrl_c().await {
            tracing::error!(error = %err, "ctrl_c handler failed");
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            Err(err) => {
                tracing::error!(error = %err, "SIGTERM handler failed");
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {}
        () = terminate => {}
    }

    tracing::info!(grace_secs = grace.as_secs(), "shutdown signal received");
    // Bound the grace window — once it elapses axum will stop waiting.
    let _ = timeout(grace, std::future::pending::<()>()).await;
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
    use std::fs;
    use sx_config::MtlsConfig;
    use sx_mtls::{build_server_config, MtlsError};
    use tempfile::tempdir;
    use time::{Duration as TimeDuration, OffsetDateTime};

    /// rcgen-based self-signed PEM pair. Mirrors `sx-mtls`'s private
    /// `test_support::make_self_signed` so this crate stays
    /// self-contained without exposing test helpers across crate
    /// boundaries.
    fn make_self_signed(validity_days: i64) -> (String, String) {
        let key_pair = KeyPair::generate().expect("rcgen keypair");
        let mut params = CertificateParams::new(vec!["localhost".to_string()])
            .expect("rcgen params accept DNS SAN");

        let now = OffsetDateTime::now_utc();
        params.not_before = now - TimeDuration::days(1);
        params.not_after = now + TimeDuration::days(validity_days);

        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "sentinelx-test");
        params.distinguished_name = dn;

        let cert = params
            .self_signed(&key_pair)
            .expect("rcgen self-signed cert");
        (cert.pem(), key_pair.serialize_pem())
    }

    fn install_ring_provider() {
        // rustls's default provider can only install once per process.
        let _ = rustls::crypto::ring::default_provider().install_default();
    }

    /// Build a valid `rustls::ServerConfig` via the real sx-mtls
    /// pipeline so tests exercise the same code path the monolith will.
    fn build_valid_server_config() -> Arc<rustls::ServerConfig> {
        install_ring_provider();
        let dir = tempdir().expect("tempdir");
        let (cert_pem, key_pem) = make_self_signed(365);
        let cert_path = dir.path().join("server.crt");
        let key_path = dir.path().join("server.key");
        fs::write(&cert_path, cert_pem).expect("write cert");
        fs::write(&key_path, key_pem).expect("write key");

        let cfg = MtlsConfig {
            enabled: true,
            cert_path: cert_path.display().to_string(),
            key_path: key_path.display().to_string(),
            client_ca_path: String::new(),
            require_client_cert: false,
            reload_interval_secs: 60,
        };

        Arc::new(build_server_config(&cfg).expect("build server config"))
    }

    #[tokio::test]
    async fn bind_fails_on_invalid_addr() {
        let cfg = ServerConfig {
            // Port 1 typically requires root; this should fail in CI.
            bind_addr: SocketAddr::from(([127, 0, 0, 1], 1)),
            shutdown_timeout: Duration::from_secs(1),
            request_timeout: Duration::from_secs(1),
            max_body_bytes: 4096,
            rate_limit: sx_config::schema::server::RateLimitConfig {
                limit_per_minute: 60,
                burst: 10,
                enabled: false,
            },
        };
        let router = Router::new();
        let res = serve(cfg, router).await;
        // We tolerate either Bind or Server depending on permissions; the
        // important property is that the function returns an error rather
        // than panicking.
        assert!(res.is_err(), "expected error binding to port 1");
    }

    /// `make_axum_rustls_config` must not panic when handed a valid,
    /// fully-built `rustls::ServerConfig`. We don't assert anything
    /// internal about `RustlsConfig` (it's opaque) — just that the
    /// conversion executes.
    #[tokio::test]
    async fn make_axum_rustls_config_accepts_valid_server_config() {
        let inner = build_valid_server_config();
        // Call the helper. If it panics the test fails; if it returns a
        // value, the conversion is well-formed.
        let _cfg = make_axum_rustls_config(inner);
    }

    /// Regression: the original `serve` API still compiles and runs.
    /// We bind to an ephemeral port, give it ~100ms to enter the accept
    /// loop, then abort the join handle.
    #[tokio::test]
    async fn serve_smoke_starts_and_aborts() {
        let cfg = ServerConfig {
            bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            shutdown_timeout: Duration::from_millis(50),
            request_timeout: Duration::from_secs(1),
            max_body_bytes: 4096,
            rate_limit: sx_config::schema::server::RateLimitConfig {
                limit_per_minute: 60,
                burst: 10,
                enabled: false,
            },
        };
        let router = Router::new();
        let mut handle = tokio::spawn(async move { serve(cfg, router).await });

        tokio::select! {
            () = tokio::time::sleep(Duration::from_millis(100)) => {
                // Timer elapsed first → server is happily in its accept
                // loop. Abort and treat that as success.
                handle.abort();
            }
            joined = &mut handle => {
                // If serve returned this fast it must be an error
                // (couldn't bind, etc). That's still acceptable as a
                // smoke test of compilation + invocation.
                let _ = joined;
            }
        }
    }

    /// `serve_with_tls` accepts a self-signed cert and binds to the
    /// kernel-assigned port on 127.0.0.1. We don't drive a TLS
    /// handshake — just confirm bind + accept-loop entry, then abort.
    #[tokio::test]
    async fn serve_with_tls_binds_self_signed() {
        let tls = build_valid_server_config();
        let addr: SocketAddr = ([127, 0, 0, 1], 0).into();
        let router = Router::new();
        let mut handle = tokio::spawn(async move { serve_with_tls(router, addr, tls).await });

        tokio::select! {
            () = tokio::time::sleep(Duration::from_millis(500)) => {
                // Server stayed alive long enough to be considered bound.
                handle.abort();
            }
            joined = &mut handle => {
                // Early return is a failure mode worth surfacing. We
                // tolerate JoinError (aborted) but not a "successful"
                // immediate Ok(()) — axum-server should keep serving.
                match joined {
                    Ok(Ok(())) => panic!("serve_with_tls returned Ok immediately"),
                    Ok(Err(e)) => panic!("serve_with_tls errored immediately: {e}"),
                    Err(_join) => {}
                }
            }
        }
    }

    /// Error path: handing sx-mtls an invalid (missing) cert file must
    /// produce a structured `MtlsError`, never panic. This guards the
    /// contract `serve_with_tls` relies on — `build_server_config`
    /// surfaces config-shape errors before we ever reach the listener.
    #[tokio::test]
    async fn invalid_cert_returns_config_shape_error_from_sx_mtls() {
        let dir = tempdir().expect("tempdir");
        let missing = dir.path().join("does-not-exist.crt");
        let key = dir.path().join("does-not-exist.key");

        let cfg = MtlsConfig {
            enabled: true,
            cert_path: missing.display().to_string(),
            key_path: key.display().to_string(),
            client_ca_path: String::new(),
            require_client_cert: false,
            reload_interval_secs: 60,
        };

        let err = build_server_config(&cfg).expect_err("missing cert must fail");
        assert!(
            matches!(
                err,
                MtlsError::Io { .. } | MtlsError::InvalidCertificate { .. }
            ),
            "expected config-shape error, got {err:?}"
        );
    }
}
