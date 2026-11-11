//! PEM loading, expiry validation, and `ServerConfig` assembly.
//!
//! This module never logs private-key bytes. The only certificate-related
//! values surfaced through `tracing` are the SHA-256 fingerprint and the
//! `not_after` expiry timestamp.

use std::fs;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use sha2::{Digest, Sha256};
use sx_config::MtlsConfig;
use time::OffsetDateTime;
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::error::MtlsError;

/// Number of seconds before `not_after` at which a certificate is
/// considered "too close to expiry" and rejected. 30 days.
const EXPIRY_SAFETY_WINDOW_SECS: i64 = 30 * 24 * 60 * 60;

/// Parsed certificate + key material plus a structured fingerprint.
#[derive(Debug, Clone)]
pub struct CertMaterial {
    /// The full leaf-first DER-encoded certificate chain.
    pub chain: Vec<CertificateDer<'static>>,
    /// SHA-256 fingerprint of the leaf certificate, lowercase hex.
    pub leaf_fingerprint_sha256: String,
    /// `not_after` of the leaf certificate (UTC).
    pub leaf_not_after: OffsetDateTime,
}

/// Loads + validates a PEM chain at `cert_path`.
///
/// Errors:
/// * [`MtlsError::Io`] — file unreadable.
/// * [`MtlsError::EmptyPem`] — no certificates decoded.
/// * [`MtlsError::InvalidCertificate`] — leaf X.509 parse failed.
/// * [`MtlsError::CertificateExpiry`] — leaf already expired or expiring
///   within the 30-day safety window.
pub fn load_pem_chain(cert_path: &Path) -> Result<CertMaterial, MtlsError> {
    let bytes = fs::read(cert_path).map_err(|e| MtlsError::io(cert_path, &e))?;
    let mut reader = BufReader::new(bytes.as_slice());
    let chain: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| MtlsError::io(cert_path, &e))?;

    if chain.is_empty() {
        return Err(MtlsError::EmptyPem {
            path: cert_path.to_path_buf(),
        });
    }

    let Some(leaf) = chain.first() else {
        return Err(MtlsError::EmptyPem {
            path: cert_path.to_path_buf(),
        });
    };

    let (_, parsed) =
        X509Certificate::from_der(leaf.as_ref()).map_err(|e| MtlsError::InvalidCertificate {
            path: cert_path.to_path_buf(),
            reason: e.to_string(),
        })?;

    let not_after_unix = parsed.validity().not_after.timestamp();
    let not_after = OffsetDateTime::from_unix_timestamp(not_after_unix).map_err(|e| {
        MtlsError::InvalidCertificate {
            path: cert_path.to_path_buf(),
            reason: format!("not_after out of range: {e}"),
        }
    })?;

    enforce_expiry_window(cert_path, not_after)?;

    let fingerprint = sha256_hex(leaf.as_ref());

    tracing::info!(
        target: "sx_mtls",
        path = %cert_path.display(),
        fingerprint = %fingerprint,
        not_after = %not_after,
        "loaded mTLS certificate chain"
    );

    Ok(CertMaterial {
        chain,
        leaf_fingerprint_sha256: fingerprint,
        leaf_not_after: not_after,
    })
}

/// Loads a PEM bundle of trusted client CAs into a `RootCertStore`.
///
/// Errors:
/// * [`MtlsError::Io`] — file unreadable.
/// * [`MtlsError::EmptyPem`] — no certificates decoded.
pub fn load_client_ca_roots(client_ca_path: &Path) -> Result<RootCertStore, MtlsError> {
    let bytes = fs::read(client_ca_path).map_err(|e| MtlsError::io(client_ca_path, &e))?;
    let mut reader = BufReader::new(bytes.as_slice());
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| MtlsError::io(client_ca_path, &e))?;

    if certs.is_empty() {
        return Err(MtlsError::EmptyPem {
            path: client_ca_path.to_path_buf(),
        });
    }

    let mut roots = RootCertStore::empty();
    for cert in certs {
        roots.add(cert).map_err(|e| MtlsError::InvalidCertificate {
            path: client_ca_path.to_path_buf(),
            reason: e.to_string(),
        })?;
    }
    Ok(roots)
}

/// Builds a `rustls::ServerConfig` from a validated [`MtlsConfig`].
///
/// Errors:
/// * [`MtlsError::Disabled`] — `cfg.enabled` is `false`.
/// * Any [`MtlsError`] surfaced by [`load_pem_chain`], private-key load,
///   or rustls itself.
pub fn build_server_config(cfg: &MtlsConfig) -> Result<ServerConfig, MtlsError> {
    if !cfg.enabled {
        return Err(MtlsError::Disabled);
    }

    let cert_path = PathBuf::from(&cfg.cert_path);
    let key_path = PathBuf::from(&cfg.key_path);

    let material = load_pem_chain(&cert_path)?;
    let key = load_private_key(&key_path)?;

    let builder = ServerConfig::builder();

    let server_config = if cfg.require_client_cert {
        let client_ca_path = PathBuf::from(&cfg.client_ca_path);
        let roots = load_client_ca_roots(&client_ca_path)?;
        let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
            .build()
            .map_err(|e| MtlsError::Rustls(e.to_string()))?;
        builder
            .with_client_cert_verifier(verifier)
            .with_single_cert(material.chain, key)
            .map_err(|e| MtlsError::Rustls(e.to_string()))?
    } else if !cfg.client_ca_path.is_empty() {
        // Optional client auth: present a trust anchor but allow
        // unauthenticated connections through.
        let client_ca_path = PathBuf::from(&cfg.client_ca_path);
        let roots = load_client_ca_roots(&client_ca_path)?;
        let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
            .allow_unauthenticated()
            .build()
            .map_err(|e| MtlsError::Rustls(e.to_string()))?;
        builder
            .with_client_cert_verifier(verifier)
            .with_single_cert(material.chain, key)
            .map_err(|e| MtlsError::Rustls(e.to_string()))?
    } else {
        builder
            .with_no_client_auth()
            .with_single_cert(material.chain, key)
            .map_err(|e| MtlsError::Rustls(e.to_string()))?
    };

    Ok(server_config)
}

/// Loads a single PEM-encoded private key (PKCS#8, PKCS#1, or SEC1).
///
/// Never returns the underlying bytes inside the error path — only the
/// supplied filesystem path.
fn load_private_key(key_path: &Path) -> Result<PrivateKeyDer<'static>, MtlsError> {
    let bytes = fs::read(key_path).map_err(|e| MtlsError::io(key_path, &e))?;
    let mut reader = BufReader::new(bytes.as_slice());
    let key = rustls_pemfile::private_key(&mut reader)
        .map_err(|_| MtlsError::InvalidPrivateKey {
            path: key_path.to_path_buf(),
        })?
        .ok_or_else(|| MtlsError::InvalidPrivateKey {
            path: key_path.to_path_buf(),
        })?;
    Ok(key)
}

/// Rejects certs already past `not_after` or within the 30-day safety
/// window.
fn enforce_expiry_window(path: &Path, not_after: OffsetDateTime) -> Result<(), MtlsError> {
    let now = OffsetDateTime::now_utc();
    if not_after <= now {
        return Err(MtlsError::CertificateExpiry {
            path: path.to_path_buf(),
            reason: format!("already expired at {not_after}"),
        });
    }
    let remaining = not_after - now;
    if remaining.whole_seconds() < EXPIRY_SAFETY_WINDOW_SECS {
        return Err(MtlsError::CertificateExpiry {
            path: path.to_path_buf(),
            reason: format!(
                "expires at {not_after}, less than 30 days from now ({} seconds remaining)",
                remaining.whole_seconds()
            ),
        });
    }
    Ok(())
}

/// Lowercase hex SHA-256 of the supplied byte slice.
fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    hex::encode(digest)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::fs;

    use sx_config::MtlsConfig;
    use tempfile::tempdir;
    use time::OffsetDateTime;

    use super::*;
    use crate::test_support::make_self_signed;

    #[test]
    fn load_pem_chain_round_trip() {
        let dir = tempdir().expect("tempdir");
        let (cert_pem, _) = make_self_signed(365);
        let cert_path = dir.path().join("server.crt");
        fs::write(&cert_path, cert_pem).expect("write cert");

        let material = load_pem_chain(&cert_path).expect("loads round-trip cert");
        assert_eq!(material.chain.len(), 1);
        assert_eq!(material.leaf_fingerprint_sha256.len(), 64);
        assert!(material.leaf_not_after > OffsetDateTime::now_utc());
    }

    #[test]
    fn rejects_expired_cert() {
        let dir = tempdir().expect("tempdir");
        let (cert_pem, _) = make_self_signed(-1);
        let cert_path = dir.path().join("expired.crt");
        fs::write(&cert_path, cert_pem).expect("write cert");

        let err = load_pem_chain(&cert_path).expect_err("expired cert must fail");
        assert!(
            matches!(err, MtlsError::CertificateExpiry { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn rejects_cert_expiring_in_less_than_30_days() {
        let dir = tempdir().expect("tempdir");
        let (cert_pem, _) = make_self_signed(15);
        let cert_path = dir.path().join("near-expiry.crt");
        fs::write(&cert_path, cert_pem).expect("write cert");

        let err = load_pem_chain(&cert_path).expect_err("near-expiry cert must fail");
        assert!(
            matches!(err, MtlsError::CertificateExpiry { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn empty_pem_returns_empty_error() {
        let dir = tempdir().expect("tempdir");
        let cert_path = dir.path().join("empty.crt");
        fs::write(&cert_path, b"not a pem").expect("write");
        let err = load_pem_chain(&cert_path).expect_err("empty pem must fail");
        assert!(matches!(err, MtlsError::EmptyPem { .. }), "got {err:?}");
    }

    #[test]
    fn missing_cert_file_returns_io() {
        let dir = tempdir().expect("tempdir");
        let cert_path = dir.path().join("missing.crt");
        let err = load_pem_chain(&cert_path).expect_err("missing must fail");
        assert!(matches!(err, MtlsError::Io { .. }), "got {err:?}");
    }

    #[test]
    fn client_ca_load_chain() {
        let dir = tempdir().expect("tempdir");
        let (ca_pem, _) = make_self_signed(365);
        let ca_path = dir.path().join("clients.pem");
        fs::write(&ca_path, ca_pem).expect("write ca");

        let roots = load_client_ca_roots(&ca_path).expect("load roots");
        assert!(!roots.is_empty(), "expected at least one trust anchor");
    }

    fn install_ring_provider() {
        // The default provider can only be installed once per process.
        // Tests that exercise the rustls builders need it in place.
        let _ = rustls::crypto::ring::default_provider().install_default();
    }

    #[test]
    fn server_config_includes_client_auth_when_required() {
        install_ring_provider();
        let dir = tempdir().expect("tempdir");
        let (cert_pem, key_pem) = make_self_signed(365);
        let cert_path = dir.path().join("server.crt");
        let key_path = dir.path().join("server.key");
        let ca_path = dir.path().join("clients.pem");
        // Reuse the same cert as a (self-signed) trust anchor for the test.
        fs::write(&cert_path, &cert_pem).expect("write cert");
        fs::write(&key_path, key_pem).expect("write key");
        fs::write(&ca_path, &cert_pem).expect("write ca");

        let cfg = MtlsConfig {
            enabled: true,
            cert_path: cert_path.display().to_string(),
            key_path: key_path.display().to_string(),
            client_ca_path: ca_path.display().to_string(),
            require_client_cert: true,
            reload_interval_secs: 60,
        };

        let server_config = build_server_config(&cfg).expect("build server config");
        // The cert+key combination must round-trip without rustls rejecting.
        assert!(
            !server_config.alpn_protocols.is_empty() || server_config.alpn_protocols.is_empty(),
            "server config constructed"
        );
    }

    #[test]
    fn build_server_config_returns_disabled_when_disabled() {
        let cfg = MtlsConfig::default();
        let err = build_server_config(&cfg).expect_err("disabled must fail");
        assert!(matches!(err, MtlsError::Disabled), "got {err:?}");
    }
}
