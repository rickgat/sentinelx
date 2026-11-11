//! Shared test helpers — gated behind `cfg(test)` so they never leak into
//! the production binary.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::redundant_pub_crate,
    unreachable_pub
)]

use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
use time::{Duration as TimeDuration, OffsetDateTime};

/// Builds a self-signed RSA-ish leaf certificate (whatever default key
/// algorithm `rcgen` chooses with the `ring` crypto provider) that
/// expires `validity_days` days from now. Negative values produce
/// expired certificates.
pub(crate) fn make_self_signed(validity_days: i64) -> (String, String) {
    let key_pair = KeyPair::generate().expect("rcgen keypair");
    let mut params =
        CertificateParams::new(vec!["localhost".to_string()]).expect("rcgen params accept DNS SAN");

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
