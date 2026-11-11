//! Production [`EvidenceSink`] backed by `aws-sdk-s3`.
//!
//! The CLI (`sx evidence ship --real`) wires this sink in when the
//! operator opts into a live AWS upload. By default the CLI uses the
//! in-memory [`super::MockSink`] so unit/integration runs and dry-runs
//! never touch a real bucket.
//!
//! ## Configuration
//!
//! The sink obtains AWS credentials and the region purely through the
//! SDK's default credential provider chain (environment, shared
//! profile, EC2/EKS instance metadata, container, SSO, …). We **never**
//! parse access keys ourselves and we **never** log them.
//!
//! [`SdkS3Sink::from_env`] additionally honours the following env vars:
//!
//! | Var | Purpose | Default |
//! | --- | ------- | ------- |
//! | `SENTINELX_S3_STORAGE_CLASS` | Default storage class for every upload (e.g. `STANDARD`, `STANDARD_IA`, `GLACIER_IR`). | `STANDARD` |
//!
//! ## Tagging
//!
//! AWS S3 expects the `x-amz-tagging` header (passed via the
//! [`put_object().tagging(...)`] builder) as a URL-encoded
//! `key1=val1&key2=val2&…` string. Each key and each value are
//! percent-encoded individually using the standard "unreserved
//! character" set from RFC 3986 (`A-Z a-z 0-9 - _ . ~`); every other
//! byte (including `&`, `=`, `+`, space, non-ASCII UTF-8) is escaped
//! as `%XX` upper-hex. See [`encode_tagging`] for the exact policy.
//!
//! ## Security
//!
//! * AWS credentials and session tokens are obtained only via the SDK's
//!   default chain — never from log lines or function arguments.
//! * Errors are scrubbed: only the AWS error *code* (e.g.
//!   `NoSuchBucket`) and a short message are bubbled into
//!   [`ShipError::Sink`]. Pre-signed URLs and credential material are
//!   never serialised into errors or `tracing` events.

use async_trait::async_trait;
use aws_sdk_s3::error::ProvideErrorMetadata;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::types::StorageClass;
use aws_sdk_s3::Client;

use super::{EvidenceSink, ShipError};

/// Default storage class used when the operator does not override it.
const DEFAULT_STORAGE_CLASS: &str = "STANDARD";

/// Environment variable consulted by [`SdkS3Sink::from_env`] for the
/// default object storage class.
pub const ENV_STORAGE_CLASS: &str = "SENTINELX_S3_STORAGE_CLASS";

/// Production [`EvidenceSink`] backed by `aws-sdk-s3`.
///
/// Clone-cheap: the underlying [`Client`] wraps an `Arc`-shared
/// connection pool, so the sink itself contains only that handle plus
/// a small string for the default storage class.
#[derive(Debug, Clone)]
pub struct SdkS3Sink {
    client: Client,
    default_storage_class: StorageClass,
}

impl SdkS3Sink {
    /// Construct an [`SdkS3Sink`] using the supplied AWS [`Client`] and
    /// default storage class.
    ///
    /// Prefer [`SdkS3Sink::from_env`] in production — this constructor
    /// exists so the integration tests (and any future caller that
    /// already owns a configured client) can inject a pre-built client.
    #[must_use]
    pub fn new(client: Client, default_storage_class: StorageClass) -> Self {
        Self {
            client,
            default_storage_class,
        }
    }

    /// Build an [`SdkS3Sink`] from the ambient process environment.
    ///
    /// Credentials and region come from the SDK's default provider
    /// chain (env, shared profile, IMDS, etc.). The default storage
    /// class is read from [`ENV_STORAGE_CLASS`], falling back to
    /// `STANDARD`.
    ///
    /// # Errors
    /// Returns [`ShipError::Sink`] if the SDK fails to materialise a
    /// configuration. The error message is scrubbed of credential
    /// material — only the SDK's high-level failure summary is
    /// surfaced.
    pub async fn from_env() -> Result<Self, ShipError> {
        let cfg = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .load()
            .await;
        let client = Client::new(&cfg);
        let storage_class = read_storage_class_from_env();
        Ok(Self::new(client, storage_class))
    }

    /// Return the storage class this sink applies by default.
    #[must_use]
    pub fn default_storage_class(&self) -> &StorageClass {
        &self.default_storage_class
    }

    /// Split an `s3://bucket/prefix/key` URI (or a `bucket/prefix/key`
    /// path) into `(bucket, object_key)`.
    ///
    /// Returns [`ShipError::Sink`] if the input lacks a bucket
    /// component.
    fn split_bucket_key(uri: &str) -> Result<(String, String), ShipError> {
        let trimmed = uri.strip_prefix("s3://").unwrap_or(uri);
        let mut parts = trimmed.splitn(2, '/');
        let bucket = parts
            .next()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| ShipError::Sink("destination uri missing bucket component".into()))?
            .to_owned();
        let key = parts.next().unwrap_or("").to_owned();
        if key.is_empty() {
            return Err(ShipError::Sink(format!(
                "destination uri missing object key for bucket={bucket}"
            )));
        }
        Ok((bucket, key))
    }
}

#[async_trait]
impl EvidenceSink for SdkS3Sink {
    async fn ship(
        &self,
        key: &str,
        body: &[u8],
        tags: &[(String, String)],
    ) -> Result<(), ShipError> {
        let (bucket, object_key) = Self::split_bucket_key(key)?;
        let tagging = encode_tagging(tags);
        let body_stream = ByteStream::from(body.to_vec());

        let mut req = self
            .client
            .put_object()
            .bucket(&bucket)
            .key(&object_key)
            .body(body_stream)
            .storage_class(self.default_storage_class.clone());

        // S3 rejects an empty `x-amz-tagging` header on some endpoints;
        // only attach the field when we actually have tags.
        if !tagging.is_empty() {
            req = req.tagging(tagging);
        }

        req.send().await.map_err(|err| {
            // Scrub the error: surface only the service-error code and
            // a short summary, never the raw `DisplayErrorContext` which
            // can leak request IDs / pre-signed URLs.
            let code = err
                .as_service_error()
                .and_then(ProvideErrorMetadata::code)
                .unwrap_or("Unknown");
            ShipError::Sink(format!(
                "s3 put_object failed (bucket={bucket}, code={code})"
            ))
        })?;

        Ok(())
    }
}

/// Encode a slice of `(key, value)` tag pairs into the URL-encoded
/// `key1=val1&key2=val2&…` string that the AWS S3 `x-amz-tagging`
/// header expects.
///
/// Each key and each value are percent-encoded individually using the
/// RFC 3986 "unreserved character" set (`A-Z a-z 0-9 - _ . ~`). Every
/// other byte — including `&`, `=`, `+`, space, and any non-ASCII
/// UTF-8 continuation byte — is escaped as `%XX` upper-hex.
///
/// Returns an empty string when `tags` is empty so the caller can
/// detect "no tags" with a simple `is_empty()` check.
#[must_use]
pub fn encode_tagging(tags: &[(String, String)]) -> String {
    let mut out = String::new();
    let mut first = true;
    for (k, v) in tags {
        if !first {
            out.push('&');
        }
        first = false;
        percent_encode_into(k, &mut out);
        out.push('=');
        percent_encode_into(v, &mut out);
    }
    out
}

/// Percent-encode `s` per RFC 3986 unreserved set and push the result
/// onto `out`. Pure ASCII helper; non-ASCII bytes (the UTF-8
/// encoding) are escaped as `%XX`.
fn percent_encode_into(s: &str, out: &mut String) {
    for &b in s.as_bytes() {
        if is_unreserved(b) {
            // Safe: `is_unreserved` only allows ASCII bytes, which are
            // valid single-byte UTF-8 scalar values.
            out.push(b as char);
        } else {
            out.push('%');
            // `b >> 4` and `b & 0x0F` are both in `0..=15`, so the
            // hex digit lookup never panics.
            out.push(hex_nibble(b >> 4));
            out.push(hex_nibble(b & 0x0F));
        }
    }
}

/// Map a 4-bit nibble (`0..=15`) to an upper-case ASCII hex digit.
const fn hex_nibble(n: u8) -> char {
    match n {
        0 => '0',
        1 => '1',
        2 => '2',
        3 => '3',
        4 => '4',
        5 => '5',
        6 => '6',
        7 => '7',
        8 => '8',
        9 => '9',
        10 => 'A',
        11 => 'B',
        12 => 'C',
        13 => 'D',
        14 => 'E',
        // The caller masks to `0..=15`; any value > 15 is a programming
        // bug. We fall through to `F` rather than panic so the function
        // stays panic-free under `#![deny(clippy::panic)]`.
        _ => 'F',
    }
}

const fn is_unreserved(b: u8) -> bool {
    matches!(b,
        b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9'
        | b'-' | b'_' | b'.' | b'~'
    )
}

#[allow(clippy::disallowed_methods)]
fn read_storage_class_from_env() -> StorageClass {
    let raw = std::env::var(ENV_STORAGE_CLASS).unwrap_or_else(|_| DEFAULT_STORAGE_CLASS.to_owned());
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        StorageClass::from(DEFAULT_STORAGE_CLASS)
    } else {
        StorageClass::from(trimmed)
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn from_env_constructs_ok() {
        // No bucket is touched; we only assert the SDK can build a
        // default config + client without panicking. This is the
        // "smoke test" that lives in CI without AWS credentials.
        let sink = SdkS3Sink::from_env().await.expect("from_env should build");
        // The default class is STANDARD unless the env var is set.
        // (Reading the env mid-test would race with parallel tests, so
        // we only check the symbolic value is *some* valid class.)
        let cls = sink.default_storage_class();
        assert!(!cls.as_str().is_empty(), "storage class must not be empty");
    }

    #[test]
    fn encode_tagging_produces_url_encoded_string() {
        let tags = vec![
            ("framework".to_owned(), "soc2".to_owned()),
            ("control_id".to_owned(), "CC1.1".to_owned()),
            ("collected_at".to_owned(), "2026-05-31T12:00:00Z".to_owned()),
        ];
        let s = encode_tagging(&tags);
        // `.` and `-` are unreserved; `:` is reserved → `%3A`.
        assert_eq!(
            s,
            "framework=soc2&control_id=CC1.1&collected_at=2026-05-31T12%3A00%3A00Z"
        );
    }

    #[test]
    fn encode_tagging_escapes_reserved_characters() {
        let tags = vec![
            ("k&y".to_owned(), "v=1".to_owned()),
            ("space key".to_owned(), "plus+sign".to_owned()),
        ];
        let s = encode_tagging(&tags);
        assert_eq!(s, "k%26y=v%3D1&space%20key=plus%2Bsign");
    }

    #[test]
    fn encode_tagging_empty_returns_empty_string() {
        let s = encode_tagging(&[]);
        assert!(s.is_empty(), "empty tag set must produce empty string");
    }

    #[test]
    fn encode_tagging_preserves_order() {
        let tags = vec![
            ("z".to_owned(), "1".to_owned()),
            ("a".to_owned(), "2".to_owned()),
            ("m".to_owned(), "3".to_owned()),
        ];
        let s = encode_tagging(&tags);
        // Order must follow input order — auditors rely on tag order
        // being deterministic for log replay.
        assert_eq!(s, "z=1&a=2&m=3");
    }

    #[test]
    fn encode_tagging_handles_non_ascii_utf8() {
        let tags = vec![("emoji".to_owned(), "✓".to_owned())];
        let s = encode_tagging(&tags);
        // `✓` (U+2713) → UTF-8 `E2 9C 93`.
        assert_eq!(s, "emoji=%E2%9C%93");
    }

    #[test]
    fn split_bucket_key_parses_s3_uri() {
        let (b, k) = SdkS3Sink::split_bucket_key("s3://my-bucket/evidence/soc2/file.json").unwrap();
        assert_eq!(b, "my-bucket");
        assert_eq!(k, "evidence/soc2/file.json");
    }

    #[test]
    fn split_bucket_key_parses_plain_path() {
        let (b, k) = SdkS3Sink::split_bucket_key("my-bucket/evidence/file.json").unwrap();
        assert_eq!(b, "my-bucket");
        assert_eq!(k, "evidence/file.json");
    }

    #[test]
    fn split_bucket_key_rejects_missing_key() {
        let err = SdkS3Sink::split_bucket_key("s3://my-bucket").unwrap_err();
        assert!(matches!(err, ShipError::Sink(_)));
    }

    #[test]
    fn split_bucket_key_rejects_missing_bucket() {
        let err = SdkS3Sink::split_bucket_key("s3://").unwrap_err();
        assert!(matches!(err, ShipError::Sink(_)));
    }

    #[tokio::test]
    async fn ship_with_empty_tags_does_not_panic() {
        // We intentionally point at an obviously-fake bucket so the
        // network request fails cleanly inside `send()`. The test only
        // asserts that the builder code path with `tags = &[]` doesn't
        // panic on the way to the network layer.
        let sink = SdkS3Sink::from_env().await.expect("from_env");
        let res = sink
            .ship(
                "s3://sentinelx-this-bucket-does-not-exist-xyz/key.json",
                b"payload",
                &[],
            )
            .await;
        // We expect an error (no creds / no bucket), not a panic.
        assert!(res.is_err(), "fake bucket must fail, not succeed");
    }

    #[tokio::test]
    #[ignore = "Requires AWS creds + bucket SENTINELX_TEST_BUCKET"]
    async fn ship_live_to_test_bucket() {
        // Live integration test. Set:
        //   SENTINELX_TEST_BUCKET=<your-bucket>
        //   AWS_REGION=<your-region>
        //   AWS credentials via the default provider chain.
        //
        // Run with:
        //   cargo test -p sx-compliance -- --ignored ship_live_to_test_bucket
        #[allow(clippy::disallowed_methods)]
        let bucket =
            std::env::var("SENTINELX_TEST_BUCKET").expect("SENTINELX_TEST_BUCKET must be set");

        let sink = SdkS3Sink::from_env().await.expect("from_env");
        let key = format!("s3://{bucket}/sentinelx-live-test/hello.json");
        let body = br#"{"hello":"world"}"#;
        let tags = vec![
            ("framework".to_owned(), "soc2".to_owned()),
            ("control_id".to_owned(), "CC1.1".to_owned()),
        ];
        sink.ship(&key, body, &tags)
            .await
            .expect("live ship should succeed");
    }
}
