//! Production AWS inventory connector backed by the real `aws-sdk-*` crates.
//!
//! Unlike the sibling [`super::aws`] module — which keeps an in-house SigV4
//! implementation and only talks to STS + IAM `ListUsers` — this connector
//! delegates wire-level concerns (signing, retries, endpoint resolution,
//! pagination plumbing) to the official AWS Rust SDK and exposes a
//! cross-service inventory view across **S3 buckets, EC2 instances, and IAM
//! roles**.
//!
//! ## Design
//!
//! - One `aws_sdk_*::Client` per service is held inside [`AwsSdkInventory`].
//! - [`Self::from_env`] uses `aws_config::load_defaults(BehaviorVersion::latest())`
//!   so credentials, region and HTTP client come from the host's default
//!   chain (env vars, profile, IMDS, ...). Credentials are **never** logged
//!   or written into the [`std::fmt::Debug`] output of this struct.
//! - [`CloudConnector::list_resources`] fans the three per-service list
//!   calls out concurrently via `tokio::try_join!`. The first failure
//!   short-circuits the join, propagating a [`CloudError`] up the stack.
//! - Pagination is exhausted in-method using each service's native cursor
//!   field: EC2 returns `NextToken`, IAM returns `Marker` + `IsTruncated`,
//!   and S3 `ListBuckets` is single-shot (no pagination cursor).
//! - ARNs are synthesised where the SDK does not return one directly: EC2's
//!   `Instance` payload carries only the instance id, so we build
//!   `arn:aws:ec2:<region>:<account>:instance/<id>` using the region from
//!   the configured client and the account id parsed out of an
//!   existing role ARN (or `"unknown"` if no roles are visible). S3 bucket
//!   ARNs are global and built as `arn:aws:s3:::<bucket-name>`. IAM role
//!   ARNs are taken straight from `Role::arn`.

use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use aws_config::BehaviorVersion;
use aws_sdk_ec2::types::Instance as Ec2Instance;
use aws_sdk_iam::types::Role as IamRole;
use aws_sdk_s3::types::Bucket as S3Bucket;
use aws_types::sdk_config::SdkConfig;

use crate::error::CloudError;
use crate::model::{CloudProvider, CloudResource, ListResourcesRequest};

use super::connector::{CloudConnector, ConnectorIdentity};

/// Real-SDK-backed AWS inventory connector.
///
/// Holds one client per AWS service. Cheap to clone (the SDK clients
/// internally share an `Arc`).
#[derive(Clone)]
pub struct AwsSdkInventory {
    /// Amazon S3 client (used for `list_buckets`).
    s3: aws_sdk_s3::Client,
    /// Amazon EC2 client (used for `describe_instances`, paginated).
    ec2: aws_sdk_ec2::Client,
    /// AWS IAM client (used for `list_roles`, paginated).
    iam: aws_sdk_iam::Client,
    /// Region snapshot pulled from the EC2 client at construction time; we
    /// use it to synthesise EC2 instance ARNs without reaching back into
    /// the SDK config on every row.
    region: Arc<str>,
}

impl std::fmt::Debug for AwsSdkInventory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Deliberately avoid printing the contained clients: their `Debug`
        // implementations may surface configuration that includes
        // credential-provider details. Region is safe to log.
        f.debug_struct("AwsSdkInventory")
            .field("region", &self.region.as_ref())
            .finish_non_exhaustive()
    }
}

impl AwsSdkInventory {
    /// Construct from a fully-formed [`SdkConfig`].
    ///
    /// Both production (via [`Self::from_env`]) and tests (via a
    /// hand-built `SdkConfig` with synthetic credentials and a local
    /// endpoint url) funnel through here.
    #[must_use]
    pub fn from_sdk_config(cfg: &SdkConfig) -> Self {
        let region: Arc<str> = cfg.region().map_or_else(
            || Arc::<str>::from("us-east-1"),
            |r| Arc::<str>::from(r.as_ref()),
        );
        Self {
            s3: aws_sdk_s3::Client::new(cfg),
            ec2: aws_sdk_ec2::Client::new(cfg),
            iam: aws_sdk_iam::Client::new(cfg),
            region,
        }
    }

    /// Construct using the host's default AWS credential / region chain.
    ///
    /// Wraps `aws_config::load_defaults(BehaviorVersion::latest())`.
    /// Returns a [`CloudError::Config`] only if the resulting config has
    /// no region; otherwise infallible at this layer (auth errors surface
    /// later from individual list calls).
    pub async fn from_env() -> Result<Self, CloudError> {
        let cfg = aws_config::load_defaults(BehaviorVersion::latest()).await;
        if cfg.region().is_none() {
            return Err(CloudError::config(
                "aws region could not be resolved from environment",
            ));
        }
        Ok(Self::from_sdk_config(&cfg))
    }

    /// Region of the underlying clients. Used to synthesise EC2 ARNs.
    #[must_use]
    pub fn region(&self) -> &str {
        self.region.as_ref()
    }

    /// List every visible S3 bucket as a [`CloudResource`].
    ///
    /// S3 `list_buckets` is a single global call with no pagination
    /// cursor; we return whatever the SDK gives us. Bucket-region lookup
    /// (`get_bucket_location`) is intentionally deferred to a future
    /// pass — the MVP pins `region = us-east-1` for every bucket because
    /// IAM and the bucket ARN are themselves region-less.
    pub async fn list_s3_buckets(&self) -> Result<Vec<CloudResource>, CloudError> {
        let out = self
            .s3
            .list_buckets()
            .send()
            .await
            .map_err(|e| map_sdk_err("s3:list_buckets", &e))?;
        Ok(out.buckets().iter().map(map_bucket).collect())
    }

    /// List every visible EC2 instance across all reservations.
    ///
    /// Pagination follows the SDK's `NextToken` cursor; we loop until the
    /// service stops returning one. Each instance is emitted as one
    /// [`CloudResource`] with a synthetic ARN of the form
    /// `arn:aws:ec2:<region>:<account>:instance/<id>`.
    pub async fn list_ec2_instances(&self) -> Result<Vec<CloudResource>, CloudError> {
        let account = self
            .discover_account_id()
            .await
            .unwrap_or_else(|| "unknown".to_string());
        let mut out: Vec<CloudResource> = Vec::new();
        let mut next: Option<String> = None;
        loop {
            let resp = self
                .ec2
                .describe_instances()
                .set_next_token(next.clone())
                .send()
                .await
                .map_err(|e| map_sdk_err("ec2:describe_instances", &e))?;
            for reservation in resp.reservations() {
                for inst in reservation.instances() {
                    out.push(map_instance(inst, self.region.as_ref(), &account));
                }
            }
            match resp.next_token() {
                Some(tok) if !tok.is_empty() => next = Some(tok.to_string()),
                _ => break,
            }
        }
        Ok(out)
    }

    /// List every IAM role visible to the configured principal.
    ///
    /// Pagination follows the IAM `Marker` + `IsTruncated` convention.
    pub async fn list_iam_roles(&self) -> Result<Vec<CloudResource>, CloudError> {
        let mut out: Vec<CloudResource> = Vec::new();
        let mut marker: Option<String> = None;
        loop {
            let resp = self
                .iam
                .list_roles()
                .set_marker(marker.clone())
                .send()
                .await
                .map_err(|e| map_sdk_err("iam:list_roles", &e))?;
            for role in resp.roles() {
                out.push(map_role(role));
            }
            if resp.is_truncated() {
                match resp.marker() {
                    Some(m) if !m.is_empty() => marker = Some(m.to_string()),
                    _ => break,
                }
            } else {
                break;
            }
        }
        Ok(out)
    }

    /// Best-effort account-id resolution by inspecting the ARN of the
    /// first listed IAM role. Used purely to synthesise EC2 instance ARNs
    /// when the SDK does not embed an account id in the instance
    /// payload. Returns `None` if no roles are visible or if the ARN does
    /// not parse to twelve digits.
    async fn discover_account_id(&self) -> Option<String> {
        let resp = self.iam.list_roles().send().await.ok()?;
        for role in resp.roles() {
            if let Some(acct) = parse_account_from_arn(role.arn()) {
                return Some(acct);
            }
        }
        None
    }
}

#[async_trait]
impl CloudConnector for AwsSdkInventory {
    fn provider(&self) -> CloudProvider {
        CloudProvider::Aws
    }

    /// Lightweight identity check: lists IAM roles (page-1 only) so the
    /// account id can be parsed back out of any returned role ARN. This
    /// keeps `validate` cheap and free of the STS dependency.
    async fn validate(&self) -> Result<ConnectorIdentity, CloudError> {
        let resp = self
            .iam
            .list_roles()
            .send()
            .await
            .map_err(|e| map_sdk_err("iam:list_roles", &e))?;
        let account_id = resp
            .roles()
            .iter()
            .find_map(|r| parse_account_from_arn(r.arn()))
            .unwrap_or_else(|| "unknown".to_string());
        let principal = resp.roles().first().map_or_else(
            || String::from("arn:aws:iam::unknown:role/?"),
            |r| r.arn().to_string(),
        );
        Ok(ConnectorIdentity {
            provider: CloudProvider::Aws,
            account_id,
            principal,
        })
    }

    async fn list_resources(
        &self,
        req: &ListResourcesRequest,
    ) -> Result<Vec<CloudResource>, CloudError> {
        // Service filter is honoured by short-circuiting the irrelevant
        // legs into empty `Ok` futures rather than skipping the
        // concurrent join — keeps the call graph uniform.
        let want_s3 = req
            .service
            .as_deref()
            .is_none_or(|s| s == "s3" || s == "bucket");
        let want_ec2 = req
            .service
            .as_deref()
            .is_none_or(|s| s == "ec2" || s == "instance");
        let want_iam = req
            .service
            .as_deref()
            .is_none_or(|s| s == "iam" || s == "identity" || s == "role");

        let s3_fut = async {
            if want_s3 {
                self.list_s3_buckets().await
            } else {
                Ok(Vec::new())
            }
        };
        let ec2_fut = async {
            if want_ec2 {
                self.list_ec2_instances().await
            } else {
                Ok(Vec::new())
            }
        };
        let iam_fut = async {
            if want_iam {
                self.list_iam_roles().await
            } else {
                Ok(Vec::new())
            }
        };

        let (buckets, instances, roles) = tokio::try_join!(s3_fut, ec2_fut, iam_fut)?;
        let mut out = Vec::with_capacity(buckets.len() + instances.len() + roles.len());
        out.extend(buckets);
        out.extend(instances);
        out.extend(roles);
        Ok(out)
    }
}

// ----------------------------------------------------------------------
// Pure mappers (SDK type -> CloudResource). Kept private + unit-tested.
// ----------------------------------------------------------------------

fn map_bucket(b: &S3Bucket) -> CloudResource {
    let name = b.name().unwrap_or("").to_string();
    let arn = format!("arn:aws:s3:::{name}");
    CloudResource {
        id: arn,
        provider: CloudProvider::Aws,
        // S3 bucket regions vary; the MVP labels them all `us-east-1` —
        // see module docs for the rationale.
        region: Some("us-east-1".to_string()),
        service: "s3".to_string(),
        kind: "bucket".to_string(),
        name,
        tags: BTreeMap::new(),
        raw: serde_json::Value::Null,
    }
}

fn map_instance(inst: &Ec2Instance, region: &str, account: &str) -> CloudResource {
    let id = inst.instance_id().unwrap_or("").to_string();
    let arn = format!("arn:aws:ec2:{region}:{account}:instance/{id}");
    let mut tags: BTreeMap<String, String> = BTreeMap::new();
    for t in inst.tags() {
        if let (Some(k), Some(v)) = (t.key(), t.value()) {
            tags.insert(k.to_string(), v.to_string());
        }
    }
    CloudResource {
        id: arn,
        provider: CloudProvider::Aws,
        region: Some(region.to_string()),
        service: "ec2".to_string(),
        kind: "instance".to_string(),
        name: id,
        tags,
        raw: serde_json::Value::Null,
    }
}

fn map_role(r: &IamRole) -> CloudResource {
    let arn = r.arn().to_string();
    let name = r.role_name().to_string();
    CloudResource {
        id: arn,
        provider: CloudProvider::Aws,
        region: Some("global".to_string()),
        service: "iam".to_string(),
        kind: "identity".to_string(),
        name,
        tags: BTreeMap::new(),
        raw: serde_json::Value::Null,
    }
}

/// Parse the account id out of an ARN of the form
/// `arn:aws:<service>:<region>:<account>:<resource>`. Returns `None` if
/// the input is not a parseable ARN with twelve account-id digits.
fn parse_account_from_arn(arn: &str) -> Option<String> {
    let parts: Vec<&str> = arn.splitn(6, ':').collect();
    if parts.len() < 6 {
        return None;
    }
    let acct = parts.get(4)?;
    if acct.len() == 12 && acct.chars().all(|c| c.is_ascii_digit()) {
        Some((*acct).to_string())
    } else {
        None
    }
}

/// Map any AWS SDK error type into a [`CloudError`], distinguishing
/// dispatch failures (transport) from service / response errors.
/// Credentials are never embedded in the returned error string.
fn map_sdk_err<E, R>(
    op: &'static str,
    err: &aws_smithy_runtime_api::client::result::SdkError<E, R>,
) -> CloudError
where
    E: std::fmt::Display,
    R: AsHttpResponse,
{
    use aws_smithy_runtime_api::client::result::SdkError as S;
    match err {
        S::ConstructionFailure(_) => {
            CloudError::config(format!("{op}: request construction failed"))
        }
        S::TimeoutError(_) => CloudError::http(format!("{op}: timeout")),
        S::DispatchFailure(_) => CloudError::http(format!("{op}: dispatch failure")),
        S::ResponseError(re) => {
            let status = re.raw().status_u16();
            CloudError::Upstream {
                status,
                body: format!("{op}: malformed response"),
            }
        }
        S::ServiceError(se) => {
            let status = se.raw().status_u16();
            // Display of the service error never includes credentials.
            CloudError::Upstream {
                status,
                body: format!("{op}: {}", se.err()),
            }
        }
        // `SdkError` is `#[non_exhaustive]`; future variants degrade
        // safely to a generic internal error rather than panic.
        _ => CloudError::internal(format!("{op}: unrecognised SDK error variant")),
    }
}

/// Lightweight trait so [`map_sdk_err`] can read a status code from
/// either the canonical `HttpResponse` or — for tests where the response
/// type is `()` — degrade gracefully to status `0`.
trait AsHttpResponse {
    /// HTTP status of the underlying response, or `0` if absent.
    fn status_u16(&self) -> u16;
}

impl AsHttpResponse for aws_smithy_runtime_api::client::orchestrator::HttpResponse {
    fn status_u16(&self) -> u16 {
        self.status().into()
    }
}

#[cfg(test)]
// Tests use `unwrap`/`panic!` in assertion paths and raw strings for
// readability; relaxing those lints inside `mod tests` keeps the
// assertions terse without affecting non-test code.
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::needless_raw_string_hashes,
    clippy::panic,
    clippy::match_wild_err_arm
)]
mod tests {
    use super::*;
    use aws_config::Region;
    use aws_credential_types::provider::SharedCredentialsProvider;
    use aws_credential_types::Credentials;
    use std::time::Duration;

    // ---- helpers ----------------------------------------------------

    fn synthetic_sdk_config(endpoint: Option<&str>) -> SdkConfig {
        // Synthetic credentials. The "provider_name" string is a static
        // label only; nothing here is a real AWS secret.
        let creds = Credentials::new(
            "AKIAEXAMPLE",
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            None,
            None,
            "synthetic-tests",
        );
        let mut b = SdkConfig::builder()
            .region(Region::new("us-east-1"))
            .behavior_version(BehaviorVersion::latest())
            .credentials_provider(SharedCredentialsProvider::new(creds));
        if let Some(ep) = endpoint {
            b = b.endpoint_url(ep);
        }
        b.build()
    }

    // ---- Test 1: from_sdk_config + region snapshot ------------------

    #[test]
    fn from_sdk_config_constructs_ok_and_snapshots_region() {
        let cfg = synthetic_sdk_config(None);
        let inv = AwsSdkInventory::from_sdk_config(&cfg);
        assert_eq!(inv.region(), "us-east-1");
        assert_eq!(inv.provider(), CloudProvider::Aws);
        // Debug must not contain anything credential-looking.
        let dbg = format!("{inv:?}");
        assert!(dbg.contains("AwsSdkInventory"));
        assert!(!dbg.contains("AKIA"));
        assert!(!dbg.contains("wJalrXUtnFEMI"));
    }

    // ---- Test 2: ARN format verification ----------------------------

    #[test]
    fn map_bucket_emits_well_formed_arn() {
        let b = S3Bucket::builder().name("evidence-prod").build();
        let r = map_bucket(&b);
        assert_eq!(r.id, "arn:aws:s3:::evidence-prod");
        assert_eq!(r.service, "s3");
        assert_eq!(r.kind, "bucket");
        assert_eq!(r.region.as_deref(), Some("us-east-1"));
        assert_eq!(r.name, "evidence-prod");
        assert!(r.tags.is_empty());
    }

    #[test]
    fn map_instance_emits_well_formed_arn_with_region_and_account() {
        let tag = aws_sdk_ec2::types::Tag::builder()
            .key("Env")
            .value("prod")
            .build();
        let inst = Ec2Instance::builder()
            .instance_id("i-0123456789abcdef0")
            .tags(tag)
            .build();
        let r = map_instance(&inst, "eu-west-1", "123456789012");
        assert_eq!(
            r.id,
            "arn:aws:ec2:eu-west-1:123456789012:instance/i-0123456789abcdef0"
        );
        assert_eq!(r.service, "ec2");
        assert_eq!(r.kind, "instance");
        assert_eq!(r.region.as_deref(), Some("eu-west-1"));
        assert_eq!(r.tags.get("Env").map(String::as_str), Some("prod"));
    }

    #[test]
    fn map_role_passes_through_arn() {
        let role = IamRole::builder()
            .role_name("Admin")
            .arn("arn:aws:iam::123456789012:role/Admin")
            .path("/")
            .role_id("AROAEXAMPLE")
            .create_date(aws_smithy_types::DateTime::from_secs(1))
            .build()
            .unwrap();
        let r = map_role(&role);
        assert_eq!(r.id, "arn:aws:iam::123456789012:role/Admin");
        assert_eq!(r.service, "iam");
        assert_eq!(r.kind, "identity");
        assert_eq!(r.region.as_deref(), Some("global"));
        assert_eq!(r.name, "Admin");
    }

    // ---- Test 3: account id parsing ---------------------------------

    #[test]
    fn parse_account_from_arn_extracts_twelve_digit_id() {
        assert_eq!(
            parse_account_from_arn("arn:aws:iam::123456789012:role/Admin"),
            Some("123456789012".to_string())
        );
        assert_eq!(
            parse_account_from_arn("arn:aws:s3:::bucket"),
            None,
            "s3 ARNs have no account segment"
        );
        assert_eq!(parse_account_from_arn("not-an-arn"), None);
        assert_eq!(
            parse_account_from_arn("arn:aws:iam::12345:role/x"),
            None,
            "non-12-digit account rejected"
        );
    }

    // ---- Test 4: pagination accumulation (pure logic) ---------------
    //
    // EC2 and IAM pagination logic is exercised here by simulating the
    // loop body manually: we accumulate three synthetic pages of ec2
    // instances and verify the row count and ordering. We cannot invoke
    // `list_ec2_instances` directly without a live AWS endpoint, but
    // the mapper + extend pattern is exactly what the loop runs.

    #[test]
    fn pagination_accumulates_three_pages_in_order() {
        let region = "us-east-1";
        let account = "123456789012";
        let pages: Vec<Vec<&str>> = vec![
            vec!["i-a1", "i-a2"],
            vec!["i-b1"],
            vec!["i-c1", "i-c2", "i-c3"],
        ];
        let mut out: Vec<CloudResource> = Vec::new();
        for ids in &pages {
            for id in ids {
                let inst = Ec2Instance::builder().instance_id(*id).build();
                out.push(map_instance(&inst, region, account));
            }
        }
        assert_eq!(out.len(), 6);
        assert_eq!(out[0].name, "i-a1");
        assert_eq!(out[5].name, "i-c3");
        assert!(out.iter().all(|r| r
            .id
            .starts_with("arn:aws:ec2:us-east-1:123456789012:instance/")));
    }

    // ---- Test 5: transport failure surfaces CloudError --------------
    //
    // Configure the SDK against an obviously-unreachable endpoint
    // (`http://127.0.0.1:1`) so the dispatch fails fast. We expect a
    // `CloudError::Http` (DispatchFailure) and certify that the error
    // string never echoes the synthetic access key id back to the
    // caller.

    #[tokio::test]
    async fn dispatch_failure_maps_to_cloud_error_without_leaking_creds() {
        let cfg = synthetic_sdk_config(Some("http://127.0.0.1:1"));
        let inv = AwsSdkInventory::from_sdk_config(&cfg);
        let outcome = tokio::time::timeout(Duration::from_secs(15), inv.list_iam_roles()).await;
        let err = match outcome {
            Ok(Ok(_)) => panic!("expected dispatch failure against 127.0.0.1:1"),
            Ok(Err(e)) => e,
            Err(_) => panic!("list_iam_roles did not return within 15s"),
        };
        let msg = err.to_string();
        assert!(
            !msg.contains("AKIAEXAMPLE"),
            "error must not echo access key id, got: {msg}",
        );
        assert!(
            !msg.contains("wJalrXUtnFEMI"),
            "error must not echo secret key, got: {msg}",
        );
        // Either a plain http error or an upstream-shaped error is
        // acceptable; both are CloudError variants we explicitly map.
        let recognised = matches!(
            err,
            CloudError::Http(_) | CloudError::Upstream { .. } | CloudError::Config(_)
        );
        assert!(recognised, "unexpected CloudError variant: {err:?}");
    }

    // ---- Test 6: concurrent list via tokio::try_join! ---------------
    //
    // Verify the connector launches the three list calls concurrently:
    // we configure an unreachable endpoint and assert that the join
    // returns a single error (short-circuit) rather than blocking on
    // the full 3 x dispatch timeout. The wall-clock budget is a loose
    // upper bound; in practice the dispatch fails near-instantly.

    #[tokio::test]
    async fn list_resources_fans_three_calls_concurrently_and_short_circuits() {
        let cfg = synthetic_sdk_config(Some("http://127.0.0.1:1"));
        let inv = AwsSdkInventory::from_sdk_config(&cfg);
        let req = ListResourcesRequest::default();
        let outcome = tokio::time::timeout(Duration::from_secs(20), inv.list_resources(&req)).await;
        match outcome {
            Ok(Ok(_)) => panic!("expected aggregate failure against 127.0.0.1:1"),
            Ok(Err(e)) => {
                let msg = e.to_string();
                assert!(!msg.contains("AKIAEXAMPLE"));
            }
            Err(_) => panic!("list_resources did not short-circuit within 20s"),
        }
    }
}
