//! Minimal serde types for the Kubernetes admission webhook protocol
//! (`admission.k8s.io/v1`).
//!
//! HIGH-009 ships `SentinelX` as a `ValidatingWebhookConfiguration` target.
//! The wire payloads are JSON; rather than pulling in the heavyweight
//! [`k8s-openapi`] admission types (which require additional generated
//! crates and a Tokio runtime to deserialise lazily-typed objects), this
//! module hand-rolls the small subset we actually consult on every
//! request: the request envelope, the request id, the parsed object
//! root (kept as untyped JSON), and the response envelope with the
//! `status` block.
//!
//! The fields use the wire-camelCase names via `serde(rename = ...)` /
//! `serde(rename_all = "camelCase")` so the JSON round-trips exactly
//! what `kube-apiserver` emits.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Top-level admission envelope. Both inbound (`request` populated,
/// `response` empty) and outbound (`response` populated, `request`
/// echoed) shapes share this type.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdmissionReview {
    /// Always `admission.k8s.io/v1` for this server.
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    /// Always `AdmissionReview` for this protocol.
    pub kind: String,
    /// Inbound request payload (apiserver → webhook).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request: Option<AdmissionRequest>,
    /// Outbound response payload (webhook → apiserver).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<AdmissionResponse>,
}

impl AdmissionReview {
    /// Build an outbound `AdmissionReview` envelope that carries only a
    /// response. This is what the webhook sends back to the apiserver.
    #[must_use]
    pub fn response(response: AdmissionResponse) -> Self {
        Self {
            api_version: "admission.k8s.io/v1".to_owned(),
            kind: "AdmissionReview".to_owned(),
            request: None,
            response: Some(response),
        }
    }
}

/// `AdmissionRequest` — the inbound side of the `AdmissionReview`.
///
/// The Kubernetes spec defines a much larger struct; we only deserialise
/// the fields HIGH-009 actually reads. Unknown fields are silently
/// ignored (default serde behaviour).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdmissionRequest {
    /// Request identifier — echoed verbatim into the response and into
    /// the audit row so an operator can correlate apiserver logs with
    /// webhook decisions.
    pub uid: String,
    /// GVR of the resource being admitted (e.g. `apps/v1/deployments`).
    /// Optional because some test fixtures omit it; the engine treats
    /// missing kinds as "unknown" and applies all kind-agnostic rules.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<GroupVersionKind>,
    /// Resource name (often empty on create — apiserver mints the
    /// random suffix only post-admission).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Target namespace. Empty for cluster-scoped resources.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    /// Verb — `CREATE`, `UPDATE`, `DELETE`, `CONNECT`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation: Option<String>,
    /// The new object as raw JSON. `None` on `DELETE`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object: Option<Value>,
    /// The old object as raw JSON. `None` on `CREATE`.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "oldObject")]
    pub old_object: Option<Value>,
    /// Username of the requester (`system:serviceaccount:default:foo`).
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "userInfo")]
    pub user_info: Option<UserInfo>,
    /// True if the apiserver is performing a dry-run — webhooks MUST
    /// honour by not committing any side effects.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "dryRun")]
    pub dry_run: Option<bool>,
}

/// `GroupVersionKind` — the GVR identifier used by `AdmissionRequest`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupVersionKind {
    /// API group (`apps`, `""` for core).
    #[serde(default)]
    pub group: String,
    /// API version (`v1`).
    #[serde(default)]
    pub version: String,
    /// Kind (`Pod`, `Deployment`, ...).
    #[serde(default)]
    pub kind: String,
}

/// `UserInfo` — minimal subset; the username is enough for audit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfo {
    /// User identifier (`system:serviceaccount:ns:sa-name`).
    #[serde(default)]
    pub username: String,
}

/// `AdmissionResponse` — webhook → apiserver side of the envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdmissionResponse {
    /// Echoes the request uid. MUST match for the apiserver to accept.
    pub uid: String,
    /// `true` → admit; `false` → deny.
    pub allowed: bool,
    /// Structured deny reason. Required when `allowed=false`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<Status>,
    /// Optional warnings — surfaced to the kubectl client even when
    /// `allowed=true`. Used by dry-run to tell operators what WOULD
    /// have been blocked.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warnings: Option<Vec<String>>,
}

impl AdmissionResponse {
    /// Construct an `allowed=true` response.
    #[must_use]
    pub fn allow(uid: impl Into<String>) -> Self {
        Self {
            uid: uid.into(),
            allowed: true,
            status: None,
            warnings: None,
        }
    }

    /// Construct an `allowed=false` response with the supplied reason.
    /// The HTTP-style code (`code`) is set to 403 to match the
    /// "forbidden by policy" semantics surfaced to `kubectl`.
    #[must_use]
    pub fn deny(uid: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            uid: uid.into(),
            allowed: false,
            status: Some(Status {
                code: 403,
                message: reason.into(),
            }),
            warnings: None,
        }
    }

    /// Attach a vector of warning strings (surfaced in `kubectl` output).
    #[must_use]
    pub fn with_warnings(mut self, warnings: Vec<String>) -> Self {
        if warnings.is_empty() {
            self.warnings = None;
        } else {
            self.warnings = Some(warnings);
        }
        self
    }
}

/// Status block embedded in a denial. Mirrors `metav1.Status` shape.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Status {
    /// HTTP-style status code (403 for forbidden).
    pub code: u16,
    /// Human-readable deny message — shown to the kubectl user.
    pub message: String,
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn deserialises_a_real_apiserver_request() {
        let raw = br#"{
            "apiVersion": "admission.k8s.io/v1",
            "kind": "AdmissionReview",
            "request": {
                "uid": "705ab4f5-6393-11e8-b7cc-42010a800002",
                "kind": {"group": "", "version": "v1", "kind": "Pod"},
                "name": "nginx",
                "namespace": "default",
                "operation": "CREATE",
                "userInfo": {"username": "alice"},
                "object": {"kind": "Pod", "metadata": {"name": "nginx"}}
            }
        }"#;
        let r: AdmissionReview =
            serde_json::from_slice(raw).expect("real-world AdmissionReview must parse");
        let req = r.request.expect("request present");
        assert_eq!(req.uid, "705ab4f5-6393-11e8-b7cc-42010a800002");
        assert_eq!(req.namespace.as_deref(), Some("default"));
        assert_eq!(req.kind.as_ref().map(|k| k.kind.as_str()), Some("Pod"));
        assert_eq!(
            req.user_info.as_ref().map(|u| u.username.as_str()),
            Some("alice"),
        );
    }

    #[test]
    fn allow_round_trips_with_uid_only() {
        let resp = AdmissionResponse::allow("uid-1");
        let env = AdmissionReview::response(resp);
        let v = serde_json::to_value(&env).expect("serialise");
        assert_eq!(v["apiVersion"], "admission.k8s.io/v1");
        assert_eq!(v["kind"], "AdmissionReview");
        assert_eq!(v["response"]["allowed"], true);
        assert_eq!(v["response"]["uid"], "uid-1");
        // status omitted on allow.
        assert!(v["response"]["status"].is_null());
    }

    #[test]
    fn deny_carries_status_block() {
        let resp = AdmissionResponse::deny("uid-2", "host network not permitted");
        let v = serde_json::to_value(&resp).expect("serialise");
        assert_eq!(v["allowed"], false);
        assert_eq!(v["status"]["code"], 403);
        assert_eq!(v["status"]["message"], "host network not permitted");
    }

    #[test]
    fn warnings_omitted_when_empty() {
        let resp = AdmissionResponse::allow("uid-3").with_warnings(vec![]);
        let v = serde_json::to_value(&resp).expect("serialise");
        assert!(v["warnings"].is_null());
    }

    #[test]
    fn warnings_surface_when_present() {
        let resp = AdmissionResponse::allow("uid-4")
            .with_warnings(vec!["would-deny: privileged".to_owned()]);
        let v = serde_json::to_value(&resp).expect("serialise");
        assert_eq!(v["warnings"][0], "would-deny: privileged");
    }

    #[test]
    fn unknown_fields_are_ignored() {
        // The apiserver evolves the request schema; we only consume a
        // subset and MUST not blow up on a new field.
        let raw = br#"{
            "apiVersion": "admission.k8s.io/v1",
            "kind": "AdmissionReview",
            "request": {
                "uid": "u",
                "newFieldThatDoesNotExistInOurStruct": {"nested": [1, 2, 3]}
            }
        }"#;
        let r: AdmissionReview = serde_json::from_slice(raw).expect("must parse");
        assert!(r.request.is_some());
    }
}
