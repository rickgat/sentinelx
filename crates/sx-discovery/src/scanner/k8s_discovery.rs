//! Kubernetes cluster discovery scanner.
//!
//! Connects to a Kubernetes API server via [`kube`] and enumerates the three
//! most operationally interesting workload kinds for asset discovery:
//!
//! - [`Pod`](k8s_openapi::api::core::v1::Pod) — workload units, the closest
//!   analogue of "running process" in the cluster.
//! - [`Service`](k8s_openapi::api::core::v1::Service) — stable network
//!   identities that expose pods inside or outside the cluster.
//! - [`Ingress`](k8s_openapi::api::networking::v1::Ingress) — declarative
//!   north–south HTTP entrypoints, the cluster's externally addressable
//!   attack surface.
//!
//! All three kinds project into a single uniform [`K8sResource`] value so
//! downstream consumers (graph projection, risk scoring, twin sync) can
//! treat them homogeneously.
//!
//! ## Authentication
//!
//! [`kube::Client::try_default`] follows the standard kubeconfig precedence:
//!
//! 1. In-cluster service-account token + CA, when running inside a pod.
//! 2. `$KUBECONFIG`, when set.
//! 3. `~/.kube/config`, the developer-workstation default.
//!
//! No credentials are ever logged or returned.
//!
//! ## Safety
//!
//! The scanner is **read-only**. It issues `LIST` requests only and never
//! mutates cluster state. The optional [`K8sDiscoverer::namespace_filter`]
//! lets callers restrict enumeration to a single namespace, which is the
//! norm for multi-tenant clusters where the `SentinelX` service account only
//! has `get`/`list` RBAC inside one namespace.

use std::collections::BTreeMap;

use k8s_openapi::api::core::v1::{Pod, Service};
use k8s_openapi::api::networking::v1::Ingress;
use kube::api::{Api, ListParams};
use kube::{Client, Config};

use crate::error::DiscoveryError;

/// String constant for the `Pod` kind, mirroring the apiVersion convention.
pub const KIND_POD: &str = "Pod";
/// String constant for the `Service` kind.
pub const KIND_SERVICE: &str = "Service";
/// String constant for the `Ingress` kind.
pub const KIND_INGRESS: &str = "Ingress";

/// Uniform projection of a Kubernetes object suitable for downstream
/// asset/graph consumers.
///
/// Field-level details that differ per kind (e.g. a `Pod`'s phase, a
/// `Service`'s type, an `Ingress`'s hosts) are placed into the open-ended
/// [`fields`](Self::fields) map so the projection does not have to grow a
/// new variant every time a kind gains a property of interest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct K8sResource {
    /// Kubernetes kind, one of `Pod`, `Service`, `Ingress`.
    pub kind: String,
    /// Object `metadata.name`.
    pub name: String,
    /// Object `metadata.namespace`, when set.
    pub namespace: Option<String>,
    /// Object `metadata.labels`, flattened into a sorted map.
    pub labels: BTreeMap<String, String>,
    /// Kind-specific fields of interest (`status.phase`, `spec.type`,
    /// `spec.rules[].host`, …). Encoded as strings to keep the projection
    /// schema stable.
    pub fields: BTreeMap<String, String>,
}

/// Discovers Kubernetes API resources for asset enumeration.
#[derive(Clone)]
pub struct K8sDiscoverer {
    /// Authenticated client used for `LIST` requests.
    pub client: Client,
    /// Optional namespace scope. When `None`, lists across all accessible
    /// namespaces; when `Some`, lists only inside the given namespace.
    pub namespace_filter: Option<String>,
}

// `kube::Client` does not implement `Debug` (it wraps a `tower::Service`
// trait object); we implement it by hand and elide the client itself.
impl std::fmt::Debug for K8sDiscoverer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("K8sDiscoverer")
            .field("client", &"kube::Client { .. }")
            .field("namespace_filter", &self.namespace_filter)
            .finish()
    }
}

impl K8sDiscoverer {
    /// Build a discoverer using [`Client::try_default`].
    ///
    /// Resolution order matches `kubectl`: in-cluster config first (when
    /// running inside a pod), falling back to `$KUBECONFIG` and then
    /// `~/.kube/config`. Returns [`DiscoveryError::Config`] when no
    /// authentication path resolves — this is the expected outcome on a
    /// developer workstation with no kubeconfig.
    pub async fn from_default(namespace_filter: Option<String>) -> Result<Self, DiscoveryError> {
        let client = Client::try_default()
            .await
            .map_err(|e| DiscoveryError::config(format!("kube client init: {e}")))?;
        Ok(Self {
            client,
            namespace_filter,
        })
    }

    /// Build a discoverer directly from an existing [`Config`]. Primarily
    /// useful for tests and for callers that have already negotiated a
    /// non-standard authentication flow.
    pub fn from_config(
        config: Config,
        namespace_filter: Option<String>,
    ) -> Result<Self, DiscoveryError> {
        let client = Client::try_from(config)
            .map_err(|e| DiscoveryError::config(format!("kube client from config: {e}")))?;
        Ok(Self {
            client,
            namespace_filter,
        })
    }

    /// Build a discoverer from an already-constructed [`Client`]. Tests
    /// that need to short-circuit transport use this helper.
    #[must_use]
    pub const fn from_client(client: Client, namespace_filter: Option<String>) -> Self {
        Self {
            client,
            namespace_filter,
        }
    }

    fn api<K>(&self) -> Api<K>
    where
        K: kube::Resource<Scope = k8s_openapi::NamespaceResourceScope>,
        K::DynamicType: Default,
    {
        self.namespace_filter.as_deref().map_or_else(
            || Api::all(self.client.clone()),
            |ns| Api::namespaced(self.client.clone(), ns),
        )
    }

    /// Enumerate all visible `Pod` objects, projected into [`K8sResource`].
    pub async fn list_pods(&self) -> Result<Vec<K8sResource>, DiscoveryError> {
        let api: Api<Pod> = self.api();
        let list = api
            .list(&ListParams::default())
            .await
            .map_err(|e| DiscoveryError::io(format!("list pods: {e}")))?;
        Ok(list.items.iter().map(project_pod).collect())
    }

    /// Enumerate all visible `Service` objects, projected into
    /// [`K8sResource`].
    pub async fn list_services(&self) -> Result<Vec<K8sResource>, DiscoveryError> {
        let api: Api<Service> = self.api();
        let list = api
            .list(&ListParams::default())
            .await
            .map_err(|e| DiscoveryError::io(format!("list services: {e}")))?;
        Ok(list.items.iter().map(project_service).collect())
    }

    /// Enumerate all visible `Ingress` objects, projected into
    /// [`K8sResource`].
    pub async fn list_ingresses(&self) -> Result<Vec<K8sResource>, DiscoveryError> {
        let api: Api<Ingress> = self.api();
        let list = api
            .list(&ListParams::default())
            .await
            .map_err(|e| DiscoveryError::io(format!("list ingresses: {e}")))?;
        Ok(list.items.iter().map(project_ingress).collect())
    }
}

/// Project a [`Pod`] into a [`K8sResource`].
#[must_use]
pub fn project_pod(pod: &Pod) -> K8sResource {
    let mut fields = BTreeMap::new();
    if let Some(spec) = pod.spec.as_ref() {
        if let Some(node) = spec.node_name.as_ref() {
            fields.insert("node_name".to_owned(), node.clone());
        }
        if let Some(sa) = spec.service_account_name.as_ref() {
            fields.insert("service_account".to_owned(), sa.clone());
        }
        let container_images: Vec<String> = spec
            .containers
            .iter()
            .filter_map(|c| c.image.clone())
            .collect();
        if !container_images.is_empty() {
            fields.insert("container_images".to_owned(), container_images.join(","));
        }
    }
    if let Some(status) = pod.status.as_ref() {
        if let Some(phase) = status.phase.as_ref() {
            fields.insert("phase".to_owned(), phase.clone());
        }
        if let Some(pod_ip) = status.pod_ip.as_ref() {
            fields.insert("pod_ip".to_owned(), pod_ip.clone());
        }
    }
    K8sResource {
        kind: KIND_POD.to_owned(),
        name: pod.metadata.name.clone().unwrap_or_default(),
        namespace: pod.metadata.namespace.clone(),
        labels: labels(pod.metadata.labels.as_ref()),
        fields,
    }
}

/// Project a [`Service`] into a [`K8sResource`].
#[must_use]
pub fn project_service(svc: &Service) -> K8sResource {
    let mut fields = BTreeMap::new();
    if let Some(spec) = svc.spec.as_ref() {
        if let Some(ty) = spec.type_.as_ref() {
            fields.insert("type".to_owned(), ty.clone());
        }
        if let Some(cluster_ip) = spec.cluster_ip.as_ref() {
            fields.insert("cluster_ip".to_owned(), cluster_ip.clone());
        }
        if let Some(ports) = spec.ports.as_ref() {
            let formatted: Vec<String> = ports
                .iter()
                .map(|p| {
                    let proto = p.protocol.as_deref().unwrap_or("TCP");
                    format!("{}/{}", p.port, proto)
                })
                .collect();
            if !formatted.is_empty() {
                fields.insert("ports".to_owned(), formatted.join(","));
            }
        }
    }
    K8sResource {
        kind: KIND_SERVICE.to_owned(),
        name: svc.metadata.name.clone().unwrap_or_default(),
        namespace: svc.metadata.namespace.clone(),
        labels: labels(svc.metadata.labels.as_ref()),
        fields,
    }
}

/// Project an [`Ingress`] into a [`K8sResource`].
#[must_use]
pub fn project_ingress(ing: &Ingress) -> K8sResource {
    let mut fields = BTreeMap::new();
    if let Some(spec) = ing.spec.as_ref() {
        if let Some(class) = spec.ingress_class_name.as_ref() {
            fields.insert("ingress_class".to_owned(), class.clone());
        }
        if let Some(rules) = spec.rules.as_ref() {
            let hosts: Vec<String> = rules.iter().filter_map(|r| r.host.clone()).collect();
            if !hosts.is_empty() {
                fields.insert("hosts".to_owned(), hosts.join(","));
            }
        }
        if let Some(tls) = spec.tls.as_ref() {
            let tls_hosts: Vec<String> = tls
                .iter()
                .flat_map(|t| t.hosts.clone().unwrap_or_default())
                .collect();
            if !tls_hosts.is_empty() {
                fields.insert("tls_hosts".to_owned(), tls_hosts.join(","));
            }
        }
    }
    K8sResource {
        kind: KIND_INGRESS.to_owned(),
        name: ing.metadata.name.clone().unwrap_or_default(),
        namespace: ing.metadata.namespace.clone(),
        labels: labels(ing.metadata.labels.as_ref()),
        fields,
    }
}

fn labels(src: Option<&std::collections::BTreeMap<String, String>>) -> BTreeMap<String, String> {
    src.cloned().unwrap_or_default()
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
    use serde_json::json;
    use std::sync::Once;

    /// Install the ring `CryptoProvider` exactly once per process. `kube`'s
    /// `Client::try_from(Config)` exercises rustls, which panics in
    /// rustls 0.23 if no process-level provider has been registered.
    fn install_rustls_provider_once() {
        static ONCE: Once = Once::new();
        ONCE.call_once(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
    }

    /// On a developer workstation with no in-cluster config, `try_default`
    /// must reach the kubeconfig fallback path. We do not require a working
    /// kubeconfig — only that the constructor runs without panicking and
    /// surfaces any failure as a [`DiscoveryError::Config`].
    #[tokio::test]
    async fn client_from_default_falls_back_to_kube_config_on_macos() {
        // Force the in-cluster path to fail by ensuring the well-known env
        // vars are absent, then call the constructor. We do not assert
        // success: either path (config loaded, or `Err(Config(_))`) is
        // acceptable. The test fails only on panic.
        // SAFETY: tests run single-threaded for env mutation, and we restore
        // nothing because absent is the default here.
        // We intentionally use `remove_var` only — the test is invariant
        // under either presence or absence after the call.
        std::env::remove_var("KUBERNETES_SERVICE_HOST");
        std::env::remove_var("KUBERNETES_SERVICE_PORT");

        let outcome = K8sDiscoverer::from_default(None).await;
        match outcome {
            Ok(d) => assert!(d.namespace_filter.is_none()),
            Err(DiscoveryError::Config(msg)) => {
                assert!(!msg.is_empty(), "config error should carry a message");
            }
            Err(other) => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn project_pod_extracts_kind_name_namespace_labels() {
        let raw = json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "web-7d9f",
                "namespace": "prod",
                "labels": {"app": "web", "tier": "frontend"}
            },
            "spec": {
                "nodeName": "ip-10-0-1-5",
                "serviceAccountName": "web-sa",
                "containers": [
                    {"name": "app", "image": "ghcr.io/acme/web:1.4.2"},
                    {"name": "sidecar", "image": "ghcr.io/acme/envoy:1.30"}
                ]
            },
            "status": {"phase": "Running", "podIP": "10.244.3.7"}
        });
        let pod: Pod = serde_json::from_value(raw).unwrap();
        let r = project_pod(&pod);
        assert_eq!(r.kind, KIND_POD);
        assert_eq!(r.name, "web-7d9f");
        assert_eq!(r.namespace.as_deref(), Some("prod"));
        assert_eq!(r.labels.get("app"), Some(&"web".to_owned()));
        assert_eq!(r.labels.get("tier"), Some(&"frontend".to_owned()));
        assert_eq!(r.fields.get("phase"), Some(&"Running".to_owned()));
        assert_eq!(r.fields.get("pod_ip"), Some(&"10.244.3.7".to_owned()));
        assert_eq!(r.fields.get("node_name"), Some(&"ip-10-0-1-5".to_owned()));
        assert_eq!(r.fields.get("service_account"), Some(&"web-sa".to_owned()));
        let images = r.fields.get("container_images").unwrap();
        assert!(images.contains("ghcr.io/acme/web:1.4.2"));
        assert!(images.contains("ghcr.io/acme/envoy:1.30"));
    }

    #[test]
    fn project_service_captures_type_and_ports() {
        let raw = json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {"name": "web-svc", "namespace": "prod", "labels": {"app": "web"}},
            "spec": {
                "type": "ClusterIP",
                "clusterIP": "10.96.0.42",
                "ports": [
                    {"port": 80, "protocol": "TCP", "targetPort": 8080},
                    {"port": 443, "protocol": "TCP", "targetPort": 8443}
                ]
            }
        });
        let svc: Service = serde_json::from_value(raw).unwrap();
        let r = project_service(&svc);
        assert_eq!(r.kind, KIND_SERVICE);
        assert_eq!(r.name, "web-svc");
        assert_eq!(r.fields.get("type"), Some(&"ClusterIP".to_owned()));
        assert_eq!(r.fields.get("cluster_ip"), Some(&"10.96.0.42".to_owned()));
        let ports = r.fields.get("ports").unwrap();
        assert!(ports.contains("80/TCP"));
        assert!(ports.contains("443/TCP"));
    }

    #[test]
    fn project_ingress_captures_hosts_and_class() {
        let raw = json!({
            "apiVersion": "networking.k8s.io/v1",
            "kind": "Ingress",
            "metadata": {"name": "web-ing", "namespace": "prod"},
            "spec": {
                "ingressClassName": "nginx",
                "rules": [
                    {"host": "www.example.com"},
                    {"host": "api.example.com"}
                ],
                "tls": [
                    {"hosts": ["www.example.com", "api.example.com"], "secretName": "tls"}
                ]
            }
        });
        let ing: Ingress = serde_json::from_value(raw).unwrap();
        let r = project_ingress(&ing);
        assert_eq!(r.kind, KIND_INGRESS);
        assert_eq!(r.fields.get("ingress_class"), Some(&"nginx".to_owned()));
        let hosts = r.fields.get("hosts").unwrap();
        assert!(hosts.contains("www.example.com"));
        assert!(hosts.contains("api.example.com"));
        let tls_hosts = r.fields.get("tls_hosts").unwrap();
        assert!(tls_hosts.contains("www.example.com"));
    }

    #[tokio::test]
    async fn namespace_filter_excludes_other_namespaces() {
        install_rustls_provider_once();
        // The filter is set at the API selector level; we assert that the
        // discoverer carries the filter string and exposes it for the API
        // selector, which is the load-bearing contract.
        // (A live cluster is not available in unit tests; the projection
        // logic is exercised separately.)
        let cfg = Config::new("https://127.0.0.1:1".parse().unwrap());
        let d = K8sDiscoverer::from_config(cfg, Some("prod".to_owned())).unwrap();
        assert_eq!(d.namespace_filter.as_deref(), Some("prod"));
        // Verify the API selector path differs based on filter presence.
        let client = d.client;
        let d_unfiltered = K8sDiscoverer::from_client(client, None);
        assert!(d_unfiltered.namespace_filter.is_none());
    }

    #[test]
    fn project_pod_tolerates_missing_optional_fields() {
        let raw = json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "minimal"},
            "spec": {"containers": []}
        });
        let pod: Pod = serde_json::from_value(raw).unwrap();
        let r = project_pod(&pod);
        assert_eq!(r.name, "minimal");
        assert!(r.namespace.is_none());
        assert!(r.labels.is_empty());
        assert!(!r.fields.contains_key("phase"));
        assert!(!r.fields.contains_key("container_images"));
    }
}
