//! Read-side adapter for [`sx_api::port::DeviceRegistryPort`].
//!
//! Wraps the per-user push device registry from `sx-webhooks` (P3-008)
//! behind the API crate's HTTP-facing trait so `GET
//! /v1/notifications/devices` returns the same data the dispatcher
//! would target. Tenant scoping is enforced at the registry layer; the
//! adapter only projects the wire DTO.

use std::sync::Arc;

use async_trait::async_trait;
use sx_api::port::{DeviceRegistryPort, Phase3PortError};
use sx_api::view::admin_view::DeviceSummaryView;
use sx_webhooks::push::registry::{DeviceRegistry, InMemoryDeviceRegistry, MobilePlatform};

/// Adapter wrapping any [`DeviceRegistry`] trait object behind the
/// API-facing [`DeviceRegistryPort`].
pub(crate) struct DeviceRegistryAdapter {
    registry: Arc<dyn DeviceRegistry>,
}

impl std::fmt::Debug for DeviceRegistryAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceRegistryAdapter")
            .finish_non_exhaustive()
    }
}

impl DeviceRegistryAdapter {
    /// Wrap an existing registry handle.
    #[allow(dead_code)] // exposed for production callers that build their own registry
    pub(crate) fn new(registry: Arc<dyn DeviceRegistry>) -> Self {
        Self { registry }
    }

    /// Convenience constructor backed by the in-memory registry shipped
    /// with `sx-webhooks`.
    pub(crate) fn in_memory() -> Self {
        let registry: Arc<dyn DeviceRegistry> = InMemoryDeviceRegistry::shared();
        Self { registry }
    }
}

#[async_trait]
impl DeviceRegistryPort for DeviceRegistryAdapter {
    async fn list_devices(
        &self,
        tenant_id: &str,
        user_id: &str,
    ) -> Result<Vec<DeviceSummaryView>, Phase3PortError> {
        let rows = self
            .registry
            .devices_for_user(tenant_id, user_id)
            .await
            .map_err(|e| Phase3PortError::Dependency(e.to_string()))?;
        Ok(rows
            .into_iter()
            .map(|r| {
                let registered_at = r
                    .registered_at
                    .format(&time::format_description::well_known::Rfc3339)
                    .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned());
                DeviceSummaryView {
                    id: r.id.to_string(),
                    tenant_id: r.tenant_id,
                    user_id: r.user_id,
                    platform: match r.platform {
                        MobilePlatform::Ios => "ios".to_owned(),
                        MobilePlatform::Android => "android".to_owned(),
                    },
                    registered_at,
                }
            })
            .collect())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use secrecy::SecretString;
    use sx_webhooks::push::registry::NewDeviceRegistration;

    #[tokio::test]
    async fn list_devices_round_trips_through_registry() {
        let inner = InMemoryDeviceRegistry::shared();
        let registry: Arc<dyn DeviceRegistry> = Arc::clone(&inner) as Arc<dyn DeviceRegistry>;
        let _id = inner
            .register(NewDeviceRegistration {
                tenant_id: "t-1".into(),
                user_id: "u-1".into(),
                platform: MobilePlatform::Ios,
                device_token: SecretString::from("tok".to_owned()),
            })
            .await
            .expect("register");

        let adapter = DeviceRegistryAdapter::new(registry);
        let rows = adapter.list_devices("t-1", "u-1").await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].platform, "ios");
        assert_eq!(rows[0].tenant_id, "t-1");
        assert_eq!(rows[0].user_id, "u-1");
    }

    #[tokio::test]
    async fn list_devices_empty_when_unregistered() {
        let adapter = DeviceRegistryAdapter::in_memory();
        let rows = adapter.list_devices("t-1", "u-1").await.unwrap();
        assert!(rows.is_empty());
    }
}
