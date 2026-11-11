//! Per-user device registration store.
//!
//! Devices are scoped to a `(tenant_id, user_id)` pair. Each
//! registration carries a [`MobilePlatform`] discriminant and a raw
//! provider token wrapped in [`secrecy::SecretString`]. Tokens are
//! never logged or surfaced through [`std::fmt::Debug`].
//!
//! This module ships an in-memory registry suitable for tests and the
//! monolith composition root; production deployments should plug in a
//! Postgres-backed implementation behind the [`DeviceRegistry`] trait.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::push::error::PushError;

/// Stable identifier for a registered device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DeviceId(pub Uuid);

impl DeviceId {
    /// Generate a fresh v4 device id.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for DeviceId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for DeviceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
    }
}

/// Mobile push platform the device is registered against.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MobilePlatform {
    /// Apple Push Notification service (APNs) over HTTP/2.
    Ios,
    /// Firebase Cloud Messaging (FCM) over HTTP/1.1.
    Android,
}

impl MobilePlatform {
    /// Parse from the JSON-wire string used by the public API
    /// (`"ios"` or `"android"`). Returns
    /// [`PushError::UnsupportedPlatform`] for unknown values.
    pub fn parse(value: &str) -> Result<Self, PushError> {
        match value {
            "ios" | "iOS" | "IOS" => Ok(Self::Ios),
            "android" | "Android" | "ANDROID" => Ok(Self::Android),
            _ => Err(PushError::UnsupportedPlatform),
        }
    }
}

/// Input shape for `POST /v1/notifications/devices`.
///
/// `device_token` is the *raw* provider token (APNs hex device token
/// or FCM registration id). It MUST be wrapped in a
/// [`SecretString`] at the HTTP extractor so the bytes never reach a
/// `tracing` span.
#[derive(Debug, Clone)]
pub struct NewDeviceRegistration {
    /// Tenant scope.
    pub tenant_id: String,
    /// User this device belongs to.
    pub user_id: String,
    /// Whether the device is an iOS or Android device.
    pub platform: MobilePlatform,
    /// Opaque provider token (APNs hex / FCM token).
    pub device_token: SecretString,
}

/// A registered device record returned by [`DeviceRegistry`] reads.
///
/// `device_token` is preserved as a [`SecretString`] so the dispatcher
/// can use it as the destination address without ever exposing the raw
/// bytes in error messages or logs. The [`std::fmt::Debug`] impl masks
/// the token.
#[derive(Clone)]
pub struct DeviceRecord {
    /// Stable per-registration identifier.
    pub id: DeviceId,
    /// Tenant scope.
    pub tenant_id: String,
    /// Owning user.
    pub user_id: String,
    /// Target platform.
    pub platform: MobilePlatform,
    /// Provider device token (never logged).
    pub device_token: SecretString,
    /// Wall-clock timestamp of the registration.
    pub registered_at: OffsetDateTime,
}

impl std::fmt::Debug for DeviceRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceRecord")
            .field("id", &self.id)
            .field("tenant_id", &self.tenant_id)
            .field("user_id", &self.user_id)
            .field("platform", &self.platform)
            .field("device_token", &"<redacted>")
            .field("registered_at", &self.registered_at)
            .finish()
    }
}

/// Audit hook fired on every registration and deregistration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryEvent {
    /// A new device was registered.
    Registered {
        /// Tenant scope.
        tenant_id: String,
        /// Owning user.
        user_id: String,
        /// Stable id of the new registration.
        device_id: DeviceId,
        /// Target platform.
        platform: MobilePlatform,
    },
    /// An existing device was deregistered.
    Deregistered {
        /// Tenant scope.
        tenant_id: String,
        /// Stable id of the removed registration.
        device_id: DeviceId,
    },
}

/// Storage abstraction for device registrations.
#[async_trait]
pub trait DeviceRegistry: Send + Sync {
    /// Persist a new registration and return the generated [`DeviceId`].
    async fn register(&self, registration: NewDeviceRegistration) -> Result<DeviceId, PushError>;

    /// Remove a registration by id.
    ///
    /// Returns [`PushError::UnknownDevice`] when no device matches.
    async fn deregister(&self, tenant_id: &str, device_id: DeviceId) -> Result<(), PushError>;

    /// All devices registered against a particular user.
    async fn devices_for_user(
        &self,
        tenant_id: &str,
        user_id: &str,
    ) -> Result<Vec<DeviceRecord>, PushError>;

    /// All devices registered against a list of users (for fan-out).
    async fn devices_for_users(
        &self,
        tenant_id: &str,
        user_ids: &[String],
    ) -> Result<Vec<DeviceRecord>, PushError>;
}

/// Process-local registry suitable for tests and single-node dev
/// deployments. Backed by a `tokio::sync::Mutex<HashMap>`.
#[derive(Default)]
pub struct InMemoryDeviceRegistry {
    inner: Mutex<HashMap<DeviceId, DeviceRecord>>,
    audit: Mutex<Vec<RegistryEvent>>,
}

impl std::fmt::Debug for InMemoryDeviceRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InMemoryDeviceRegistry")
            .finish_non_exhaustive()
    }
}

impl InMemoryDeviceRegistry {
    /// Construct an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Wrap in an [`Arc`] for sharing across handler state.
    #[must_use]
    pub fn shared() -> Arc<Self> {
        Arc::new(Self::new())
    }

    /// Drain and return all audit events recorded since the last
    /// call. Tests use this to assert per-registration / per-removal
    /// audit emission.
    pub async fn drain_audit(&self) -> Vec<RegistryEvent> {
        let mut guard = self.audit.lock().await;
        std::mem::take(&mut *guard)
    }
}

#[async_trait]
impl DeviceRegistry for InMemoryDeviceRegistry {
    async fn register(&self, registration: NewDeviceRegistration) -> Result<DeviceId, PushError> {
        let id = DeviceId::new();
        let token_clone = SecretString::from(registration.device_token.expose_secret().to_owned());
        let record = DeviceRecord {
            id,
            tenant_id: registration.tenant_id.clone(),
            user_id: registration.user_id.clone(),
            platform: registration.platform,
            device_token: token_clone,
            registered_at: OffsetDateTime::now_utc(),
        };
        {
            let mut guard = self.inner.lock().await;
            guard.insert(id, record);
        }
        tracing::info!(
            tenant = %registration.tenant_id,
            user = %registration.user_id,
            device_id = %id,
            platform = ?registration.platform,
            "device registered for push"
        );
        self.audit.lock().await.push(RegistryEvent::Registered {
            tenant_id: registration.tenant_id,
            user_id: registration.user_id,
            device_id: id,
            platform: registration.platform,
        });
        Ok(id)
    }

    async fn deregister(&self, tenant_id: &str, device_id: DeviceId) -> Result<(), PushError> {
        let removed = {
            let mut guard = self.inner.lock().await;
            match guard.get(&device_id) {
                Some(record) if record.tenant_id == tenant_id => guard.remove(&device_id).is_some(),
                _ => false,
            }
        };
        if !removed {
            return Err(PushError::UnknownDevice);
        }
        tracing::info!(tenant = %tenant_id, device_id = %device_id, "device deregistered");
        self.audit.lock().await.push(RegistryEvent::Deregistered {
            tenant_id: tenant_id.to_owned(),
            device_id,
        });
        Ok(())
    }

    async fn devices_for_user(
        &self,
        tenant_id: &str,
        user_id: &str,
    ) -> Result<Vec<DeviceRecord>, PushError> {
        let guard = self.inner.lock().await;
        Ok(guard
            .values()
            .filter(|r| r.tenant_id == tenant_id && r.user_id == user_id)
            .cloned()
            .collect())
    }

    async fn devices_for_users(
        &self,
        tenant_id: &str,
        user_ids: &[String],
    ) -> Result<Vec<DeviceRecord>, PushError> {
        let guard = self.inner.lock().await;
        let allow: std::collections::HashSet<&String> = user_ids.iter().collect();
        Ok(guard
            .values()
            .filter(|r| r.tenant_id == tenant_id && allow.contains(&r.user_id))
            .cloned()
            .collect())
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::panic
)]
mod tests {
    use super::*;

    #[test]
    fn platform_parse_accepts_known_strings() {
        assert!(matches!(
            MobilePlatform::parse("ios"),
            Ok(MobilePlatform::Ios)
        ));
        assert!(matches!(
            MobilePlatform::parse("Android"),
            Ok(MobilePlatform::Android)
        ));
        assert!(matches!(
            MobilePlatform::parse("blackberry"),
            Err(PushError::UnsupportedPlatform)
        ));
    }

    #[test]
    fn debug_record_redacts_token() {
        let rec = DeviceRecord {
            id: DeviceId::new(),
            tenant_id: "t".into(),
            user_id: "u".into(),
            platform: MobilePlatform::Ios,
            device_token: SecretString::from("super-secret-token".to_owned()),
            registered_at: OffsetDateTime::now_utc(),
        };
        let dbg = format!("{rec:?}");
        assert!(!dbg.contains("super-secret-token"));
        assert!(dbg.contains("<redacted>"));
    }

    #[tokio::test]
    async fn register_and_lookup_roundtrip() {
        let reg = InMemoryDeviceRegistry::new();
        let id = reg
            .register(NewDeviceRegistration {
                tenant_id: "tA".into(),
                user_id: "alice".into(),
                platform: MobilePlatform::Ios,
                device_token: SecretString::from("tok".to_owned()),
            })
            .await
            .expect("register");
        let devices = reg.devices_for_user("tA", "alice").await.expect("lookup");
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].id, id);
        assert_eq!(devices[0].platform, MobilePlatform::Ios);

        let audit = reg.drain_audit().await;
        assert_eq!(audit.len(), 1);
        assert!(matches!(audit[0], RegistryEvent::Registered { .. }));
    }

    #[tokio::test]
    async fn deregister_unknown_returns_error() {
        let reg = InMemoryDeviceRegistry::new();
        let err = reg
            .deregister("tA", DeviceId::new())
            .await
            .expect_err("expected UnknownDevice");
        assert!(matches!(err, PushError::UnknownDevice));
    }

    #[tokio::test]
    async fn deregister_wrong_tenant_is_unknown() {
        let reg = InMemoryDeviceRegistry::new();
        let id = reg
            .register(NewDeviceRegistration {
                tenant_id: "tA".into(),
                user_id: "alice".into(),
                platform: MobilePlatform::Android,
                device_token: SecretString::from("tok".to_owned()),
            })
            .await
            .expect("register");
        let err = reg
            .deregister("tB", id)
            .await
            .expect_err("expected UnknownDevice");
        assert!(matches!(err, PushError::UnknownDevice));
    }
}
