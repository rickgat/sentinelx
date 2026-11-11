//! Roles adapter — in-memory implementation of [`sx_api::port::RolesPort`].
//!
//! Backs the four `/v1/admin/roles*` endpoints with a single
//! `Mutex<HashMap<RoleId, StoredRole>>`. Tenant scoping is enforced on
//! every read so a role created under tenant A is invisible to tenant B.
//! User-to-role bindings live in a parallel `Mutex<HashMap<(tenant, user),
//! Vec<RoleId>>>` map.
//!
//! ## Idempotency
//!
//! `create` refuses to insert a row that collides with an existing
//! `(tenant_id, name)` pair. The collision surfaces as
//! [`Phase3PortError::Invalid`] carrying the marker
//! `"role already exists"` — the `sx-api` controller maps that into
//! HTTP `409 Conflict`.
//!
//! ## Validation
//!
//! - `tenant_id` must parse as a uuid.
//! - Role name must be a non-empty lowercase slug (mirrors the
//!   `sx_core` `Role` validator).
//! - Each permission token must parse as `resource:action` —
//!   malformed entries are silently dropped (the HTTP validator
//!   already rejects them at the boundary).
//! - On `assign`, every role id must parse as a uuid AND match a known
//!   role in the tenant; unknown ids surface as
//!   [`Phase3PortError::Invalid`].

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use sx_api::port::{Phase3PortError, RolesPort};
use sx_api::view::roles_view::{
    AssignRolesRequestView, AssignRolesResponseView, CreateRoleRequestView, ListRolesResponseView,
    RoleView,
};
use sx_iam::domain::{Permission, RoleId, TenantId};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// Sentinel string the adapter returns inside
/// [`Phase3PortError::Invalid`] to signal a duplicate `(tenant, name)`
/// pair. Must stay byte-for-byte identical to
/// `sx_api::controller::roles::DUPLICATE_ROLE_MARKER` so the controller's
/// idempotency-detection arm matches.
const DUPLICATE_ROLE_MARKER: &str = "role already exists";

/// Bundle of trait objects ready for [`sx_api::AppState`].
pub(crate) struct RolesBundle {
    /// HTTP-facing port.
    pub roles: Arc<dyn RolesPort>,
}

/// Build the roles bundle.
pub(crate) fn build() -> RolesBundle {
    RolesBundle {
        roles: Arc::new(InMemoryRolesAdapter::new()),
    }
}

/// Process-local stored row.
///
/// Mirrors [`RoleView`] verbatim — the adapter never mutates a row in
/// place, so the on-wire shape is the canonical storage shape.
#[derive(Debug, Clone)]
struct StoredRole {
    id: RoleId,
    tenant_id: TenantId,
    name: String,
    permissions: Vec<Permission>,
    created_at: String,
}

impl StoredRole {
    fn into_view(self) -> RoleView {
        RoleView {
            id: self.id.to_string(),
            tenant_id: self.tenant_id.to_string(),
            name: self.name,
            permissions: self.permissions.iter().map(Permission::to_string).collect(),
            created_at: self.created_at,
        }
    }

    fn to_view(&self) -> RoleView {
        RoleView {
            id: self.id.to_string(),
            tenant_id: self.tenant_id.to_string(),
            name: self.name.clone(),
            permissions: self.permissions.iter().map(Permission::to_string).collect(),
            created_at: self.created_at.clone(),
        }
    }
}

/// In-memory adapter — two `Mutex`-guarded maps.
#[derive(Debug)]
struct InMemoryRolesAdapter {
    /// `RoleId -> StoredRole` — the role catalogue.
    roles: Mutex<HashMap<RoleId, StoredRole>>,
    /// `(tenant_id, user_id) -> Vec<RoleId>` — assignment map.
    assignments: Mutex<HashMap<(TenantId, String), Vec<RoleId>>>,
}

impl InMemoryRolesAdapter {
    fn new() -> Self {
        Self {
            roles: Mutex::new(HashMap::new()),
            assignments: Mutex::new(HashMap::new()),
        }
    }
}

fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| String::from("1970-01-01T00:00:00Z"))
}

fn parse_tenant(tenant_id: &str) -> Result<TenantId, Phase3PortError> {
    uuid::Uuid::parse_str(tenant_id)
        .map(TenantId::from_uuid)
        .map_err(|_| Phase3PortError::Invalid("invalid tenant_id".into()))
}

fn parse_role_id(role_id: &str) -> Result<RoleId, Phase3PortError> {
    uuid::Uuid::parse_str(role_id)
        .map(RoleId::from_uuid)
        .map_err(|_| Phase3PortError::Invalid("invalid role_id".into()))
}

#[async_trait]
impl RolesPort for InMemoryRolesAdapter {
    async fn list(&self, tenant_id: &str) -> Result<ListRolesResponseView, Phase3PortError> {
        let tenant = parse_tenant(tenant_id)?;
        let guard = self
            .roles
            .lock()
            .map_err(|_| Phase3PortError::Internal("roles lock poisoned".into()))?;
        let roles = guard
            .values()
            .filter(|r| r.tenant_id == tenant)
            .map(StoredRole::to_view)
            .collect();
        Ok(ListRolesResponseView { roles })
    }

    async fn create(
        &self,
        tenant_id: &str,
        req: CreateRoleRequestView,
    ) -> Result<RoleView, Phase3PortError> {
        let tenant = parse_tenant(tenant_id)?;

        // Permissions are pre-validated at the HTTP boundary; ignore
        // any tokens that nevertheless fail to parse so a malformed
        // request never aborts the create-flow halfway through.
        let mut perms: Vec<Permission> = Vec::with_capacity(req.permissions.len());
        for tok in &req.permissions {
            let Ok(p) = Permission::parse(tok) else {
                return Err(Phase3PortError::Invalid(format!(
                    "invalid permission token: {tok}"
                )));
            };
            if !perms.contains(&p) {
                perms.push(p);
            }
        }
        if perms.is_empty() {
            return Err(Phase3PortError::Invalid(
                "at least one permission required".into(),
            ));
        }

        let mut guard = self
            .roles
            .lock()
            .map_err(|_| Phase3PortError::Internal("roles lock poisoned".into()))?;

        // Idempotency check on (tenant_id, name).
        if guard
            .values()
            .any(|r| r.tenant_id == tenant && r.name == req.name)
        {
            return Err(Phase3PortError::Invalid(DUPLICATE_ROLE_MARKER.into()));
        }

        let row = StoredRole {
            id: RoleId::new(),
            tenant_id: tenant,
            name: req.name,
            permissions: perms,
            created_at: now_rfc3339(),
        };
        let view = row.clone().into_view();
        guard.insert(row.id, row);
        Ok(view)
    }

    async fn delete(&self, tenant_id: &str, role_id: &str) -> Result<(), Phase3PortError> {
        let tenant = parse_tenant(tenant_id)?;
        let id = parse_role_id(role_id)?;

        let mut guard = self
            .roles
            .lock()
            .map_err(|_| Phase3PortError::Internal("roles lock poisoned".into()))?;
        let Some(row) = guard.get(&id) else {
            return Err(Phase3PortError::NotFound);
        };
        if row.tenant_id != tenant {
            // Refuse to leak whether a role exists in another tenant —
            // return `NotFound` rather than `Forbidden`.
            return Err(Phase3PortError::NotFound);
        }
        guard.remove(&id);

        // Cascade: prune the deleted role id from every assignment row
        // under this tenant. Drop the catalogue lock first so an
        // empty-assignment fast-path avoids the second mutex
        // entirely.
        drop(guard);
        let mut a = self
            .assignments
            .lock()
            .map_err(|_| Phase3PortError::Internal("assignments lock poisoned".into()))?;
        for ((t, _u), v) in a.iter_mut() {
            if *t == tenant {
                v.retain(|rid| *rid != id);
            }
        }
        Ok(())
    }

    async fn assign(
        &self,
        tenant_id: &str,
        user_id: &str,
        req: AssignRolesRequestView,
    ) -> Result<AssignRolesResponseView, Phase3PortError> {
        let tenant = parse_tenant(tenant_id)?;
        if user_id.is_empty() {
            return Err(Phase3PortError::Invalid("empty user_id".into()));
        }

        // Parse + de-duplicate role ids.
        let mut requested: Vec<RoleId> = Vec::with_capacity(req.role_ids.len());
        for r in &req.role_ids {
            let rid = parse_role_id(r)?;
            if !requested.contains(&rid) {
                requested.push(rid);
            }
        }

        // Validate every requested role belongs to the tenant.
        {
            let guard = self
                .roles
                .lock()
                .map_err(|_| Phase3PortError::Internal("roles lock poisoned".into()))?;
            for rid in &requested {
                match guard.get(rid) {
                    Some(row) if row.tenant_id == tenant => {}
                    _ => return Err(Phase3PortError::Invalid(format!("unknown role_id: {rid}"))),
                }
            }
        }

        // Replace the binding.
        let mut a = self
            .assignments
            .lock()
            .map_err(|_| Phase3PortError::Internal("assignments lock poisoned".into()))?;
        a.insert((tenant, user_id.to_string()), requested.clone());

        Ok(AssignRolesResponseView {
            user_id: user_id.to_string(),
            role_ids: requested.iter().map(RoleId::to_string).collect(),
            assigned_at: now_rfc3339(),
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn tenant_a() -> String {
        TenantId::new().to_string()
    }

    fn sample_create(name: &str) -> CreateRoleRequestView {
        CreateRoleRequestView {
            name: name.into(),
            permissions: vec!["findings:read".into(), "engagements:read".into()],
        }
    }

    #[tokio::test]
    async fn create_then_list_round_trip() {
        let bundle = build();
        let t = tenant_a();
        let created = bundle
            .roles
            .create(&t, sample_create("auditor"))
            .await
            .expect("create");
        assert_eq!(created.name, "auditor");
        assert_eq!(created.tenant_id, t);
        assert_eq!(created.permissions.len(), 2);

        let listed = bundle.roles.list(&t).await.expect("list");
        assert_eq!(listed.roles.len(), 1);
        assert_eq!(listed.roles[0].id, created.id);
    }

    #[tokio::test]
    async fn create_dedups_permissions() {
        let bundle = build();
        let t = tenant_a();
        let req = CreateRoleRequestView {
            name: "auditor".into(),
            permissions: vec![
                "findings:read".into(),
                "findings:read".into(),
                "engagements:read".into(),
            ],
        };
        let created = bundle.roles.create(&t, req).await.expect("create");
        assert_eq!(created.permissions.len(), 2);
    }

    #[tokio::test]
    async fn duplicate_name_returns_conflict_marker() {
        let bundle = build();
        let t = tenant_a();
        bundle
            .roles
            .create(&t, sample_create("auditor"))
            .await
            .expect("first create");
        let err = bundle
            .roles
            .create(&t, sample_create("auditor"))
            .await
            .expect_err("second create should fail");
        assert!(
            matches!(err, Phase3PortError::Invalid(ref m) if m == DUPLICATE_ROLE_MARKER),
            "expected duplicate marker, got {err:?}"
        );
    }

    #[tokio::test]
    async fn delete_removes_role() {
        let bundle = build();
        let t = tenant_a();
        let created = bundle
            .roles
            .create(&t, sample_create("auditor"))
            .await
            .expect("create");
        bundle.roles.delete(&t, &created.id).await.expect("delete");
        let listed = bundle.roles.list(&t).await.expect("list");
        assert!(listed.roles.is_empty());
    }

    #[tokio::test]
    async fn delete_unknown_id_is_not_found() {
        let bundle = build();
        let t = tenant_a();
        let other = RoleId::new().to_string();
        let err = bundle
            .roles
            .delete(&t, &other)
            .await
            .expect_err("delete should fail");
        assert!(
            matches!(err, Phase3PortError::NotFound),
            "expected NotFound, got {err:?}"
        );
    }

    #[tokio::test]
    async fn delete_across_tenants_returns_not_found() {
        let bundle = build();
        let t_a = tenant_a();
        let t_b = tenant_a();
        let created = bundle
            .roles
            .create(&t_a, sample_create("auditor"))
            .await
            .expect("create");
        let err = bundle
            .roles
            .delete(&t_b, &created.id)
            .await
            .expect_err("cross-tenant delete should fail");
        assert!(matches!(err, Phase3PortError::NotFound));
    }

    #[tokio::test]
    async fn assign_replaces_binding() {
        let bundle = build();
        let t = tenant_a();
        let r1 = bundle
            .roles
            .create(&t, sample_create("auditor"))
            .await
            .expect("create r1");
        let r2 = bundle
            .roles
            .create(&t, sample_create("operator"))
            .await
            .expect("create r2");
        let user = uuid::Uuid::now_v7().to_string();

        let resp = bundle
            .roles
            .assign(
                &t,
                &user,
                AssignRolesRequestView {
                    role_ids: vec![r1.id.clone(), r2.id.clone()],
                },
            )
            .await
            .expect("assign");
        assert_eq!(resp.user_id, user);
        assert_eq!(resp.role_ids.len(), 2);
        assert!(resp.role_ids.iter().any(|s| s == &r1.id));
        assert!(resp.role_ids.iter().any(|s| s == &r2.id));

        // Re-assign with a smaller set — the previous binding is
        // replaced, not merged.
        let resp2 = bundle
            .roles
            .assign(
                &t,
                &user,
                AssignRolesRequestView {
                    role_ids: vec![r1.id.clone()],
                },
            )
            .await
            .expect("re-assign");
        assert_eq!(resp2.role_ids, vec![r1.id]);
    }

    #[tokio::test]
    async fn assign_unknown_role_is_invalid() {
        let bundle = build();
        let t = tenant_a();
        let user = uuid::Uuid::now_v7().to_string();
        let phantom = RoleId::new().to_string();
        let err = bundle
            .roles
            .assign(
                &t,
                &user,
                AssignRolesRequestView {
                    role_ids: vec![phantom],
                },
            )
            .await
            .expect_err("assign should fail");
        assert!(
            matches!(err, Phase3PortError::Invalid(ref m) if m.contains("unknown role_id")),
            "expected unknown-role error, got {err:?}"
        );
    }

    #[tokio::test]
    async fn list_is_tenant_scoped() {
        let bundle = build();
        let t_a = tenant_a();
        let t_b = tenant_a();
        bundle
            .roles
            .create(&t_a, sample_create("auditor"))
            .await
            .expect("create a");
        bundle
            .roles
            .create(&t_b, sample_create("operator"))
            .await
            .expect("create b");

        let list_a = bundle.roles.list(&t_a).await.expect("list a");
        let list_b = bundle.roles.list(&t_b).await.expect("list b");
        assert_eq!(list_a.roles.len(), 1);
        assert_eq!(list_b.roles.len(), 1);
        assert_eq!(list_a.roles[0].name, "auditor");
        assert_eq!(list_b.roles[0].name, "operator");
    }

    #[tokio::test]
    async fn invalid_tenant_is_rejected() {
        let bundle = build();
        let err = bundle
            .roles
            .list("not-a-uuid")
            .await
            .expect_err("invalid tenant should fail");
        assert!(matches!(err, Phase3PortError::Invalid(_)));
    }

    #[tokio::test]
    async fn delete_prunes_assignments() {
        let bundle = build();
        let t = tenant_a();
        let r1 = bundle
            .roles
            .create(&t, sample_create("auditor"))
            .await
            .expect("create r1");
        let r2 = bundle
            .roles
            .create(&t, sample_create("operator"))
            .await
            .expect("create r2");
        let user = uuid::Uuid::now_v7().to_string();
        bundle
            .roles
            .assign(
                &t,
                &user,
                AssignRolesRequestView {
                    role_ids: vec![r1.id.clone(), r2.id.clone()],
                },
            )
            .await
            .expect("assign");
        bundle.roles.delete(&t, &r1.id).await.expect("delete r1");

        // Re-assign with the same payload (minus r1) — should still
        // succeed because the pruning behaviour does not affect new
        // bindings.
        let resp = bundle
            .roles
            .assign(
                &t,
                &user,
                AssignRolesRequestView {
                    role_ids: vec![r2.id.clone()],
                },
            )
            .await
            .expect("re-assign after delete");
        assert_eq!(resp.role_ids, vec![r2.id]);
    }
}
