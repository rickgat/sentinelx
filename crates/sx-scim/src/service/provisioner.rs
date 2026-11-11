//! Provisioner port + in-memory implementation.

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::error::ScimError;
use crate::filter::{parse as parse_filter, Filter};
use crate::schema::group::ScimGroup;
use crate::schema::meta::Meta;
use crate::schema::user::ScimUser;

/// Query parameters for `GET /Users` (and `/Groups`).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ListUsersQuery {
    /// SCIM filter expression (e.g. `userName eq "alice"`).
    pub filter: Option<String>,
    /// 1-based start index per RFC 7644 §3.4.2.
    pub start_index: Option<usize>,
    /// Per-page row cap.
    pub count: Option<usize>,
}

/// Paged result envelope for `list_users`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListUsersResult {
    /// Total resource count matching the filter (across all pages).
    pub total_results: usize,
    /// 1-based start index of this page.
    pub start_index: usize,
    /// Rows on this page.
    pub items_per_page: usize,
    /// Resources on this page.
    pub resources: Vec<ScimUser>,
}

/// Paged result envelope for `list_groups`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListGroupsResult {
    /// Total resource count matching the filter (across all pages).
    pub total_results: usize,
    /// 1-based start index of this page.
    pub start_index: usize,
    /// Rows on this page.
    pub items_per_page: usize,
    /// Resources on this page.
    pub resources: Vec<ScimGroup>,
}

/// SCIM provisioning port the HTTP layer talks to.
#[async_trait]
pub trait ScimProvisioner: Send + Sync {
    /// Create a new user. Returns the persisted user with `id` + `meta` set.
    async fn create_user(&self, tenant_id: &str, user: ScimUser) -> Result<ScimUser, ScimError>;

    /// Fetch a user by id.
    async fn get_user(&self, tenant_id: &str, id: &str) -> Result<ScimUser, ScimError>;

    /// Replace a user — PUT semantics. `id` MUST match `user.id` if set.
    async fn replace_user(
        &self,
        tenant_id: &str,
        id: &str,
        user: ScimUser,
    ) -> Result<ScimUser, ScimError>;

    /// Soft-delete (sets `active = false`) per SCIM deprovisioning conventions.
    async fn delete_user(&self, tenant_id: &str, id: &str) -> Result<(), ScimError>;

    /// List users, applying the filter and pagination from `query`.
    async fn list_users(
        &self,
        tenant_id: &str,
        query: ListUsersQuery,
    ) -> Result<ListUsersResult, ScimError>;

    /// Create a new group.
    async fn create_group(&self, tenant_id: &str, group: ScimGroup)
        -> Result<ScimGroup, ScimError>;

    /// Fetch a group by id.
    async fn get_group(&self, tenant_id: &str, id: &str) -> Result<ScimGroup, ScimError>;

    /// List groups, applying the filter and pagination from `query`.
    async fn list_groups(
        &self,
        tenant_id: &str,
        query: ListUsersQuery,
    ) -> Result<ListGroupsResult, ScimError>;
}

// ---------------------------------------------------------------------------
// In-memory implementation
// ---------------------------------------------------------------------------

/// In-memory provisioner used by the adapter when no Postgres path is wired.
///
/// Storage is keyed by `(tenant_id, user_id)` so a single instance can serve
/// every tenant in the monolith.
#[derive(Default)]
pub struct InMemoryScimProvisioner {
    users: Mutex<HashMap<String, HashMap<String, ScimUser>>>,
    groups: Mutex<HashMap<String, HashMap<String, ScimGroup>>>,
    /// Hook used by tests to inject a deterministic id/timestamp pair.
    clock: Mutex<Option<Box<dyn Fn() -> (String, String) + Send + Sync>>>,
}

impl std::fmt::Debug for InMemoryScimProvisioner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InMemoryScimProvisioner")
            .finish_non_exhaustive()
    }
}

impl InMemoryScimProvisioner {
    /// Create an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Install a deterministic `(id, ts)` source for tests.
    pub fn set_clock<F>(&self, f: F)
    where
        F: Fn() -> (String, String) + Send + Sync + 'static,
    {
        let mut g = self
            .clock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *g = Some(Box::new(f));
    }

    fn next_id_and_ts(&self) -> (String, String) {
        let clock = self
            .clock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(ref f) = *clock {
            f()
        } else {
            let id = uuid::Uuid::new_v4().to_string();
            let ts = time::OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned());
            (id, ts)
        }
    }

    fn locked_users(
        &self,
    ) -> std::sync::MutexGuard<'_, HashMap<String, HashMap<String, ScimUser>>> {
        self.users
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn locked_groups(
        &self,
    ) -> std::sync::MutexGuard<'_, HashMap<String, HashMap<String, ScimGroup>>> {
        self.groups
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[async_trait]
impl ScimProvisioner for InMemoryScimProvisioner {
    async fn create_user(
        &self,
        tenant_id: &str,
        mut user: ScimUser,
    ) -> Result<ScimUser, ScimError> {
        user.validate().map_err(ScimError::invalid_request)?;
        let mut guard = self.locked_users();
        let tenant_users = guard.entry(tenant_id.to_owned()).or_default();
        // Duplicate `userName` is a 409 per RFC 7644 §3.3.
        if tenant_users
            .values()
            .any(|u| u.user_name.eq_ignore_ascii_case(&user.user_name))
        {
            return Err(ScimError::conflict("userName already exists"));
        }
        let (id, ts) = self.next_id_and_ts();
        user.id = Some(id.clone());
        user.meta = Some(Meta::new("User", &ts, format!("/scim/v2/Users/{id}")));
        tenant_users.insert(id, user.clone());
        Ok(user)
    }

    async fn get_user(&self, tenant_id: &str, id: &str) -> Result<ScimUser, ScimError> {
        let guard = self.locked_users();
        guard
            .get(tenant_id)
            .and_then(|m| m.get(id))
            .cloned()
            .ok_or(ScimError::NotFound)
    }

    async fn replace_user(
        &self,
        tenant_id: &str,
        id: &str,
        mut user: ScimUser,
    ) -> Result<ScimUser, ScimError> {
        user.validate().map_err(ScimError::invalid_request)?;
        let mut guard = self.locked_users();
        let tenant_users = guard.get_mut(tenant_id).ok_or(ScimError::NotFound)?;
        let existing = tenant_users.get(id).cloned().ok_or(ScimError::NotFound)?;
        // `userName` change must not collide with another user.
        if !existing.user_name.eq_ignore_ascii_case(&user.user_name)
            && tenant_users
                .values()
                .any(|u| u.user_name.eq_ignore_ascii_case(&user.user_name))
        {
            return Err(ScimError::conflict("userName already exists"));
        }
        let (_, ts) = self.next_id_and_ts();
        user.id = Some(id.to_owned());
        let mut meta = existing
            .meta
            .clone()
            .unwrap_or_else(|| Meta::new("User", &ts, format!("/scim/v2/Users/{id}")));
        meta.touch(&ts);
        user.meta = Some(meta);
        tenant_users.insert(id.to_owned(), user.clone());
        Ok(user)
    }

    async fn delete_user(&self, tenant_id: &str, id: &str) -> Result<(), ScimError> {
        let mut guard = self.locked_users();
        let tenant_users = guard.get_mut(tenant_id).ok_or(ScimError::NotFound)?;
        let Some(user) = tenant_users.get_mut(id) else {
            return Err(ScimError::NotFound);
        };
        // SCIM deprovisioning convention: flip `active = false` rather than
        // hard-delete so audit trails survive.
        user.active = false;
        let (_, ts) = self.next_id_and_ts();
        if let Some(meta) = user.meta.as_mut() {
            meta.touch(&ts);
        }
        Ok(())
    }

    async fn list_users(
        &self,
        tenant_id: &str,
        query: ListUsersQuery,
    ) -> Result<ListUsersResult, ScimError> {
        let guard = self.locked_users();
        let rows: Vec<ScimUser> = guard
            .get(tenant_id)
            .map(|m| m.values().cloned().collect())
            .unwrap_or_default();
        let filtered = apply_user_filter(rows, query.filter.as_deref())?;
        let total = filtered.len();
        let (start, count) = pagination(query.start_index, query.count, total);
        let resources: Vec<ScimUser> = filtered.into_iter().skip(start - 1).take(count).collect();
        Ok(ListUsersResult {
            total_results: total,
            start_index: start,
            items_per_page: resources.len(),
            resources,
        })
    }

    async fn create_group(
        &self,
        tenant_id: &str,
        mut group: ScimGroup,
    ) -> Result<ScimGroup, ScimError> {
        group.validate().map_err(ScimError::invalid_request)?;
        let mut guard = self.locked_groups();
        let tenant_groups = guard.entry(tenant_id.to_owned()).or_default();
        if tenant_groups
            .values()
            .any(|g| g.display_name.eq_ignore_ascii_case(&group.display_name))
        {
            return Err(ScimError::conflict("displayName already exists"));
        }
        let (id, ts) = self.next_id_and_ts();
        group.id = Some(id.clone());
        group.meta = Some(Meta::new("Group", &ts, format!("/scim/v2/Groups/{id}")));
        tenant_groups.insert(id, group.clone());
        Ok(group)
    }

    async fn get_group(&self, tenant_id: &str, id: &str) -> Result<ScimGroup, ScimError> {
        let guard = self.locked_groups();
        guard
            .get(tenant_id)
            .and_then(|m| m.get(id))
            .cloned()
            .ok_or(ScimError::NotFound)
    }

    async fn list_groups(
        &self,
        tenant_id: &str,
        query: ListUsersQuery,
    ) -> Result<ListGroupsResult, ScimError> {
        let guard = self.locked_groups();
        let rows: Vec<ScimGroup> = guard
            .get(tenant_id)
            .map(|m| m.values().cloned().collect())
            .unwrap_or_default();
        let filtered = apply_group_filter(rows, query.filter.as_deref())?;
        let total = filtered.len();
        let (start, count) = pagination(query.start_index, query.count, total);
        let resources: Vec<ScimGroup> = filtered.into_iter().skip(start - 1).take(count).collect();
        Ok(ListGroupsResult {
            total_results: total,
            start_index: start,
            items_per_page: resources.len(),
            resources,
        })
    }
}

fn pagination(start_index: Option<usize>, count: Option<usize>, total: usize) -> (usize, usize) {
    // RFC 7644 §3.4.2: `startIndex` is 1-based. Out-of-range start → empty
    // page (but `startIndex` echoed back must clamp to total+1 for clarity).
    let start = start_index.unwrap_or(1).max(1);
    let start = if start > total { total + 1 } else { start };
    let count = count.unwrap_or(100).min(1_000);
    (start, count)
}

fn apply_user_filter(
    rows: Vec<ScimUser>,
    filter: Option<&str>,
) -> Result<Vec<ScimUser>, ScimError> {
    let Some(raw) = filter else {
        let mut sorted = rows;
        sorted.sort_by(|a, b| a.user_name.cmp(&b.user_name));
        return Ok(sorted);
    };
    let ast: Filter = parse_filter(raw)?;
    let mut kept: Vec<ScimUser> = rows
        .into_iter()
        .filter(|u| {
            let v = serde_json::to_value(u).unwrap_or(serde_json::Value::Null);
            ast.matches(&v)
        })
        .collect();
    kept.sort_by(|a, b| a.user_name.cmp(&b.user_name));
    Ok(kept)
}

fn apply_group_filter(
    rows: Vec<ScimGroup>,
    filter: Option<&str>,
) -> Result<Vec<ScimGroup>, ScimError> {
    let Some(raw) = filter else {
        let mut sorted = rows;
        sorted.sort_by(|a, b| a.display_name.cmp(&b.display_name));
        return Ok(sorted);
    };
    let ast: Filter = parse_filter(raw)?;
    let mut kept: Vec<ScimGroup> = rows
        .into_iter()
        .filter(|g| {
            let v = serde_json::to_value(g).unwrap_or(serde_json::Value::Null);
            ast.matches(&v)
        })
        .collect();
    kept.sort_by(|a, b| a.display_name.cmp(&b.display_name));
    Ok(kept)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
#[allow(clippy::expect_used)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn provisioner_with_clock() -> InMemoryScimProvisioner {
        let p = InMemoryScimProvisioner::new();
        let counter = std::sync::Arc::new(std::sync::Mutex::new(0u64));
        p.set_clock(move || {
            let mut n = counter.lock().unwrap();
            *n += 1;
            (format!("id-{n:04}"), "2026-06-12T00:00:00Z".to_owned())
        });
        p
    }

    #[tokio::test]
    async fn create_then_get_user_round_trips() {
        let p = provisioner_with_clock();
        let u = ScimUser::new("alice");
        let created = p.create_user("t1", u).await.unwrap();
        assert_eq!(created.id.as_deref(), Some("id-0001"));
        let got = p.get_user("t1", "id-0001").await.unwrap();
        assert_eq!(got.user_name, "alice");
        assert!(got.meta.is_some());
    }

    #[tokio::test]
    async fn create_user_rejects_duplicate_user_name() {
        let p = provisioner_with_clock();
        p.create_user("t1", ScimUser::new("alice")).await.unwrap();
        let err = p
            .create_user("t1", ScimUser::new("ALICE"))
            .await
            .expect_err("dup");
        assert!(matches!(err, ScimError::Conflict(_)));
    }

    #[tokio::test]
    async fn create_user_tenant_isolated() {
        let p = provisioner_with_clock();
        p.create_user("t1", ScimUser::new("alice")).await.unwrap();
        // Same userName allowed in a different tenant.
        let r = p.create_user("t2", ScimUser::new("alice")).await;
        assert!(r.is_ok());
    }

    #[tokio::test]
    async fn delete_user_soft_deletes() {
        let p = provisioner_with_clock();
        p.create_user("t1", ScimUser::new("alice")).await.unwrap();
        p.delete_user("t1", "id-0001").await.unwrap();
        let got = p.get_user("t1", "id-0001").await.unwrap();
        assert!(!got.active);
    }

    #[tokio::test]
    async fn replace_user_updates_attrs_and_meta() {
        let p = provisioner_with_clock();
        p.create_user("t1", ScimUser::new("alice")).await.unwrap();
        let mut updated = ScimUser::new("alice");
        updated.display_name = Some("Alice Liddell".into());
        let r = p.replace_user("t1", "id-0001", updated).await.unwrap();
        assert_eq!(r.display_name.as_deref(), Some("Alice Liddell"));
        assert!(r.meta.is_some());
    }

    #[tokio::test]
    async fn list_users_applies_filter_and_paginates() {
        let p = provisioner_with_clock();
        p.create_user("t1", ScimUser::new("alice")).await.unwrap();
        p.create_user("t1", ScimUser::new("bob")).await.unwrap();
        p.create_user("t1", ScimUser::new("carol")).await.unwrap();
        let res = p
            .list_users(
                "t1",
                ListUsersQuery {
                    filter: Some(r#"userName sw "a""#.to_owned()),
                    start_index: None,
                    count: None,
                },
            )
            .await
            .unwrap();
        assert_eq!(res.total_results, 1);
        assert_eq!(res.resources[0].user_name, "alice");

        let res = p
            .list_users(
                "t1",
                ListUsersQuery {
                    filter: None,
                    start_index: Some(2),
                    count: Some(1),
                },
            )
            .await
            .unwrap();
        assert_eq!(res.total_results, 3);
        assert_eq!(res.items_per_page, 1);
        assert_eq!(res.resources[0].user_name, "bob");
    }

    #[tokio::test]
    async fn create_group_then_get_round_trips() {
        let p = provisioner_with_clock();
        let g = ScimGroup::new("engineers");
        let created = p.create_group("t1", g).await.unwrap();
        assert!(created.id.is_some());
        let got = p
            .get_group("t1", created.id.as_deref().unwrap())
            .await
            .unwrap();
        assert_eq!(got.display_name, "engineers");
    }

    #[tokio::test]
    async fn list_groups_filters_by_display_name() {
        let p = provisioner_with_clock();
        p.create_group("t1", ScimGroup::new("engineers"))
            .await
            .unwrap();
        p.create_group("t1", ScimGroup::new("operations"))
            .await
            .unwrap();
        let res = p
            .list_groups(
                "t1",
                ListUsersQuery {
                    filter: Some(r#"displayName co "engin""#.to_owned()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        // Only `engineers` contains the substring `engin`.
        assert_eq!(res.total_results, 1);
        assert_eq!(res.resources[0].display_name, "engineers");
    }

    #[tokio::test]
    async fn get_user_404s_for_unknown_tenant() {
        let p = provisioner_with_clock();
        let err = p.get_user("t1", "nope").await.expect_err("not found");
        assert!(matches!(err, ScimError::NotFound));
    }

    #[tokio::test]
    async fn delete_user_404s_for_unknown_id() {
        let p = provisioner_with_clock();
        p.create_user("t1", ScimUser::new("alice")).await.unwrap();
        let err = p.delete_user("t1", "nope").await.expect_err("not found");
        assert!(matches!(err, ScimError::NotFound));
    }
}
