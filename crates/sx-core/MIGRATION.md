# sx-core consolidation migration map

This document is the authoritative pointer from each sibling crate's **local
stub** for a canonical domain type to the **canonical** path now exposed by
`sx-core`. The stubs were introduced so each crate could compile and test in
isolation while `sx-core` was being scaffolded; they are now redundant.

## Why a migration document

A future turn will edit each sibling stub file to be a `pub use sx_core::…`
re-export (no behaviour change). This document tells future agents:

1. Which stub maps to which canonical path.
2. Which canonical paths are new (added in this pass).
3. The repeatable recipe for performing the re-export swap.

The current pass is **additive-only**: no sibling stubs were removed, no
existing `sx-core` types were renamed, no signatures changed.

## Canonical path table

### `sx-iam::domain` stubs

| Sibling stub | Canonical sx-core path |
| --- | --- |
| `sx_iam::domain::TenantId` | `sx_core::value_object::ids::TenantId` |
| `sx_iam::domain::UserId` | `sx_core::value_object::ids::UserId` |
| `sx_iam::domain::RoleId` | `sx_core::value_object::ids::RoleId` |
| `sx_iam::domain::Permission` | `sx_core::entity::permission::Permission` |
| `sx_iam::domain::Role` | `sx_core::entity::role::Role` |
| `sx_iam::domain::User` | `sx_core::entity::user::User` |

Notes:
- `Permission` parsing differs slightly: the sibling stub's `Permission::parse(&str)`
  is equivalent to `sx_core::entity::permission::Permission::from_str` (the
  canonical type implements `FromStr`).
- `User` in `sx-core` has a `display_name` field and `status: UserStatus`
  instead of `(is_active, password_hash, roles)`. The IAM crate's view of a
  user with auth secrets and role list will likely live in an IAM-specific
  projection rather than `sx_core::entity::user::User`.

### `sx-engagement::model` stubs

| Sibling stub | Canonical sx-core path |
| --- | --- |
| `sx_engagement::model::engagement::Engagement` | `sx_core::entity::engagement::Engagement` |
| `sx_engagement::model::engagement::EngagementStatus` | `sx_core::entity::engagement::EngagementStatus` |
| `sx_engagement::model::engagement::EngagementApproval` | `sx_core::entity::engagement::EngagementApproval` |
| `sx_engagement::model::scope_target::ScopeTarget` | `sx_core::value_object::scope::ScopeTarget` |
| `sx_engagement::model::intensity::ScanIntensity` | `sx_core::value_object::intensity::ScanIntensity` |
| `sx_engagement::model::window::TimeWindow` | `sx_core::value_object::time_window::TimeWindow` |
| `sx_engagement::port::EngagementRepository` | `sx_core::port::engagement_repository::EngagementRepository` |
| `sx_engagement::service::kill_switch::KillSwitchScope` | `sx_core::port::kill_switch::KillSwitchScope` |
| `sx_engagement::service::kill_switch::KillSwitch` (trait) | `sx_core::port::kill_switch::KillSwitchPort` |

Notes:
- `ScopeTarget` now has all the variants needed by the engagement crate
  (`Cidr`, `IpV4`, `IpV6`, `Domain(Fqdn)`, `Url`, `Arn`, `RepoUrl`, plus the
  new free-form `RepoUrlStr`). The canonical scope-match algorithm is exposed
  as the inherent method `ScopeTarget::matches(&self, other: &Self) -> bool`.
- `EngagementApproval` retains its existing constructor `new(approver, at,
  note)`. The sibling crate's signature is provided as
  `EngagementApproval::with_timestamp(approver, approved_at)`.
- `Engagement::new_draft(id, tenant_id, name, scope, window, max_intensity, now)`
  is the canonical constructor that mirrors the engagement crate; the older
  `Engagement::new(...)` is retained.
- `Engagement::try_transition(next, now)` is the canonical FSM-only
  transition (no approval / window guards); the older `transition(...)` keeps
  those guards. Use whichever fits the call site.
- `KillSwitchPort` is the canonical port trait. The engagement crate also
  exposes `KillReason`, `KillSwitchEvent`, and broadcast subscribers — those
  are runtime concerns and stay in the engagement crate; sx-core only owns
  the contract `is_tripped` / `trip`.

### `sx-discovery::contracts` stubs

| Sibling stub | Canonical sx-core path |
| --- | --- |
| `sx_discovery::contracts::TenantId` | `sx_core::value_object::ids::TenantId` |
| `sx_discovery::contracts::EngagementId` | `sx_core::value_object::ids::EngagementId` |
| `sx_discovery::contracts::AssetId` | `sx_core::value_object::ids::AssetId` |
| `sx_discovery::contracts::Fqdn` | `sx_core::value_object::fqdn::Fqdn` |
| `sx_discovery::contracts::ScopeTarget` | `sx_core::value_object::scope::ScopeTarget` |
| `sx_discovery::contracts::ScanIntensity` | `sx_core::value_object::intensity::ScanIntensity` |
| `sx_discovery::contracts::KillSwitchScope` | `sx_core::port::kill_switch::KillSwitchScope` |
| `sx_discovery::contracts::KillSwitch` (trait) | `sx_core::port::kill_switch::KillSwitchPort` |
| `sx_discovery::contracts::Engagement` (shim) | `sx_core::entity::engagement::Engagement` (use canonical aggregate; map `allowed_scope` to `scope`) |
| `sx_discovery::contracts::ScopeValidator` | stays local to `sx-discovery`; not a canonical sx-core port |
| `sx_discovery::contracts::ScanRequest` | stays local to `sx-discovery`; runtime DTO |
| `sx_discovery::contracts::InMemoryScopeValidator` / `InMemoryKillSwitch` | stay local — they are test/in-process implementations of the trait |

Notes:
- Discovery's local `ScanIntensity` has variants `Passive | Light | Standard
  | Aggressive`. These map onto canonical `ScanIntensity` as:
  - `Passive → PassiveValidation`
  - `Light → SafeInteractive`
  - `Standard → ActiveExploit`
  - `Aggressive → RedTeam`
  (mirroring `ProbeIntensity` ↔ `ScanIntensity` in `sx_core::entity::engagement`).
- Discovery's `KillSwitchScope` variant `Engagement(EngagementId)` does NOT
  carry a `TenantId`. The canonical form is `Engagement(TenantId, EngagementId)`.
  Migration callers will need to supply the missing tenant id at the call
  site.

### `sx-storage::domain` stubs

| Sibling stub | Canonical sx-core path |
| --- | --- |
| `sx_storage::domain::value_object::{TenantId,UserId,EngagementId,AssetId,FindingId,CveId}` | `sx_core::value_object::ids::*` |
| `sx_storage::domain::value_object::{Page,PagedResult}` | `sx_core::value_object::page::{Page, PagedResult}` |
| `sx_storage::domain::entity::{Tenant,User,Engagement,Asset,Finding,Cve}` | `sx_core::entity::{tenant::Tenant, user::User, engagement::Engagement, asset::Asset, finding::Finding, cve::Cve}` |
| `sx_storage::domain::port::TenantRepository` | `sx_core::port::tenant_repository::TenantRepository` |
| `sx_storage::domain::port::UserRepository` | `sx_core::port::user_repository::UserRepository` |
| `sx_storage::domain::port::EngagementRepository` | `sx_core::port::engagement_repository::EngagementRepository` |
| `sx_storage::domain::port::AssetRepository` | `sx_core::port::asset_repository::AssetRepository` |
| `sx_storage::domain::port::FindingRepository` | `sx_core::port::finding_repository::FindingRepository` |
| `sx_storage::domain::port::CveRepository` | `sx_core::port::cve_repository::CveRepository` |
| `sx_storage::domain::error::DomainError` | `sx_core::DomainError` |

Notes:
- The storage mirror models entities as flat data-bag structs (e.g. `Engagement::scope: JsonValue`),
  whereas the canonical types carry validated invariants. The storage repository
  adapters will need a thin row→entity translation layer when they switch to
  the canonical types; that is a follow-up turn's job, not this one's.
- The storage port traits expose `save(...)` whereas the canonical sibling
  ports use `create(...) + update(...)`. The `EngagementRepository::update`
  default has been added to `sx-core` to give adapters a single entry point.

## What was added to sx-core in this turn

- `value_object::intensity::ScanIntensity` — new module; canonical totally-ordered ladder.
- `value_object::time_window::TimeWindow` — new module; canonical validated `[start, end]`.
- `value_object::scope::ScopeTarget` — new variants `IpV4`, `IpV6`, `RepoUrlStr`.
- `value_object::scope::ScopeTarget::matches(&Self) -> bool` — canonical
  scope/match algorithm (CIDR containment, IP-in-CIDR, domain wildcard,
  URL host+prefix, ARN regex, repo-url exact).
- `value_object::scope::ScopeTarget::domain_pattern(&str)` — wildcard-aware
  domain constructor.
- `value_object::scope::ScopeTarget::kind_label()` — tracing-friendly label.
- `value_object::fqdn::Fqdn::new_wildcard(&str)` — leading-`*.` Fqdn form.
- `value_object::fqdn::Fqdn::is_wildcard()` — predicate.
- `entity::engagement::EngagementApproval::with_timestamp(approver, approved_at)`
  — canonical sibling-crate constructor.
- `entity::engagement::EngagementApproval::approved_at()` — alias.
- `entity::engagement::Engagement::new_draft(...)` — canonical aggregate constructor.
- `entity::engagement::Engagement::try_transition(next, now)` — FSM-only transition.
- `entity::engagement::Engagement::unique_approver_count()` — dedup count.
- `entity::engagement::Engagement::scan_intensity()` — canonical-typed accessor.
- `entity::engagement::Engagement::window()` — canonical-typed accessor.
- `port::engagement_repository::EngagementRepository::update(&Engagement)` —
  default impl over `update_status` + `add_approval`.
- `port::cve_repository::CveRepository::list_recent_n(limit)` — default impl.
- `port::kill_switch::KillSwitchPort` — new trait + `KillSwitchScope`.

## Migration recipe

For each sibling crate, perform the following (one PR per crate keeps the
review tractable):

1. **Edit the local stub file** to be a thin re-export. For example,
   `crates/sx-iam/src/domain.rs` should become:
   ```rust
   //! Canonical domain types are owned by `sx-core`. This module re-exports
   //! them so call sites in `sx-iam` keep their existing import paths.
   pub use sx_core::entity::permission::Permission;
   pub use sx_core::entity::role::Role;
   pub use sx_core::entity::user::User;
   pub use sx_core::value_object::ids::{RoleId, TenantId, UserId};
   ```
   (and similar for each sibling).

2. **Update the sibling crate's tests** to match any minor API differences
   (e.g. canonical `Permission::from_str` instead of `Permission::parse`,
   canonical `User { display_name, status, … }` instead of
   `{ password_hash, is_active, roles, … }`). Where a sibling needs richer
   per-crate state (e.g. IAM's `password_hash`), introduce a sibling-local
   projection struct that *contains* the canonical type rather than
   duplicating it.

3. **Bump `Cargo.toml`** if the sibling did not already depend on `sx-core`.
   All four sibling crates above already do, so no Cargo work is expected.

4. **Run** `cargo fmt -p <sibling> && cargo clippy -p <sibling> --all-targets
   -- -D warnings && cargo test -p <sibling>` to confirm the swap is clean.

5. **Workspace check**: `cargo check --workspace` should remain green for
   every crate that previously compiled (pre-existing failures in
   `services/sx-monolith` are unrelated and out of scope).

## Out-of-scope follow-ups

- Removing the canonical `ProbeIntensity` enum in favour of `ScanIntensity`
  (would be a breaking change; do it once every sibling has migrated).
- Folding the `Url`-typed `ScopeTarget::RepoUrl` into the new `RepoUrlStr`
  string form (or vice-versa) once persisted state has been re-projected.
- Promoting the engagement crate's `KillReason` / `KillSwitchEvent` /
  `subscribe` API into `sx-core` if/when other crates need to observe trip
  events.
