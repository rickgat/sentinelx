# sx-iam → sx-core consolidation notes

## 2026-05-30 — `TenantId`, `UserId`, `RoleId` re-exported from `sx-core`

### What migrated this turn

The three identifier newtypes that used to live in
`crates/sx-iam/src/domain.rs` as local stubs are now re-exported from
`sx_core::value_object::ids`:

```rust
pub use sx_core::value_object::ids::{RoleId, TenantId, UserId};
```

The local `struct TenantId(Uuid); impl TenantId { fn new(); fn
from_uuid(); fn as_uuid(); … }` blocks are gone, along with their
`Default`, `Display`, and `Serialize/Deserialize(transparent)` impls —
the canonical sx-core macro generates the exact same set of items plus
a strict superset (`FromStr`, `From<Uuid>`, `Into<Uuid>`, `into_uuid`,
`entity_name`). Existing call-sites compile unchanged because they
only ever touched the subset.

### Why these and not `Permission` / `Role` / `User`

The canonical sx-core `entity::permission::Permission`,
`entity::role::Role`, and `entity::user::User` carry additional fields
that sx-iam does not yet need (and would force a wider migration to
introduce):

* `sx_core::entity::user::User` adds `created_at` / `updated_at` /
  account-lifecycle status flags that sx-iam's auth flows do not
  currently load.
* `sx_core::entity::role::Role` has a richer permission representation
  (typed `Permission` set rather than a `Vec`) tied to the
  permission-grant audit log.
* `sx_core::entity::permission::Permission` is parsed from the same
  `resource:action` grammar but exposes a different constructor surface
  (`Permission::grant(...)`) that the local sx-iam `parse(...)` helper
  does not.

Swapping these out today would require sx-iam controllers to populate
the extra fields with sentinel values and would push the type-shape
change into every storage adapter that returns a `User` to sx-iam.
That ripple belongs on its own turn — see *Next migration target*
below.

### Verification

Run from the repo root:

```bash
cargo check -p sx-iam
cargo clippy -p sx-iam --all-targets --no-deps -- -D warnings
cargo test  -p sx-iam
```

Result of the run made on 2026-05-30:

* `cargo check -p sx-iam` — clean (`Finished dev profile`, no errors).
* `cargo clippy -p sx-iam --all-targets --no-deps -- -D warnings` —
  clean.
* `cargo test  -p sx-iam` — **59 tests passed**, 0 failed. The
  domain-level tests
  (`permission_parse_round_trip`,
  `permission_parse_invalid_string_errors`,
  `user_permissions_flatten_and_dedupe`) and all controller / service
  / model / view test modules stayed green.

### Next migration target

1. **`User`** — the largest hot spot. Used in eight files across
   sx-iam's `controller/`, `port/`, `model/`, and `service/` layers.
   The blocker is the extra `created_at` / `updated_at` /
   account-state fields on `sx_core::entity::user::User`; sx-iam will
   need to either thread those through the storage adapter or accept a
   reduced `UserView` projection.
2. **`Role`** — paired with `User` (transitive). The richer
   permission-set representation lands at the same time as the `User`
   swap.
3. **`Permission`** — last, because its parser is deeply embedded in
   the RBAC engine tests; the sx-core API surface differs more than
   the id newtypes did, so the swap is mechanical but noisy.
