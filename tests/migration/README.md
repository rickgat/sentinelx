# Migration parity test suite

Two bash scripts that exercise the production storage path against real
Postgres, both runnable from the workspace root:

| Script | Asserts | Runtime |
| --- | --- | --- |
| `parity_check.sh` | Schema after forward-only migration is byte-identical to schema after a down/up round-trip (or, in forward-only mode, that all migrations apply cleanly to a fresh DB). | ~30 s |
| `seed_parity.sh` | The bootstrap admin + demo-data seed path inside `services/sx-monolith` is idempotent on a real Postgres — re-booting with `BOOTSTRAP__ENABLED=false` produces the same `pg_dump --data-only` as the seeded boot. Verifies M2 against PG (the in-memory equivalent already passes in `seed_gate_and_pg_masking.rs`). | ~90 s |

## Why bash + docker, not docker-compose

Portability — these run on a CI runner with only `docker` + `bash`
present. No compose file means no version skew on the compose CLI
across runners, and no implicit network state to debug.

## Tested against

- Postgres 16-alpine (default `PG_IMAGE`).
- The migration set under `crates/sx-storage/migrations` (20 files at
  the time of writing — all forward-only, no `.down.sql`).
- The `sx-monolith` binary built with the workspace toolchain.

## Forward-only policy

`crates/sx-storage/migrations` is forward-only by policy
(`docs/RDBMS.md:1972` — `sqlx migrate add … → sqlx migrate run`).
`parity_check.sh` handles this gracefully:

- No `.down.sql` files found → the script records "forward-only mode"
  and exits 0 after a single clean apply.
- If down migrations are added later, the script automatically picks
  them up and performs the full down/up parity diff.

## Quick run

```bash
# Schema parity:
./tests/migration/parity_check.sh

# Seed idempotency (requires sx-monolith built):
cargo build --bin sx-monolith
./tests/migration/seed_parity.sh
```

## Exit codes

Both scripts use the same convention:

| Code | Meaning |
| --- | --- |
| 0 | Parity verified |
| 1 | Prereq missing (docker / sqlx / build artefact) |
| 2 | Migration / monolith boot failure |
| 3 | `pg_dump` failure |
| 4 | Parity diff non-empty (regression) |
