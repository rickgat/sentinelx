# ADR 0002 — Zero hardcoded operational values

Status: Accepted
Date: 2026-05-29

## Context
SentinelX scans customer infrastructure. Any hardcoded URL, port, threshold
or weight is a bug waiting to happen — and a probable security issue when
it survives into production.

## Decision
- All operational values flow through `sx-config`. Defaults are never
  silently applied: a missing required value returns
  `ConfigError::MissingValue { key }`.
- `clippy.toml` bans `std::env::var` and `std::println` so configuration
  cannot be parsed ad hoc.
- Risk weights, severity bands, denylist patterns, scanner timeouts and
  rate limits are all expressed as configuration types.

## Consequences
- Operators must supply a real configuration file or environment.
- Tests configure deterministic values explicitly and never depend on
  production defaults.
- Behaviour is auditable: every value is traceable to a config key.
