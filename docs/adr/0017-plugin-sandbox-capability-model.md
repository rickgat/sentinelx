# ADR 0017 — Plugin sandbox capability model: capability-scoped host functions, HMAC-signed webhooks, no WASM in MVP

Status: Accepted
Date: 2026-06-12
Deciders: Principal Platform Engineer, Principal Security Engineer, CTO
Supersedes: None
Superseded by: None

## Context

Customers and partners want to ship custom SentinelX integrations:
a custom SOAR action, a custom log normaliser, a custom enrichment
function. The naive option ("compile your code into the SentinelX
monolith and we'll redeploy") doesn't scale beyond a handful of
launch partners.

We need a plugin host that:

- runs untrusted code with **least privilege** (no filesystem
  access, no network access, no ambient capability);
- exposes the platform's data only through **explicit capabilities**
  the plugin must request and the tenant must grant;
- carries the existing audit and tenant-isolation guarantees into
  the plugin's data accesses;
- has an operational story that doesn't blow up the deploy.

WASM sandboxes (Wasmtime, Wasmer) are the canonical answer in
2026; they're well-suited to this problem on paper. The cost is
non-trivial: the platform's data interface must be re-projected
into the WASM ABI, every host function must be re-typed for the
WASM memory model, and the test surface doubles. For the MVP,
shipping a WASM host is more engineering than we're prepared to
spend.

## Decision

### MVP shape: HMAC-signed webhook plugins, no WASM

A plugin in the MVP is **an HTTP endpoint** the customer hosts.
The platform sends a JSON payload to the endpoint, the plugin
responds with a JSON payload, and the platform consumes the
response. The plugin is wholly out-of-process — no in-process code
execution.

The plugin host:

1. signs every outgoing request with HMAC-SHA-256 keyed on a
   per-plugin secret minted at registration time;
2. includes a structured `X-SentinelX-Capabilities` header listing
   the capabilities the plugin is invoking under (the platform
   refuses to send data the plugin hasn't been granted to read);
3. verifies the plugin's HMAC on the inbound response (replay
   protection via a per-request nonce + 5-min skew window);
4. enforces a 30 s response budget and 256 KB response size cap.

### Capability scoping

Every plugin manifest declares the capabilities it needs:

```yaml
plugin: my-soar-action
version: 1.2.3
capabilities:
  - data.read: [findings, assets]
  - data.write: [audit_event]
  - action.invoke: [okta.deactivate_user]
  - net.egress: ["okta.com", "*.okta.com"]
```

The capabilities form an allow-list. The plugin host:

- refuses to send `data.read` payloads for any table not on the
  list;
- refuses to honour a `data.write` response from a plugin whose
  manifest doesn't include the write target;
- refuses to allow `action.invoke` for actions not on the list
  (a SOAR workflow that references a forbidden action errors at
  save time);
- the `net.egress` capability is informational at the host (we
  don't control the plugin's outbound network) — it surfaces on
  the dashboard so the tenant admin sees what hosts the plugin
  intends to contact before granting consent.

The tenant admin reviews and explicitly grants capabilities at
plugin install time. The grant lands as a signed audit-event row
naming the user and the capability set.

### Tenant context propagation

Every outgoing webhook carries `X-SentinelX-Tenant-Id` in the
header (signed in the HMAC). The plugin's response is processed
under that tenant's context — RLS predicates on every downstream
DB write key on the tenant id, so a buggy plugin that returns
data attributed to the wrong tenant has its write rejected by
Postgres RLS.

### Replay / man-in-the-middle defence

- TLS 1.3 only; the plugin endpoint MUST present a cert that
  matches the configured DNS name. The tenant admin can pin a
  specific cert fingerprint per plugin.
- HMAC over `(method, path, body, X-SentinelX-Tenant-Id, X-Nonce,
  X-Timestamp)`. The nonce is a UUIDv7 and the timestamp is
  refused outside ±5 min.
- The per-plugin HMAC secret is rotated by the tenant admin.
  Compromise of a secret is contained to one plugin.

### Why no WASM in MVP

WASM sandboxes are the technically superior answer for in-process,
high-throughput plugins. We are explicit that the MVP defers
in-process execution to a follow-up release because:

- The platform's data interface (Postgres + Neo4j + ClickHouse)
  re-projection into a WASM ABI is a ~6-month engineering effort
  in its own right.
- The risk surface of running customer WASM in-process (memory
  safety, side channels, host-function exposure) is non-trivial
  and warrants a dedicated review.
- The webhook model covers ~90 % of the launch-partner use cases
  (custom SOAR action, custom enrichment) at a fraction of the
  engineering cost.

A future ADR will revisit WASM. The capability model defined here
is forward-compatible: the same capability declarations would
gate WASM host functions.

### Plugin registration

A plugin manifest is registered through
`POST /v1/plugins/{tenant}/install` with:

- the manifest YAML (capabilities + version + endpoint URL);
- the plugin's public webhook URL;
- the HMAC secret (generated at install, returned once).

The registration writes an audit-event row, mints the HMAC secret,
and the plugin is invocable thereafter. Revocation deletes the
manifest row and rotates the HMAC secret to a value the platform
never reveals — effectively killing the plugin.

## Consequences

- **Customer plugins are out-of-process.** Customers host their
  own plugins; the platform doesn't run customer code on our
  infrastructure.
- **Capability auditability is explicit.** Every plugin's grants
  are an audit-event trail; an external auditor can answer
  "what data could plugin P read for tenant T at time X".
- **Latency cost.** A webhook round-trip is ~50–200 ms vs. ~ms
  for an in-process call. SOAR workflows that depend on plugin
  actions inherit the latency.
- **Plugin reliability is the customer's responsibility.** The
  platform retries on timeout (per the SOAR retry policy) but a
  consistently failing plugin is a customer-side problem.
- **The capability vocabulary is forward-compatible with WASM.**
  When we ship WASM, the same capabilities gate host functions.

## Alternatives Considered

- **Ship WASM in MVP.** Rejected — engineering cost vs. coverage
  of the launch-partner use cases.
- **Allow loading native shared libraries.** Hard rejected — no
  sandbox, no audit trail, breaks the security model.
- **Run plugins as separate processes on our infra (e.g. per-
  tenant container).** Rejected — operational complexity per
  plugin × per tenant.
- **No plugin system; every integration is a built-in.** Rejected
  — limits the partner ecosystem and forces every customer-
  specific integration into our release cycle.
