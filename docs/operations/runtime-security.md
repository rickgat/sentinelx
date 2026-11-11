# SentinelX Runtime Security (P2-016)

> **Last reviewed:** 2026-06-13
> **Maintainer:** Detection Engineering (`detection-eng@sentinelx.example`)
> **Next review:** 2026-09-13 (quarterly)
> **Document owner:** Director of Detection Engineering
> **Classification:** Internal — Restricted

Runtime security is the second line of defence behind shift-left controls
(SBOM, signed images, OPA-Gatekeeper admission, K8s admission analyzer
P2-014). It catches behaviour that "looks fine on disk" but turns malicious
once running: a chmod inside a distroless pod, a shell that should not
exist, an outbound to a destination no SentinelX component ever talks to,
a service-account-token mount inside a pod that should not have one.

This document describes the runtime stack delivered by P2-016: Falco
emitting OCSF-normalised events into the `sx-runtime` HMAC-authenticated
webhook, correlated with the `sx-graph` K8s asset model, with golden
alert fixtures and a per-rule response playbook.

---

## 1. Stack overview

```
   tenant-scoped HMAC-SHA256 webhook keys
                  |
                  v
+------------------+        +-----------------------+        +---------------+
| Falco DS (eBPF)  | ---->  | sx-runtime ingestor   | ---->  | OCSF events   |
|  + Falcosidekick |        | (Axum POST handler)   |        | (ClickHouse + |
+------------------+        |  - HMAC verify        |        |  audit chain) |
                            |  - OCSF normalisation |        +---------------+
                            |  - tenant resolution  |
                            +-----------+-----------+
                                        |
                                        | correlate
                                        v
                            +-----------+-----------+
                            |  sx-graph K8s asset   |
                            |  model (pod, image,   |
                            |  service-account)     |
                            +-----------------------+
                                        |
                  +---------------------+---------------------+
                  v                     v                     v
              SIEM webhook          Slack #sx-runtime    OpenSearch (90d)
              (notice+)              (critical+)         (KQL hunting)
```

Two cooperating systems:

| Layer        | Tool      | Detects                                  | Source of truth                          |
|--------------|-----------|------------------------------------------|-------------------------------------------|
| Mesh / mTLS  | Linkerd   | Unauthenticated callers, bad routes      | `deploy/linkerd/*.yaml`                  |
| Host / pod   | Falco     | Filesystem, process, network anomalies   | `deploy/falco/rules/sentinelx_runtime_rules.yaml` |

The mesh enforces "who is allowed to talk to whom and on which routes";
Falco enforces "what is allowed to happen inside the pod once traffic is
admitted".

---

## 2. Install Falco + provision the tenant webhook key

### 2.1 Install Falco

```bash
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update

helm upgrade --install falco falcosecurity/falco \
  --namespace falco --create-namespace \
  --version 4.x \
  --set driver.kind=ebpf \
  --set tty=true \
  --set falcosidekick.enabled=true \
  --set falcosidekick.config.webhook.address=https://sentinelx.example/v1/runtime/falco \
  -f deploy/falco/falco-helm-values.yaml

kubectl -n falco rollout status ds/falco --timeout=5m
```

### 2.2 Provision the per-tenant webhook key

The webhook ingestor (`crates/sx-runtime/src/ingest`) authenticates every
event with HMAC-SHA256 over `(timestamp || body)` using the tenant's
webhook key. The key is stored encrypted in `sx-secrets`.

```bash
# 1. Generate the key.
NEW_KEY=$(openssl rand -base64 32)

# 2. Register it for the tenant.
sx-cli runtime falco rotate-webhook-key \
  --tenant 11111111-1111-1111-1111-111111111111 \
  --new-key "$NEW_KEY" \
  --grace-period 0   # first install — no prior key to keep

# 3. Push it into Falcosidekick.
kubectl -n falco patch secret falcosidekick-secrets \
  --type='json' \
  -p="[{\"op\":\"replace\",\"path\":\"/data/sentinelx-key\",\"value\":\"$(printf '%s' "$NEW_KEY" | base64)\"}]"

# 4. Restart Falcosidekick to pick the new key.
kubectl -n falco rollout restart deploy/falcosidekick
```

Falcosidekick must be configured to set:

```yaml
customHeaders: |-
  X-SentinelX-Tenant: <tenant-id>
  X-SentinelX-Timestamp: ${timestamp}
  X-SentinelX-Signature: hmac-sha256=${hmac}
```

The webhook adds `X-SentinelX-Timestamp` to the inputs of the HMAC so a
captured event cannot be replayed outside a 5-minute window.

### 2.3 Falco rule file

The SentinelX rule file is `deploy/falco/rules/sentinelx_runtime_rules.yaml`.
All rules reference the `sentinelx_workload_pod` macro so the pod selector
is defined once and reused.

| # | Rule                                              | Priority  | Tags                                                              |
|---|---------------------------------------------------|-----------|-------------------------------------------------------------------|
| 1 | SentinelX Sensitive Path Write Outside Monolith   | CRITICAL  | sentinelx, filesystem, integrity, audit, mitre_persistence, t1565 |
| 2 | SentinelX Unexpected Chmod Exec In Workload       | WARNING   | sentinelx, process, crypto, mitre_defense_evasion, t1222          |
| 3 | SentinelX Egress To Non-Allowlisted Destination   | WARNING   | sentinelx, network, egress, mitre_command_and_control, t1071      |
| 4 | SentinelX Unexpected Shell In Container           | CRITICAL  | sentinelx, container, process, mitre_execution, t1059             |
| 5 | SentinelX Secret Env Read From Foreign Process    | CRITICAL  | sentinelx, secrets, credential_access, mitre_t1552                |
| 6 | SentinelX Privileged Escalation Inside Container  | CRITICAL  | sentinelx, container, mitre_privilege_escalation, t1611            |
| 7 | SentinelX K8s Admin Token Mounted Where Forbidden | CRITICAL  | sentinelx, k8s, secrets, mitre_credential_access, t1552            |

---

## 3. HMAC-SHA256 verification flow

The webhook handler:

1. Reads `X-SentinelX-Tenant`, `X-SentinelX-Timestamp`, `X-SentinelX-Signature` headers.
2. Looks up the tenant's webhook key (or its grace-period predecessor)
   from `sx-secrets`.
3. Computes `hmac_sha256(key, timestamp || raw_body)`.
4. **Constant-time compare** against the value in the header.
5. Rejects timestamps outside `[now-5min, now+5min]`.
6. Emits `sx_runtime_falco_events_received_total{auth=<ok|bad_sig|bad_ts|unknown_tenant>}`.

Failed verification returns HTTP 401 with no body. Successful events
proceed to OCSF normalisation. A configurable predecessor-key window
(default 60 min) supports zero-downtime rotation.

Audit row contract:

| Inbound outcome     | `action`                                  | Severity  |
|---------------------|-------------------------------------------|-----------|
| Verified, accepted  | `runtime.falco_event_ingested`            | low       |
| Bad signature       | `runtime.falco_event_rejected_bad_sig`    | high      |
| Stale timestamp     | `runtime.falco_event_rejected_stale_ts`   | medium    |
| Unknown tenant      | `runtime.falco_event_rejected_unknown_tenant` | high  |

---

## 4. OCSF normalisation

Inbound Falco JSON is normalised to **OCSF 1.1** (Open Cybersecurity
Schema Framework) so the downstream pipeline (search, hunting, SOAR)
has a single shape regardless of source. The mapping lives in
`crates/sx-runtime/src/ocsf/mod.rs`.

Categorical mapping:

| OCSF class                  | OCSF UID  | Falco source                                        |
|-----------------------------|-----------|------------------------------------------------------|
| Process Activity            | `1007`    | `spawned_process`, `execve`                          |
| File System Activity        | `1001`    | `open`, `openat`, `rename`, `unlink` of sensitive paths |
| Network Activity            | `4001`    | `outbound` connections                                |
| Kernel Activity             | `1003`    | `mount`, `bpf`, `kmod`                                |
| Authentication              | `3002`    | secret env read events                                |
| Process Privilege Escalation| `1007.4`  | setuid, capability gain                               |

Field-level mapping (excerpt):

| OCSF field                | Falco source                                        |
|---------------------------|------------------------------------------------------|
| `time`                    | `evt.time`                                           |
| `actor.user.uid`          | `user.uid`                                           |
| `actor.user.name`         | `user.name`                                          |
| `actor.process.pid`       | `proc.pid`                                           |
| `actor.process.name`      | `proc.name`                                          |
| `actor.process.cmd_line`  | `proc.cmdline`                                       |
| `device.uid`              | `container.id`                                       |
| `device.name`             | `container.name`                                     |
| `device.image.name`       | `container.image.repository`                          |
| `device.image.tag`        | `container.image.tag`                                 |
| `cloud.account.uid`       | resolved from `X-SentinelX-Tenant`                    |
| `metadata.product.name`   | `"sentinelx-runtime"` (constant)                      |
| `enrichments[].type`      | `"k8s_asset"` if matched against `sx-graph`           |

Custom OCSF observables added by SentinelX:

```json
"observables": [
  { "type": "tenant_id",        "value": "11111111-..." },
  { "type": "k8s.namespace",    "value": "sentinelx" },
  { "type": "k8s.pod.name",     "value": "sx-monolith-7f6dd9-abc" },
  { "type": "k8s.service_account.name", "value": "sx-monolith" },
  { "type": "falco.rule",       "value": "SentinelX Unexpected Shell In Container" },
  { "type": "mitre.technique",  "value": "T1059" }
]
```

The OCSF payload is persisted into ClickHouse `events_ocsf` and a digest
of the same payload is recorded in the audit chain (`action =
runtime.falco_event_ingested`) so the event is tamper-evident even if a
hot-tier ClickHouse part is later corrupted.

---

## 5. Golden alert fixtures

Five canonical events are pinned in `crates/sx-runtime/tests/fixtures/`
and used both as snapshot tests for the OCSF normaliser **and** as the
manual smoke-test cases listed below. They exercise the highest-signal
rules end-to-end.

### 5.1 Privileged escalation inside container (Rule 6)

Synthetic trigger:

```bash
kubectl -n sentinelx debug -it deploy/sentinelx --image=busybox -- \
  sh -c 'capsh --gain=cap_sys_admin -- -c "id"'
```

Expected OCSF event:

```json
{
  "category_uid": 1, "class_uid": 1007, "type_uid": 100704,
  "activity_id": 4, "activity_name": "Privilege Escalation",
  "severity_id": 5, "severity": "Critical",
  "actor": { "process": { "name": "capsh", "cmd_line": "capsh --gain=cap_sys_admin -- -c id" } },
  "device": { "name": "sx-monolith-...", "image": { "tag": "v1.4.0" } },
  "observables": [
    { "type": "falco.rule",      "value": "SentinelX Privileged Escalation Inside Container" },
    { "type": "mitre.technique", "value": "T1611" }
  ]
}
```

### 5.2 Shell in container (Rule 4)

```bash
kubectl -n sentinelx exec -it deploy/sentinelx -- /bin/sh
```

`actor.process.name` resolves to `sh` or `bash`; rule fires within 2 s.

### 5.3 K8s admin token mount (Rule 7)

A pod manifest with `automountServiceAccountToken: true` AND a
ServiceAccount whose role bindings include cluster-admin is treated as
a critical finding.

```bash
kubectl -n sentinelx apply -f - <<'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: bad-pod
  namespace: sentinelx
spec:
  serviceAccountName: cluster-admin   # forbidden in sentinelx ns
  automountServiceAccountToken: true
  containers:
    - name: c
      image: busybox
      command: ["sleep","3600"]
EOF
```

Falco watches the `kube-audit` log via the K8s audit-log plugin and
emits the rule the moment the pod is admitted.

### 5.4 Egress to non-allowlisted destination (Rule 3)

```bash
kubectl -n sentinelx exec deploy/sentinelx -- \
  curl -sS https://example.invalid-not-in-allowlist
```

Rule fires; OCSF event includes `dst_endpoint.ip` and `dst_endpoint.domain`.

### 5.5 Secret env read from foreign process (Rule 5)

```bash
kubectl -n sentinelx debug -it deploy/sentinelx --image=busybox -- \
  sh -c 'cat /proc/1/environ | tr "\0" "\n" | grep JWT'
```

Rule fires; `actor.process.name = cat` and the OCSF observable
`mitre.technique = T1552`.

A clean run of the five fixtures plus the existing `runtime-security`
integration tests is the gate for a release that touches `sx-runtime`.

---

## 6. Correlation with sx-graph K8s asset model

When an event is normalised, the `enrichers::k8s_asset` enricher
queries `sx-graph` for the asset node matching:

`(tenant_id, k8s.namespace, k8s.pod.name)`

A hit attaches the following enrichment:

```json
"enrichments": [
  {
    "type": "k8s_asset",
    "data": {
      "asset_id":             "asset_01J...",
      "criticality":           "high",
      "owning_team":           "platform-eng",
      "blast_radius_neighbours": 14,
      "exposed_to_internet":    false,
      "mounts_secrets":         ["sentinelx-secrets"],
      "service_account_roles":  ["sx-monolith-sa"]
    }
  }
]
```

The `blast_radius_neighbours` value comes from the same graph traversal
used by P1-010 (cloud blast-radius), so a runtime alert on a high-blast
asset is automatically promoted to CRITICAL even if the underlying Falco
priority is only WARNING.

Operator query — show CRITICAL events on high-blast assets in the last
hour:

```bash
sx-cli hunt query --kql '
  events_ocsf
  | where time > now() - 1h
    and severity == "Critical"
    and enrichments.data.criticality == "high"
    and enrichments.data.blast_radius_neighbours >= 10
  | project time, device.name, observables[?type=="falco.rule"].value, enrichments.data.owning_team
'
```

---

## 7. Alert routing

Falco events leave the daemon over HTTP and land at the `sx-runtime`
ingestor. From there they fan out to three sinks:

| Sink         | Trigger threshold | Audience          | Purpose                                       |
|--------------|-------------------|-------------------|------------------------------------------------|
| SIEM webhook | `notice`          | Tier-2 / SOAR     | Authoritative event store; opens tickets       |
| Slack        | `critical`        | On-call (Tier-1)  | Synchronous page in `#sentinelx-runtime-alerts`|
| OpenSearch   | `notice`          | Threat hunting    | 90-day retention, KQL hunting, dashboards      |

Sustained `linkerd_authz_failures_total > 0` on `Server=sx-monolith-admin`
pages the same channel as Falco CRITICAL.

---

## 8. Response playbook

A common response shape regardless of which sensor fired:

1. **Acknowledge** the page in Slack (or SIEM ticket).
2. **Contain** — see per-rule actions below.
3. **Triage** — read the OCSF payload (full process tree, k8s labels,
   container image digest, sx-graph enrichments).
4. **Eradicate** — see per-rule actions below.
5. **Recover** — restart pod / rotate secret / redeploy.
6. **Lessons learned** — file a postmortem under
   `docs/runbooks/post-mortems/`.

### 8.1 Per-rule response

| Rule fired                                       | Contain                                                            | Eradicate                                                      |
|--------------------------------------------------|--------------------------------------------------------------------|----------------------------------------------------------------|
| Sensitive path write outside monolith            | `kubectl -n sentinelx cordon` node; preserve pod for forensics     | Restore `/opt/sentinelx/audit` from backup, rotate secrets     |
| Unexpected chmod +x in workload                  | None automatic; investigate first (may be a debug image)           | If unsanctioned: delete pod, scan image for embedded droppers  |
| Egress to non-allowlisted destination            | NetworkPolicy already drops it; investigate why pod tried          | Update allowlist if legit; otherwise treat as C2                |
| Unexpected shell in container                    | `kubectl -n sentinelx delete pod --grace-period=0 <pod>`           | Roll back to last known good image; `cosign verify`             |
| Secret env read from foreign process             | Same as shell: delete pod, kill the node session                   | Rotate JWT signing key + admin PHC immediately                  |
| Privileged escalation inside container           | `kubectl -n sentinelx delete pod` + cordon node                     | Image scan, capability audit, force-roll the workload          |
| K8s admin token mounted where forbidden          | `kubectl -n sentinelx delete pod`                                   | Revoke the ServiceAccount RoleBinding; open ADR for exception   |

For "secret env read" specifically, follow JWT rotation in
[`runbook.md`](./runbook.md#3-rotate-the-jwt-signing-key) and the admin
PHC rotation in the same file.

---

## 9. Tuning

- Falco rule changes are GitOps — edit
  `deploy/falco/rules/sentinelx_runtime_rules.yaml`, open a PR. The
  Falco watcher hot-reloads from the mounted ConfigMap within 60 s.
- The OCSF normaliser has snapshot tests in
  `crates/sx-runtime/tests/fixtures/`. Any rule change that mutates the
  emitted JSON requires a snapshot review.
- Egress allowlist (Rule 3) is the most frequently tuned. Update
  `sentinelx_egress_allowlist_cidrs` at the top of the rule file and
  document the rationale in the PR description.
- Webhook-key rotation is documented in
  [`runbook.md`](./runbook.md#6-rotate-the-falco-webhook-key-p2-016).

---

## 10. Verification

| Check                              | Command                                                                |
|------------------------------------|------------------------------------------------------------------------|
| Mesh is injected                   | `kubectl -n sentinelx get pod -o jsonpath='{.items[*].spec.containers[*].name}' \| grep linkerd-proxy` |
| Admin route is denied unauth       | `kubectl -n sentinelx run curl --rm -it --image=curlimages/curl -- curl -sv http://sx-monolith/v1/admin/users` (expect 403) |
| Falco daemonset is running         | `kubectl -n falco get ds falco`                                        |
| Falco rules loaded                 | `kubectl -n falco exec ds/falco -- falco --list \| grep -c SentinelX`  |
| Webhook auth is healthy            | `kubectl -n sentinelx logs deploy/sentinelx \| jq 'select(.target=="sx-runtime::ingest" and .auth=="ok")' \| wc -l` |
| Synthetic shell fires Rule 4       | `kubectl -n sentinelx exec -it deploy/sentinelx -- /bin/sh` (expect rule + alert) |
| Synthetic chmod fires Rule 2       | `kubectl -n sentinelx debug -it <pod> --image=busybox -- chmod +x /tmp/x` |
| Synthetic priv-esc fires Rule 6    | `kubectl -n sentinelx debug ... -- capsh --gain=cap_sys_admin -- -c id` |

A green run on all eight rows means the runtime layer is healthy.
Failures should be filed against this document.

---

## 11. Related documents

- [`runbook.md`](./runbook.md) — application-level operations: secret
  rotation, KEK rotation, kill-switch trip.
- [`gitops.md`](./gitops.md) — promotion + rollback flow.
- [`compliance-evidence.md`](./compliance-evidence.md) — how runtime
  alerts contribute to control evidence.
- [`../security/threat-model-stride.md`](../security/threat-model-stride.md) —
  the threat model the rules derive from (E-3, E-4).
- [`../runbooks/incident-response.md`](../runbooks/incident-response.md) —
  the IR playbook that consumes CRITICAL Falco events.
