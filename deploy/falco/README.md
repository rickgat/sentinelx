# Falco runtime detection for SentinelX

Falco runs as a DaemonSet (eBPF driver) on every worker node and watches for
suspicious activity within the `sx-monolith` container. Rules are tuned to the
SentinelX threat model documented in `docs/TRD.md` §6.1.

## Apply

Falco is installed via the upstream Helm chart with this overlay:

```
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm upgrade --install falco falcosecurity/falco \
  -n falco --create-namespace \
  -f values.yaml \
  --set-file customRules.sentinelx_runtime_rules\\.yaml=rules/sentinelx_runtime_rules.yaml
```

Rule updates do not require a Falco restart (they're hot-reloaded by the
Falco watcher). See `docs/operations/gitops.md#falco-rules-hot-reload`.

## Rule catalog

| Rule | Priority | Tag |
| ---- | -------- | --- |
| Unexpected shell in sx-monolith pod | CRITICAL | container, process |
| Outbound to non-allowlisted egress from monolith | WARNING | network, egress |
| Write to sensitive path | CRITICAL | filesystem, persistence |
| K8s API call from monolith pod | NOTICE | k8s, lateral_movement |

## Egress allowlist

| Service | CIDR | Notes |
| ------- | ---- | ----- |
| postgres | `10.40.0.0/24` | Internal RDS subnet |
| redis | `10.40.1.0/24` | Internal ElastiCache subnet |
| otel-collector | `10.40.2.0/24` | In-cluster service CIDR |
| NVD | `23.185.0.0/21` | services.nvd.nist.gov |
| FIRST.org EPSS | `185.85.16.0/22` | api.first.org |
| CISA KEV | `13.32.0.0/15` | cisa.gov CDN |

These CIDRs are placeholders. Replace with actual CIDRs from your VPC + IP
intel feed before going to prod. Override via the `sentinelx_egress_allowlist`
list at the top of `rules/sentinelx_runtime_rules.yaml`.
