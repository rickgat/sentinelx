# SentinelX Helm Chart

Deploys the `sx-monolith` service plus optional supporting resources
(NetworkPolicy, PodDisruptionBudget, ServiceMonitor, Ingress, one-shot
migration Job).

## Quick install

```bash
helm upgrade --install sentinelx deploy/helm/sentinelx \
  --namespace sentinelx --create-namespace \
  -f my-values.yaml
```

Copy `values.example.yaml` to a working file, override the fields flagged
`MUST override` (image, secrets, hostnames, egress CIDRs), then deploy.

## Lint

```bash
helm lint deploy/helm/sentinelx
helm template sentinelx deploy/helm/sentinelx --debug | kubeconform -strict
```

## What it deploys

| Kind                | Name suffix      | Always on?              |
|---------------------|------------------|-------------------------|
| Deployment          | (release)        | yes                     |
| Service             | (release)        | yes                     |
| ConfigMap           | -config          | yes                     |
| Secret              | -secrets         | unless `existingSecret` |
| ServiceAccount      | (release)        | `serviceAccount.create` |
| NetworkPolicy       | (release)        | `networkPolicy.enabled` |
| PodDisruptionBudget | (release)        | `pdb.enabled`           |
| ServiceMonitor      | (release)        | `metrics.serviceMonitor.enabled` |
| Ingress             | (release)        | `ingress.enabled`       |
| Job                 | -migrate         | `migrationJob.enabled`  |

## Security defaults (least-privilege)

- runAsNonRoot, UID/GID 65532
- readOnlyRootFilesystem
- drop ALL capabilities, no privilege escalation
- seccompProfile: RuntimeDefault
- ServiceAccount token automount disabled
- default-deny NetworkPolicy: only same-namespace ingress (+ optional
  ingress-nginx) and explicit egress to Postgres / Redis / OTel + cluster DNS

## Values overview

See `values.example.yaml` for the fully-commented reference. Most-changed:

| Key                              | Purpose                                        |
|----------------------------------|------------------------------------------------|
| `image.repository`, `image.tag`  | Pin a specific image                           |
| `secrets.*` or `secrets.existingSecret` | DB / Redis / JWT / pepper / admin PHC   |
| `networkPolicy.egress.*.cidrs`   | DB / Redis / OTel destinations                 |
| `ingress.*`                      | Expose externally (TLS via cert-manager)       |
| `metrics.serviceMonitor.enabled` | Scrape via Prometheus Operator                 |
| `migrationJob.enabled`           | Run `sx-monolith migrate run` before rollout   |

## Required environment variables (rendered by the chart)

The chart injects the following env vars into the container from the
secret named in `secrets.existingSecret` (or the generated one):

- `SENTINELX__DATABASE__URL`
- `SENTINELX__REDIS__URL`
- `SENTINELX__JWT__SIGNING_KEY`
- `SENTINELX__IAM__ATTEMPT_EMAIL_PEPPER`
- `SENTINELX__IAM__BOOTSTRAP_ADMIN_PHC`
- `SENTINELX__TELEMETRY__OTLP_ENDPOINT` (from `telemetry.otlpEndpoint`)

All other config comes from the ConfigMap mounted at
`/etc/sentinelx/config.yaml`.

## Uninstall

```bash
helm uninstall sentinelx -n sentinelx
```

This deletes the Deployment, Service, ConfigMap, Secret, NetworkPolicy,
PDB, ServiceMonitor, Ingress, and (if still present) the migration Job.
Persistent state (Postgres, Redis) is unaffected.
