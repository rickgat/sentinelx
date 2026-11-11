# ArgoCD GitOps for SentinelX

This directory holds the ArgoCD `AppProject`, `ApplicationSet`, and per-application
`Application` manifests that drive GitOps for SentinelX. The pattern is:

```
git push  ->  release.yml (build + sign)  ->  ArgoCD detects new chart values
          ->  ApplicationSet fans out per environment / per cluster
          ->  Argo Rollouts performs canary
          ->  AnalysisTemplates promote or roll back
```

## Layout

| File | Purpose |
| ---- | ------- |
| `project.yaml` | AppProject `sentinelx` — restricts sources/destinations and forbids dangerous cluster-scoped writes. |
| `applicationset.yaml` | Generates one `Application` per `(env, chart)` tuple using a matrix of `clusters` + `list` generators. |
| `apps/sentinelx-monolith.yaml` | Standalone Application example referencing `deploy/helm/sentinelx`. |
| `apps/sentinelx-rollouts.yaml` | Installs the `argo-rollouts` controller + CRDs from the upstream Helm chart. |
| `apps/sentinelx-cert-manager.yaml` | Subscribes cert-manager (TLS for ingress + Linkerd trust anchor renewal). |

## Bootstrapping

1. Install ArgoCD into the cluster (`argo-cd` Helm chart, namespace `argocd`).
2. Label each managed cluster secret with `env=<dev|staging|prod>` so the
   `clusters` generator can match it:
   ```
   kubectl -n argocd label secret cluster-dev-eks env=dev
   kubectl -n argocd label secret cluster-staging-eks env=staging
   kubectl -n argocd label secret cluster-prod-eks env=prod
   ```
3. `kubectl apply -f project.yaml`
4. `kubectl apply -f apps/sentinelx-rollouts.yaml`
5. `kubectl apply -f apps/sentinelx-cert-manager.yaml`
6. `kubectl apply -f applicationset.yaml`

The ApplicationSet then materialises:
- `sentinelx-monolith-dev`
- `sentinelx-monolith-staging`
- `sentinelx-monolith-prod`

## Sync policy

- `automated.prune: true` — deleting a manifest in git removes it from the cluster.
- `automated.selfHeal: true` — drift caused by manual `kubectl edit` is reverted.
- `automated.allowEmpty: false` — an empty render aborts the sync (guardrail against
  accidental wipe of the production namespace).
- Sync waves: `Namespace` (wave -2), `ServiceAccount`/`Secret`/`ExternalSecret`
  (wave -1), workloads (wave 0), `Rollout`/`AnalysisTemplate` (wave 1).

## Rollback

```
argocd app history sentinelx-monolith-prod
argocd app rollback sentinelx-monolith-prod <revision>
```

See `docs/operations/gitops.md` for the full lifecycle and break-glass procedure.
