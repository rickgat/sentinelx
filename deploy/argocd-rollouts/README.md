# Argo Rollouts — SentinelX canary strategy

This folder contains the `Rollout` CR that replaces the Deployment shipped by
the Helm chart, plus two `AnalysisTemplate` CRs used during canary steps.

## Strategy

```
setWeight 10  ->  pause 2m  ->  analysis (success-rate + latency-p95)
setWeight 30  ->  pause 2m  ->  analysis
setWeight 60  ->  pause 2m  ->  analysis
setWeight 100 (promote)
```

If either analysis fails (success rate < 99.5%, or p95 latency > 500ms) the
rollout is automatically aborted and traffic shifts back to the stable
ReplicaSet. The full rollout window is ~12 minutes worst case.

### Why these thresholds?

| Metric | Threshold | Rationale |
| ------ | --------- | --------- |
| HTTP success rate | >= 99.5% over 2m | Allows for 0.5% baseline 4xx noise (auth retries, malformed scans), well above SLO of 99.0%. |
| p95 latency       | <= 500 ms      | Matches the SLO target documented in `docs/TRD.md` §7.1. Tighter than the 1s SLA so we catch latency regressions early. |

### Traffic routing

We use **Linkerd native service switching** rather than the SMI TrafficSplit
shim. Rationale:
- Linkerd 2.15+ has first-class support for Argo Rollouts via `setHeaderRoute`
  and weighted `Service` selectors without requiring SMI CRDs.
- SMI is deprecated in Linkerd; the SMI extension is no longer maintained.
- Linkerd's `Server` + `HTTPRoute` CRDs let us split weight without ever
  exposing the canary pod to ingress directly.

The `Rollout` references the `stable` and `canary` ClusterIP `Service`s that
the Helm chart renders; Argo Rollouts patches their pod selectors on each
step.

## Apply

Best applied via the ApplicationSet (it picks up `kustomization.yaml`). For
manual smoke testing:

```
kubectl -n sentinelx apply -k deploy/argocd-rollouts
```

## Files

| File | Purpose |
| ---- | ------- |
| `rollout-monolith.yaml` | The Rollout CR for `sx-monolith`. |
| `analysistemplate-success-rate.yaml` | Prometheus-based pass/fail on HTTP 5xx rate. |
| `analysistemplate-latency-p95.yaml`  | Prometheus-based pass/fail on p95 request latency. |
| `kustomization.yaml` | Kustomize base listing the above. |
