# Linkerd — SentinelX service mesh

This folder pins SentinelX-specific Linkerd policy CRs (Server, AuthorizationPolicy,
MeshTLSAuthentication, ServiceProfile) plus the injected namespace. The control
plane itself is installed via the Linkerd CLI (out of band) since Linkerd's
upstream guidance discourages running its control plane from a vanilla Helm
release.

## Install

```
# 1. Trust anchor + identity issuer (rotated yearly via cert-manager).
linkerd install --crds | kubectl apply -f -
linkerd install \
  --identity-trust-anchors-file=ca.crt \
  --identity-issuer-certificate-file=issuer.crt \
  --identity-issuer-key-file=issuer.key \
  | kubectl apply -f -

# 2. Verify.
linkerd check

# 3. Apply SentinelX policy.
kubectl apply -f namespace.yaml
kubectl apply -f meshconfig.yaml
kubectl apply -f policy-monolith-server.yaml
kubectl apply -f policy-monolith-authorization.yaml
kubectl apply -f policy-monolith-mtls.yaml
```

## Cert rotation

The trust anchor is renewed by cert-manager via the `trust-manager` bundle:

1. cert-manager issues a new intermediate from the root CA stored in Vault PKI.
2. trust-manager publishes the new bundle to a `ConfigMap` watched by Linkerd.
3. Linkerd hot-reloads the issuer cert; no proxy restarts required.

Manual rotation (break-glass) is documented in
`docs/operations/gitops.md#rotate-linkerd-trust-anchor`.

## Files

| File | Purpose |
| ---- | ------- |
| `namespace.yaml` | `sentinelx` namespace with `linkerd.io/inject: enabled`. |
| `meshconfig.yaml` | ServiceProfile defining HTTP routes for monolith endpoints. |
| `policy-monolith-server.yaml` | Server CR exposing port 8080 as HTTP/2. |
| `policy-monolith-authorization.yaml` | Allow only ingress + same-NS for `/v1/*`; open probe paths. |
| `policy-monolith-mtls.yaml` | MeshTLSAuthentication + per-NS rate limit. |

## Routes

Defined in the ServiceProfile, with retry budgets DISABLED on POST/PUT/DELETE
to avoid duplicate side effects, and timeouts of 30s across the board:

| Route | Method | Timeout | Retry |
| ----- | ------ | ------- | ----- |
| `/v1/auth/login` | POST | 30s | none |
| `/v1/engagements` | POST | 30s | none |
| `/v1/engagements` | GET | 30s | budgeted |
| `/v1/findings` | GET | 30s | budgeted |
