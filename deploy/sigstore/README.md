# Sigstore image signing + cluster policy

SentinelX uses **cosign keyless** (Fulcio + Rekor) signing. There are no
long-lived signing keys. The OIDC identity used during signing is the
GitHub Actions OIDC token issued to the release workflow.

## How signing happens

1. `release.yml` builds the OCI image with `docker buildx`.
2. `cosign sign --yes ghcr.io/sentinelx/sx-monolith@sha256:...` requests a
   short-lived certificate from Fulcio bound to the workflow's OIDC subject.
3. The signature is appended to the image manifest and a transparency log
   entry is written to Rekor.
4. The SBOM (CycloneDX JSON) is attached via `cosign attest --type cyclonedx`.

## How verification happens

The `policy-controller` (Sigstore) admission webhook enforces
`cosign-policy.yaml`:

```
spec:
  authorities:
    - keyless:
        identities:
          - issuer: https://token.actions.githubusercontent.com
            subjectRegExp: ^https://github.com/sentinelx/sentinelx/.github/workflows/release.yml@refs/tags/v.*$
```

Any pod pulling `ghcr.io/sentinelx/*` whose image does not satisfy this
policy is rejected at admission. The policy applies cluster-wide.

## Install

```
helm repo add sigstore https://sigstore.github.io/helm-charts
helm upgrade --install policy-controller sigstore/policy-controller \
  -n cosign-system --create-namespace
kubectl apply -f cosign-policy.yaml
```

## Verify locally

```
cosign verify ghcr.io/sentinelx/sx-monolith:v1.2.3 \
  --certificate-identity-regexp '^https://github.com/sentinelx/sentinelx/.github/workflows/release.yml@refs/tags/v.*$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```
