# SentinelX GitOps Operations Guide

> **Last reviewed:** 2026-06-13
> **Maintainer:** Platform Engineering (`platform-eng@sentinelx.example`)
> **Next review:** 2026-09-13 (quarterly)
> **Document owner:** Director of Platform Engineering
> **Classification:** Internal — Restricted

This document covers the end-to-end lifecycle of a SentinelX change: how the
monorepo is structured, what CI gates apply at PR time, how branches and
commits are conventioned, how the merge strategy preserves audit history, and
how ArgoCD + Argo Rollouts pick up images and roll them out across clusters.

It assumes ArgoCD, Argo Rollouts, Linkerd, Falco (P2-016) and the Sigstore
policy-controller are installed per `deploy/`.

---

## 1. Monorepo layout

```
.
├── crates/                  # Rust workspace
│   ├── sx-api/              # Axum HTTP gateway (middleware, error envelope)
│   ├── sx-audit/            # Hash-chained audit log + RFC 3161 anchoring (P1-015)
│   ├── sx-bas/              # Breach-and-attack simulation (P1-008, P2-015)
│   ├── sx-cloud/            # Cloud blast-radius graph (P1-010)
│   ├── sx-compliance/       # P1-004 collectors + bundle/WORM/GRC plumbing
│   ├── sx-device-trust/     # Device-trust posture middleware (P2-008)
│   ├── sx-dlp/              # Content inspection — 12+ detectors (P2-006)
│   ├── sx-graph/            # Tenant knowledge graph (Neo4j adapter)
│   ├── sx-iam/              # WebAuthn (P1-002), SAML (P0-004), SCIM (P0-005)
│   ├── sx-integrations/     # GRC outbound + bug bounty bridges (P2-009, P3-010)
│   ├── sx-ir-playbooks/     # NIST 800-61 IR playbooks (P3-004)
│   ├── sx-ml/               # UEBA baselines + anomaly detection (P2-005)
│   ├── sx-rba/              # Risk-based authentication (P1-003)
│   ├── sx-remediation/      # Remediation outcomes + regression tracking (P1-011)
│   ├── sx-runtime/          # Falco webhook + OCSF normaliser (P2-016)
│   ├── sx-secrets/          # KMS providers (P1-005 AWS, P1-006 GCP, P1-007 Azure)
│   ├── sx-vuln-ingest/      # P0-002 + NVD/KEV (P0-006)
│   └── ...                  # 30+ crates in total
├── services/
│   ├── sx-monolith/         # Compose-all binary for Phase 1
│   ├── sx-agent/            # On-prem scanner
│   └── sx-cli/              # Operator CLI
├── api/openapi.yaml         # Single source of truth for the HTTP surface
├── migrations/              # Postgres migrations (sqlx)
├── web/dashboard/           # Next.js operator dashboard
├── deploy/                  # Helm, ArgoCD apps, Falco rules, Linkerd policies
├── infra/                   # Terraform for AWS / GCP / Azure
├── docs/                    # Architecture, ADRs, runbooks, compliance
└── scripts/                 # Operational scripts referenced by runbooks
```

The single workspace `Cargo.toml` enforces the workspace lint profile:

```toml
[workspace.lints.rust]
unsafe_code = "forbid"

[workspace.lints.clippy]
unwrap_used    = "deny"
expect_used    = "deny"
panic          = "deny"
todo           = "deny"
dbg_macro      = "deny"
```

Every crate declares `#![forbid(unsafe_code)]` at the top of `lib.rs`.

---

## 2. Branch convention

| Branch pattern              | Purpose                                                       |
|-----------------------------|----------------------------------------------------------------|
| `main`                      | Protected. Only fast-forward via `merge --no-ff` from `feat/*` |
| `feat/<task>-<slug>`        | Feature branch per P-task or remediation work                  |
| `fix/<crate>-<short-desc>`  | Bug fix (no new behaviour)                                     |
| `chore/<scope>-<desc>`      | Tooling, dependency bumps, CI changes                          |
| `docs/<area>-<desc>`        | Documentation-only updates                                     |
| `hotfix/<sev>-<desc>`       | Reserved for P0/P1 release-branch hotfixes                     |

Examples taken from the current repo log:

- `feat/p1-006-gcp-kms-kek-provider`
- `feat/p2-008-device-trust-middleware`
- `feat/docs-ops-compliance-update`  ← this branch

Branch protection on `main` requires:

- Required reviews: ≥ 1 reviewer; security-sensitive paths require an
  additional `@sentinelx/security` reviewer (enforced by `CODEOWNERS`).
- Required status checks: `ci/clippy`, `ci/test`, `ci/web-build`,
  `ci/openapi-lint`, `ci/cargo-deny`, `ci/audit-bundle-verify`.
- Linear history is **not** required — we keep merge commits so the
  branch topology of a release is reconstructible.
- Force-push is denied; deletion is denied.

---

## 3. Commit convention

We use a constrained Conventional Commits subset:

```
<type>(<scope>): <imperative summary> (<task-id> [MVP|HOTFIX|RC])
```

| Field        | Rule                                                                       |
|--------------|----------------------------------------------------------------------------|
| `type`       | `feat | fix | docs | refactor | test | chore | perf | merge`              |
| `scope`      | One or more comma-separated crate names (no `sx-` prefix? keep prefix), or area like `web`, `api`, `infra`, `runbooks` |
| `task-id`    | `P<phase>-<NNN>` (e.g. `P1-006`) — must exist in `docs/SECURITY_GAP_REMEDIATION_TASKS.md` |
| Stage tag    | `MVP` while building, `HOTFIX` for cherry-picks, `RC` for release-stage cuts |

Real examples from `git log`:

```
feat(sx-secrets): GCP Cloud KMS KEK provider (P1-006) on top of P1-007 trait
merge: P2-008 device-trust posture middleware (resolve port/router/state conflicts)
merge: P1-011 remediation outcomes + regression tracking (resolve port/router/migration conflicts)
docs(ops/compliance/security/runbooks): comprehensive subdir refresh
```

Commit messages are linted by `commitlint` running on the pre-commit hook
**and** in CI (`ci/commit-message`).

---

## 4. CI gates (PR-time)

Every PR to `main` runs the matrix below. Each gate is mandatory — a red
gate blocks merge regardless of reviewer state.

| Gate                        | Command                                                                                                  | Failing condition                                  |
|-----------------------------|----------------------------------------------------------------------------------------------------------|----------------------------------------------------|
| `ci/clippy`                 | `cargo clippy --all-targets --all-features -- -D warnings`                                               | Any `warning` becomes a hard error                 |
| `ci/test`                   | `cargo test --workspace --all-features --no-fail-fast`                                                   | Any test failure                                   |
| `ci/web-build`              | `npm --prefix web/dashboard ci && npm --prefix web/dashboard run build`                                  | Next.js build error                                |
| `ci/openapi-lint`           | `spectral lint api/openapi.yaml --ruleset .spectral.yaml`                                                | Any error-severity violation                       |
| `ci/cargo-deny`             | `cargo deny check advisories bans licenses sources`                                                       | New CVE w/o `.cargo-deny-skip` entry; banned crate |
| `ci/audit-bundle-verify`    | `cargo run -p sx-cli -- compliance bundle --dry-run` against fixtures                                    | Deterministic bytes drift                          |
| `ci/migrations`             | `sqlx migrate run --dry-run` against an ephemeral Postgres                                                | Migration cannot be applied or rolled back         |
| `ci/spec-trace`             | `scripts/spec-trace.sh` — every `(P<phase>-<NNN>)` mentioned in CHANGELOG resolves in tasks doc          | Unknown task id                                    |

Local pre-push (recommended):

```bash
cargo clippy --all-targets --all-features -- -D warnings \
  && cargo test --workspace --all-features --no-fail-fast \
  && npm --prefix web/dashboard run build
```

---

## 5. Merge strategy

`main` uses **merge commits with `--no-ff`**, never squash, never rebase.
This preserves the per-task branch topology, which is what auditors and
the bisect tool rely on to trace a feature back to its review.

Merge-commit convention (the first line of the merge commit subject):

```
merge: <task-id> <short summary> (<optional: resolve-conflicts: list>)
```

Examples:

```
merge: P2-008 device-trust posture middleware (resolve port/router/state conflicts)
merge: P2-005 UEBA baseline + anomaly detection
merge: P1-011 remediation outcomes + regression tracking (resolve port/router/migration conflicts)
```

The "resolve-conflicts" tail is mandatory whenever the merge required
manual conflict resolution; it tells `git log --grep="resolve-conflicts"`
where the integration risk lives.

---

## 6. ADR requirement for architectural decisions

A change requires an **Architecture Decision Record** (`docs/adr/NNNN-<slug>.md`)
when any of the following apply:

- A new trust boundary is introduced (B1–B8 in
  `docs/security/threat-model-stride.md`).
- A new external integration (GRC provider, KMS, TSA, etc.).
- A new crate is added to the workspace.
- A schema change touches `audit_events`, `evidence_runs`, or any
  row-level-security policy.
- A new request path bypasses an existing middleware layer.

ADR template lives at `docs/adr/0000-template.md`. ADRs are **immutable**
once `Accepted`; supersession is by a new ADR that links the old one as
`Supersedes: NNNN`.

PR template asks the author to either link an existing ADR or justify
why none is needed; reviewers default to "needs ADR" when in doubt.

---

## 7. Install ArgoCD + Argo Rollouts

### 7.1 ArgoCD bootstrap

```bash
kubectl create namespace argocd
kubectl apply -n argocd \
  -f https://raw.githubusercontent.com/argoproj/argo-cd/v2.13.0/manifests/install.yaml
kubectl -n argocd rollout status deploy/argocd-server --timeout=5m
```

Pin the `argo-cd` minor version in `deploy/argocd/values.yaml`. Renovate
opens the upgrade PR; a human merges after reading the upstream changelog.

### 7.2 Argo Rollouts controller

```bash
kubectl create namespace argo-rollouts
kubectl apply -n argo-rollouts \
  -f https://github.com/argoproj/argo-rollouts/releases/download/v1.7.2/install.yaml
kubectl -n argo-rollouts rollout status deploy/argo-rollouts --timeout=5m
```

### 7.3 Register the app-of-apps

Bootstrap order matters — the AppProject must exist before any child syncs.

```bash
kubectl apply -f deploy/argocd/projects/sentinelx.yaml      # AppProject
kubectl apply -f deploy/argocd/app-of-apps.yaml             # Root Application

argocd app list
argocd app wait sentinelx-app-of-apps --health --timeout 300
```

Subsequent changes flow purely through `git merge` to `main`. Never `kubectl
apply` an Application directly after bootstrap.

---

## 8. The happy path (PR → production)

```
                                                              cosign verify
        PR opened          PR merged                        (policy-controller)
            |                  |                                    |
            v                  v                                    v
   +----------------+   +---------------+   +----------------+   +------+
   | clippy -D      |-->| release.yml   |-->| GHCR signed    |-->| pod  |
   | cargo test     |   | (tag = v*)    |   | image + SBOM   |   | runs |
   | npm run build  |   | cosign sign   |   | + attestation  |   +------+
   +----------------+   +---------------+   +----------------+
                                |
                                v
        +------------------------------------------+
        | ArgoCD ApplicationSet picks up new image |
        |   1. dev cluster sync                    |
        |   2. Argo Rollouts canary 10/30/60/100   |
        |   3. promote on AnalysisRun pass         |
        +------------------------------------------+
                                |
                                v
        promote to staging -> staging canary -> promote prod -> prod canary
```

Each promotion is a separate ApplicationSet target. Cluster promotion is
triggered by bumping the image tag in `values-<env>.yaml` via a PR — never by
direct kubectl.

---

## 9. Rollback via ArgoCD UI

1. Open `https://argocd.sentinelx.example.invalid` and select the affected
   Application (e.g. `sentinelx-monolith-prod`).
2. Click **History and rollback**.
3. Pick the previous revision whose deployed-at predates the regression.
4. Click **Rollback**. ArgoCD switches `targetRevision` to that git SHA and
   begins a new sync.
5. The new sync triggers an Argo Rollouts canary — even on rollback. This is
   deliberate; rolling back a regression should still be observed.

CLI equivalent:

```bash
argocd app history sentinelx-monolith-prod
argocd app rollback sentinelx-monolith-prod <history-id>
```

If the rollback target is older than the last 10 revisions (the default
`revisionHistoryLimit`), revert the git commit and let ArgoCD sync forward —
this preserves audit history.

---

## 10. Break-glass: kubectl when ArgoCD is down

If ArgoCD is offline and a P0 must ship, you can bypass GitOps with kubectl,
but every break-glass action emits a SentinelX audit log entry. Procedure:

1. **Announce in `#sentinelx-incident`**: state the change, the duration, and
   the ticket id.
2. Authenticate to the affected cluster with your **break-glass kubeconfig**
   from 1Password (item `sentinelx-prod-breakglass`). The kubeconfig uses a
   separate IAM role whose actions are logged to a dedicated CloudTrail trail.
3. Apply the change with:
   ```bash
   kubectl --context=prod-breakglass -n sentinelx apply -f hotfix.yaml
   ```
4. Within 5 minutes of bringing ArgoCD back online, you **must** check in a PR
   matching the live state. `selfHeal: true` will otherwise revert your hotfix.
5. The break-glass action emits:
   - A CloudTrail event in `sentinelx-breakglass`.
   - A SentinelX audit row `action=breakglass.kubectl_apply` chained under the
     ops tenant; TSA-anchored at the next rotor tick (P1-015).
   - A Slack notification to `#sentinelx-incident`.

---

## 11. Rotate Vault recovery keys

See `deploy/vault/README.md#unseal-key-rotation`. Summary:

1. `vault operator generate-root -init` to get a one-time pad.
2. Each recovery share holder runs `vault operator generate-root -otp=<OTP>`.
3. Once threshold is met, decode the encoded root token.
4. Use the temporary root to run `vault operator rekey -init -recovery-key`.
5. Distribute the new shares via 1Password share links — one share per item,
   ACL'd to a single recipient.
6. Revoke the temporary root with `vault token revoke <root>`.

Auto-unseal via AWS KMS means **Vault never needs the recovery keys at boot**.
They are required only for `generate-root` and `rekey` flows.

---

## 12. Update Falco (P2-016) rules without disrupting active scans

Falco hot-reloads its rule files. To ship a rule change without rolling pods:

1. Edit `deploy/falco/rules/sentinelx_runtime_rules.yaml`.
2. Open a PR. CI lints the rule with `falcoctl rules validate` plus a
   `cargo test -p sx-runtime ocsf_normaliser` shadow against the rule.
3. Merge to main. ArgoCD syncs the updated `ConfigMap` to the `falco`
   namespace.
4. Falco's `--watch-config-file` flag picks up the change within 10 s and
   reloads its rule engine. No restart of the DaemonSet, no dropped events.
5. Validate by tailing alerts:
   ```bash
   kubectl -n falco logs -l app.kubernetes.io/name=falco --tail=100 -f
   ```

If a rule is malformed, Falco continues running with the **previous** rule set
and emits a `rules_reload_failed` metric you can alert on. The `sx-runtime`
webhook also gates ingestion on HMAC-SHA256 signature verification — see
[`runtime-security.md`](./runtime-security.md).

---

## 13. Rotate Linkerd trust anchor

`cert-manager` + `trust-manager` rotate the trust anchor automatically on a
yearly schedule (the `Certificate` CR has `renewBefore: 720h`).

Manual rotation (compromise scenario):

1. Generate a new root: `step certificate create root.linkerd.cluster.local ca.crt ca.key --profile root-ca`.
2. Generate a new intermediate signed by the new root.
3. Update the `vault-pki` intermediate via `vault write pki/root/rotate/internal ...`.
4. Update the `trust-manager` Bundle ConfigMap.
5. Linkerd hot-reloads; no proxy restart.

Verify with `linkerd check --proxy`.

---

## 14. On-call runbook excerpts

### 14.1 ArgoCD sync stuck on `Progressing`

- Check `kubectl -n argocd logs deploy/argocd-application-controller`.
- Most common cause: an OPA Gatekeeper constraint or the SentinelX K8s
  admission analyzer (P2-014, 16 rules) rejected a workload. Look for
  `admission webhook ... denied the request`.
- Fix: amend the PR (e.g. add the missing resource limit) and re-merge.

### 14.2 Rollout aborted on AnalysisRun failure

- `kubectl -n sentinelx describe analysisrun <run-id>` shows which metric
  failed and the actual value.
- Compare with the SLO dashboard in Grafana
  (`https://grafana.sentinelx.example.invalid/d/sentinelx-slo`).
- If the regression is in the new image, leave the rollout aborted and revert
  the image tag PR. If the regression is environmental (e.g. database CPU
  saturated), pause the rollout, fix the upstream, then
  `kubectl argo rollouts promote sx-monolith`.

### 14.3 Vault is sealed

- KMS auto-unseal handles startup. A sealed Vault means KMS is unreachable.
- Check IRSA: `kubectl -n vault exec -it vault-0 -- aws kms describe-key --key-id alias/sentinelx-vault`.
- If IAM is fine, check the KMS key state in the AWS console.
- Last resort: manual unseal with 3 of 5 recovery key shares.

### 14.4 Falco firing on `SentinelX Egress To Non-Allowlisted Destination`

- Identify the destination IP from the alert payload (already OCSF-normalised
  by P2-016 — the OCSF `dst_endpoint.ip` field).
- Decide whether it's a legitimate new dependency or an indicator of
  compromise.
- If legit: add the CIDR to `sentinelx_egress_allowlist` in
  `deploy/falco/rules/sentinelx_runtime_rules.yaml` and merge.
- If suspicious: isolate the pod with `kubectl -n sentinelx label pod <p> quarantine=true`.
  A NetworkPolicy selector on `quarantine=true` denies all egress.

### 14.5 Sigstore policy rejects a pod

- The pod's image is not signed by the SentinelX release workflow.
- Usually means someone tagged an image manually outside CI.
- Fix: re-tag via `release.yml` (cut a `v*` tag in git). Do **not** disable
  the policy.

---

## 15. Troubleshooting matrix

| Symptom | Likely cause | First check | Fix |
|---|---|---|---|
| `ComparisonError: unable to load values` | Multi-source `$values` repo not yet cloned | `argocd app get <app> -o json \| jq .status.sync` | `argocd repo add` the missing repo |
| `OutOfSync` flapping on a Rollout | ArgoCD seeing replica drift | `kubectl -n sentinelx get rs -l app.kubernetes.io/name=sx-monolith` | Confirm `ignoreDifferences` covers `/spec/replicas` on Rollout + ReplicaSet |
| `AnalysisRun` stuck `Pending` | Prometheus unreachable from `argo-rollouts` ns | `kubectl -n argo-rollouts exec deploy/argo-rollouts -- curl -s prometheus.sentinelx-observability:9090/-/healthy` | Open NetworkPolicy egress from `argo-rollouts` to `sentinelx-observability:9090` |
| `Failed to load admin password` | Initial secret deleted before bootstrap captured it | `kubectl -n argocd get secret argocd-initial-admin-secret` | Re-issue via `argocd admin initial-password -n argocd` |
| Child app stuck `Missing` | Path typo or branch protection rejected push | `argocd app get <app> -o yaml \| yq .status.conditions` | Open PR, fix `spec.source.path` |
| `repo not permitted` | Source URL absent from AppProject `sourceRepos` | `kubectl -n argocd get appproject sentinelx -o yaml` | Add URL to `deploy/argocd/projects/sentinelx.yaml` |

### 15.1 Force-resync without restarting controllers

```bash
argocd app sync sentinelx-monolith --force --prune --replace=false
```

`--replace=false` matters: combined with `syncOptions: [Replace=false]` it
guarantees ArgoCD uses three-way merge (preserving Argo Rollouts' in-place
mutations to Service selectors).

### 15.2 Verify every Application is project-scoped (CI guard)

```bash
for f in deploy/argocd/app-of-apps.yaml deploy/argocd/apps/*.yaml; do
  grep -q '^  project: sentinelx$' "$f" || { echo "MISSING project: $f"; exit 1; }
done
echo "all Applications are project: sentinelx"
```

### 15.3 OIDC bindings

The AppProject `roles[]` map to OIDC groups asserted by the IdP (Okta).
Add a new operator without an ArgoCD admin by:

1. Add the user to the `sentinelx:ops-readonly` group in Okta.
2. Wait one ID-token refresh cycle (default 60 s).
3. The user can `argocd login` and read every Application; no write paths.

Release managers go in `sentinelx:release-managers` instead.

---

## 16. Compliance evidence emitted by this pipeline

Pipeline-level evidence is harvested alongside the P1-004 control evidence
(see [`compliance-evidence.md`](./compliance-evidence.md)).

| Control               | Artefact                                                                |
|-----------------------|--------------------------------------------------------------------------|
| NIST CM-3             | Git history of `deploy/argocd/**` + `argocd app history` JSON           |
| ISO 27001 A.8.32      | Sealed PR + reviewer audit log + ArgoCD sync event                       |
| SOC2 CC8.1            | Same PR + ArgoCD `applicationSyncResults` events forwarded to S3 (WORM) |
| NIST SI-4             | AnalysisRun outcomes streamed to Prometheus + Loki                       |
| PCI DSS 4.0 6.5.1     | PR + approval + change ticket + post-deploy verification recorded        |
| PCI DSS 4.0 11.5.2    | Image SBOM diff per deploy via the `audit-bundle-verify` gate            |

Evidence collection is automated; manual re-harvest:
`scripts/compliance/collect_gitops_evidence.sh` writes a bundle compatible
with the P1-004 manifest schema.
