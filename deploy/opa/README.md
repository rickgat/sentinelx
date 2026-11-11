# OPA Gatekeeper policies for SentinelX

Five `ConstraintTemplate`s + five `Constraint`s gate every workload in the
`sentinelx` namespace. They reject Deployments and Rollouts that:

1. Run as root.
2. Have a writable root filesystem.
3. Use `hostNetwork`.
4. Run a privileged container.
5. Omit CPU/memory requests + limits.

All Rego uses **Rego v1** syntax (`import rego.v1`). Each constraint has a
header comment tagging the upstream control id.

## Apply

```
kubectl apply -f constrainttemplates/
kubectl apply -f constraints/
```

Gatekeeper itself is installed out of band via its upstream Helm chart. See
`https://open-policy-agent.github.io/gatekeeper/`.

## Audit

Constraints are in `enforcementAction: deny` mode. To dry-run in a new env,
switch the action to `dryrun` and inspect violations:

```
kubectl get constraints -A -o yaml | grep -A5 violations
```

## Files

| File | Control mapping |
| ---- | --------------- |
| `constrainttemplates/require-non-root.yaml` | NIST SC-3, ISO A.5.15 |
| `constrainttemplates/require-readonly-rootfs.yaml` | NIST SI-7, ISO A.8.7 |
| `constrainttemplates/deny-host-network.yaml` | NIST SC-7, ISO A.8.20 |
| `constrainttemplates/deny-privileged.yaml` | NIST AC-6, ISO A.8.2 |
| `constrainttemplates/require-resource-limits.yaml` | NIST SC-6, ISO A.8.6 |
