# HashiCorp Vault for SentinelX

Vault is the secrets backbone for SentinelX. It runs in HA mode (Raft storage)
in the `vault` namespace and is auto-unsealed by an AWS KMS CMK so we don't
have to manage Shamir shares manually. Application pods consume secrets via
the Vault Agent Injector (sidecar pattern).

## Install

```
helm repo add hashicorp https://helm.releases.hashicorp.com
helm upgrade --install vault hashicorp/vault \
  -n vault --create-namespace \
  -f values.yaml
```

## First-time init

After the pods come up:

```
kubectl -n vault exec -it vault-0 -- vault operator init \
  -recovery-shares=5 -recovery-threshold=3
```

The KMS seal **does not eliminate** recovery keys — it makes them recovery
shares instead of unseal shares. Distribute the 5 recovery key shares to 5
oncall officers per the runbook. KMS auto-unseal handles startup; recovery
keys are needed only for `generate-root` (e.g. to recover a lost root token).

## Apply Kubernetes auth + policies

```
kubectl -n vault apply -f kubernetes-auth-config.yaml
kubectl -n vault exec -it vault-0 -- vault policy write monolith-secrets - < policies/monolith-secrets.hcl
kubectl -n vault exec -it vault-0 -- vault policy write ops-readonly    - < policies/ops-readonly.hcl
```

## Secret layout

```
sentinelx/
  data/
    dev/
      db-url                  # postgres://...
      redis-url               # redis://...
      jwt-signing-key         # base64 32-byte HS256 secret
      attempt-email-pepper    # 32-byte pepper for login attempt hashing
      bootstrap-admin-phc     # Argon2id PHC for the bootstrap admin
    staging/
      ... same shape
    prod/
      ... same shape
```

## Unseal key rotation

Auto-unseal via KMS means there is **no Shamir unseal step** in normal
operation. To rotate the recovery keys (e.g. an oncall officer leaves):

```
vault operator generate-root -init                # generates an OTP
# each remaining recovery share holder runs:
vault operator generate-root -otp=<OTP>           # gives back encoded root
vault operator generate-root -decode=<encoded> -otp=<OTP>
vault operator rekey -init -recovery-key -key-shares=5 -key-threshold=3
# each share holder runs the rekey nonce flow
```

The new shares should be distributed via 1Password sharing (each share to a
separate vault item that only the recipient can access).

## CMK + IAM

The KMS key referenced by the seal block must:
- Live in `ap-southeast-1` (Singapore region).
- Allow the IRSA role of the `vault` ServiceAccount to `kms:Encrypt`,
  `kms:Decrypt`, `kms:DescribeKey`, `kms:GenerateDataKey`.
- Have a key alias `alias/sentinelx-vault`.

Terraform definition lives in `deploy/terraform/aws-vault-kms.tf` (out of scope
for this folder).
