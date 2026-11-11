# SentinelX — AWS dev environment (Terraform)

Minimum-viable AWS stack for the SentinelX dev cluster. Everything sits in
this one folder; no external modules required.

## Prerequisites

- Terraform `>= 1.6.0`
- AWS CLI configured (`aws configure` / SSO profile) for an account with
  permissions to create VPCs, EKS, RDS, ElastiCache, IAM, KMS, Secrets Manager.
- The target region defaults to `ap-southeast-1` (see `variables.tf`).

## Quick start

```bash
cd deploy/terraform/dev

terraform init
terraform plan -out tfplan
terraform apply tfplan
```

State is stored locally by default (`./terraform.tfstate`). See
[Remote state for prod](#remote-state-for-prod) below for the S3 + DynamoDB
backend block.

## Populating Secrets Manager

Terraform creates each secret with the placeholder string `REPLACE_ME`. Real
values are injected out-of-band so they never sit in tfvars or state. After
`terraform apply` completes, run:

```bash
ENV=dev
REGION=ap-southeast-1

# 32-byte random JWT signing key (raw base64)
aws --region "$REGION" secretsmanager put-secret-value \
  --secret-id "sentinelx/$ENV/jwt-signing-key" \
  --secret-string "$(openssl rand -base64 32)"

# Email pepper for hashing login attempts
aws --region "$REGION" secretsmanager put-secret-value \
  --secret-id "sentinelx/$ENV/attempt-email-pepper" \
  --secret-string "$(openssl rand -base64 32)"

# Argon2id PHC string for the bootstrap admin password (generate offline)
aws --region "$REGION" secretsmanager put-secret-value \
  --secret-id "sentinelx/$ENV/bootstrap-admin-phc" \
  --secret-string '$argon2id$v=19$m=65536,t=3,p=4$...'

# RDS master password — must also be set BEFORE first `terraform apply`,
# because rds.tf reads it via aws_secretsmanager_secret_version. Re-run
# `terraform apply` afterwards if the cluster needs to pick it up.
aws --region "$REGION" secretsmanager put-secret-value \
  --secret-id "sentinelx/$ENV/rds-master-password" \
  --secret-string "$(openssl rand -base64 24 | tr -d '/+=' | head -c 24)"

# Redis AUTH token — same flow as RDS master password.
aws --region "$REGION" secretsmanager put-secret-value \
  --secret-id "sentinelx/$ENV/redis-auth-token" \
  --secret-string "$(openssl rand -base64 32 | tr -d '/+=' | head -c 40)"

# Connection URLs are best written AFTER apply since they include the
# Aurora / Redis endpoints from `terraform output`.
DB_URL="postgres://sentinelx_admin:<rds-master-password>@$(terraform output -raw rds_writer_endpoint):5432/sentinelx"
aws --region "$REGION" secretsmanager put-secret-value \
  --secret-id "sentinelx/$ENV/db-url" --secret-string "$DB_URL"

REDIS_URL="rediss://:<redis-auth-token>@$(terraform output -raw redis_primary_endpoint):6379"
aws --region "$REGION" secretsmanager put-secret-value \
  --secret-id "sentinelx/$ENV/redis-url" --secret-string "$REDIS_URL"
```

## Outputs

After `apply` the useful endpoints are exported:

```bash
terraform output cluster_endpoint
terraform output rds_writer_endpoint
terraform output redis_primary_endpoint
terraform output irsa_role_arn
terraform output secret_arns
```

Annotate the `sx-monolith` ServiceAccount with the IRSA role:

```bash
kubectl -n sentinelx annotate sa sx-monolith \
  eks.amazonaws.com/role-arn=$(terraform output -raw irsa_role_arn)
```

## Cost note

A continuously-running idle dev stack lands around **USD 250–320 / month**:

| Component | Approx monthly |
| --- | --- |
| EKS control plane | $72 |
| 2x t3.medium nodes | $60 |
| NAT gateway + EIP | $35 |
| Aurora Serverless v2 (1 ACU idle) | $70 |
| ElastiCache cache.t4g.small ×2 | $30 |
| CloudWatch logs + observability | $5–15 |
| Secrets Manager (7 entries) | $3 |

Numbers exclude data transfer and snapshot storage. `terraform destroy`
when finished — RDS has `deletion_protection = true` so you'll need to
flip that bit to `false` first.

## Remote state for prod

Local state is fine for dev. For prod, switch to the S3 + DynamoDB backend
block already commented in `versions.tf`:

```hcl
backend "s3" {
  bucket         = "sentinelx-tfstate-prod"
  key            = "prod/terraform.tfstate"
  region         = "ap-southeast-1"
  dynamodb_table = "sentinelx-tfstate-locks"
  encrypt        = true
}
```

The bucket + DynamoDB table must exist before `terraform init -migrate-state`:

```bash
aws s3api create-bucket --bucket sentinelx-tfstate-prod \
  --region ap-southeast-1 \
  --create-bucket-configuration LocationConstraint=ap-southeast-1
aws s3api put-bucket-versioning --bucket sentinelx-tfstate-prod \
  --versioning-configuration Status=Enabled
aws s3api put-bucket-encryption --bucket sentinelx-tfstate-prod \
  --server-side-encryption-configuration \
  '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'

aws dynamodb create-table --table-name sentinelx-tfstate-locks \
  --attribute-definitions AttributeName=LockID,AttributeType=S \
  --key-schema AttributeName=LockID,KeyType=HASH \
  --billing-mode PAY_PER_REQUEST
```

## Verification steps

```bash
terraform fmt -recursive    # must produce no diff
terraform validate          # checks syntax + resource references
terraform plan              # dry-run before any apply
```
