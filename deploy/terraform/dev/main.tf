###############################################################################
# Composition root.
#
# All resources live in sibling *.tf files (network / eks / rds / ...).
# This file only owns shared locals + the data sources every other file reads.
###############################################################################

# Account + AZ discovery — referenced from network.tf, eks.tf, iam.tf.
data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_availability_zones" "available" {
  state = "available"
}

locals {
  # First three AZs in the region — keeps subnet math predictable and dev cost low.
  az_names = slice(data.aws_availability_zones.available.names, 0, 3)

  # Naming prefix used across resources (cluster, IAM, secrets paths).
  name_prefix = "sentinelx-${var.environment}"

  # Secret paths centralised so iam.tf, secrets.tf, outputs.tf agree on the ARNs.
  secret_names = {
    db_url             = "sentinelx/${var.environment}/db-url"
    redis_url          = "sentinelx/${var.environment}/redis-url"
    jwt_signing_key    = "sentinelx/${var.environment}/jwt-signing-key"
    email_pepper       = "sentinelx/${var.environment}/attempt-email-pepper"
    bootstrap_admin    = "sentinelx/${var.environment}/bootstrap-admin-phc"
    redis_auth_token   = "sentinelx/${var.environment}/redis-auth-token"
    rds_master_user_pw = "sentinelx/${var.environment}/rds-master-password"
  }

  # Tags merged inline on resources that need extra labels beyond default_tags.
  common_tags = {
    Project     = "SentinelX"
    Environment = var.environment
    ManagedBy   = "Terraform"
  }
}
