###############################################################################
# Outputs — consumed by kubectl / Helm / sx-api configuration.
###############################################################################

output "account_id" {
  description = "AWS account hosting this stack."
  value       = data.aws_caller_identity.current.account_id
}

output "region" {
  description = "AWS region this stack lives in."
  value       = var.region
}

output "vpc_id" {
  description = "VPC id."
  value       = aws_vpc.main.id
}

output "cluster_name" {
  description = "EKS cluster name."
  value       = aws_eks_cluster.main.name
}

output "cluster_endpoint" {
  description = "EKS API server endpoint."
  value       = aws_eks_cluster.main.endpoint
}

output "cluster_oidc_issuer_url" {
  description = "OIDC issuer URL — required when binding IRSA roles to ServiceAccounts."
  value       = aws_eks_cluster.main.identity[0].oidc[0].issuer
}

output "rds_writer_endpoint" {
  description = "Aurora writer DNS endpoint."
  value       = aws_rds_cluster.main.endpoint
}

output "rds_reader_endpoint" {
  description = "Aurora reader DNS endpoint (round-robins replicas; falls back to writer if no replicas)."
  value       = aws_rds_cluster.main.reader_endpoint
}

output "redis_primary_endpoint" {
  description = "Primary Redis endpoint (cluster-mode-disabled)."
  value       = aws_elasticache_replication_group.main.primary_endpoint_address
}

output "kms_key_arn" {
  description = "CMK ARN — wire into RDS/Redis/secrets configuration."
  value       = aws_kms_key.main.arn
}

output "irsa_role_arn" {
  description = "IRSA role ARN — annotate the sx-monolith ServiceAccount with eks.amazonaws.com/role-arn=<this>."
  value       = aws_iam_role.irsa_monolith.arn
}

output "secret_arns" {
  description = "Map of logical secret name to Secrets Manager ARN."
  value       = { for k, s in aws_secretsmanager_secret.this : k => s.arn }
}
