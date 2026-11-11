###############################################################################
# Observability — CloudWatch log groups + Container Insights.
###############################################################################

# EKS control-plane log destination (matches enabled_cluster_log_types).
resource "aws_cloudwatch_log_group" "eks_cluster" {
  name              = "/aws/eks/${local.name_prefix}/cluster"
  retention_in_days = 30
  kms_key_id        = aws_kms_key.main.arn
}

# Application-level log group consumed by Fluent Bit / CloudWatch agent on nodes.
resource "aws_cloudwatch_log_group" "app" {
  name              = "/sentinelx/${var.environment}/app"
  retention_in_days = 30
  kms_key_id        = aws_kms_key.main.arn
}

# Container Insights — performance, pod, and node metrics aggregated.
resource "aws_cloudwatch_log_group" "container_insights" {
  name              = "/aws/containerinsights/${local.name_prefix}/performance"
  retention_in_days = 14
  kms_key_id        = aws_kms_key.main.arn
}

# Enable Container Insights via EKS addon. CloudWatch Observability addon
# bundles the CloudWatch agent + Fluent Bit and ships pod/node metrics.
resource "aws_eks_addon" "cloudwatch_observability" {
  cluster_name                = aws_eks_cluster.main.name
  addon_name                  = "amazon-cloudwatch-observability"
  resolve_conflicts_on_create = "OVERWRITE"
  resolve_conflicts_on_update = "OVERWRITE"

  depends_on = [
    aws_eks_node_group.main,
    aws_cloudwatch_log_group.container_insights,
  ]
}
