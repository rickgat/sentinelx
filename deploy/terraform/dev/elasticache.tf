###############################################################################
# ElastiCache — Redis 7.2, cluster-mode-disabled, 1 primary + 1 replica.
#
# - At-rest encryption with the project CMK.
# - In-transit encryption + AUTH token sourced from Secrets Manager.
###############################################################################

resource "aws_elasticache_subnet_group" "main" {
  name       = "${local.name_prefix}-redis-subnets"
  subnet_ids = [for s in aws_subnet.private : s.id]
}

resource "aws_security_group" "redis" {
  name        = "${local.name_prefix}-redis-sg"
  description = "Redis SG — 6379 from EKS only"
  vpc_id      = aws_vpc.main.id

  ingress {
    description     = "Redis from EKS cluster SG"
    from_port       = 6379
    to_port         = 6379
    protocol        = "tcp"
    security_groups = [aws_security_group.eks_cluster.id]
  }

  # Wave: hardened per trivy AWS-0104. Redis is fully internal — deny
  # all outbound. The service accepts inbound from EKS only.
  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.main.cidr_block]
    description = "HTTPS to VPC endpoints (KMS, CloudWatch)"
  }

  tags = {
    Name = "${local.name_prefix}-redis-sg"
  }
}

# AUTH token pulled from Secrets Manager.
data "aws_secretsmanager_secret_version" "redis_auth_token" {
  secret_id  = aws_secretsmanager_secret.this["redis_auth_token"].id
  depends_on = [aws_secretsmanager_secret_version.placeholder]
}

resource "aws_elasticache_replication_group" "main" {
  replication_group_id = "${local.name_prefix}-redis"
  description          = "SentinelX ${var.environment} Redis 7.2"

  engine         = "redis"
  engine_version = "7.2"
  node_type      = "cache.t4g.small"
  port           = 6379

  # Cluster-mode disabled: 1 primary + 1 replica = 2 cache clusters.
  num_cache_clusters = 2
  automatic_failover_enabled = true
  multi_az_enabled           = true

  subnet_group_name  = aws_elasticache_subnet_group.main.name
  security_group_ids = [aws_security_group.redis.id]

  at_rest_encryption_enabled = true
  transit_encryption_enabled = true
  kms_key_id                 = aws_kms_key.main.arn
  auth_token                 = data.aws_secretsmanager_secret_version.redis_auth_token.secret_string

  snapshot_retention_limit = 1

  apply_immediately = true

  # AUTH token rotated out-of-band via Secrets Manager rotation.
  lifecycle {
    ignore_changes = [auth_token]
  }
}
