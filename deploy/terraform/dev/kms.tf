###############################################################################
# Customer-managed KMS key.
#
# Single CMK reused by:
#   - Secrets Manager (secrets.tf)
#   - RDS Aurora at-rest encryption (rds.tf)
#   - ElastiCache at-rest encryption (elasticache.tf)
#   - EKS envelope-encryption of K8s secrets (eks.tf)
###############################################################################

resource "aws_kms_key" "main" {
  description             = "SentinelX ${var.environment} CMK (secrets + RDS + Redis + EKS)"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  policy = data.aws_iam_policy_document.kms_main.json

  tags = {
    Name = "${local.name_prefix}-cmk"
  }
}

resource "aws_kms_alias" "main" {
  name          = "alias/${local.name_prefix}-cmk"
  target_key_id = aws_kms_key.main.key_id
}

# Account-root admin + AWS service principals allowed for managed integrations.
data "aws_iam_policy_document" "kms_main" {
  statement {
    sid     = "AccountRootFullControl"
    actions = ["kms:*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
    resources = ["*"]
  }

  statement {
    sid = "AllowAWSServicesUseOfKey"
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:DescribeKey",
    ]
    principals {
      type = "Service"
      identifiers = [
        "rds.${var.region}.amazonaws.com",
        "elasticache.${var.region}.amazonaws.com",
        "secretsmanager.${var.region}.amazonaws.com",
        "logs.${var.region}.amazonaws.com",
      ]
    }
    resources = ["*"]
  }
}
