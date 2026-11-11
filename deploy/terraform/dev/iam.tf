###############################################################################
# IRSA — IAM Role for the sx-monolith Kubernetes ServiceAccount.
#
# Trust:  EKS OIDC provider, scoped to system:serviceaccount:sentinelx:sx-monolith
# Grants: secretsmanager:GetSecretValue on the project secret ARNs + kms:Decrypt
#         on the project CMK. Nothing else.
###############################################################################

locals {
  irsa_namespace       = "sentinelx"
  irsa_service_account = "sx-monolith"

  oidc_provider_url = replace(aws_iam_openid_connect_provider.eks.url, "https://", "")
}

# Trust policy: only the named SA from the OIDC issuer can assume this role.
data "aws_iam_policy_document" "irsa_assume" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.eks.arn]
    }

    condition {
      test     = "StringEquals"
      variable = "${local.oidc_provider_url}:sub"
      values   = ["system:serviceaccount:${local.irsa_namespace}:${local.irsa_service_account}"]
    }

    condition {
      test     = "StringEquals"
      variable = "${local.oidc_provider_url}:aud"
      values   = ["sts.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "irsa_monolith" {
  name               = "${local.name_prefix}-irsa-monolith"
  assume_role_policy = data.aws_iam_policy_document.irsa_assume.json

  tags = {
    Name = "${local.name_prefix}-irsa-monolith"
  }
}

# Least-privilege permissions: read the listed secrets, decrypt with the CMK.
data "aws_iam_policy_document" "irsa_monolith" {
  statement {
    sid     = "ReadProjectSecrets"
    actions = ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"]
    resources = [for s in aws_secretsmanager_secret.this : s.arn]
  }

  statement {
    sid     = "DecryptWithProjectCmk"
    actions = ["kms:Decrypt"]
    resources = [aws_kms_key.main.arn]
  }
}

resource "aws_iam_policy" "irsa_monolith" {
  name        = "${local.name_prefix}-irsa-monolith"
  description = "Least-privilege policy for sx-monolith ServiceAccount"
  policy      = data.aws_iam_policy_document.irsa_monolith.json
}

resource "aws_iam_role_policy_attachment" "irsa_monolith" {
  role       = aws_iam_role.irsa_monolith.name
  policy_arn = aws_iam_policy.irsa_monolith.arn
}
