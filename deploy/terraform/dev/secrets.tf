###############################################################################
# AWS Secrets Manager entries.
#
# Every entry is created with a REPLACE_ME placeholder so plan/apply is safe.
# Real values are injected out-of-band — see README for the
# `aws secretsmanager put-secret-value` workflow.
###############################################################################

resource "aws_secretsmanager_secret" "this" {
  for_each = local.secret_names

  name        = each.value
  description = "SentinelX ${var.environment} secret: ${each.key}"
  kms_key_id  = aws_kms_key.main.arn

  # Dev: 7-day window so we can recover quickly during testing.
  recovery_window_in_days = 7

  tags = {
    Name = each.value
  }
}

# Placeholder values — DO NOT hold real secrets in state.
resource "aws_secretsmanager_secret_version" "placeholder" {
  for_each = aws_secretsmanager_secret.this

  secret_id     = each.value.id
  secret_string = "REPLACE_ME"

  # Once an out-of-band put-secret-value rotates the real secret in, Terraform
  # must not flap it back to the placeholder.
  lifecycle {
    ignore_changes = [secret_string]
  }
}
