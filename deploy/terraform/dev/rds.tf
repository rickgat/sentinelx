###############################################################################
# RDS — Aurora PostgreSQL 16, Serverless v2 (1–8 ACU).
#
# - Encrypted at-rest with the project CMK.
# - Master password rotated via Secrets Manager (placeholder in secrets.tf;
#   real value set out-of-band).
# - Deletion protection on. 7-day automated backups.
# - Multi-AZ only when var.rds_multi_az = true (off in dev).
###############################################################################

# DB subnet group covers every private subnet.
resource "aws_db_subnet_group" "main" {
  name       = "${local.name_prefix}-db-subnets"
  subnet_ids = [for s in aws_subnet.private : s.id]

  tags = {
    Name = "${local.name_prefix}-db-subnets"
  }
}

# Aurora cluster SG: only EKS nodes reach 5432.
resource "aws_security_group" "rds" {
  name        = "${local.name_prefix}-rds-sg"
  description = "Aurora cluster SG — Postgres 5432 from EKS only"
  vpc_id      = aws_vpc.main.id

  ingress {
    description     = "Postgres from EKS cluster SG"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.eks_cluster.id]
  }

  # Wave: hardened per trivy AWS-0104 (unrestricted egress).
  # RDS holds highly-sensitive data — deny all outbound. Aurora only
  # needs internal AWS endpoints via the VPC-endpoints Route table.
  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.main.cidr_block]
    description = "HTTPS to VPC endpoints (KMS, S3-backups)"
  }

  tags = {
    Name = "${local.name_prefix}-rds-sg"
  }
}

# Pulls the placeholder/real master password from Secrets Manager so the
# `master_password` argument never sits as plaintext in any tfvars file.
data "aws_secretsmanager_secret_version" "rds_master_user_pw" {
  secret_id  = aws_secretsmanager_secret.this["rds_master_user_pw"].id
  depends_on = [aws_secretsmanager_secret_version.placeholder]
}

resource "aws_rds_cluster" "main" {
  cluster_identifier = "${local.name_prefix}-aurora"
  engine             = "aurora-postgresql"
  engine_mode        = "provisioned"
  engine_version     = "16.2"
  database_name      = "sentinelx"
  master_username    = "sentinelx_admin"
  master_password    = data.aws_secretsmanager_secret_version.rds_master_user_pw.secret_string

  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.rds.id]

  storage_encrypted   = true
  kms_key_id          = aws_kms_key.main.arn
  deletion_protection = true

  backup_retention_period      = 7
  preferred_backup_window      = "17:00-18:00" # UTC; ~midnight Singapore.
  preferred_maintenance_window = "sun:18:30-sun:19:30"

  # Serverless v2 capacity bounds — overridden per instance below.
  serverlessv2_scaling_configuration {
    min_capacity = 1
    max_capacity = 8
  }

  # Final snapshot disabled for dev convenience; flip for prod.
  skip_final_snapshot = true

  # Master password is rotated out-of-band via Secrets Manager — don't reset
  # it on every plan from a stale data-source read.
  lifecycle {
    ignore_changes = [master_password]
  }
}

# Writer instance.
resource "aws_rds_cluster_instance" "writer" {
  identifier          = "${local.name_prefix}-aurora-writer"
  cluster_identifier  = aws_rds_cluster.main.id
  instance_class      = "db.serverless"
  engine              = aws_rds_cluster.main.engine
  engine_version      = aws_rds_cluster.main.engine_version
  publicly_accessible = false
}

# Optional read replica when multi-AZ is requested.
resource "aws_rds_cluster_instance" "reader" {
  count = var.rds_multi_az ? 1 : 0

  identifier          = "${local.name_prefix}-aurora-reader"
  cluster_identifier  = aws_rds_cluster.main.id
  instance_class      = "db.serverless"
  engine              = aws_rds_cluster.main.engine
  engine_version      = aws_rds_cluster.main.engine_version
  publicly_accessible = false
}
