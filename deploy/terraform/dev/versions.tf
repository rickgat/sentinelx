###############################################################################
# Required Terraform + provider versions.
#
# State backend defaults to LOCAL (./terraform.tfstate). For prod, switch to
# the S3 + DynamoDB block at the bottom of this file.
###############################################################################

terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.60"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
  }

  # ---------------------------------------------------------------------------
  # Local state (default for dev).
  # ---------------------------------------------------------------------------
  # backend "local" {
  #   path = "terraform.tfstate"
  # }

  # ---------------------------------------------------------------------------
  # Remote state for prod — uncomment and adjust, then run `terraform init -migrate-state`.
  #
  # backend "s3" {
  #   bucket         = "sentinelx-tfstate-prod"
  #   key            = "prod/terraform.tfstate"
  #   region         = "ap-southeast-1"
  #   dynamodb_table = "sentinelx-tfstate-locks"
  #   encrypt        = true
  # }
  # ---------------------------------------------------------------------------
}
