###############################################################################
# AWS provider — region from var.region.
#
# default_tags propagate to every taggable resource for cost attribution.
###############################################################################

provider "aws" {
  region = var.region

  default_tags {
    tags = {
      Project     = "SentinelX"
      Environment = var.environment
      ManagedBy   = "Terraform"
    }
  }
}
