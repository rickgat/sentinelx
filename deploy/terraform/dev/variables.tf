###############################################################################
# Input variables.
#
# Every variable carries a description, type, and either default or
# `nullable = false` per ops conventions.
###############################################################################

variable "environment" {
  description = "Logical environment name (dev / staging / prod). Drives tags + resource prefixes."
  type        = string
  default     = "dev"
}

variable "region" {
  description = "AWS region the dev stack lives in."
  type        = string
  default     = "ap-southeast-1"
}

variable "vpc_cidr" {
  description = "Primary VPC CIDR. Public subnets are /24 carved from this; private subnets are /22."
  type        = string
  default     = "10.42.0.0/16"
}

variable "rds_multi_az" {
  description = "Whether the Aurora cluster has a Multi-AZ writer fallback. Off for dev to save cost."
  type        = bool
  default     = false
}

variable "eks_version" {
  description = "EKS control-plane Kubernetes version (e.g. 1.30)."
  type        = string
  default     = "1.30"
}

variable "node_instance_type" {
  description = "EC2 instance type for the managed node group."
  type        = string
  default     = "t3.medium"
}

variable "node_desired_size" {
  description = "Desired count of worker nodes in the managed node group."
  type        = number
  default     = 2
}

variable "node_max_size" {
  description = "Hard ceiling for the managed node group autoscaler."
  type        = number
  default     = 5
}

# Wave: hardened per trivy AWS-0040 / AWS-0041 (EKS public endpoint).
# Empty list keeps the API endpoint reachable only from within the VPC.
# For emergency ops without a bastion, add specific office / VPN CIDRs.
variable "eks_public_access_cidrs" {
  description = "Allowlist of CIDRs permitted to reach the EKS public API. Empty = private-only."
  type        = list(string)
  default     = []
}
