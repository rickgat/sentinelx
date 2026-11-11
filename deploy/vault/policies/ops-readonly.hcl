# Vault policy: read-only ops engineer
#
# Allows oncall engineers to observe Vault health + seal status without
# ever touching secret material.
#
# Mapped controls:
#   NIST AU-12, IA-2
#   ISO/IEC 27001 A.5.16, A.8.15
#   SOC2 CC6.1, CC7.2

path "sys/health" {
  capabilities = ["read"]
}

path "sys/seal-status" {
  capabilities = ["read"]
}
