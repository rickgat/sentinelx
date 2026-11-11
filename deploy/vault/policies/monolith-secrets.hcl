# Vault policy: sx-monolith service account
#
# Grants read on the five operational secrets the monolith requires.
# No write, no list, no delete.
#
# Mapped controls:
#   NIST AC-3, IA-5
#   ISO/IEC 27001 A.5.15, A.8.5
#   SOC2 CC6.1

path "sentinelx/data/dev/db-url" {
  capabilities = ["read"]
}

path "sentinelx/data/dev/redis-url" {
  capabilities = ["read"]
}

path "sentinelx/data/dev/jwt-signing-key" {
  capabilities = ["read"]
}

path "sentinelx/data/dev/attempt-email-pepper" {
  capabilities = ["read"]
}

path "sentinelx/data/dev/bootstrap-admin-phc" {
  capabilities = ["read"]
}

# Allow self-introspection so the agent can renew its own token.
path "auth/token/renew-self" {
  capabilities = ["update"]
}

path "auth/token/lookup-self" {
  capabilities = ["read"]
}
