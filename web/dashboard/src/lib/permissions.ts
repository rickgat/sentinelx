/**
 * Permission utilities for the SentinelX dashboard.
 *
 * Backend `sx-iam` mints access tokens with a `permissions` claim shaped
 * as `["<resource>:<action>", ...]`. The bootstrap admin role receives
 * the wildcard `"*:*"` (grant everything), documented in
 * `crates/sx-iam/src/service/policy.rs`. Individual permissions may
 * carry their own wildcard on the resource OR action half — e.g.
 * `"admin:*"` (all admin actions) or `"*:read"` (read anywhere).
 *
 * The dashboard's per-page authorisation gates (IAM, SCIM, admin/secrets,
 * sidebar item `requiresPermission`) previously called
 * `permissions.includes("<needle>")` as a literal-string check, which
 * treated a wildcard-holding admin as unauthorised. `hasPermission`
 * centralises the wildcard-aware check so every gate agrees.
 *
 * Rules:
 *   1. `"*:*"` matches anything.
 *   2. `"<resource>:*"` matches every action on that resource.
 *   3. `"*:<action>"` matches that action on any resource.
 *   4. Otherwise, exact string equality.
 */
export function hasPermission(
  permissions: readonly string[],
  needle: string,
): boolean {
  const parts = needle.split(":");
  if (parts.length !== 2) {
    return permissions.includes(needle);
  }
  const [needResource, needAction] = parts;
  for (const p of permissions) {
    if (p === needle) {
      return true;
    }
    if (p === "*:*") {
      return true;
    }
    const pParts = p.split(":");
    if (pParts.length !== 2) {
      continue;
    }
    const [pResource, pAction] = pParts;
    const resourceMatches = pResource === "*" || pResource === needResource;
    const actionMatches = pAction === "*" || pAction === needAction;
    if (resourceMatches && actionMatches) {
      return true;
    }
  }
  return false;
}
