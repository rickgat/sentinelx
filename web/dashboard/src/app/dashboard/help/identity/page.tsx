import { redirect } from "next/navigation";

import { getAccessToken } from "@/lib/server-fetch";

import { HelpCategoryLayout } from "../help-layout";
import type { MenuTutorial } from "../help-types";

/**
 * Identity category — users, roles, MFA, RBA scoring, device trust,
 * SCIM provisioning, and tenant switching.
 *
 * Routes covered (7):
 *   - /dashboard/iam
 *   - /dashboard/mfa
 *   - /dashboard/rba
 *   - /dashboard/rba/devices
 *   - /dashboard/device-trust
 *   - /dashboard/scim
 *   - /dashboard/tenants
 */
const TUTORIALS: ReadonlyArray<MenuTutorial> = [
  {
    id: "iam",
    title: "IAM (users and roles)",
    route: "/dashboard/iam",
    purpose:
      "Provision new users, assign roles (admin / analyst / ops), and review who has what permission. The platform's identity source of truth lives here.",
    whenToUse: [
      "Onboarding a new operator who needs platform access.",
      "Off-boarding when someone leaves — to deactivate their account immediately.",
      "Periodic access reviews for SOC 2 or ISO 27001 evidence.",
    ],
    workflow: [
      "Open IAM. Requires `admin:users` — non-admins see a clear 403 card.",
      "Create a user by submitting email + initial role; the system mints an invitation.",
      "Assign / edit roles per user: `admin` (full grants), `analyst` (findings/engagements/reports/compliance), or `ops` (assets/engagements/safety/cloud).",
      "Deactivate a user when they leave; their access tokens revoke and SCIM upstream sees the disable signal.",
    ],
    inputs: [
      "`GET /v1/admin/users` — user list per tenant.",
      "Role definitions are in `crates/sx-iam/src/controller/exchange_oidc.rs` (`role_for_name`).",
    ],
    outputs: [
      "User records + role assignments; downstream SCIM sync (if configured).",
    ],
    roles: ["admin"],
    faqs: [
      {
        q: "Why does my role have fewer permissions than I expected?",
        a: "The platform fails closed: unknown roles get an empty permission set. If `analyst` is missing `findings:update`, the JIT mapping in `exchange_oidc.rs` is the source of truth. Ask an admin to grant a missing permission via a custom role.",
      },
      {
        q: "Can I create a custom role?",
        a: "Custom roles aren't exposed through this UI yet (currently the three built-ins). Request one via the GRC team — they'll provision it backend-side.",
      },
    ],
    references: [
      { label: "/dashboard/scim", href: "/dashboard/scim" },
      { label: "/dashboard/mfa", href: "/dashboard/mfa" },
      { label: "Help: Governance", href: "/dashboard/help/governance" },
    ],
  },
  {
    id: "mfa",
    title: "MFA enrolment",
    route: "/dashboard/mfa",
    purpose:
      "Self-service MFA enrolment surface. The page renders a TOTP QR code + verification flow so a user can bind their authenticator app to the platform.",
    whenToUse: [
      "First time you log in (the platform recommends MFA for every operator).",
      "When migrating to a new authenticator device.",
      "When re-enrolling after a stolen-device incident.",
    ],
    workflow: [
      "Open MFA from the Identity & Access sidebar group.",
      "Scan the QR code with your authenticator app (1Password, Authy, Google Authenticator).",
      "Enter the 6-digit code from the app into the verify field.",
      "Click Verify. The platform stores the enrolment, and adaptive auth (RBA) will treat your sessions as recently-MFA from then on.",
    ],
    inputs: [
      "Currently a stub — the QR code is a placeholder SVG. The verify button does not call the backend yet.",
      "Real backing endpoint will be `POST /v1/auth/mfa/enroll` once delivered.",
    ],
    outputs: [
      "(Future) A persisted TOTP secret bound to the user record; the `mfa_recent` RBA feature flips to true.",
    ],
    roles: ["analyst", "ops", "admin"],
    faqs: [
      {
        q: "Why does the verify button not actually verify?",
        a: "The TOTP flow is stubbed for visual completeness; the backing endpoint lands in a future round. Use SAML/OIDC SSO for production logins until then.",
      },
      {
        q: "Does MFA satisfy the RBA `w_mfa_recent` weight?",
        a: "Yes — once the real enrolment endpoint lands. The RBA scorer reads the `mfa_recent` boolean from the session and applies the weight to the risk score.",
      },
    ],
    references: [
      { label: "/dashboard/rba", href: "/dashboard/rba" },
      { label: "/dashboard/iam", href: "/dashboard/iam" },
    ],
  },
  {
    id: "rba",
    title: "Adaptive auth (RBA)",
    route: "/dashboard/rba",
    purpose:
      "View the most recent risk-based authentication decisions and tune the scoring weights + thresholds that determine whether a sign-in is allowed, challenged, or blocked.",
    whenToUse: [
      "When investigating why a legitimate user got challenged for MFA.",
      "When tuning the scoring weights for a new threat model.",
      "Auditing the last 100 decisions for false-positive rate.",
    ],
    workflow: [
      "Open RBA. Decisions + active config render SSR.",
      "Inspect the decisions table: timestamp, user, ip, score, outcome (`allow`, `challenge`, `block`).",
      "If you spot a misfire, open the config panel and adjust the relevant weight (e.g. drop `w_ip_geo` if IP geolocation is too aggressive).",
      "Confirm thresholds: `allow_threshold` (default 30) and `block_threshold` (default 70). Scores in between trigger challenge.",
      "Save — the new config applies to the next sign-in.",
    ],
    inputs: [
      "`GET /v1/rba/decisions?limit=100` — recent decisions.",
      "`GET /v1/rba/config` — active per-tenant config.",
      "`POST /v1/rba/config` — write tuned weights.",
      "Default weights: `w_ip_geo=0.25, w_velocity=0.20, w_business_hours=0.10, w_device_fp=0.15, w_mfa_recent=0.10, w_success_rate=0.05, w_impossible_travel=0.15`.",
    ],
    outputs: [
      "Updated scoring config (audit-logged).",
      "Downstream behaviour change on every subsequent sign-in.",
    ],
    roles: ["admin"],
    faqs: [
      {
        q: "Why does a user with low historical risk get a high score?",
        a: "Velocity + impossible-travel features look at the last 24h of activity. If the user logged in from two geographies in quick succession, those signals dominate the score. Inspect the decision's per-feature breakdown to confirm.",
      },
      {
        q: "What is the `business_hours` feature?",
        a: "A feature that penalises sign-ins outside the tenant's configured business window. Disable via the feature flag panel if your team is global.",
      },
    ],
    references: [
      { label: "/dashboard/rba/devices", href: "/dashboard/rba/devices" },
      { label: "/dashboard/mfa", href: "/dashboard/mfa" },
      { label: "Help: SOC + Detection", href: "/dashboard/help/soc-detection" },
    ],
  },
  {
    id: "rba-devices",
    title: "RBA known devices",
    route: "/dashboard/rba/devices",
    purpose:
      "Per-user inventory of 'known devices' tracked by the RBA fingerprint scorer. Lets you review a user's device list and revoke any device you don't recognise.",
    whenToUse: [
      "After a user reports a suspected account compromise — to revoke unknown devices.",
      "Quarterly hygiene — pruning long-stale device entries.",
      "When tuning RBA: high `w_device_fp` only makes sense if the device list is curated.",
    ],
    workflow: [
      "Open RBA → Known Devices. The user picker is SSR-populated.",
      "Pick a user. The client fetches their device list on demand.",
      "Inspect each row: device fingerprint, first seen, last seen.",
      "Click 'Revoke' on any unfamiliar device; the next sign-in from that fingerprint scores as new.",
    ],
    inputs: [
      "`GET /v1/admin/users` — user picker source.",
      "`GET /v1/rba/devices?user_id={id}` — per-user list.",
      "`POST /v1/rba/devices/{id}/revoke` — revoke action.",
    ],
    outputs: [
      "Revocation events surfaced in the user's audit log + the RBA decision feed.",
    ],
    roles: ["admin"],
    faqs: [
      {
        q: "Why is the picker empty?",
        a: "Either the admin-user-list endpoint failed or the tenant has no users. The page still renders so you can retry without a hard error.",
      },
    ],
    references: [
      { label: "/dashboard/rba", href: "/dashboard/rba" },
      { label: "/dashboard/iam", href: "/dashboard/iam" },
    ],
  },
  {
    id: "device-trust",
    title: "Device trust",
    route: "/dashboard/device-trust",
    purpose:
      "Define and inspect device-posture policy: which OSes are allowed, minimum versions, accepted EDR vendors, screen-lock requirements. Every active session is evaluated against the policy.",
    whenToUse: [
      "When tightening posture for a regulated tenant (e.g. PCI scope).",
      "Investigating why a session was downgraded or blocked.",
      "Quarterly policy review for SOC 2 evidence.",
    ],
    workflow: [
      "Open Device Trust. The policy + the latest 50 sessions render SSR.",
      "Inspect the policy: OS allow-list, OS block-list, minimum OS versions, EDR vendor allow-list, max screen-lock minutes.",
      "Inspect the sessions table: each row shows the session's OS, EDR vendor, screen-lock minutes, and policy verdict.",
      "If a session is blocked, the user gets a posture-fail message at sign-in and must remediate (e.g. update OS) before retrying.",
    ],
    inputs: [
      "`GET /v1/device-trust/policy` — active policy.",
      "`GET /v1/device-trust/sessions?limit=50` — recent posture checks.",
    ],
    outputs: [
      "Policy changes (audit-logged); session verdicts (read-only telemetry).",
    ],
    roles: ["admin"],
    faqs: [
      {
        q: "Why does the policy say 'no rules'?",
        a: "Empty defaults mean every session is allowed — useful in dev but never for production. Add at least an OS allow-list before opening to real users.",
      },
      {
        q: "Does this gate ALL sign-ins or only some?",
        a: "Device-trust is consulted on every sign-in after RBA scoring. A `block` verdict overrides an RBA `allow`.",
      },
    ],
    references: [
      { label: "/dashboard/rba", href: "/dashboard/rba" },
      { label: "/dashboard/ueba", href: "/dashboard/ueba" },
    ],
  },
  {
    id: "scim",
    title: "SCIM provisioning",
    route: "/dashboard/scim",
    purpose:
      "Mint and revoke SCIM 2.0 tokens so an external IdP (Okta, Azure AD, Google Workspace) can provision users + roles into the platform automatically.",
    whenToUse: [
      "When connecting the platform to a corporate IdP for the first time.",
      "Rotating a SCIM token after a suspected leak.",
      "Confirming the upstream IdP successfully synced a user list.",
    ],
    workflow: [
      "Open SCIM. The token catalogue + recent synced-user snapshot render SSR.",
      "Click 'Mint token'. Provide a name (e.g. `Okta production`); the page returns the token exactly once — copy it now.",
      "Paste the token into the upstream IdP's SCIM connector.",
      "Confirm sync by watching the synced-user table update.",
      "Revoke a token when no longer needed; the corresponding sync stops immediately.",
    ],
    inputs: [
      "`GET /v1/scim/tokens` — token catalogue.",
      "`POST /v1/scim/tokens` — mint.",
      "`DELETE /v1/scim/tokens/{id}` — revoke.",
      "Upstream IdP requests authenticate with the minted token.",
    ],
    outputs: [
      "Provisioned user records (visible in IAM).",
      "Audit log of every token mint/revoke.",
    ],
    roles: ["admin"],
    faqs: [
      {
        q: "I lost the token — can I show it again?",
        a: "No. Tokens are shown once at mint time and never persisted in cleartext. Mint a new one and update the upstream IdP.",
      },
      {
        q: "Why is a user I deleted in Okta still in IAM?",
        a: "SCIM 2.0 issues a soft-disable (`active: false`) by default — the user is deactivated, not deleted. If you need a hard delete, do it in IAM.",
      },
    ],
    references: [
      { label: "/dashboard/iam", href: "/dashboard/iam" },
    ],
  },
  {
    id: "tenants",
    title: "Tenants",
    route: "/dashboard/tenants",
    purpose:
      "View the current tenant context and switch to a different tenant when an operator has multi-tenant access.",
    whenToUse: [
      "When you're an MSSP analyst rotating between customer tenants.",
      "When diagnosing a tenant-isolation issue (to confirm which tenant your session is in).",
      "When demoing — to quickly hop between sandbox + customer tenants.",
    ],
    workflow: [
      "Open Tenants. The current tenant card renders SSR via `GET /v1/tenants/me`.",
      "Read the tenant id and name to confirm context.",
      "Use the 'Switch by id' form for manual switching — paste the target tenant id and submit.",
      "The session re-issues against the new tenant; you land back on the dashboard scoped to the new context.",
    ],
    inputs: [
      "`GET /v1/tenants/me` — current tenant identity.",
      "`POST /v1/tenants/switch` — manual switch.",
    ],
    outputs: [
      "Session refresh under the new tenant scope.",
    ],
    roles: ["analyst", "ops", "admin"],
    faqs: [
      {
        q: "Why is there no tenant dropdown?",
        a: "No listing endpoint exists yet — every operator pastes the target tenant id manually for now. The dropdown lands when `GET /v1/tenants` ships.",
      },
    ],
    references: [
      { label: "/dashboard/iam", href: "/dashboard/iam" },
    ],
  },
];

export default async function IdentityHelpPage() {
  const token = await getAccessToken();
  if (token === null) {
    redirect("/login");
  }
  return (
    <HelpCategoryLayout
      category="identity"
      title="Identity and access"
      intro="Users, roles, MFA, adaptive risk-based auth, device-posture policy, SCIM provisioning, and tenant switching. Most of these surfaces require the admin role; the per-tutorial badge tells you which."
      tutorials={TUTORIALS}
    />
  );
}
