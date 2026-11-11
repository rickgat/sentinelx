import { redirect } from "next/navigation";

import { apiGet } from "@/lib/api-client";
import { getAccessToken } from "@/lib/server-fetch";

import { RbaDevicesClient, type AdminUserOption } from "./devices-client";

/**
 * "Known devices" panel — LOW-008 (HIGH-001 follow-up).
 *
 * Server-rendered: pre-loads the tenant-scoped user list so the
 * autocomplete picker has something to filter against on first paint.
 * The client component fetches per-user device inventories on demand
 * and handles the revoke flow.
 *
 * Permission gating: the underlying sx-api endpoints require
 * `admin:users`. The sidebar already gates `/dashboard/rba` on that
 * permission, so reaching this page implies the operator has it.
 * If the upstream user-list call fails (e.g. the operator's token
 * lapsed), the client still renders with an empty picker so they can
 * trigger a retry.
 */

interface AdminUserSummary {
  id: string;
  tenant_id: string;
  email: string;
  is_active: boolean;
  role_count: number;
  created_at: string;
}

// Backend `/v1/admin/users` returns the users list directly as the
// envelope's `data` field (an array), NOT nested under a `users`
// key. `apiGet<T>` unwraps `data` into `T`, so `T` here must be the
// array shape, not a wrapper object. Previous
// `interface ListUsersBody { users: AdminUserSummary[] }` caused
// `result.value.users` to be `undefined` and the server-side `.map`
// crashed, dropping the RBA devices page into an error boundary and
// blocking the LOW-008 flow from ever hydrating in the browser.
type ListUsersBody = AdminUserSummary[];

export default async function RbaDevicesPage(): Promise<React.JSX.Element> {
  const token = await getAccessToken();
  if (token === null) {
    redirect("/login");
  }

  const result = await Promise.allSettled([
    apiGet<ListUsersBody>("/v1/admin/users?limit=500&offset=0", token),
  ]);

  const users: AdminUserOption[] =
    result[0].status === "fulfilled"
      ? result[0].value.map((u) => ({
          id: u.id,
          email: u.email,
          is_active: u.is_active,
        }))
      : [];

  return <RbaDevicesClient initialUsers={users} />;
}
