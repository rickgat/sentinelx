import { redirect } from "next/navigation";

import { apiGet, ApiError } from "@/lib/api-client";
import { getAccessToken } from "@/lib/server-fetch";

import { TenantsClient, type TenantSummaryView } from "./tenants-client";

/**
 * Tenant switcher.
 *
 * Fetches the current tenant via `GET /v1/tenants/me`. There is no
 * listing endpoint yet, so the page also exposes a manual "switch by
 * id" form for operators with multi-tenant access.
 */
export default async function TenantsPage() {
  const token = await getAccessToken();
  if (token === null) {
    redirect("/login");
  }

  let current: TenantSummaryView | null = null;
  let apiAvailable = true;
  try {
    current = await apiGet<TenantSummaryView>("/v1/tenants/me", token);
  } catch (err) {
    apiAvailable = false;
    void (err instanceof ApiError);
  }

  return <TenantsClient current={current} apiAvailable={apiAvailable} />;
}
