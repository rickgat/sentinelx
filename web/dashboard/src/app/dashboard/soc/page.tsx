import { redirect } from "next/navigation";

import { apiGet, ApiError } from "@/lib/api-client";
import { getAccessToken } from "@/lib/server-fetch";

import { SocClient, type SocAlert } from "./soc-client";

/**
 * SOC alert feed.
 *
 * Server-rendered initial snapshot of the live SOC correlator buffer via
 * `GET /v1/soc/alerts`. The client component then polls the same endpoint
 * (proxied through `/api/soc/alerts`) every 30 s using the Auth.js bearer.
 */

interface ListSocAlertsResponse {
  items: SocAlert[];
}

export default async function SocPage() {
  const token = await getAccessToken();
  if (token === null) {
    redirect("/login");
  }

  let items: ReadonlyArray<SocAlert> = [];
  let apiAvailable = true;
  try {
    const page = await apiGet<ListSocAlertsResponse>("/v1/soc/alerts", token);
    items = page.items;
  } catch (err) {
    apiAvailable = false;
    void (err instanceof ApiError);
  }

  return <SocClient initialData={items} apiAvailable={apiAvailable} />;
}
