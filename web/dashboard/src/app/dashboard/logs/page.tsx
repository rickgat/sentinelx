import { redirect } from "next/navigation";

import { apiGet, ApiError } from "@/lib/api-client";
import { getAccessToken } from "@/lib/server-fetch";

import { LogsClient, type OcsfEventView } from "./logs-client";

/**
 * OCSF log ingest viewer.
 *
 * Server-rendered initial snapshot of the per-tenant ring buffer via
 * `GET /v1/logs?limit=50`. The client component then polls the same
 * endpoint (proxied through `/api/logs`) on demand and exposes a manual
 * ingest form that POSTs to `/api/logs/ingest`.
 */

interface ListLogsResponse {
  items: OcsfEventView[];
}

export default async function LogsPage() {
  const token = await getAccessToken();
  if (token === null) {
    redirect("/login");
  }

  let items: ReadonlyArray<OcsfEventView> = [];
  let apiAvailable = true;
  try {
    const page = await apiGet<ListLogsResponse>("/v1/logs?limit=50", token);
    items = page.items;
  } catch (err) {
    apiAvailable = false;
    void (err instanceof ApiError);
  }

  return <LogsClient initialData={items} apiAvailable={apiAvailable} />;
}
