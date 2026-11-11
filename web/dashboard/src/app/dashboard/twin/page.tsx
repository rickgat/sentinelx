import { redirect } from "next/navigation";

import { apiGet, ApiError } from "@/lib/api-client";
import { getAccessToken } from "@/lib/server-fetch";
import type { Engagement, Page } from "@/lib/types";

import { TwinClient } from "./twin-client";

/**
 * Cyber Digital Twin viewer.
 *
 * Server-side bootstrap: resolves the access token and pre-loads the
 * engagement list so the client component can offer a selector without
 * a second round trip. The actual twin projection is fetched lazily by
 * the client when the operator picks an engagement and clicks "Load twin".
 */
export default async function TwinPage() {
  const token = await getAccessToken();
  if (token === null) {
    redirect("/login");
  }

  let engagements: ReadonlyArray<Engagement> = [];
  let apiAvailable = true;
  try {
    const page = await apiGet<Page<Engagement>>(
      "/v1/engagements?limit=200",
      token,
    );
    engagements = page.items;
  } catch (err) {
    apiAvailable = false;
    void (err instanceof ApiError);
  }

  return <TwinClient engagements={engagements} apiAvailable={apiAvailable} />;
}
