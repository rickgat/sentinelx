import { redirect } from "next/navigation";

import { apiGet, ApiError } from "@/lib/api-client";
import { getAccessToken } from "@/lib/server-fetch";
import type { Engagement, Page } from "@/lib/types";
import { EngagementsClient } from "./engagements-client";

export default async function EngagementsPage() {
  const token = await getAccessToken();
  if (token === null) {
    redirect("/login");
  }

  let items: ReadonlyArray<Engagement> = [];
  let apiAvailable = true;
  try {
    const page = await apiGet<Page<Engagement>>("/v1/engagements?limit=200", token);
    items = page.items;
  } catch (err) {
    apiAvailable = false;
    void (err instanceof ApiError);
  }

  return <EngagementsClient initialData={items} apiAvailable={apiAvailable} />;
}
