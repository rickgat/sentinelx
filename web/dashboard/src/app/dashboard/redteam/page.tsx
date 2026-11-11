import { redirect } from "next/navigation";

import { apiGet, ApiError } from "@/lib/api-client";
import { getAccessToken } from "@/lib/server-fetch";
import type { Engagement, Page } from "@/lib/types";

import { RedTeamClient } from "./redteam-client";

export default async function RedTeamPage() {
  const token = await getAccessToken();
  if (token === null) {
    redirect("/login");
  }

  let engagements: ReadonlyArray<Engagement> = [];
  let apiAvailable = true;
  try {
    const page = await apiGet<Page<Engagement>>("/v1/engagements?limit=200", token);
    engagements = page.items;
  } catch (err) {
    apiAvailable = false;
    void (err instanceof ApiError);
  }

  return <RedTeamClient engagements={engagements} apiAvailable={apiAvailable} />;
}
