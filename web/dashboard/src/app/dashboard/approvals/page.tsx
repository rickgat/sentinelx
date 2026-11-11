import { redirect } from "next/navigation";

import { apiGet, ApiError } from "@/lib/api-client";
import { auth } from "@/lib/auth";
import { getAccessToken } from "@/lib/server-fetch";
import type { Engagement, Page } from "@/lib/types";
import { ApprovalsClient } from "./approvals-client";

export default async function ApprovalsPage() {
  const token = await getAccessToken();
  if (token === null) {
    redirect("/login");
  }

  const session = await auth();
  const defaultEmail = session?.user?.email ?? "";

  let engagements: ReadonlyArray<Engagement> = [];
  let apiAvailable = true;
  try {
    const page = await apiGet<Page<Engagement>>("/v1/engagements?limit=200", token);
    engagements = page.items;
  } catch (err) {
    apiAvailable = false;
    void (err instanceof ApiError);
  }

  return (
    <ApprovalsClient
      engagements={engagements}
      apiAvailable={apiAvailable}
      defaultEmail={defaultEmail}
    />
  );
}
