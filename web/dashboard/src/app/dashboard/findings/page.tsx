import { redirect } from "next/navigation";

import { apiGet, ApiError } from "@/lib/api-client";
import { getAccessToken } from "@/lib/server-fetch";
import type { Finding, Page } from "@/lib/types";
import { FindingsClient } from "./findings-client";

export default async function FindingsPage() {
  const token = await getAccessToken();
  if (token === null) {
    redirect("/login");
  }

  let items: ReadonlyArray<Finding> = [];
  let apiAvailable = true;
  try {
    const page = await apiGet<Page<Finding>>("/v1/findings?limit=200", token);
    items = page.items;
  } catch (err) {
    apiAvailable = false;
    void (err instanceof ApiError);
  }

  return <FindingsClient initialData={items} apiAvailable={apiAvailable} />;
}
