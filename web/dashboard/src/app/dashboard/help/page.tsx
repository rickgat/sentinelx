import { redirect } from "next/navigation";

import { getAccessToken } from "@/lib/server-fetch";

import { HelpIndexClient } from "./help-index-client";

/**
 * Help index page (`/dashboard/help`).
 *
 * Server-rendered shell that gates on the same Auth.js session check
 * used by every other dashboard surface, then delegates to the client
 * island that owns the search filter + category card grid. The index
 * itself doesn't fetch from sx-api — its data is the static category
 * catalogue defined in `help-categories.ts`.
 */
export default async function HelpIndexPage() {
  const token = await getAccessToken();
  if (token === null) {
    redirect("/login");
  }
  return <HelpIndexClient />;
}
