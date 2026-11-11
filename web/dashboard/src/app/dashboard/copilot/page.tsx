import { redirect } from "next/navigation";

import { getAccessToken } from "@/lib/server-fetch";

import { CopilotClient } from "./copilot-client";

/**
 * AI Copilot — chat surface backed by `POST /v1/copilot/chat`.
 *
 * The transcript stays in component state; each submit fires a fresh
 * single-turn request through the `/api/copilot/chat` proxy so the
 * bearer token never leaves the server. The client detects a 422
 * envelope (the disabled-provider shape) and swaps the banner copy in
 * place, so this page only ships the steady-state disclaimer.
 */
export default async function CopilotPage() {
  const token = await getAccessToken();
  if (token === null) {
    redirect("/login");
  }
  return <CopilotClient />;
}
