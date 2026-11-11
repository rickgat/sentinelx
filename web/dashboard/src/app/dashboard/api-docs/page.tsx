import type { ReactElement } from "react";
import { redirect } from "next/navigation";

import { getAccessToken } from "@/lib/server-fetch";

import { SwaggerClient } from "./swagger-client";

/**
 * API Docs — Swagger UI rendering the sx-api OpenAPI 3.1 schema.
 *
 * The page is gated by the same Auth.js session check used by the rest
 * of the dashboard: if the caller has no usable access token we bounce
 * them to `/login`. The actual schema is fetched by the client via the
 * `/api/openapi` same-origin proxy, which forwards to `${SX_API}/openapi.json`.
 *
 * The proxy + Swagger UI together expose no secrets — the schema is a
 * public read on the backend's `public` subrouter — but gating on
 * session keeps the surface inside the authenticated dashboard so we
 * don't accidentally publish an internal description to anonymous
 * visitors hitting the marketing origin.
 */
export default async function ApiDocsPage(): Promise<ReactElement> {
  const token = await getAccessToken();
  if (token === null) {
    redirect("/login");
  }
  return <SwaggerClient />;
}
