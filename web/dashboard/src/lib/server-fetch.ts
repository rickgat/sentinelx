import { auth } from "@/lib/auth";

/**
 * Resolve the sx-api access token from the current Auth.js session.
 *
 * Returns `null` when there is no session at all OR when the JWT exists
 * but lacks `accessToken` (e.g. immediately after a refresh failure).
 * Server components should respond to `null` with `redirect("/login")`.
 */
export async function getAccessToken(): Promise<string | null> {
  const session = await auth();
  return session?.accessToken ?? null;
}
