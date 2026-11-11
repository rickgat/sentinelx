import { redirect } from "next/navigation";

/**
 * Root index: send users to the dashboard. Auth-gated routes will
 * bounce unauthenticated visitors back to /login once Auth.js is wired.
 */
export default function RootIndex(): never {
  redirect("/dashboard");
}
