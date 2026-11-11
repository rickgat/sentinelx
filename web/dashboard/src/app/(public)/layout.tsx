import * as React from "react";

/**
 * Layout for unauthenticated customer-facing auth pages
 * (signup, verify-email, forgot-password, reset-password).
 *
 * Intentionally minimal — no sidebar, no dashboard chrome — so it matches
 * the centered-card aesthetic of `/login`.
 */
export default function PublicLayout({ children }: { children: React.ReactNode }) {
  return <>{children}</>;
}
