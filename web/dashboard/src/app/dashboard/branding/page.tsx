import { redirect } from "next/navigation";
import { Palette } from "lucide-react";

import { auth } from "@/lib/auth";
import { hasPermission } from "@/lib/permissions";
import { getAccessToken } from "@/lib/server-fetch";
import { apiGet } from "@/lib/api-client";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";

import { BrandingClient, type BrandingView } from "./branding-client";

/**
 * Per-tenant report branding (P2-002 MSSP white-label). Operators upload a
 * logo, pick a primary colour, and set optional cover/footer Markdown; the
 * report renderer applies them to executive and technical PDFs. Gated on
 * `report:read` to view and `report:write` to change (enforced again by
 * the backend).
 */
export default async function BrandingPage(): Promise<React.JSX.Element> {
  const session = await auth();
  if (session?.accessToken === undefined) {
    redirect("/login");
  }

  const permissions = session.user.permissions ?? [];
  if (!hasPermission(permissions, "report:read")) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Palette className="h-4 w-4 text-accent" aria-hidden />
            Report Branding
          </CardTitle>
          <CardDescription>
            403 — you do not have the <code>report:read</code> permission.
            Ask an administrator for access.
          </CardDescription>
        </CardHeader>
      </Card>
    );
  }

  const token = await getAccessToken();
  if (token === null) {
    redirect("/login");
  }

  let initial: BrandingView = {
    logo_png_base64: null,
    primary_color_hex: "#C71920",
    cover_md: null,
    footer_md: null,
  };
  try {
    initial = await apiGet<BrandingView>("/v1/reports/branding", token);
  } catch {
    // Fall back to house defaults; the client surfaces load/save errors.
  }

  const canWrite = hasPermission(permissions, "report:write");

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Report Branding</h1>
        <p className="text-muted-foreground">
          White-label the executive and technical PDF reports for your tenant.
        </p>
      </div>
      <Card>
        <CardHeader>
          <CardTitle>White-label settings</CardTitle>
          <CardDescription>
            Logo (PNG, ≤ 200 KiB), primary colour, and optional cover/footer
            Markdown. Changes apply to the next rendered report.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <BrandingClient initial={initial} canWrite={canWrite} />
        </CardContent>
      </Card>
    </div>
  );
}
