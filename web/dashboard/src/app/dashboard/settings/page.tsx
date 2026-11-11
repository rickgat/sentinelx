import Link from "next/link";
import { redirect } from "next/navigation";
import {
  Fingerprint,
  Palette,
  ShieldCheck,
  KeyRound,
  Laptop,
  Users,
  ClipboardCheck,
} from "lucide-react";

import { auth } from "@/lib/auth";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";

/**
 * Settings hub — a single landing surface for the tenant's configurable
 * areas, each of which has its own dedicated page. Linked from the top-bar
 * account menu. Items whose backing permission the caller lacks still link
 * through; the target page enforces its own gate.
 */

interface SettingLink {
  href: string;
  title: string;
  description: string;
  icon: React.ComponentType<{ className?: string; "aria-hidden"?: boolean }>;
}

const LINKS: ReadonlyArray<SettingLink> = [
  {
    href: "/dashboard/mfa",
    title: "Multi-factor authentication",
    description: "Enroll, verify, or disable TOTP / WebAuthn factors.",
    icon: Fingerprint,
  },
  {
    href: "/dashboard/branding",
    title: "Report branding",
    description: "White-label report logo, colour, and cover/footer.",
    icon: Palette,
  },
  {
    href: "/dashboard/rba",
    title: "Adaptive authentication",
    description: "Risk-based auth signal weights and thresholds.",
    icon: ShieldCheck,
  },
  {
    href: "/dashboard/device-trust",
    title: "Device trust policy",
    description: "Posture requirements for devices accessing the tenant.",
    icon: Laptop,
  },
  {
    href: "/dashboard/admin/secrets",
    title: "Vault secrets & KMS",
    description: "Inspect proxied secret paths and rotate the DEK.",
    icon: KeyRound,
  },
  {
    href: "/dashboard/scim",
    title: "SCIM provisioning",
    description: "Directory-driven user provisioning and tokens.",
    icon: Users,
  },
  {
    href: "/dashboard/compliance/evidence",
    title: "Compliance evidence",
    description: "Collect and export control-evidence bundles.",
    icon: ClipboardCheck,
  },
];

export default async function SettingsPage(): Promise<React.JSX.Element> {
  const session = await auth();
  if (session?.accessToken === undefined) {
    redirect("/login");
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Settings</h1>
        <p className="text-muted-foreground">
          Configure your tenant&apos;s security, identity, and reporting surfaces.
        </p>
      </div>

      <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
        {LINKS.map(({ href, title, description, icon: Icon }) => (
          <Link key={href} href={href} className="group">
            <Card className="h-full transition-colors group-hover:border-accent">
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-base">
                  <Icon className="h-4 w-4 text-accent" aria-hidden />
                  {title}
                </CardTitle>
                <CardDescription>{description}</CardDescription>
              </CardHeader>
              <CardContent>
                <span className="text-sm text-accent group-hover:underline">Open →</span>
              </CardContent>
            </Card>
          </Link>
        ))}
      </div>
    </div>
  );
}
