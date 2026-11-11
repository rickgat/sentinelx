import Link from "next/link";
import { redirect } from "next/navigation";
import { BookOpen } from "lucide-react";

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { getAccessToken } from "@/lib/server-fetch";
import { COMPLIANCE_FRAMEWORKS } from "@/lib/types";

const LABELS: Record<(typeof COMPLIANCE_FRAMEWORKS)[number], string> = {
  iso27001: "ISO 27001",
  soc2: "SOC 2",
  pci_dss: "PCI DSS",
  hipaa: "HIPAA",
  nist_800_53: "NIST 800-53",
  cis_aws: "CIS AWS",
  fedramp_moderate: "FedRAMP Moderate",
};

export default async function ComplianceIndexPage() {
  const token = await getAccessToken();
  if (token === null) {
    redirect("/login");
  }

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle>Compliance frameworks</CardTitle>
          <CardDescription>
            Choose a framework to view its controls. Sourced from the sx-api compliance registry.
          </CardDescription>
        </CardHeader>
        <CardContent className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {COMPLIANCE_FRAMEWORKS.map((framework) => (
            <Link
              key={framework}
              href={`/dashboard/compliance/${framework}`}
              className="group flex items-center gap-3 rounded-sx border border-border bg-transparent px-3 py-2 text-sm text-foreground transition-colors hover:bg-muted"
            >
              <BookOpen className="h-4 w-4 text-accent" aria-hidden />
              <span className="font-medium">{LABELS[framework]}</span>
              <span className="ml-auto text-xs text-muted-foreground group-hover:text-foreground">→</span>
            </Link>
          ))}
        </CardContent>
      </Card>
    </div>
  );
}
