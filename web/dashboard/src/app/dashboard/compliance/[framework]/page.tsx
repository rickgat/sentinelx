import Link from "next/link";
import { notFound, redirect } from "next/navigation";

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { apiGet, ApiError } from "@/lib/api-client";
import { getAccessToken } from "@/lib/server-fetch";
import { COMPLIANCE_FRAMEWORKS, type ComplianceFramework, type FrameworkControls } from "@/lib/types";

const LABELS: Record<ComplianceFramework, string> = {
  iso27001: "ISO 27001",
  soc2: "SOC 2",
  pci_dss: "PCI DSS",
  hipaa: "HIPAA",
  nist_800_53: "NIST 800-53",
  cis_aws: "CIS AWS",
  fedramp_moderate: "FedRAMP Moderate",
};

/**
 * Map the dashboard route slug to the backend framework code. The sx-api
 * `Framework` enum serialises without separators (`pcidss`, `nist80053`,
 * `cisaws`), whereas the dashboard uses readable underscore slugs — without
 * this map the PCI DSS / NIST 800-53 / CIS AWS drill-downs 404.
 */
const BACKEND_CODE: Record<ComplianceFramework, string> = {
  iso27001: "iso27001",
  soc2: "soc2",
  pci_dss: "pcidss",
  hipaa: "hipaa",
  nist_800_53: "nist80053",
  cis_aws: "cisaws",
  fedramp_moderate: "fedrampmoderate",
};

function isFramework(value: string): value is ComplianceFramework {
  return (COMPLIANCE_FRAMEWORKS as ReadonlyArray<string>).includes(value);
}

interface PageProps {
  params: Promise<{ framework: string }>;
}

export default async function FrameworkDetailPage({ params }: PageProps) {
  const { framework } = await params;
  if (!isFramework(framework)) {
    notFound();
  }

  const token = await getAccessToken();
  if (token === null) {
    redirect("/login");
  }

  let controls: FrameworkControls | null = null;
  let errorMessage: string | null = null;
  try {
    controls = await apiGet<FrameworkControls>(
      `/v1/compliance/frameworks/${BACKEND_CODE[framework]}`,
      token,
    );
  } catch (err) {
    errorMessage = err instanceof ApiError ? err.message : "Failed to load framework.";
  }

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0">
          <div>
            <CardTitle>{LABELS[framework]}</CardTitle>
            <CardDescription>
              Controls registered for the {LABELS[framework]} framework.
            </CardDescription>
          </div>
          <Link
            href="/dashboard/compliance"
            className="text-xs text-muted-foreground hover:text-foreground"
          >
            ← All frameworks
          </Link>
        </CardHeader>
        <CardContent>
          {errorMessage !== null ? (
            <div
              role="alert"
              className="rounded-sx border border-critical/40 bg-critical/10 px-3 py-2 text-xs text-critical"
            >
              {errorMessage}
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>ID</TableHead>
                  <TableHead>Family</TableHead>
                  <TableHead>Title</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {controls === null || controls.controls.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={3} className="py-8 text-center text-xs text-muted-foreground">
                      No controls registered for this framework yet.
                    </TableCell>
                  </TableRow>
                ) : (
                  controls.controls.map((control) => (
                    <TableRow key={control.id}>
                      <TableCell className="font-mono text-xs">{control.id}</TableCell>
                      <TableCell className="text-xs uppercase tracking-wide text-muted-foreground">
                        {control.family}
                      </TableCell>
                      <TableCell>{control.title}</TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
