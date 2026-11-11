import Link from "next/link";
import { redirect } from "next/navigation";
import { Library } from "lucide-react";

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { getAccessToken } from "@/lib/server-fetch";

import { TechniquesClient, type Technique } from "./techniques-client";

/**
 * BAS technique catalogue browser (read-only).
 *
 * Renders the embedded MITRE ATT&CK technique catalogue shipped by the BAS
 * planner (Agent QQQ). The list is inlined here because sx-api does not yet
 * expose a `GET /v1/bas/techniques` endpoint; once it does, this server
 * component will swap the constant for a tenant-scoped fetch and the client
 * island can stay unchanged.
 *
 * The catalogue is grouped by ATT&CK tactic (phase) and ordered along the
 * canonical reconnaissance → impact axis. Each row deep-links to the
 * MITRE ATT&CK technique page for further context.
 */

const TECHNIQUES: ReadonlyArray<Technique> = [
  {
    technique_id: "T1595",
    name: "Active Scanning",
    phase: "reconnaissance",
    required_intensity: "theoretical",
    platforms: ["pre"],
  },
  {
    technique_id: "T1592",
    name: "Gather Victim Host Information",
    phase: "reconnaissance",
    required_intensity: "theoretical",
    platforms: ["pre"],
  },
  {
    technique_id: "T1583",
    name: "Acquire Infrastructure",
    phase: "resource-development",
    required_intensity: "theoretical",
    platforms: ["pre"],
  },
  {
    technique_id: "T1190",
    name: "Exploit Public-Facing Application",
    phase: "initial-access",
    required_intensity: "active_exploit",
    platforms: ["linux", "windows", "macos", "containers"],
  },
  {
    technique_id: "T1566",
    name: "Phishing",
    phase: "initial-access",
    required_intensity: "safe_interactive",
    platforms: ["linux", "windows", "macos"],
  },
  {
    technique_id: "T1133",
    name: "External Remote Services",
    phase: "initial-access",
    required_intensity: "passive_validation",
    platforms: ["linux", "windows", "macos"],
  },
  {
    technique_id: "T1078",
    name: "Valid Accounts",
    phase: "initial-access",
    required_intensity: "passive_validation",
    platforms: ["linux", "windows", "macos", "azure-ad", "office-365"],
  },
  {
    technique_id: "T1199",
    name: "Trusted Relationship",
    phase: "initial-access",
    required_intensity: "passive_validation",
    platforms: ["linux", "windows", "macos", "azure-ad", "office-365"],
  },
  {
    technique_id: "T1059",
    name: "Command and Scripting Interpreter",
    phase: "execution",
    required_intensity: "safe_interactive",
    platforms: ["linux", "windows", "macos"],
  },
  {
    technique_id: "T1204",
    name: "User Execution",
    phase: "execution",
    required_intensity: "safe_interactive",
    platforms: ["linux", "windows", "macos"],
  },
  {
    technique_id: "T1547",
    name: "Boot or Logon Autostart Execution",
    phase: "persistence",
    required_intensity: "safe_interactive",
    platforms: ["linux", "windows", "macos"],
  },
  {
    technique_id: "T1136",
    name: "Create Account",
    phase: "persistence",
    required_intensity: "safe_interactive",
    platforms: ["linux", "windows", "macos", "azure-ad", "office-365"],
  },
  {
    technique_id: "T1098",
    name: "Account Manipulation",
    phase: "persistence",
    required_intensity: "passive_validation",
    platforms: ["linux", "windows", "macos", "azure-ad", "office-365"],
  },
  {
    technique_id: "T1505",
    name: "Server Software Component",
    phase: "persistence",
    required_intensity: "passive_validation",
    platforms: ["linux", "windows", "macos"],
  },
  {
    technique_id: "T1543",
    name: "Create or Modify System Process",
    phase: "persistence",
    required_intensity: "passive_validation",
    platforms: ["linux", "windows", "macos"],
  },
  {
    technique_id: "T1068",
    name: "Exploitation for Privilege Escalation",
    phase: "privilege-escalation",
    required_intensity: "active_exploit",
    platforms: ["linux", "windows", "macos"],
  },
  {
    technique_id: "T1548",
    name: "Abuse Elevation Control Mechanism",
    phase: "privilege-escalation",
    required_intensity: "safe_interactive",
    platforms: ["linux", "windows", "macos"],
  },
  {
    technique_id: "T1078.004",
    name: "Valid Accounts: Cloud Accounts",
    phase: "privilege-escalation",
    required_intensity: "passive_validation",
    platforms: ["azure-ad", "office-365", "aws", "gcp"],
  },
  {
    technique_id: "T1134",
    name: "Access Token Manipulation",
    phase: "privilege-escalation",
    required_intensity: "theoretical",
    platforms: ["windows"],
  },
  {
    technique_id: "T1611",
    name: "Escape to Host",
    phase: "privilege-escalation",
    required_intensity: "passive_validation",
    platforms: ["containers"],
  },
  {
    technique_id: "T1027",
    name: "Obfuscated Files or Information",
    phase: "defense-evasion",
    required_intensity: "safe_interactive",
    platforms: ["linux", "windows", "macos"],
  },
  {
    technique_id: "T1070",
    name: "Indicator Removal",
    phase: "defense-evasion",
    required_intensity: "safe_interactive",
    platforms: ["linux", "windows", "macos"],
  },
  {
    technique_id: "T1003",
    name: "OS Credential Dumping",
    phase: "credential-access",
    required_intensity: "active_exploit",
    platforms: ["linux", "windows", "macos"],
  },
  {
    technique_id: "T1110",
    name: "Brute Force",
    phase: "credential-access",
    required_intensity: "safe_interactive",
    platforms: ["linux", "windows", "macos", "azure-ad", "office-365"],
  },
  {
    technique_id: "T1056",
    name: "Input Capture",
    phase: "credential-access",
    required_intensity: "theoretical",
    platforms: ["linux", "windows", "macos"],
  },
  {
    technique_id: "T1212",
    name: "Exploitation for Credential Access",
    phase: "credential-access",
    required_intensity: "theoretical",
    platforms: ["linux", "windows", "macos"],
  },
  {
    technique_id: "T1552",
    name: "Unsecured Credentials",
    phase: "credential-access",
    required_intensity: "passive_validation",
    platforms: ["linux", "windows", "macos", "azure-ad", "office-365"],
  },
  {
    technique_id: "T1087",
    name: "Account Discovery",
    phase: "discovery",
    required_intensity: "passive_validation",
    platforms: ["linux", "windows", "macos", "azure-ad", "office-365"],
  },
  {
    technique_id: "T1018",
    name: "Remote System Discovery",
    phase: "discovery",
    required_intensity: "passive_validation",
    platforms: ["linux", "windows", "macos"],
  },
  {
    technique_id: "T1021",
    name: "Remote Services",
    phase: "lateral-movement",
    required_intensity: "safe_interactive",
    platforms: ["linux", "windows", "macos"],
  },
  {
    technique_id: "T1534",
    name: "Internal Spearphishing",
    phase: "lateral-movement",
    required_intensity: "safe_interactive",
    platforms: ["linux", "windows", "macos", "office-365"],
  },
  {
    technique_id: "T1080",
    name: "Taint Shared Content",
    phase: "lateral-movement",
    required_intensity: "passive_validation",
    platforms: ["linux", "windows", "macos"],
  },
  {
    technique_id: "T1210",
    name: "Exploitation of Remote Services",
    phase: "lateral-movement",
    required_intensity: "theoretical",
    platforms: ["linux", "windows", "macos"],
  },
  {
    technique_id: "T1570",
    name: "Lateral Tool Transfer",
    phase: "lateral-movement",
    required_intensity: "passive_validation",
    platforms: ["linux", "windows", "macos"],
  },
  {
    technique_id: "T1005",
    name: "Data from Local System",
    phase: "collection",
    required_intensity: "passive_validation",
    platforms: ["linux", "windows", "macos"],
  },
  {
    technique_id: "T1071",
    name: "Application Layer Protocol",
    phase: "command-and-control",
    required_intensity: "safe_interactive",
    platforms: ["linux", "windows", "macos"],
  },
  {
    technique_id: "T1572",
    name: "Protocol Tunneling",
    phase: "command-and-control",
    required_intensity: "safe_interactive",
    platforms: ["linux", "windows", "macos"],
  },
  {
    technique_id: "T1041",
    name: "Exfiltration Over C2 Channel",
    phase: "exfiltration",
    required_intensity: "active_exploit",
    platforms: ["linux", "windows", "macos"],
  },
  {
    technique_id: "T1486",
    name: "Data Encrypted for Impact",
    phase: "impact",
    required_intensity: "active_exploit",
    platforms: ["linux", "windows", "macos"],
  },
];

export default async function BasTechniquesPage() {
  const token = await getAccessToken();
  if (token === null) {
    redirect("/login");
  }

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0">
          <div className="space-y-1.5">
            <CardTitle className="flex items-center gap-2">
              <Library className="h-4 w-4 text-accent" aria-hidden />
              BAS technique catalogue
            </CardTitle>
            <CardDescription>
              Read-only catalogue of MITRE ATT&amp;CK techniques known to the BAS planner.
              Search by id or name; expand a phase to drill in. Each row links to the
              upstream MITRE ATT&amp;CK technique page.
            </CardDescription>
          </div>
          <Link href="/dashboard/bas" className="text-xs text-muted-foreground hover:text-foreground">
            BAS runs
          </Link>
        </CardHeader>
        <CardContent>
          <TechniquesClient techniques={TECHNIQUES} />
        </CardContent>
      </Card>
    </div>
  );
}
