import { Badge } from "@/components/ui/badge";
import type { Severity } from "@/types/finding";

interface SeverityBadgeProps {
  severity: Severity;
}

export function SeverityBadge({ severity }: SeverityBadgeProps) {
  return <Badge variant={severity}>{severity}</Badge>;
}
