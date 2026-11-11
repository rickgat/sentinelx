import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

const badgeVariants = cva(
  "inline-flex items-center rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide",
  {
    variants: {
      variant: {
        default: "bg-muted text-foreground",
        critical: "bg-critical/15 text-critical border border-critical/40",
        high: "bg-high/15 text-high border border-high/40",
        medium: "bg-medium/15 text-medium border border-medium/40",
        low: "bg-low/15 text-low border border-low/40",
        info: "bg-info/15 text-info border border-info/40",
        success: "bg-success/15 text-success border border-success/40",
        outline: "border border-border text-foreground",
      },
    },
    defaultVariants: {
      variant: "default",
    },
  },
);

export interface BadgeProps
  extends React.HTMLAttributes<HTMLSpanElement>,
    VariantProps<typeof badgeVariants> {}

function Badge({ className, variant, ...props }: BadgeProps) {
  return <span className={cn(badgeVariants({ variant }), className)} {...props} />;
}

export { Badge, badgeVariants };
