import * as React from "react";
import Link from "next/link";
import { Mail, ShieldCheck } from "lucide-react";

import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";

export default function VerifyEmailSentPage() {
  return (
    <main className="flex min-h-screen items-center justify-center bg-background p-6">
      <Card className="w-full max-w-sm">
        <CardHeader className="space-y-3">
          <div className="flex items-center gap-2">
            <ShieldCheck className="h-5 w-5 text-accent" aria-hidden />
            <span className="text-sm font-semibold tracking-tight">SentinelX</span>
          </div>
          <div>
            <CardTitle className="text-base">Check your inbox</CardTitle>
            <CardDescription>
              We&apos;ve sent a verification link to your email. Click the link to
              activate your account.
            </CardDescription>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-start gap-3 rounded-sx border border-border bg-muted/40 p-3">
            <Mail className="mt-0.5 h-4 w-4 text-muted-foreground" aria-hidden />
            <p className="text-xs text-muted-foreground">
              The link is valid for a limited time. If you don&apos;t see the email,
              check your spam folder.
            </p>
          </div>
          <p className="text-xs text-muted-foreground">
            Didn&apos;t get the email?{" "}
            <Link
              href="/signup"
              className="text-accent underline-offset-4 hover:underline"
            >
              Try signing up again
            </Link>
            .
          </p>
          <p className="text-xs text-muted-foreground">
            <Link
              href="/login"
              className="text-accent underline-offset-4 hover:underline"
            >
              Back to sign in
            </Link>
          </p>
        </CardContent>
      </Card>
    </main>
  );
}
