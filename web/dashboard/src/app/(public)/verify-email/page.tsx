"use client";

import * as React from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { ShieldCheck } from "lucide-react";

import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";

type Status = "pending" | "success" | "error";

interface ErrorEnvelope {
  error?: { message?: string };
}

/**
 * Next 15 requires `useSearchParams()` consumers to sit under a Suspense
 * boundary so the page can prerender without it.
 */
export default function VerifyEmailPage() {
  return (
    <React.Suspense fallback={<VerifyShell title="Verifying email" body="Loading…" />}>
      <VerifyEmailInner />
    </React.Suspense>
  );
}

function VerifyShell({ title, body }: { title: string; body: string }) {
  return (
    <main className="flex min-h-screen items-center justify-center bg-background p-6">
      <Card className="w-full max-w-sm">
        <CardHeader className="space-y-3">
          <div className="flex items-center gap-2">
            <ShieldCheck className="h-5 w-5 text-accent" aria-hidden />
            <span className="text-sm font-semibold tracking-tight">SentinelX</span>
          </div>
          <div>
            <CardTitle className="text-base">{title}</CardTitle>
            <CardDescription>{body}</CardDescription>
          </div>
        </CardHeader>
      </Card>
    </main>
  );
}

function VerifyEmailInner() {
  const searchParams = useSearchParams();
  const token = searchParams.get("token");

  const [status, setStatus] = React.useState<Status>("pending");
  const [message, setMessage] = React.useState<string>("Confirming your email…");

  React.useEffect(() => {
    if (token === null || token.trim().length === 0) {
      setStatus("error");
      setMessage("Missing verification token.");
      return;
    }

    let cancelled = false;
    void (async () => {
      try {
        const res = await fetch("/api/auth/verify-email", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ token }),
        });
        if (cancelled) {
          return;
        }
        if (res.ok) {
          setStatus("success");
          setMessage("Your email has been verified. You can now sign in.");
          return;
        }
        let detail = "Verification failed. The link may have expired.";
        try {
          const body = (await res.json()) as ErrorEnvelope;
          if (typeof body.error?.message === "string") {
            detail = body.error.message;
          }
        } catch {
          // keep default
        }
        setStatus("error");
        setMessage(detail);
      } catch {
        if (!cancelled) {
          setStatus("error");
          setMessage("Network error while verifying. Please try again.");
        }
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [token]);

  return (
    <main className="flex min-h-screen items-center justify-center bg-background p-6">
      <Card className="w-full max-w-sm">
        <CardHeader className="space-y-3">
          <div className="flex items-center gap-2">
            <ShieldCheck className="h-5 w-5 text-accent" aria-hidden />
            <span className="text-sm font-semibold tracking-tight">SentinelX</span>
          </div>
          <div>
            <CardTitle className="text-base">
              {status === "pending"
                ? "Verifying email"
                : status === "success"
                  ? "Email verified"
                  : "Verification failed"}
            </CardTitle>
            <CardDescription>{message}</CardDescription>
          </div>
        </CardHeader>
        <CardContent className="space-y-3">
          {status === "success" ? (
            <p className="text-xs text-muted-foreground">
              <Link
                href="/login"
                className="text-accent underline-offset-4 hover:underline"
              >
                Continue to sign in
              </Link>
            </p>
          ) : null}
          {status === "error" ? (
            <p className="text-xs text-muted-foreground">
              <Link
                href="/signup"
                className="text-accent underline-offset-4 hover:underline"
              >
                Try signing up again
              </Link>
            </p>
          ) : null}
        </CardContent>
      </Card>
    </main>
  );
}
