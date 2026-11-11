"use client";

import * as React from "react";
import { MessageSquareCode } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { cn } from "@/lib/utils";

/**
 * Prompt-collapsing strategy
 * --------------------------
 * The sx-api `POST /v1/copilot/chat` route is single-turn: it accepts one
 * `prompt` string and bounds it to 4000 chars (see CopilotChatRequest in
 * `sx-api/src/view/copilot_view.rs`). To stay within that contract while
 * still giving the model a little local context, we collapse the on-screen
 * transcript by emitting the trailing N turns (most recent first preserved
 * order) as a short labelled block followed by the freshly submitted user
 * line. If the rendered block would exceed `PROMPT_BUDGET_CHARS`, older
 * turns are dropped until it fits. In practice the typical submission
 * carries only the user's current line because most sessions begin empty.
 */
const MAX_CONTEXT_TURNS = 6;
const PROMPT_BUDGET_CHARS = 3500;

type Role = "user" | "assistant";

interface Message {
  id: number;
  role: Role;
  text: string;
  at: string;
}

interface ChatEnvelope {
  data?: { reply: string; model: string };
  error?: { code?: string; message?: string; request_id?: string };
}

interface BannerState {
  kind: "default" | "disabled" | "error" | "pending_approval";
  message: string;
  approvalToken?: string;
}

const PENDING_APPROVAL_REGEX = /\[pending-approval token=([0-9a-fA-F-]{36})\]/;

const DEFAULT_BANNER: BannerState = {
  kind: "default",
  message:
    "AI Copilot — when configured, replies come from Anthropic Claude. Currently stubbed in dev.",
};

function collapseTranscript(
  history: ReadonlyArray<Message>,
  latestUserText: string,
): string {
  const tail = history.slice(-MAX_CONTEXT_TURNS);
  if (tail.length === 0) {
    return latestUserText;
  }
  const lines: string[] = [];
  for (const msg of tail) {
    const label = msg.role === "user" ? "User" : "Assistant";
    lines.push(`${label}: ${msg.text}`);
  }
  lines.push(`User: ${latestUserText}`);
  let composed = lines.join("\n");
  // Drop oldest turns until we fit the per-prompt budget. Always keep the
  // last entry (the user's current message).
  let dropFrom = 0;
  while (composed.length > PROMPT_BUDGET_CHARS && dropFrom < lines.length - 1) {
    dropFrom += 1;
    composed = lines.slice(dropFrom).join("\n");
  }
  if (composed.length > PROMPT_BUDGET_CHARS) {
    // Final guard: hard-truncate to the budget. The 4000-char wire cap is
    // still safe because PROMPT_BUDGET_CHARS sits below it.
    composed = composed.slice(composed.length - PROMPT_BUDGET_CHARS);
  }
  return composed;
}

export function CopilotClient() {
  const [messages, setMessages] = React.useState<ReadonlyArray<Message>>([]);
  const [draft, setDraft] = React.useState("");
  const [sending, setSending] = React.useState(false);
  const [banner, setBanner] = React.useState<BannerState>(DEFAULT_BANNER);
  const [modelLabel, setModelLabel] = React.useState<string | null>(null);
  const idRef = React.useRef(0);
  const scrollerRef = React.useRef<HTMLDivElement | null>(null);

  React.useEffect(() => {
    const el = scrollerRef.current;
    if (el !== null) {
      el.scrollTop = el.scrollHeight;
    }
  }, [messages, sending]);

  const append = React.useCallback((role: Role, text: string) => {
    idRef.current += 1;
    const id = idRef.current;
    setMessages((current) => [
      ...current,
      { id, role, text, at: new Date().toISOString() },
    ]);
  }, []);

  const submit = React.useCallback(
    async (text: string) => {
      const trimmed = text.trim();
      if (trimmed.length === 0 || sending) {
        return;
      }
      // 1. Optimistically render the user line + clear the draft.
      append("user", trimmed);
      setDraft("");
      setSending(true);

      // 2. Build the prompt payload from the transcript snapshot we just
      //    pushed into. `messages` from closure is the prior history;
      //    appending the user line is handled inside the collapser.
      const prompt = collapseTranscript(messages, trimmed);

      try {
        const res = await fetch("/api/copilot/chat", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          cache: "no-store",
          // SAFETY: never log this body — it carries the operator prompt.
          body: JSON.stringify({ prompt }),
        });
        let parsed: ChatEnvelope = {};
        try {
          parsed = (await res.json()) as ChatEnvelope;
        } catch {
          parsed = {};
        }

        if (res.ok && parsed.data !== undefined) {
          append("assistant", parsed.data.reply);
          setModelLabel(parsed.data.model);
          // P1-012 — if the reply carries a pending-approval marker, swap
          // the banner copy to point reviewers at the approvals queue.
          const match = PENDING_APPROVAL_REGEX.exec(parsed.data.reply);
          if (match !== null && match[1] !== undefined) {
            setBanner({
              kind: "pending_approval",
              message:
                "Action queued for human review. Review it on the Copilot Approvals page.",
              approvalToken: match[1],
            });
          } else {
            setBanner(DEFAULT_BANNER);
          }
          return;
        }

        const code = parsed.error?.code ?? "UNKNOWN";
        const message =
          parsed.error?.message ?? `Copilot request failed (HTTP ${res.status})`;

        // 422 with the disabled / config-rejection envelope: swap the
        // banner copy in place and surface the upstream message inline.
        if (res.status === 422) {
          setBanner({
            kind: "disabled",
            message: `AI Copilot is unavailable: ${message}`,
          });
          append("assistant", `Copilot unavailable — ${message}`);
          return;
        }

        setBanner({
          kind: "error",
          message: `Copilot request failed (${code}): ${message}`,
        });
        append("assistant", `Error: ${message}`);
      } catch {
        const message = "Network error contacting the Copilot proxy.";
        setBanner({ kind: "error", message });
        append("assistant", `Error: ${message}`);
      } finally {
        setSending(false);
      }
    },
    [append, messages, sending],
  );

  function onFormSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    void submit(draft);
  }

  function onKeyDown(event: React.KeyboardEvent<HTMLTextAreaElement>) {
    if (event.key === "Enter" && !event.shiftKey) {
      event.preventDefault();
      void submit(draft);
    }
  }

  const badgeVariant: "medium" | "low" | "critical" =
    banner.kind === "disabled" || banner.kind === "pending_approval"
      ? "medium"
      : banner.kind === "error"
        ? "critical"
        : "low";
  const badgeLabel =
    banner.kind === "disabled"
      ? "preview · disabled"
      : banner.kind === "error"
        ? "preview · error"
        : banner.kind === "pending_approval"
          ? "preview · pending approval"
          : modelLabel !== null
            ? `preview · ${modelLabel}`
            : "preview · live";

  const bannerClasses = cn(
    "mb-3 rounded-sx border px-3 py-2 text-xs",
    banner.kind === "default" && "border-medium/40 bg-medium/10 text-medium",
    banner.kind === "disabled" && "border-medium/40 bg-medium/10 text-medium",
    banner.kind === "pending_approval" &&
      "border-medium/40 bg-medium/10 text-medium",
    banner.kind === "error" && "border-critical/40 bg-critical/10 text-critical",
  );

  return (
    <div className="max-w-3xl space-y-4">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <MessageSquareCode className="h-4 w-4 text-accent" aria-hidden />
            AI Copilot
            <Badge variant={badgeVariant} className="ml-2">
              {badgeLabel}
            </Badge>
          </CardTitle>
          <CardDescription>
            Single-turn chat backed by sx-api. Prompts are bounded at 4000
            characters; the last few turns are collapsed into a short context
            block before each request.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div role="alert" className={bannerClasses}>
            {banner.message}
            {banner.kind === "pending_approval" &&
            banner.approvalToken !== undefined ? (
              <>
                {" "}
                <a
                  href="/dashboard/copilot-approvals"
                  className="underline underline-offset-2 hover:text-foreground"
                >
                  Open Approvals
                </a>
                <span className="ml-1 font-mono text-[10px] opacity-70">
                  token={banner.approvalToken.slice(0, 8)}…
                </span>
              </>
            ) : null}
          </div>
          <div
            ref={scrollerRef}
            className="mb-3 max-h-80 min-h-32 space-y-2 overflow-y-auto rounded-sx border border-border bg-background/40 p-3"
          >
            {messages.length === 0 && !sending ? (
              <p className="text-xs text-muted-foreground">
                Start a conversation below. Replies come from the configured
                LLM provider when AI Copilot is enabled in the workspace
                config.
              </p>
            ) : (
              <>
                {messages.map((message) => (
                  <div
                    key={message.id}
                    className={cn(
                      "flex flex-col gap-0.5 rounded-sx px-3 py-2 text-sm",
                      message.role === "user"
                        ? "bg-accent/10 text-foreground"
                        : "bg-muted/40 text-foreground",
                    )}
                  >
                    <span className="text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">
                      {message.role === "user" ? "you" : "copilot"} ·{" "}
                      {message.at.slice(11, 19)}
                    </span>
                    <span className="whitespace-pre-wrap">{message.text}</span>
                  </div>
                ))}
                {sending ? (
                  <div
                    className="flex flex-col gap-0.5 rounded-sx bg-muted/40 px-3 py-2 text-sm text-foreground"
                    aria-live="polite"
                  >
                    <span className="text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">
                      copilot · thinking
                    </span>
                    <span className="text-muted-foreground">
                      Contacting Copilot…
                    </span>
                  </div>
                ) : null}
              </>
            )}
          </div>
          <form onSubmit={onFormSubmit} className="flex flex-col gap-2">
            <textarea
              value={draft}
              onChange={(event) => setDraft(event.currentTarget.value)}
              onKeyDown={onKeyDown}
              rows={3}
              disabled={sending}
              placeholder="Ask the Copilot anything. Enter to send, Shift+Enter for newline."
              className="w-full rounded-sx border border-border bg-transparent p-2 text-sm text-foreground placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent disabled:cursor-not-allowed disabled:opacity-60"
            />
            <div className="flex items-center justify-between gap-2">
              <span className="text-[10px] uppercase tracking-wide text-muted-foreground">
                {sending
                  ? "Awaiting reply…"
                  : modelLabel !== null
                    ? `Last reply from ${modelLabel}`
                    : "Ready"}
              </span>
              <Button
                type="submit"
                disabled={sending || draft.trim().length === 0}
              >
                {sending ? "Sending…" : "Send"}
              </Button>
            </div>
          </form>
        </CardContent>
      </Card>
    </div>
  );
}
