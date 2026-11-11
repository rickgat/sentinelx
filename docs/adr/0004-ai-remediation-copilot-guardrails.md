# ADR 0004 — Guardrails for the AI remediation copilot

Status: Accepted
Date: 2026-05-30

## Context

The `sx-remediation` crate hosts an AI copilot that drafts remediation
guidance for findings: given a finding (CVE id, asset metadata, vendor
advisories), it produces an English summary and a step-by-step plan
suitable for an engineer to action. The model of record is Anthropic
Claude, accessed through the official Rust SDK.

LLM features are high-risk in a security product. A wrong remediation
recommendation does not just embarrass the vendor; it can break
production systems, leak data, or steer responders toward the wrong fix.
We need a small set of non-negotiable guardrails before this feature
ships.

We surveyed prior public guardrails from GitHub Copilot for Docs,
Microsoft Security Copilot, and Anthropic's own constitutional-AI work,
and distilled the list below.

## Decision

The remediation copilot **must** implement every one of the following
guardrails. The list is enforced by code (each guardrail has a paired
test in `sx-remediation/tests/`) and by review (PRs that touch the
copilot path require a security reviewer's sign-off).

1. **Prompt-injection defence.** Inputs sourced from third-party fields
   (finding `description`, advisory text, vendor blurbs) are passed to
   the model wrapped in a dedicated `<user_content>` XML tag and a
   preamble telling the model to treat anything inside the tag as data,
   not instructions. The system prompt explicitly refuses tool use.
2. **PII redaction.** Before any prompt is sent, the input passes through
   the `pii::redactor` module which strips email addresses, phone
   numbers, ipv4/ipv6 literals, AWS access keys, JWTs, GitHub PATs, and
   anything matching the customer-supplied custom regex list. The
   redactor is fail-closed: if it errors, the request is rejected.
3. **Citation enforcement.** Every recommendation in the response must
   carry a citation to either an authoritative CVE record (NVD), a
   vendor advisory, or a customer-uploaded runbook. The post-processor
   parses the response and rejects any answer without at least one
   citation per recommended action.
4. **No autonomous execution.** The copilot returns text only. It never
   has the ability to mutate engagement state, file tickets, run
   commands, or call back into SentinelX. The relevant `tool_use` field
   is explicitly empty in every request and the response post-processor
   refuses messages whose `stop_reason` is `tool_use`.
5. **Token budget.** Every request is capped at `max_tokens = 1024` for
   output and `max_input_tokens = 12_000` for input. Requests exceeding
   the budget are short-circuited with `RemediationError::BudgetExceeded`
   rather than truncated, so the user is told explicitly that the
   finding is too large to summarise and offered a manual workflow.
6. **Per-tenant rate limiting.** The copilot endpoint inherits the
   tenant-scoped rate limit from `sx-api`'s middleware (default
   `60 req/min` per tenant, configurable via
   `SENTINELX__REMEDIATION__RATE_LIMIT`).
7. **Audit logging.** Every copilot invocation writes a record to
   `sx-audit` capturing the redacted prompt hash, the response hash,
   the model id and the user id. The plaintext prompt and response are
   stored encrypted under a tenant-scoped KMS key with a 30-day TTL.

## Consequences

- The copilot is **slower and more expensive** than a naked Claude call:
  PII redaction, citation parsing, and audit writes add overhead per
  request (target p95 < 3.5 s end-to-end at 12 k input tokens).
- The copilot **cannot answer some questions** (those that require
  citations we cannot produce, or that exceed the token budget). The UX
  shows a clear "not answerable automatically — escalate to a human"
  state in those cases.
- Adding a new model or model version requires updating both the SDK
  pin and the citation/PII regression test corpus. The corpus lives in
  `sx-remediation/tests/fixtures/` and grows with every incident.
- Customers in regulated industries get a deterministic story for "what
  data did the model see and what did it produce", because every prompt
  and response is hashed into the audit chain.
