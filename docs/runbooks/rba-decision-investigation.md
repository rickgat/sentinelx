# RBA Decision Investigation Playbook

> **Audience:** SOC analyst / IAM operator running a post-incident or
> live-fire investigation against a Risk-Based Authentication (RBA)
> decision.
> **Scope:** read-only retrieval and interpretation of per-signal
> contributions surfaced by LOW-007. Does not cover decision *override*
> (that's the step-up / block override path, separate runbook).
> **Prerequisites:** caller carries the `admin:users` capability —
> regular operators see the composite score + reason but not the raw
> per-signal voting.

## 1. When to reach for this playbook

You need this playbook when:

1. A user reports being step-up-MFA'd or blocked unexpectedly and you
   need to explain why.
2. A red-team / purple-team exercise produced a decision you want to
   reverse-engineer.
3. The SOC threshold tuning loop ("are our weights still right?") needs
   per-signal evidence rather than aggregate stats.
4. A regression test in the integration harness flapped and you want to
   see exactly which signal moved.

You do **not** need this for a high-volume tuning sweep — use the
LOW-006 Prometheus histograms for that.

## 2. Pulling the breakdown

The breakdown rides on the existing decision-audit endpoint. The wire
shape only adds the `signals` field for admin callers; everything else
is unchanged.

```bash
curl -sS \
  -H "Authorization: Bearer ${SX_ADMIN_TOKEN}" \
  "https://api.sentinelx.example/v1/rba/decisions?limit=20" \
  | jq '.data.decisions[0]'
```

```jsonc
{
  "id": "fa3e…",
  "tenant_id": "…",
  "user_id": "…",
  "ip": "203.0.113.42",
  "score": 67,
  "action": "step_up_mfa",
  "reason": "ip-geo signal dominant (sub-score 80)",
  "decided_at": "2026-06-14T22:17:03Z",
  "signals": [
    { "signal": "ip_geo",            "sub_score": 80, "weight": 0.25, "weighted": 20.0 },
    { "signal": "velocity",          "sub_score": 30, "weight": 0.20, "weighted":  6.0 },
    { "signal": "business_hours",    "sub_score": 60, "weight": 0.10, "weighted":  6.0 },
    { "signal": "device_fp",         "sub_score":  0, "weight": 0.15, "weighted":  0.0 },
    { "signal": "mfa_recent",        "sub_score": 25, "weight": 0.10, "weighted":  2.5 },
    { "signal": "success_rate",      "sub_score":  0, "weight": 0.05, "weighted":  0.0 },
    { "signal": "impossible_travel", "sub_score":  0, "weight": 0.15, "weighted":  0.0 }
  ]
}
```

The composite `score` is the weighted average across the rows where
`weight > 0`. In the example above:

> `(20 + 6 + 6 + 0 + 2.5 + 0 + 0) / (0.25 + 0.20 + 0.10 + 0.15 + 0.10 + 0.05 + 0.15) = 34.5 / 1.00 ≈ 35`

(The headline `score` shows 67 instead of 35 because the engine also
applies the per-tenant baseline-calibrated allow / block thresholds and
the deep-night business-hours bump that the worked example skips.)

If `signals` is missing from the response payload, either (a) you're not
calling as an admin or (b) the row predates LOW-007 — both of those
collapse the breakdown to an absent field.

## 3. What each signal weight means

| Signal | Sub-score band | What "high" means |
|---|---|---|
| `ip_geo` | `0` home country, `40` private network, `60` known foreign country, `80` unknown / unresolved address | The IP could not be confidently localised to the tenant's anchor country. |
| `velocity` | linear ramp `0…100` over 1…10 attempts in the sliding window | The same identity is hammering the login surface. |
| `business_hours` | `0` in window, `40` after-hours, `+20` deep-night (00:00–05:00 local) | The attempt happened when this tenant's users almost never log in. |
| `device_fp` | `0` known, `30` unknown, `100` revoked | The fingerprint either isn't on file or has been explicitly revoked. |
| `mfa_recent` | `0` fresh (<1h), `10` recent, `25` stale, `50` never | MFA hasn't been challenged recently for this user. |
| `success_rate` | `0` healthy 7-day rate, `20…90` deteriorating | The user's 7-day rolling success rate has fallen — implies credential stuffing or brute force. |
| `impossible_travel` | `0` plausible, `30` suspicious, `100` impossible | Implied great-circle speed between this login and the previous one exceeds the physical ceiling. |

A `weighted` of `0.0` in a row where `sub_score > 0` and `weight > 0` is
impossible — if you see it, flag a scorer bug (file under `sx-rba` +
attach the audit row).

## 4. Common false-positive patterns + dispositions

### 4.1 Travelling salesperson — `ip_geo` and `impossible_travel` both red

> Symptom: composite ~75–95, `ip_geo` 60–80, `impossible_travel` 100,
> everything else green.

This is the classic remote-worker hotel-Wi-Fi false positive. The
in-person `device_fp` row should still be `0` (known device). The
disposition is to step-up rather than block (the engine usually
auto-degrades to `step_up_mfa` in this band — verify), confirm the user
by an out-of-band channel, then mark the new IP range as expected via
the tenant's geo-fence allow-list (NOT by lowering the impossible-travel
weight, which would weaken the signal for every other user).

### 4.2 Stale MFA — fresh device, fresh country, but `mfa_recent` 50

> Symptom: composite 25–45, `mfa_recent` is the single dominant
> contributor.

The user hasn't touched MFA in months. Step-up is the right call. Do
NOT engage incident response — just verify the user, complete the MFA
challenge, and move on. The fact that the engine surfaced this in the
audit row is *evidence the signal works*, not an incident.

### 4.3 Burst on a single failed credential — velocity red, everything else green

> Symptom: composite ramps from 5 → 70+ in <60 s, `velocity` runs up to
> 100, every other row stays low.

If `user_id` is `null` on every row, this is anonymous credential
stuffing against a non-existent account — the engine's "unknown user"
fall-throughs make the per-user signals report green. The disposition is
to confirm the IP isn't a corporate gateway, then add the IP to the
sx-firewall blocklist via the runtime API. No action on the user (there
isn't one).

### 4.4 Revoked-device storm — `device_fp` 100 on every row, same `fp_hash`

> Symptom: a freshly-revoked device is still being used by an unaware
> user. Composite saturates the block threshold.

This is the system working as designed. Confirm with the user that the
device is in their hands (lost-device false flag) and either re-enrol it
(`POST /v1/rba/users/{id}/devices/enroll`) or escalate to physical
recovery. Do NOT undo the revocation by hand-editing the row.

### 4.5 Baseline observation phase — composite high but action `allow`

> Symptom: `action: "allow"` despite `score >= 70` and several red
> signals. The `reason` string starts with `observation-mode`.

This is per-tenant passive observation (HIGH-001). The tenant's
baseline-store has not yet collected enough data to ship calibrated
thresholds, so the engine logs the *would-be* action without enforcing
it. Verify the per-tenant baseline is genuinely young (`< 30 days` since
provisioning) — if not, the engine is mis-configured and the operator
needs to lock the baseline via `lock_baseline`.

## 5. Persistence + retention

Decision rows live in `rba_decisions` (`crates/sx-storage/migrations/
20270101000300_create_rba_decisions.sql`), tenant-isolated under FORCE
ROW LEVEL SECURITY. The LOW-007 `signal_contributions` JSONB column is
NULL-able for pre-LOW-007 rows; every new row populates it. Retention
follows the platform-wide audit-log policy — see the audit-anchor
runbook for the chain-of-custody requirements. **Do not** `DELETE` rows
by hand; let the retention scheduler do it so the audit anchor stays
intact.

## 6. When to escalate

Escalate to the on-call IAM lead if:

* The composite score and the `weighted` rows don't agree (potential
  scorer bug or a manual SQL edit on the row).
* `signal_contributions` is `NULL` on a row whose `decided_at` is after
  the LOW-007 migration applied — implies the engine wasn't redeployed
  with the new code.
* You see `signal` values outside the seven documented kinds — implies
  a future-version row replayed against an older API.

For tenant-side configuration questions ("can we drop the
`impossible_travel` weight to 0?"), route through the per-tenant
operator, not the SOC.
