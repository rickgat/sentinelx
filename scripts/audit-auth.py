#!/usr/bin/env python3
"""
Handler auth-coverage audit for SentinelX.

Ported from nex-erp's `qc/audit-auth.py` (Wave 9).
The idea: enumerate every `.route(...)` registered in the axum router,
determine which group (public / authed / scim) each was declared in,
and cross-check against the auth-middleware bypass allowlist. Any
route that is:

  * declared in the `public` router group AND missing from
    `AuthConfig::bypass_prefixes`, OR
  * declared in `authed` / `scim` router groups AND present in
    `bypass_prefixes` (silent fall-open),

is reported as a violation.

Exit code: 0 = clean · 1 = violations found.

Usage:
    python3 scripts/audit-auth.py
    python3 scripts/audit-auth.py --json    # machine-readable
    python3 scripts/audit-auth.py --ci      # CI mode: only summary + exit
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
ROUTER_FILE = REPO_ROOT / "crates" / "sx-api" / "src" / "router.rs"
AUTH_MW_FILE = REPO_ROOT / "crates" / "sx-api" / "src" / "middleware" / "auth.rs"

# Documented shadowing exceptions: routes registered in an "authed" group
# but intentionally bypassing the JWT middleware because they use a
# different auth mechanism (SCIM per-tenant token, HMAC webhook signature,
# etc.). Reviewer must justify each entry with a code comment.
ALLOWED_SHADOWING_PREFIXES: list[str] = [
    # SCIM 2.0 endpoints authenticate via per-tenant bearer token in
    # `controller::scim::authenticate` — see middleware/auth.rs line 72-77.
    "/scim/v2",
    # Falco webhook self-authenticates via HMAC-SHA256 signature — see
    # `sx_runtime::TenantKeyStore` and the /v1/runtime/falco/alerts path.
    "/v1/runtime/falco",
    # K8s admission webhook uses TLS client cert auth from the cluster's
    # webhook config — see /v1/runtime/k8s/admit.
    "/v1/runtime/k8s/admit",
]


# ---------------------------------------------------------------------------
# Router parser: walk the file, keep a "current group" marker whenever we
# see `let <name> = Router::new()`, and attribute every `.route("...", ...)`
# following it to that group until the next `let ... = Router::new()`.
# ---------------------------------------------------------------------------

GROUP_DECL_RE = re.compile(r"^\s*let\s+(\w+)\s*=\s*Router::new\(\s*\)")
ROUTE_RE = re.compile(r'\.route\(\s*"([^"]+)"')


def parse_router() -> dict[str, list[str]]:
    """Return {group_name: [paths]}."""
    groups: dict[str, list[str]] = {}
    current: str | None = None
    with ROUTER_FILE.open() as f:
        for line in f:
            m_group = GROUP_DECL_RE.search(line)
            if m_group:
                current = m_group.group(1)
                groups.setdefault(current, [])
                continue
            m_route = ROUTE_RE.search(line)
            if m_route and current is not None:
                groups[current].append(m_route.group(1))
    return groups


# ---------------------------------------------------------------------------
# Bypass parser: extract every string in AuthConfig::default() bypass_prefixes.
# ---------------------------------------------------------------------------

def parse_bypass_prefixes() -> list[str]:
    text = AUTH_MW_FILE.read_text()
    # Find the `bypass_prefixes: vec![ ... ],` block via a state machine.
    start = text.find("bypass_prefixes:")
    if start < 0:
        return []
    # Advance to opening [
    bracket = text.find("[", start)
    if bracket < 0:
        return []
    depth = 1
    end = bracket + 1
    while end < len(text) and depth > 0:
        if text[end] == "[":
            depth += 1
        elif text[end] == "]":
            depth -= 1
        end += 1
    body = text[bracket + 1 : end - 1]
    return re.findall(r'"([^"]+)"', body)


def path_is_bypassed(path: str, bypass: list[str]) -> bool:
    """Match on exact prefix or `<prefix>/...` per AuthConfig.default doc."""
    for p in bypass:
        if path == p or path.startswith(p + "/"):
            return True
    return False


# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--json", action="store_true", help="Machine-readable output")
    ap.add_argument("--ci", action="store_true", help="Summary only")
    args = ap.parse_args()

    if not ROUTER_FILE.exists():
        print(f"error: router not found at {ROUTER_FILE}", file=sys.stderr)
        return 2
    if not AUTH_MW_FILE.exists():
        print(f"error: auth middleware not found at {AUTH_MW_FILE}", file=sys.stderr)
        return 2

    groups = parse_router()
    bypass = parse_bypass_prefixes()

    if not groups:
        print("error: parsed 0 route groups; router shape changed?", file=sys.stderr)
        return 2

    public_paths = groups.get("public", [])
    authed_paths = [p for name, paths in groups.items()
                    if name not in ("public",)
                    for p in paths]

    # Deduplicate
    authed_paths = sorted(set(authed_paths))

    # Violations
    public_missing_bypass = [p for p in public_paths if not path_is_bypassed(p, bypass)]

    def is_allowed_shadow(path: str) -> bool:
        for allow in ALLOWED_SHADOWING_PREFIXES:
            if path == allow or path.startswith(allow + "/") or path.startswith(allow + ":"):
                return True
        return False

    authed_shadowed = [
        p for p in authed_paths
        if path_is_bypassed(p, bypass) and not is_allowed_shadow(p)
    ]
    authed_shadowed_documented = [
        p for p in authed_paths
        if path_is_bypassed(p, bypass) and is_allowed_shadow(p)
    ]

    # Bypass entries that don't correspond to any registered public route
    bypass_orphan = []
    for b in bypass:
        matches_any = any(p == b or p.startswith(b + "/") for p in public_paths + authed_paths)
        if not matches_any:
            bypass_orphan.append(b)

    total_routes = sum(len(paths) for paths in groups.values())
    violations = len(public_missing_bypass) + len(authed_shadowed)

    if args.json:
        report = {
            "total_routes": total_routes,
            "route_groups": {k: len(v) for k, v in groups.items()},
            "bypass_prefixes": bypass,
            "violations": {
                "public_missing_bypass": public_missing_bypass,
                "authed_shadowed_by_bypass": authed_shadowed,
            },
            "documented_shadowing": authed_shadowed_documented,
            "bypass_orphan": bypass_orphan,
            "ok": violations == 0,
        }
        print(json.dumps(report, indent=2))
        return 0 if violations == 0 else 1

    print(f"=== SentinelX Handler Auth Audit ===")
    print(f"Router file: {ROUTER_FILE.relative_to(REPO_ROOT)}")
    print(f"Total routes: {total_routes}")
    for name, paths in groups.items():
        print(f"  - {name}: {len(paths)} routes")
    print(f"Bypass prefixes: {len(bypass)}")
    print()

    if public_missing_bypass:
        print(f"[X] {len(public_missing_bypass)} public routes MISSING from bypass allowlist:")
        for p in public_missing_bypass:
            print(f"    - {p}")
        print()

    if authed_shadowed:
        print(f"[X] {len(authed_shadowed)} authed routes SHADOWED by bypass "
              f"(silent fall-open):")
        for p in authed_shadowed:
            print(f"    - {p}")
        print()

    if authed_shadowed_documented:
        print(f"[i] {len(authed_shadowed_documented)} shadowing entries with "
              f"documented alternative auth (informational):")
        for p in authed_shadowed_documented:
            print(f"    - {p}")
        print()

    if bypass_orphan:
        print(f"[?] {len(bypass_orphan)} bypass entries with no matching route "
              f"(dead code?):")
        for b in bypass_orphan:
            print(f"    - {b}")
        print()

    if violations == 0:
        print("PASS: every authed route requires auth; every public route "
              "is explicitly allowlisted.")
        return 0
    print(f"FAIL: {violations} violations.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
