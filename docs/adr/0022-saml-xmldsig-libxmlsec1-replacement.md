# ADR 0022 — Replace hand-rolled SAML XMLDSig verifier with `libxmlsec1` (FFI via `sx-xmlsec`)

Status: Accepted
Date: 2026-06-25
Deciders: Principal Security Engineer, Principal Platform Engineer, PO
Supersedes: [ADR-0010](0010-saml-xmldsig-handrolled.md)
Superseded by: None

> **Note on numbering** — the natural sequential slot (0011) was
> already allocated to `0011-scim-2-0-bearer-token-separation.md`
> before this ADR was drafted. We keep numbers monotonic across the
> repo's ADR directory; ADR-0022 is the next free slot and supersedes
> ADR-0010 explicitly via the header above.

## Context

`SX-PLAN-TOP5-001` (`docs/plans/top5-1-xmldsig-replacement.md`) and
the senior review 2026-Q2 §1 + §7 escalated "hand-rolled XMLDSig
verifier" to a Top-5 production blocker. ADR-0010 (2026-06-12)
accepted the hand-rolled implementation under the constraint that the
XSW defence corpus was complete and the senior team would re-evaluate
on receipt of the first XSW-class incident or as the SP footprint
crossed the "more than one Fortune-500 IdP" threshold. Both triggers
fired:

* HIGH-003 fuzz harness flagged that the hand-rolled `extract_element_slice`
  is sensitive to namespace-prefix games that libxmlsec1's
  identity-comparison would catch outright.
* The SP now serves 12 enterprise IdPs (Okta, Azure AD, ADFS, OneLogin,
  Ping, Keycloak, plus six tenant-local Shibboleth deployments) —
  beyond the "one IdP" threshold ADR-0010 named.

The ecosystem option set for the replacement is unchanged since
SX-PLAN-TOP5-001 §1: no pure-Rust XMLDSig crate has reached
enterprise-grade XSW coverage; the de-facto reference verifier behind
every audited SAML SP is `libxmlsec1` (Keycloak, Shibboleth, OneLogin's
`python-saml`, SimpleSAMLphp).

## Decision

**Replace the hand-rolled XMLDSig verifier with `libxmlsec1` via the
`sx-xmlsec` workspace crate, using a staged shadow-mode migration
gated on a quantitative cutover SLO.**

Concretely:

1. **`sx-xmlsec` owns the FFI surface.** Hand-written `extern "C"`
   bindings to ~24 libxmlsec1 / libxml2 / OpenSSL-engine symbols
   (`xmlSecDSigCtxVerify`, `xmlSecKeysMngrAdoptKey`, `xmlReadMemory`,
   `xmlSecTransformIdsRegistryDisable`, …). No `samael` wrapper — we
   want explicit per-tenant transform allow-list policy. Linkage is
   gated behind the `xmlsec1` Cargo feature; workspace-default builds
   stay green without the system package.
2. **Defence-in-depth gates stay in Rust.** The byte-level
   `pre_parse_gates` (multi-Assertion XSW, DOCTYPE/DTD, transform
   allow-list, Reference-URI binding, deprecated-algo, single-Signature,
   embedded-X.509 hygiene) continue to run BEFORE the FFI call.
   `LayeredVerifier` in `sx-xmlsec` composes the gate closure with any
   inner verifier. The C library never sees an XSW-shaped or
   DOCTYPE-laden document.
3. **Shadow-mode dispatch via `DualVerifier`.** `sx-xmlsec::DualVerifier`
   runs both verifiers on the same input, returns the *primary*
   result, and emits `xmldsig.shadow.mismatch.<kind>` tracing events
   plus the `xmldsig_shadow_mismatch_total{kind}` Prometheus counter
   on disagreement. Three mismatch kinds: `both_accept_differ`,
   `primary_only_accept`, `secondary_only_accept`.
4. **Config-driven mode selection.** `saml.xmldsig.verifier` in the
   operator YAML accepts the wire-stable tokens `handrolled` /
   `shadow` / `xmlsec1`. PHASE-2A introduced the field;
   PHASE-2B wires it through to the SAML SP `EnabledSamlAdapter` so
   no further code change is needed to flip modes. Default stays
   `handrolled` — the cutover is an operational decision the PO
   makes after the SLO gate fires.
5. **Cutover SLO.** Default does not flip to `shadow` until the
   shadow-mode rollout proves stable. Default does not flip to
   `xmlsec1` until **zero shadow-mode disagreements (Class A or
   Class B in the senior plan §2.2 taxonomy) for 14 consecutive
   days against real production traffic** is observed. Class C
   "both reject, different variant" noise is silently aggregated
   per the planner's §2.2 explicit allowance.
6. **Rollback window.** The hand-rolled verifier path stays
   compileable for ONE minor version after the cutover so an
   operator can flip back via the YAML knob if a CVE or behaviour
   regression surfaces. The libxmlsec1-side CVE response uses the
   same hot-config-reload path (see `docs/runbooks/supply-chain.md`
   §8 mitigation playbook). After the rollback window closes, the
   hand-rolled module is deleted; this ADR will be amended at that
   point with a "Phase-3 deletion completed" note.

## Consequences

### Operational

* **libxmlsec1 CVEs are tracked outside `cargo audit`.** Advisory
  sources live at the gnome.org Bugzilla, libxmlsec1 GitHub
  releases, and NVD — none of which surface through our existing
  `cargo audit` / `cargo deny` gate. `docs/runbooks/supply-chain.md`
  §8 ("libxmlsec1 CVE tracking (TOP5-#1)") was added to enumerate
  the monitoring sources, monthly review cadence, and the hot-config
  rollback playbook.
* **Build matrix grows.** Linux production needs `apt install
  libxmlsec1-openssl libxml2`. macOS dev workstations need `brew
  install libxmlsec1 libxml2`. CI's apt-install line is the pinning
  surface; the `vendored-libxmlsec1` Cargo feature is the fallback
  for release images that pin a specific CVE-patched libxmlsec1
  source tree.
* **+150 LOC `build.rs`** vs. zero today. The `sx-xmlsec` build
  script uses `pkg-config` for system-package discovery and is
  documented in `crates/sx-xmlsec/build.rs`.

### Security

* **XSW defence is now layered.** Rust-side byte gates catch the
  Somorovsky/Schwenk shapes BEFORE any C code runs;
  `xmlSecDSigCtxVerify` is the authoritative cryptographic verdict.
  The hand-rolled identity-comparison disappears as a maintenance
  burden, replaced by libxmlsec1's `enabledReferenceUris` machinery.
* **Transform allow-list is explicit.** `xmlSecTransformIdsRegistryDisable`
  removes XSLT, XPath, and XPath2 transforms at process start (see
  `crates/sx-xmlsec/src/transforms.rs`). The hand-rolled equivalent
  (text-substring scan for `Algorithm="…xslt…"`) stays as the
  pre-parse gate's belt-and-braces.
* **Shadow window surfaces regressions before cutover.** The
  `xmldsig_shadow_mismatch_total` counter is the leading-edge signal.

### Maintenance

* **+1 system dep (`libxmlsec1`) + 1 transitive (`libxml2`).**
  Tracked in `docs/runbooks/supply-chain.md` §8.
* **Hand-rolled code stays compileable through one minor version
  post-cutover** to preserve the rollback path. Targeted for
  deletion in a TOP5-#1-PHASE-3 task after the rollback window
  closes.

## Alternatives Considered

* **`xml-security-c` (Apache Santuario C++).** Same security
  posture as libxmlsec1; rejected for `cxx` FFI fragility (C++
  name mangling, exceptions across FFI). Kept as documented Plan B
  in SX-PLAN-TOP5-001 §1 if a libxmlsec1 CVE proves uncomfortable
  to track during rollout.
* **`samael` crate (Rust wrapper around libxmlsec1).** Rejected —
  wraps libxmlsec1 with API constraints (no per-tenant transform
  allow-list). We would end up writing our own bindings anyway.
  Owning the FFI surface costs the same and frees the design.
* **Pure-Rust `signxml-rs` / `xmlsec` crates.** Rejected — stalled
  (last commit >18 months) or toy implementations. No XSW corpus
  coverage. SX-PLAN-TOP5-001 §1.2 has the full comparison.
* **Status quo (continue hand-rolled).** Rejected — see Context.
  The whole point of this ADR is to stop owning hand-rolled crypto.

## References

* [SX-PLAN-TOP5-001](../plans/top5-1-xmldsig-replacement.md) — the
  implementation plan and risk register this ADR implements.
* [ADR-0010](0010-saml-xmldsig-handrolled.md) — the decision being
  reversed (status updated in lockstep with this ADR).
* [Supply-chain runbook §8](../runbooks/supply-chain.md) — libxmlsec1
  CVE tracking outside `cargo audit`; mitigation playbook for the
  hot-config rollback.
* [HIGH-003 fuzz harness + corpus](../security/saml-xmldsig-fuzzing.md)
  — the 18-shape corpus that gates the cutover via
  `crates/sx-xmlsec/tests/corpus_parity.rs`.
* Senior review 2026-Q2 §1 + §7 — the policy escalation that
  authorised the replacement.
