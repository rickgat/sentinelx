# ADR 0010 — SAML XMLDSig hand-rolled (`quick-xml` + `rsa` + `sha2`), not `samael`

Status: Accepted
Date: 2026-06-12
Deciders: Principal Security Engineer, Principal Platform Engineer
Supersedes: None
Superseded by: [ADR-0022](0022-saml-xmldsig-libxmlsec1-replacement.md)

## Status update 2026-06-25

**SUPERSEDED by [ADR-0022](0022-saml-xmldsig-libxmlsec1-replacement.md)**
— the hand-rolled XMLDSig verifier remains in production until the
TOP5-#1-PHASE-2B cutover SLO fires (zero shadow-mode disagreements for
14 consecutive days against real production traffic). Maintain in
parallel; **do not delete** until ADR-0022's rollback window closes
(one minor release after the operator flips
`saml.xmldsig.verifier: xmlsec1` in production).

Operational posture:

* The hand-rolled `verify_assertion` in
  `crates/sx-iam/src/service/saml/response.rs` is still the production
  default and is invoked behind the
  `sx_iam::service::saml::HandRolledVerifier` adapter wired into the
  `verifier_factory` in PHASE-2A.
* The `pre_parse_gates` defence-in-depth byte-level checks stay in
  place after the cutover (they are layered onto the libxmlsec1
  verifier via `sx_xmlsec::LayeredVerifier`). ADR-0022 §Decision
  bullet 2 makes this explicit.
* Rollback to this ADR's decision is one YAML knob away
  (`saml.xmldsig.verifier: handrolled`) for as long as the
  hand-rolled module stays compileable.

Original decision text below preserved verbatim for historical
context. Do not edit the original sections — amendments belong in
ADR-0022 or in a follow-up status block.

---


## Context

P0-004 ships SAML 2.0 SP (Service Provider) support so enterprise
customers can federate SentinelX with their existing IdP (ADFS,
Okta, Azure AD, OneLogin, Ping). The SP must:

- consume an IdP `<saml:Response>` carrying an `<saml:Assertion>`;
- verify the embedded `<ds:Signature>` over the assertion subtree;
- defend against the XML Signature Wrapping (XSW) attack family;
- handle a non-trivial cert / digest matrix (SHA-1, SHA-256, SHA-384;
  RSA-PKCS#1 v1.5; canonicalisation method `Exclusive XML
  Canonicalization 1.0`).

The Rust ecosystem option set was:

1. **`samael` crate.** The most-recommended Rust SAML library. Wraps
   `libxml2` + `xmlsec1` via FFI. Mature C deps, but pulls a large
   transitive surface (`libxml2`, `xmlsec1`, `openssl`, `gnutls`
   on some platforms) and binds us to whatever XSW defences those
   C libraries ship — historically incomplete.
2. **`samael-saml` fork.** Same C deps, smaller community.
3. **Hand-rolled XMLDSig verifier on top of `quick-xml` + `rsa` +
   `sha2`.** Pure-Rust, smaller dep tree, lets us implement the
   XSW defences explicitly in code we control.

XSW is the dominant SAML attack family: an attacker who can mutate
the `<saml:Response>` between the IdP and the SP wraps a *signed*
assertion subtree around a *forged* assertion and tricks the SP
into reading the forged one while the signature still verifies. A
defence requires the verifier to compare the **node verified by the
signature** against the **node consumed by the application** by
identity, not by XPath.

## Decision

We hand-roll the XMLDSig verifier in
`services/sx-monolith/src/adapters/saml.rs` on top of:

- `quick-xml` (parser, no DTD support, no external entity expansion);
- `rsa` (RSA-PKCS#1 v1.5 verification);
- `sha2` (SHA-256, SHA-384) and `sha1` (only behind the `legacy-
  sha1` feature flag, off by default);
- `x509-parser` (cert chain parsing; the IdP cert is loaded
  per-tenant from `saml_idp_config.x509_cert_pem`).

The verifier flow:

1. Parse the response with `quick-xml`, refusing DOCTYPE / external
   entities (XXE defence).
2. Locate **every** `<saml:Assertion>` element in the document.
   Refuse if there is more than one.
3. Locate the `<ds:Signature>` element. Compute the signed bytes by
   applying the declared canonicalisation method (exc-c14n) to the
   **referenced subtree**, identified by `<ds:Reference URI="#…">`
   pointing to the assertion's `ID` attribute.
4. **XSW defence — identity comparison.** Walk back from the
   signed-bytes computation to the actual DOM node. Compare *by
   pointer* (after parsing into a typed `Assertion` struct, the
   verifier stores the node id used for signature input and
   compares it to the node id the application reads from). If the
   ids differ, refuse the response.
5. Verify `RSA-PKCS#1 v1.5(sha256, signed_bytes, idp_pubkey) ==
   <ds:SignatureValue>`.
6. Verify the assertion's `Conditions` window (`NotBefore`,
   `NotOnOrAfter`, ±5 min skew).
7. Verify the assertion's `Issuer` equals
   `saml_idp_config.entity_id`.
8. Reject if the chosen `SignatureMethod` is `rsa-sha1` and
   `signing_algo != 'sha1'` in `saml_idp_config`.

The verifier is unit-tested against the OWASP XSW corpus (8
canonical attack cases) and a custom suite of malformed responses
collected from production IdP misconfigurations.

## Consequences

- **Smaller dep tree.** No `libxml2`, no `xmlsec1`, no FFI surface.
  CVE-mitigation work shrinks accordingly.
- **Full XSW defence under our control.** The 8-case OWASP XSW
  suite is part of the test matrix; any future XSW class would be
  caught by adding a fixture.
- **SHA-1 is gated.** `signing_algo = 'sha1'` is supported only for
  legacy ADFS tenants and emits a `warn!` log + a deprecation
  banner in the dashboard. New tenants default to `sha256`.
- **DOCTYPE / XXE explicitly refused.** `quick-xml` is configured
  with `trim_text(false)` and the verifier rejects responses
  containing a DOCTYPE declaration.
- **Maintenance cost.** We own a non-trivial security-sensitive
  parser. The mitigation is the test corpus (OWASP + production
  misconfigurations) and a yearly review by the security team.
- **SP-initiated SLO supported.** When `saml_idp_config.slo_url` is
  populated, the SP supports SAML logout (Single Logout). Absent
  SLO returns 422 to `GET /v1/auth/saml/logout`.
- **No IdP-initiated unsolicited responses by default.** The SP
  refuses responses that do not match a pending `RelayState`
  cookie. An operator can opt-in per-tenant by setting
  `saml_idp_config.allow_unsolicited = TRUE` (off by default).

## Alternatives Considered

- **`samael` (libxml2 + xmlsec1 via FFI).** Rejected — transitive
  C surface, historical XSW gaps in `xmlsec1`, FFI cost on cross-
  platform builds (some Linux distros ship without `xmlsec1`).
- **Use `xmlsec` directly (without `samael`).** Same dep surface,
  worse ergonomics.
- **Outsource SAML to an OIDC bridge (e.g. Auth0 / Keycloak as a
  front).** Rejected — adds an external dependency to the auth
  hot path and breaks the air-gapped / sovereign deployment story.
- **Support SAML POST binding only; refuse Redirect.** Adopted as
  default — the verifier supports both bindings, but Redirect is
  off by default per the IdP profile guide.
