# SAML XSW / XEE / Transform attack fixtures

> Provenance: copied verbatim from
> `crates/sx-iam/fuzz/corpus/saml_response_fuzz/`. The fuzz corpus is
> the canonical source — these copies exist so the k6 load harness
> (which lives outside the `sx-iam` crate sandbox) does not depend on
> a build-time path that would break first under a Cargo workspace
> shuffle. Same justification used inside
> `services/sx-monolith/tests/saml_attack_emits_finding.rs:151`.
>
> When updating: re-copy from the fuzz corpus; do not hand-edit here.

| File | Attack kind | What the SP rejects on |
| --- | --- | --- |
| `xsw1.xml` | XSW (signature wrapping) | nested `<saml:Assertion>` elements; multi-signature OR Reference-URI rule |
| `xsw2.xml` | XSW | signed assertion moved to header / different subtree |
| `xsw3.xml` | XSW | signature wraps a sibling rather than the included assertion |
| `xsw8.xml` | XSW | comment / namespace nuance variant |
| `xee1_billion_laughs.xml` | XEE (XML external entity / billion-laughs) | entity expansion limits before parsing the assertion |
| `transform2_xpath.xml` | Transform bypass | non-allowlisted `Transform` algorithm URI on a signed reference |

The k6 script `tests/load/k6/saml_acs.js` iterates over every file in
this directory, base64-encodes the body, posts it to
`/v1/auth/saml/acs` per SAML 2.0 HTTP-POST binding (Bindings §3.5.4),
and asserts the SP returns a non-200 within the timing budget.

`SamlAttackKind` enum (production source of truth):
`crates/sx-iam/src/service/saml/observer.rs:34`. The four variants the
SP recognises are `Xsw`, `Xee`, `TransformBypass`, `C14nViolation`;
this fixture set exercises the first three (`C14nViolation` is
covered by the in-process unit tests inside the observer module).
