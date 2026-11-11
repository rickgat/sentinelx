# SAML SP XMLDSig Fuzzing (HIGH-003)

The SentinelX SAML 2.0 Service Provider verifier ships its own
hand-rolled XMLDSig pipeline (`crates/sx-iam/src/service/saml/`). XML
signature processing has a notorious bug history (XSW, XEE, transform
abuse, canonicalisation ambiguity); CISO sign-off requires *continuous
automated adversarial testing* of that surface, not a single
hand-audited review.

This document covers:

- The fuzz harness and how to run it locally.
- How to add new corpus examples.
- The catalogue of known XSW attack patterns and which seed covers each.
- The defensive gates the byte-input verifier enforces.

## Surface under test

The fuzz target calls
[`sx_iam::service::saml::verify_saml_response`](../../crates/sx-iam/src/service/saml/fuzz_entry.rs)
— a `&[u8] -> Result<ParsedAssertion, SamlError>` boundary that runs
every defensive gate before delegating to the cryptographic verifier.

The contract under fuzz is:

1. **No panic.** Any panic on adversarial input is a CVE-class bug.
2. **Bounded time.** The verifier is single-pass and clamped by the
   1 MB body cap; libFuzzer's per-input 10 s timeout will catch any
   regression.
3. **Determinism.** Same `&[u8]` MUST yield the same `Result` variant
   across runs.

## Defensive gates

Before the RSA/signature verification fires, the byte-input entry
point enforces all of:

| Gate | What it rejects |
| --- | --- |
| Body cap | Inputs above `MAX_RESPONSE_BYTES` (1 MB). |
| UTF-8 | Non-UTF-8 bytes — surface as `XmlMalformed`, never panic. |
| DOCTYPE / DTD | Any `<!DOCTYPE …>` token. Kills XEE / Billion Laughs / parameter-entity exfil. |
| C14N 1.1 strict | Mixed canonicalisation versions; legacy non-exclusive C14N 1.0. |
| Default-NS in SignedInfo | `xmlns=` re-declared inside `<SignedInfo>` (W3C C14N 1.1 §2.4). |
| Single `<Signature>` | More than one top-level `<Signature>` element. |
| `<Reference URI>` binding | Must be `#<id>` matching the embedded `<Assertion>/@ID`. |
| Transform allow-list | Only `enveloped-signature`, `xml-c14n11`, `exc-c14n`, `xml-c14n` accepted. XSLT/XPath outright rejected. |
| Algorithm allow-list | `rsa-sha1`, `rsa-md5`, `sha1` digest, `md5` digest rejected. |
| Embedded X.509 hygiene | If `<X509Certificate>` is present, it MUST DER-parse and MUST NOT be expired. |
| Single `<Assertion>` | (Inherited from P0-004.) `MultipleAssertions` on any `>1` count. |
| Time window | `NotBefore` / `NotOnOrAfter` with operator-configured skew. |
| Audience | `<AudienceRestriction>` must contain the SP `entity_id`. |
| Constant-time sig compare | RSA verification uses the `rsa` crate's constant-time PKCS#1 v1.5 path; no early-exit byte comparison in the SP. |

A failure on any gate surfaces as `SamlError::XmlMalformed(...)` or one
of the other coarse variants. The error string is intentionally
non-specific so the boundary does not help an attacker calibrate
forgeries.

## Running locally

The fuzz target requires a **nightly** toolchain and `cargo-fuzz`:

```bash
# One-off install
rustup toolchain install nightly
cargo install --locked cargo-fuzz

# 5-minute smoke run
cd crates/sx-iam
cargo +nightly fuzz run saml_response_fuzz -- -max_total_time=300

# Full 6-hour CI-style run
cargo +nightly fuzz run saml_response_fuzz -- \
    -max_total_time=21600 \
    -timeout=10 \
    -rss_limit_mb=2048 \
    -print_final_stats=1
```

A coverage report can be generated after a run with:

```bash
cargo +nightly fuzz coverage saml_response_fuzz
```

The HTML output is written to
`crates/sx-iam/fuzz/coverage/saml_response_fuzz/`.

If the harness finds a crash, the offending byte buffer is written to
`crates/sx-iam/fuzz/artifacts/saml_response_fuzz/`. Reproduce with:

```bash
cargo +nightly fuzz run saml_response_fuzz \
    crates/sx-iam/fuzz/artifacts/saml_response_fuzz/<crash-id>
```

## Seed corpus

The seed corpus lives at
`crates/sx-iam/fuzz/corpus/saml_response_fuzz/`. Each file is a single
SAML 2.0 `<Response>` document chosen to exercise one named attack
shape. The fuzz engine mutates these seeds to explore neighbouring
inputs.

### Adding a new seed

1. Create a new XML file under
   `crates/sx-iam/fuzz/corpus/saml_response_fuzz/`. Name it
   `<class>_<one-liner>.xml` (e.g. `xee5_param_entity_ref.xml`).
2. If the seed represents one of the 8 named XSW variants, also add it
   to the `xsw_corpus` module in
   `crates/sx-iam/src/service/saml/fuzz_entry.rs` via `include_str!`
   and add a `#[test]` that asserts rejection.
3. Run `cargo test -p sx-iam --lib saml::fuzz_entry` to confirm the
   gate layer still rejects the new shape.
4. Open the PR — the `corpus-sanity` workflow job confirms the corpus
   compiles into the harness and the 6h `fuzz` job exercises it.

## XSW attack catalogue

The 8 named XSW shapes covered (Somorovsky & Schwenk 2012, plus Tavis
Ormandy's 2018 wrap-and-promote follow-ups):

| Variant | Seed file | What it does | Gate that rejects it |
| --- | --- | --- | --- |
| XSW#1 | `xsw1.xml` | Signed `<Assertion>` inserted as child of an unsigned wrapper assertion. | `MultipleAssertions` |
| XSW#2 | `xsw2.xml` | Signature moved out to the `<Response>` body; attacker assertion takes the signed slot. | `Reference URI does not resolve to embedded Assertion` |
| XSW#3 | `xsw3.xml` | Attacker assertion becomes the top-level `<Assertion>`; signed assertion buried. | `MultipleAssertions` |
| XSW#4 | `xsw4.xml` | Signed assertion moved into the attacker's `<Subject>`. | `MultipleAssertions` |
| XSW#5 | `xsw5.xml` | Signed assertion wrapped under `<Extensions>` inside the attacker assertion. | `MultipleAssertions` |
| XSW#6 | `xsw6.xml` | Two `<Assertion>`s share the same `ID`; signature references the collision. | `MultipleAssertions` |
| XSW#7 | `xsw7.xml` | Signature moved into `<Extensions>`; attacker assertion replaces the signed one at top level. | `Reference URI does not resolve` / single-Signature check |
| XSW#8 | `xsw8.xml` | Double-wrapped: outer signed shell with a nested signed assertion in the Subject. | `MultipleAssertions` + multi-Signature |

## XEE / DTD-bomb catalogue

| Seed file | Shape | Gate |
| --- | --- | --- |
| `xee1_billion_laughs.xml` | Nested entity expansion | `DOCTYPE/DTD rejected` |
| `xee2_external_entity.xml` | `SYSTEM "file:///etc/passwd"` | `DOCTYPE/DTD rejected` |
| `xee3_parameter_entity.xml` | Out-of-band parameter-entity exfil | `DOCTYPE/DTD rejected` |
| `xee4_quadratic_blowup.xml` | Linear entity refs amplifying expanded size | `DOCTYPE/DTD rejected` |

## Transform abuse catalogue

| Seed file | Shape | Gate |
| --- | --- | --- |
| `transform1_xslt.xml` | `<Transform Algorithm="…REC-xslt…">` with embedded stylesheet | `transform forbidden: XSLT` |
| `transform2_xpath.xml` | XPath transform that strips the `<Signature>` ancestor | `transform forbidden: XPath` |
| `transform3_unknown_uri.xml` | Custom attacker-supplied transform URI | `transform forbidden: unknown URI` |
| `transform4_mixed_c14n.xml` | `CanonicalizationMethod` uses exc-c14n; `<Transform>` uses C14N 1.1 | `C14N strict: mixed canonicalisation versions` |

## Other notable seeds

| Seed file | Shape | Gate |
| --- | --- | --- |
| `replay_same_assertion.xml` | Single signed assertion (exercises the replay cache when re-fed). | `SignatureInvalid` at the byte-input boundary; the live ACS endpoint additionally surfaces `ReplayAssertion` from `process_acs_response`. |
| `self_signed_attacker_ca.xml` | Embedded `<X509Certificate>` signed by an attacker CA. | `embedded x509: parse` / `SignatureInvalid` |

## CI integration

The fuzz job lives in
[`.github/workflows/fuzz-saml.yml`](../../.github/workflows/fuzz-saml.yml).
It runs on every pull request that touches:

- `crates/sx-iam/src/service/saml/**`
- `crates/sx-iam/fuzz/**`
- `.github/workflows/fuzz-saml.yml` itself.

Two jobs run in parallel:

1. **`corpus-sanity`** — 15 min budget. Confirms the seed XML compiles
   into the harness via `include_str!` and that the 8 named XSW unit
   tests still reject every corpus example.
2. **`fuzz`** — 400 min budget. Runs `cargo fuzz run saml_response_fuzz`
   for 6 hours with `-timeout=10` (per-input hang detector) and
   `-rss_limit_mb=2048` (memory-blowup detector). Uploads the
   coverage report as an artifact (always) and the crash corpus as an
   artifact (only on failure).

Any new panic or hang fails CI and surfaces the crashing input via the
`saml-fuzz-crashes` artifact.
