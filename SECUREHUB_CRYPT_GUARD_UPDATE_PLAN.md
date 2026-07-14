# crypt_guard HPKE and ML-KEM standardization plan

> Historical filename only: this is a **standalone `crypt_guard` crate** plan.
> It defines no secureHUB, database, tenant, service, or application policy.

## Purpose and compliance boundary

Replace the current "HPKE-shaped" helper with a genuine HPKE implementation
whose behavior is tested against published vectors and whose documentation
uses precise standards language.

The current helper is **not HPKE**: it derives a single AEAD key from
`HKDF(salt = kem_ct, info = crypt_guard:v2:aead:<alg>)`, generates an
independent nonce, and prepends `info`/`aad` to encrypted plaintext. It does
not implement RFC 9180 `KeySchedule`, `LabeledExtract`, `LabeledExpand`,
stateful nonce sequencing, or the HPKE sender/recipient context API. It must
therefore never be described as RFC 9180 compliant.

The target has two distinct conformance claims:

1. **RFC 9180 HPKE core conformance** — exact key schedule, context behavior,
   modes, serialization roles, standard KDF/AEAD identifiers, errors, and test
   vectors.
2. **ML-KEM HPKE profile conformance** — FIPS 203 ML-KEM used through the
   current `draft-ietf-hpke-pq` mapping. As of 2026-07-14, that mapping is an
   active Internet-Draft, not an RFC. The crate may say "implements
   draft-ietf-hpke-pq-05" only after matching its vectors; it must not call
   that profile fully standardized or assign permanent interoperability
   guarantees before an RFC is published.

The generic CGv2 envelope remains a separate, versioned protocol. No existing
CGv2 bytes, `Encryptor`/`Decryptor` semantics, or `api::hpke` framing are
silently reinterpreted as HPKE.

## Current implementation status: v2.0.4

Version 2.0.4 contains a **partial RFC 9180 core**, not a complete HPKE
implementation or an interoperability claim:

- `crypt_guard::hpke` implements the RFC 9180 labeled key-schedule operations,
  Base-mode schedule derivation, a non-`Clone` context with RFC nonce
  sequencing and exporter derivation, and the registered ChaCha20-Poly1305
  `Seal` / `Open` operation.
- It does not implement `SetupBaseS` / `SetupBaseR`, KEM serialization and
  shared-secret setup, complete AEAD coverage, or a vector-verified public
  suite. Those missing pieces prevent a full RFC 9180 conformance claim.
- The `hpke-pq-draft-05` feature exposes an additive, revision-named public
  Base-mode API for the two pinned FIPS 203 ML-KEM-768/1024 draft profiles.
  It remains experimental Internet-Draft work behind an explicit opt-in
  feature—not standardized HPKE support—and must retain its pinned vectors,
  literal draft revision, and promotion gates before any broader claim.
- CGv2 and the misnamed `api::hpke::{seal, open}` compatibility framing remain
  unchanged, separate, and explicitly non-HPKE.

## 1. Normative baseline and source policy

| Source | Role in this work | Required use |
| --- | --- | --- |
| [FIPS 203, ML-KEM](https://csrc.nist.gov/pubs/fips/203/final) | NIST definition of ML-KEM-512/768/1024 | Key generation, encapsulation, decapsulation, fixed-size serialization, input validation, and known-answer tests. |
| [NIST SP 800-227](https://csrc.nist.gov/pubs/sp/800/227/final) | Current NIST implementation/use guidance for KEMs | Validate inputs at the KEM boundary, preserve KEM failure handling, protect secret lifetimes, and use a KDF/AEAD composition rather than raw shared secrets. |
| [RFC 9180, HPKE](https://www.rfc-editor.org/rfc/rfc9180.html) | Normative HPKE core | Implement Sections 4, 5, 6, and 7 exactly for every supported standard suite. |
| [draft-ietf-hpke-pq-05](https://datatracker.ietf.org/doc/draft-ietf-hpke-pq-05) | Current ML-KEM and PQ/T HPKE mapping | Pin the exact draft revision and vector corpus; isolate it behind the explicit `hpke-pq-draft-05` feature/profile until it is finalized. |
| [PQCA/PQCP rust-libcrux](https://github.com/pq-code-package/rust-libcrux) | Required ML-KEM backend | Use the published `libcrux-ml-kem` package, after version/API/vector review; do not extend the current RustCrypto `ml-kem` backend for the HPKE path. |

The implementation owner records each pinned dependency version, Cargo feature
set, source commit/checksum for downloaded vectors, and applicable target
architectures in the release evidence. A crate being maintained by PQCA does
not itself establish protocol conformance; vector results do.

### 1.1 Draft-05 posture and immutable vector lock

`draft-ietf-hpke-pq-05` is an **active Internet-Draft**, published on
2026-07-06 and expiring on 2027-01-07. It is a Standards Track work item, but
it is not an RFC and its registry assignments, byte-level behavior, and suite
recommendations remain subject to revision. Accordingly, `crypt_guard` keeps
the exact Cargo feature and profile identifier **`hpke-pq-draft-05`**. The
identifier `draft-ietf-hpke-pq-05` is the specification name only; neither it
nor a passed local test confers a permanent interoperability or standards claim.

The following two byte streams are the only initial conformance inputs. Their
commit URLs are immutable, and the SHA-256 values are over the raw downloaded
file bytes (not a Git blob hash, an archive, a pretty-printed JSON rendering,
or a line-ending-normalized copy).

| Corpus | Immutable source commit URL | Pinned bytes | SHA-256 |
| --- | --- | ---: | --- |
| RFC 9180 core JSON vectors | [cfrg/draft-irtf-cfrg-hpke `5f503c564da00b0687b3de75f1dfbdfc4079ad31`](https://github.com/cfrg/draft-irtf-cfrg-hpke/blob/5f503c564da00b0687b3de75f1dfbdfc4079ad31/test-vectors.json) | 5,892,257 | `61fc662f01996cd06d713dacf5e133167bd309a1f329442d53f1e21a47b3ede6` |
| draft-ietf-hpke-pq-05 JSON vectors | [hpkewg/hpke-pq `11b5b9541e9976fc9ce25902011d20dacc089066`](https://github.com/hpkewg/hpke-pq/blob/11b5b9541e9976fc9ce25902011d20dacc089066/test-vectors.json) | 122,735 | `35c59f4a0132e5631e50ac039d8ca3a72e99f5e92dfd94d45338d6ae243f613c` |

The draft vector commit above is pinned separately because it regenerated the
draft corpus on 2026-07-06 after correcting the P-256 seed size. It is the
reviewed test-vector input for this plan, not a claim that the Internet-Draft
has been finalized. Phase 0 records the corresponding specification-source
commit (`9a0c2914d0554c90805d4bffb8710c44120533a6`) and confirms that any
relevant draft/vector divergence has explicit reviewer approval before a
profile is promoted.

### 1.2 Offline vendoring and source-integrity policy

- Vendor the two pinned raw JSON files byte-for-byte in a reviewed,
  repository-controlled test-fixture location before implementing vector
  tests. Commit a small adjacent provenance manifest containing the corpus
  name, immutable URL, source commit, byte count, SHA-256, retrieval date,
  and applicable license/notice.
- Test, release, and reproducible-build jobs read only those vendored files.
  They must not fetch vectors, fall back to a network URL, regenerate a corpus,
  or silently accept a checksum mismatch. CI runs with network access disabled
  for vector execution where the runner supports that control.
- Acquisition is a two-person review: one reviewer retrieves from the immutable
  URL and calculates SHA-256; a second independently verifies the recorded
  digest and byte count before the fixture is committed. The provenance
  manifest is the test harness's allowlist, not comments alone.
- Any new draft revision, upstream vector regeneration, source-commit change,
  or checksum/byte-count change is a new corpus. It requires a new manifest
  entry, review of the spec and vector diff, rerunning every applicable vector
  and negative suite, and an explicit promotion decision. It may not overwrite
  the draft-05 fixture or reuse the `hpke-pq-draft-05` profile name.

## 2. Checked-out gap inventory

| Area | Checked-out behavior | Required correction |
| --- | --- | --- |
| ML-KEM backend | `ml-kem = 0.3.2` (RustCrypto) still backs `src/kem/ml_kem.rs`. A separate private `libcrux-ml-kem = 0.0.9` adapter now validates ML-KEM-768/1024 serialized keys and preserves the draft's 64-byte private-key seed representation. | Connect the reviewed adapter only through draft-vector-verified HPKE setup. Do not replace the current generic KEM path until compatibility and tests prove it safe. |
| Context binding | `api::hpke::{seal, open}` puts `HFv1 || len(info) || info || len(aad) || aad` inside encrypted plaintext. | Remove the HPKE name from this compatibility helper or deprecate it. Real HPKE hashes `info` into `KeySchedule`; `aad` goes directly to each AEAD operation. |
| Key schedule | `src/hpke/mod.rs` now has a dedicated Base-mode RFC 9180 labeled KDF and derives `info_hash`, key, base nonce, and exporter secret without using the CGv2 KDF. | Verify intermediate values against the pinned RFC corpus and add the remaining supported-mode/setup boundaries; do not repurpose generic CGv2 KDF helpers. |
| AEAD profile | The safe CGv2 API exposes XChaCha20-Poly1305 and AES-256-GCM-SIV, neither an RFC 9180 AEAD. The partial HPKE core currently operates only registered ChaCha20-Poly1305. | Add only registered AES-128-GCM, AES-256-GCM, or ChaCha20-Poly1305 operations that have the applicable vector evidence. XChaCha and GCM-SIV remain non-HPKE CGv2 algorithms. |
| Nonces | CGv2 generates and serializes one random nonce per envelope. The partial HPKE context computes `base_nonce XOR I2OSP(seq, Nn)` internally and advances only after a successful AEAD operation. | Carry that context behavior through KEM setup and vector verification; retain no caller-controlled nonce API and enforce the message limit before reuse. |
| Wire format | CGv2 serializes a private header and fields into `Envelope`. | HPKE outputs `enc` at setup and ciphertexts from a context. Transport framing and recipient-key selection are application responsibilities under RFC 9180; any crypt_guard convenience envelope is a new, explicitly versioned wrapper. |
| Modes | The partial core derives Base-mode schedules and rejects other modes after applying RFC 9180 PSK-pair validation. The legacy helper has no HPKE modes. | Add PSK only with exact RFC 9180 setup and vectors. ML-KEM draft profiles do not implement RFC 9180 asymmetric-key authenticated modes, so Auth/AuthPSK must be unavailable for them. |
| Parser claims | CGv2 parser accepts trailing bytes and nonzero reserved fields. | Keep parser hardening as a separate CGv2 task. It is not evidence of HPKE conformance and must not delay a clean HPKE implementation boundary. |

## 3. Target public API and trust boundary

The HPKE surface is independent from `Envelope`, `Encryptor`, and
`Decryptor`. The minimum public API is stateful, since RFC 9180 derives a
context with a sequence number and exporter secret:

```text
HpkeSuite { kem_id, kdf_id, aead_id }

setup_base_sender(suite, recipient_public_key, info)
    -> (enc, SenderContext)
setup_base_recipient(suite, enc, recipient_private_key, info)
    -> RecipientContext

SenderContext::seal(aad, plaintext) -> ciphertext
RecipientContext::open(aad, ciphertext) -> plaintext
Context::export(exporter_context, length) -> secret bytes
```

`SenderContext` and `RecipientContext` own zeroizing key material and mutable
sequence state. They must not be `Clone`; concurrent use requires an explicit
caller-owned synchronization policy rather than accidental nonce reuse.
`seal`/`open` increment the sequence only after the corresponding AEAD
operation succeeds. They return a dedicated `MessageLimitReached` error before
the sequence can wrap.

An additive one-shot convenience API may be provided only as a thin wrapper:
`setup_base_*`, then one `seal` or `open`. It returns `enc` separately and
does not invent a CGv2-compatible serialized format. Existing
`api::hpke::{seal, open}` stays source-compatible during a named deprecation
window but cannot be aliased to this API.

The crate validates cryptographic inputs and protocol state. Applications own
recipient key discovery, identity/authentication, transport framing, replay
handling, persistence, authorization, and selection of an application-level
domain separator inside `info` or `aad`.

## 4. Exact protocol requirements

### RFC 9180 core

- Construct `suite_id = "HPKE" || I2OSP(kem_id, 2) || I2OSP(kdf_id, 2) || I2OSP(aead_id, 2)`.
- Implement `LabeledExtract` as `Extract(salt, "HPKE-v1" || suite_id || label || ikm)` and `LabeledExpand` as `Expand(prk, I2OSP(L, 2) || "HPKE-v1" || suite_id || label || info, L)`.
- Implement `KeySchedule(mode, shared_secret, info, psk, psk_id)` exactly:
  `psk_id_hash`, `info_hash`, `key_schedule_context`, `secret`, `key`,
  `base_nonce`, and `exporter_secret` use RFC labels and ordering.
- Enforce RFC KDF input/output bounds before allocating or calling a backend.
- Compute each nonce from `base_nonce` and the current sequence as RFC 9180
  specifies; never serialize the base nonce and never permit manual nonce
  injection.
- Keep `enc` serialization KEM-defined. The HPKE context must not derive its
  suite from attacker-selected bytes; the caller selects one explicit,
  supported suite before parsing `enc`.
- Return typed protocol errors for unsupported suite/mode, invalid PSK inputs,
  invalid public/private/ciphertext encoding, AEAD authentication failure,
  output-length violation, and message-limit exhaustion. Do not expose raw
  plaintext, private key, or shared-secret material through errors or logs.

### FIPS 203 + PQCA backend

- Use `libcrux-ml-kem` (`mlkem512`, `mlkem768`, `mlkem1024`) after locking a
  reviewed release. Its serialized-key API requires `validate_public_key`
  before encapsulation and `validate_private_key` before decapsulation for
  FIPS 203-compliant use; make those checks unavoidable in the adapter.
- Keep ML-KEM public-key, private-key, and ciphertext lengths parameter-set
  specific. Reject malformed and wrong-suite encodings before an HPKE context
  is created.
- Preserve the PQ draft's ML-KEM private-key representation: 64-byte seed
  form for the HPKE KEM interface, expanded internally only as needed.
- Do not assume that a generic ML-KEM keypair helper implements HPKE
  `DeriveKeyPair`. The draft requires SHAKE256 `LabeledDerive` and the FIPS
  203 `KeyGen_internal` relationship; add this only when it can be tested
  against the draft corpus.

### Initial profile policy

Implement profiles in this order, with exact identifiers and vectors:

1. `ML-KEM-768 / HKDF-SHA256 / AES-128-GCM` — draft PQ HPKE Base mode.
2. `ML-KEM-1024 / HKDF-SHA384 / AES-256-GCM` — draft PQ HPKE Base mode.
3. Additional RFC 9180 core suites only after the shared context/KDF harness
   passes their official RFC vectors.
4. PQ/T hybrid KEMs only after their referenced draft dependencies, KEM
   combiner behavior, and vectors are independently reviewed.

ML-KEM-512 remains available only when a caller explicitly opts in; it is not
the crate's recommended HPKE default. Never add a suite merely because a
primitive is present elsewhere in `crypt_guard`.

## 5. Compatibility and migration

1. Leave CGv2 serialization and safe builders unchanged in the initial HPKE
   release. They are a separate protocol family.
2. Mark the existing plaintext-framing helper as `legacy_hpke_framing` in
   documentation and prepare a source-compatible deprecation path. It may be
   retained for its existing consumers but must not gain new features.
3. Publish a distinct HPKE module and explicit feature gate. New HPKE output
   is never written as `CGv2` and never parsed by `Envelope::from_bytes`.
4. Provide a documented application migration recipe: preserve old payload
   bytes, identify protocol by an application-owned record/version field,
   use only the identified reader, then write the new HPKE transport shape.
   There is no trial decryption or implicit downgrade.
5. Rename or remove the old HPKE claim in README and rustdoc in the same
   release that exposes the new API. Examples must say "RFC 9180 HPKE" only
   for suites that pass the relevant vector suite; draft ML-KEM suites must
   name the exact draft revision.

## 6. Verification gates

No HPKE profile is enabled by default before all applicable gates pass.

- **Official vectors:** RFC 9180 vectors for the core KDF/context/AEAD suite;
  pinned `draft-ietf-hpke-pq-05` JSON vectors for each ML-KEM profile. Verify
  setup values (`enc`, shared-secret dependent outputs, key, base nonce,
  exporter secret), ciphertexts, opens, and exporter outputs.
- **Cross-implementation:** encrypt/decrypt and exporter checks against an
  independent implementation that declares support for the same exact draft
  version. Record implementation name/version and the vectors used.
- **KAT and validation:** FIPS 203 KATs plus valid/invalid public-key,
  private-key, and ciphertext cases through the PQCA adapter.
- **Negative protocol tests:** wrong `info`, wrong `aad`, altered `enc`,
  altered ciphertext, wrong suite, malformed sizes, bad PSK pairing, forbidden
  mode, oversized KDF inputs, exporter length overflow, and sequence exhaustion
  all fail with the expected typed error and no plaintext release.
- **Misuse tests:** compile-time and runtime tests prove there is no manual
  nonce API, no context cloning, no ML-KEM Auth/AuthPSK constructor, and no
  accidental use of XChaCha20-Poly1305 or AES-GCM-SIV in an HPKE suite.
- **Backend review:** audit `Cargo.lock`, enabled PQCA features, `no_std`/SIMD
  selection, supported architectures, zeroization, and the dependency's
  validation preconditions. Pin and review the exact release before shipping.
- **Regression:** run formatting, focused HPKE tests, all default tests,
  no-default-feature checks, legacy-read feature checks, doctests, and the
  existing typestate compile-fail suite.

### 6.1 Explicit promotion gates for `hpke-pq-draft-05`

| Gate | Evidence required | Promotion effect |
| --- | --- | --- |
| V0 — corpus integrity | The vendored RFC and draft JSON files exactly match the byte counts and SHA-256 values in Section 1.1; the provenance manifest links each to its immutable commit URL; an offline test proves that no vector fetch occurs. | The corpus may be used by tests. A mismatch blocks implementation and release. |
| V1 — RFC core | Every supported RFC 9180 vector case, including required intermediate values and exporter results, passes against the pinned RFC corpus; negative/context-sequencing tests pass. | A selected non-PQ suite may make the narrow RFC 9180 conformance claim for that exact suite only. |
| V2 — draft profile | Every applicable ML-KEM Base-mode case in the pinned draft corpus passes with the `hpke-pq-draft-05` feature; FIPS 203 validation/KATs and the draft-specific negative tests pass; independent interoperation is recorded against the same draft revision. | The feature/profile may be released as **draft-ietf-hpke-pq-05 experimental support**, still non-default and still without an RFC or permanent-interoperability claim. |
| V3 — public exposure | Security review, dependency/source review, semver review, full regression, and documentation review confirm the exact feature/profile name and draft warning. | The additive public API may be released. Failure leaves the code or feature non-public/non-default. |
| V4 — draft or RFC update | A new corpus is vendored under a new provenance entry; the exact source/diff is reviewed; V0 through V3 are repeated for the new revision. | The new revision receives a distinct versioned profile name (for example, `hpke-pq-draft-06`). The draft-05 profile and fixtures remain immutable; aliasing is allowed only after byte-level equivalence is demonstrated and approved. |

## 7. Delivery phases

| Phase | Deliverable | Promotion condition |
| --- | --- | --- |
| 0 — specification lock | Pinned RFC/draft/PQCA versions; suite registry; error taxonomy; vector provenance | Review confirms exact compliance labels and draft posture. |
| 1 — primitive adapter | `libcrux-ml-kem` adapter with FIPS 203 validation/KATs, no public HPKE API | PQCA API and FIPS vectors pass on supported targets. |
| 2 — RFC core | Labeled KDF, Base context, AES-GCM adapter, nonce sequencing, exporter, RFC vectors | RFC 9180 vector and negative suites pass. |
| 3 — ML-KEM draft profile | ML-KEM-768/1024 Base profiles plus draft vectors | Draft vectors and independent interoperability evidence pass. |
| 4 — public release | Additive public module, docs correction, compatibility deprecation, release notes | Full regression, security review, and semver review pass. |
| 5 — standard transition | Re-evaluate the finalized PQ HPKE RFC and its registries | Exact final RFC vectors pass; draft profile either aliases only after byte-level proof or remains separately versioned. |

## Explicit non-goals

- Calling the current CGv2 envelope or `HFv1` plaintext framing HPKE.
- Claiming that FIPS 203 alone standardizes an ML-KEM HPKE ciphersuite.
- Adding tenant models, databases, authorization, recipient-key lookup, or
  application transport framing to this library.
- Supporting ML-KEM Auth/AuthPSK modes when the selected KEM mapping does not
  define them.
- Using non-registered XChaCha20-Poly1305 or AES-256-GCM-SIV as an HPKE AEAD.
- Replacing an existing dependency or changing a public API before the pinned
  PQCA release and the exact test-vector contract have been approved.

## Decisions requiring approval before implementation

1. Confirm the pinned PQ HPKE draft revision and the policy for updating it.
2. Confirm the exact `libcrux-ml-kem` release, enabled features, license,
   architecture support, and supply-chain review record.
3. Approve Base-only initial support versus including PSK in the first release.
4. Approve the first public profile set and whether ML-KEM-512 stays opt-in.
5. Approve the deprecation/versioning plan for the existing misnamed
   `api::hpke` helper and any feature defaults.
