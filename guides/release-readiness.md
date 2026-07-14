# Release Readiness

This guide tracks what remains before publishing `2.0.4`.

## Current status

Phase 4 is functionally complete:

- safe ML-KEM + ML-DSA defaults are active
- `legacy-pqclean` is opt-in
- the CGv2 envelope path is implemented
- `Encryptor` / `Decryptor` staged builders are available
- frozen legacy CGv2/HFv1 `api::hpke::{seal, open}` compatibility wrappers exist
- the separate `hpke/` module has a partial RFC 9180 Base-mode core (labeled
  key schedule, context state, nonce sequencing, exporter derivation, and
  ChaCha20-Poly1305); it has no KEM setup or vector-verified complete suite
- the opt-in `hpke_pq::draft_ietf_hpke_pq_05` module exposes the two pinned,
  vector-gated active-draft Base-mode profiles with separate `enc` transport;
  it is explicitly not an RFC-standardized PQ HPKE profile
- content-axis and staged-builder misuse are covered by `trybuild`
- CI has default, ML-only, and legacy-only lanes

Required release verification:

```bash
cargo fmt --check
RUSTC_WRAPPER= cargo test
RUSTC_WRAPPER= cargo test --no-default-features --features ml-kem-backend,ml-dsa-backend
RUSTC_WRAPPER= cargo test --no-default-features --features legacy-pqclean
RUSTC_WRAPPER= cargo test --no-default-features --features hpke-pq-draft-05
RUSTC_WRAPPER= cargo clippy --lib
```

Historical, pre-2.0.4 external-consumer verification passed from
`/tmp/crypt_guard_consumer`. It is retained only as historical evidence and
does not substitute for the 2.0.4 verification matrix above:

```bash
RUSTC_WRAPPER= cargo test
RUSTC_WRAPPER= cargo test --no-default-features --features ml-only
RUSTC_WRAPPER= cargo test --no-default-features --features legacy-pqclean
```

## Release blockers

These should be closed before publishing:

1. Clean the Git index.

   `old/.cargo-home/**` and `test.log` are already tracked/staged in the local
   index. `.gitignore` prevents future additions but does not untrack existing
   entries.

2. Confirm the release version.

   The package manifest version is now `2.0.4`. Rerun the required matrix,
   including the focused HPKE tests, after the patch bump before publishing.

3. Keep release linting green.

   `RUSTC_WRAPPER= cargo clippy --lib` currently passes. Full warning-clean CI
   remains a Phase 5 goal unless explicitly promoted to a release blocker.

4. Audit public docs against the actual API.

   The README and guides now describe the Phase 4 state. Before publishing,
   rerun doctests and inspect docs.rs output for stale 1.x or pre-release
   claims.

5. Keep HPKE protocol families distinct.

   The legacy `api::hpke` names remain CGv2/HFv1 compatibility framing and
   must not be advertised as RFC 9180 HPKE. The partial `hpke/` core is not an
   interoperable suite because it has no KEM setup or complete vector evidence.
   The additive draft-05 feature has its own separate `enc` transport and
   profile identity; it must not serialize as CGv2, parse through `Envelope`,
   or reinterpret existing bytes. Applications select the reader from an
   application-owned protocol/version/profile discriminator; trial decryption
   and fallback are not migration mechanisms.

6. Keep the post-quantum claim precise.

   `draft-ietf-hpke-pq-05` is an active Internet-Draft, not a standardized RFC
   profile. The opt-in public Base-mode API is limited to its two pinned,
   vector-gated profiles; it must retain its literal revision in code,
   transport metadata, and release evidence.

## Accepted post-release design debt

These are not current test blockers, but they are still below the full redesign
ideal from the Obsidian assessment:

- `Encryptor` and `Decryptor` still accept raw key bytes (`Vec<u8>`). The lower
  `kem` layer has typed key wrappers, but the top-level builders do not yet
  require them.
- `api::hpke` is frozen legacy CGv2/HFv1 framing: its `info` and `aad` remain
  inside encrypted plaintext and it will not be converted into real HPKE.
- `hpke/` provides the beginning of a separate RFC 9180 stateful context, but
  it still requires KEM setup and complete vector evidence before any full RFC
  9180 suite claim. The distinct `draft-ietf-hpke-pq-05` feature is limited to
  its vector-gated experimental Base-mode profiles and makes no RFC
  standardization claim.
- `src/lib.rs` still preserves broad compatibility re-exports.
- Legacy type identity still depends on `src/core/kyber` while implementation
  lives under `src/legacy`.
- Warning cleanup and dead-code cleanup are Phase 5 work.

## Exit criteria

For `2.0.4`:

- all release blockers above are closed
- test matrix is green
- README, guides, crate docs, and Cargo metadata agree on the version
- no generated/cache artifacts are staged

For publish:

- release evidence establishes that `2.0.4` has no known correctness
  regressions in its verified scope
- any remaining public API debt is documented as intentional compatibility debt
- CI runs the three feature lanes successfully on the release branch
