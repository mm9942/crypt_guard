# Release Readiness

This guide tracks what remains before publishing `2.0.0`.

## Current status

Phase 4 is functionally complete:

- safe ML-KEM + ML-DSA defaults are active
- `legacy-pqclean` is opt-in
- the CGv2 envelope path is implemented
- `Encryptor` / `Decryptor` staged builders are available
- HPKE-style `api::hpke::{seal, open}` wrappers exist
- content-axis and staged-builder misuse are covered by `trybuild`
- CI has default, ML-only, and legacy-only lanes

Current green verification:

```bash
cargo fmt --check
RUSTC_WRAPPER= cargo test
RUSTC_WRAPPER= cargo test --no-default-features --features ml-kem-backend,ml-dsa-backend
RUSTC_WRAPPER= cargo test --no-default-features --features legacy-pqclean
RUSTC_WRAPPER= cargo clippy --lib
```

External consumer verification also passed from `/tmp/crypt_guard_consumer`
against the local `crypt_guard v2.0.0` path dependency:

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

   The version is now `2.0.0` after an external consumer project passed the
   default, ML-only, and legacy-only lanes. Keep remaining design debt documented
   as post-release maintenance.

3. Keep release linting green.

   `RUSTC_WRAPPER= cargo clippy --lib` currently passes. Full warning-clean CI
   remains a Phase 5 goal unless explicitly promoted to a release blocker.

4. Audit public docs against the actual API.

   The README and guides now describe the Phase 4 state. Before publishing,
   rerun doctests and inspect docs.rs output for stale 1.x or pre-release
   claims.

## Accepted post-release design debt

These are not current test blockers, but they are still below the full redesign
ideal from the Obsidian assessment:

- `Encryptor` and `Decryptor` still accept raw key bytes (`Vec<u8>`). The lower
  `kem` layer has typed key wrappers, but the top-level builders do not yet
  require them.
- HPKE-style `info` and `aad` are currently protected by framing inside the
  encrypted plaintext in `api::hpke`. They are not yet threaded directly into
  the HKDF key schedule or `build_aad` metadata path.
- `src/lib.rs` still preserves broad compatibility re-exports.
- Legacy type identity still depends on `src/core/kyber` while implementation
  lives under `src/legacy`.
- Warning cleanup and dead-code cleanup are Phase 5 work.

## Exit criteria

For `2.0.0`:

- all release blockers above are closed
- test matrix is green
- README, guides, crate docs, and Cargo metadata agree on the version
- no generated/cache artifacts are staged

For publish:

- `2.0.0` has no known correctness regressions
- any remaining public API debt is documented as intentional compatibility debt
- CI runs the three feature lanes successfully on the release branch
