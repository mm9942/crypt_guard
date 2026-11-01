# Security policy

## Reporting a vulnerability

Please **do not** open a public issue for a security problem. Report it
privately through GitHub's private vulnerability reporting:
<https://github.com/mm9942/crypt_guard/security/advisories/new>.

Include the affected crate and version, a description of the impact, and if
possible a minimal reproduction. You will get an acknowledgement, and a fix
is developed in a private fork and released together with a RustSec /
GitHub advisory.

## Supported versions

| Version | Supported |
|---|---|
| 3.x (latest minor) | yes |
| < 3.0 | no; migrate via `cgv2-compat` / `legacy-pqclean` (see README) |

## Panic-freedom contract

Modules marked `// Panic-freedom contract: see SECURITY.md` follow these rules:

- Production code never calls `unwrap`, `expect` or `panic!`. Each such module
  denies `clippy::unwrap_used` and `clippy::expect_used` outside of tests.
- Every length, parse and decoding failure is returned as a typed error.
- Entropy failures are returned as errors on the `TryOsRng` paths
  (`pq_hpke::generate_recipient_seed`, `MlDsa*Impl::generate_seed`,
  `try_keypair`, `sign_with_context`).
- Entropy failures are also returned as errors by `sharing::split`,
  `pq_stream::random_prefix` and the content-key / throwaway-seed draws of
  `pq_multi::seal_multi` / `dummy_wrap`.

Known, documented exceptions:

- `kem::backend::OsRng` panics if the OS entropy source fails, because its
  `rand_core` error type is `Infallible`. Use `TryOsRng` (or the seed-based
  functions above) where a panic is unacceptable.
- KEM encapsulation inside `pq_hpke::HpkeEnvelope::seal` (and therefore
  `pq_multi::seal_multi` / `dummy_wrap`) and `generate_recipient_key_pair`
  still use `rand::rngs::OsRng`, which panics if the OS entropy source fails.
- Legacy code behind `legacy-pqclean` and `cgv2-compat` is retained for
  migration only and is not covered by the contract.
- Third-party crates may still contain internal assertions.

## Secret handling

- Secret key material lives in zeroizing types (`Zeroizing`, `ZeroizeOnDrop`)
  and is never printed: `Debug` implementations of secret types are redacted.
- Error values carry no key, seed or plaintext bytes.

## Dependency and audit status

- `ml-dsa` (RustCrypto) states in its own README that it has **not** been
  independently audited.
- `slh-dsa` is used at a release-candidate version.
- The post-quantum HPKE mapping follows `draft-ietf-hpke-pq-05`, an
  Internet-Draft, not a final IANA registration.
- `cargo deny` checks RustSec advisories, licences and sources in CI;
  `deny.toml` documents every accepted advisory with a reason.
- Accepted for now: RUSTSEC-2026-0387 (`crypto-bigint 0.5`, timing
  variability in constant-time operations) through `hpke 0.13` →
  `p256`/`p384 0.13`, which the classical DHKEM suites of the RFC 9180
  wrapper use. The hybrid PQ KEMs of `pq_hpke` use `p256`/`p384 0.14`
  (`crypto-bigint 0.7`) and are not affected. The path disappears with the
  `hpke 0.15` migration (see CHANGELOG "Unreleased").
- Fuzz targets for every parser live in `fuzz/`.
