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
- The same holds for the new cascade paths: the content-key, throwaway-seed
  and filler draws of `pq_multi::seal_multi_cascade` / `dummy_cascade_wrap`
  and the nonce draw of `pq_cascade::seal_random` use `TryOsRng` and return
  an error. `pq_cascade` (and the cascade functions of `pq_multi`) never
  panics on malformed input: a wrong key, AAD, nonce, scheme, length, wrap
  version or filler is the single opaque `CryptError::AuthenticationFailed`
  (programming errors such as an all-zero root key, an empty `domain`, a
  wrong in-place buffer length, a second `CascadeSealer::seal` or a zero
  `Stream` prefix are `InvalidParameters`; a suite other than
  `MAXIMAL_SUITE` is `UnsupportedAlgorithm`).

Known, documented exceptions:

- `kem::backend::OsRng` panics if the OS entropy source fails, because its
  `rand_core` error type is `Infallible`. Use `TryOsRng` (or the seed-based
  functions above) where a panic is unacceptable.
- KEM encapsulation inside `pq_hpke::HpkeEnvelope::seal` (and therefore
  `pq_multi::seal_multi` / `dummy_wrap`) and `generate_recipient_key_pair`
  still use `rand::rngs::OsRng`, which panics if the OS entropy source fails.
  The new `pq_cascade::seal_envelope` (and therefore
  `pq_multi::seal_multi_cascade` / `dummy_cascade_wrap`), and every HPKE
  sender context created with `setup_base_sender_inner` for a `CascadeSealer`,
  share this limitation, because the single KEM encapsulation of a cascade
  envelope goes through the same `pq_hpke` sender setup.
- Legacy code behind `legacy-pqclean` and `cgv2-compat` is retained for
  migration only and is not covered by the contract.
- Third-party crates may still contain internal assertions.

## Secret handling

- Secret key material lives in zeroizing types (`Zeroizing`, `ZeroizeOnDrop`)
  and is never printed: `Debug` implementations of secret types are redacted.
- Error values carry no key, seed or plaintext bytes.
- `pq_cascade::Cascade` is not `Clone`, holds its layer keys in `Zeroizing`
  buffers and has a redacted `Debug`; intermediate plaintext (the inner
  ciphertext of a cascade, the padded single-layer body) and the HPKE exporter
  outputs live in `Zeroizing` buffers. The `Cascade` of `seal_once` is
  consumed, so one derived-nonce key can never seal a second message.
- Known gap in a dependency: `aes-gcm-siv` 0.11.1 derives per-nonce
  sub-keys into a `polyval::Polyval` that is only wiped on drop when
  `polyval` is built with its (optional) `zeroize` feature. With the default
  build the per-message POLYVAL sub-keys of the AES-256-GCM-SIV layer (not the
  root key and not the layer key) can stay in freed memory. Enabling
  `polyval/zeroize` closes the gap only for the portable ("soft") backend,
  which `polyval` 0.6.2 uses on every target except `x86`/`x86_64` and
  `aarch64` builds with `--cfg polyval_armv8`; in particular a default
  `aarch64` (Android) build is covered. It does **not** help on
  `x86`/`x86_64` (nor on `aarch64` with `--cfg polyval_armv8`): there
  `polyval` 0.6.2 wraps the hardware backend in an auto-detecting `union` of
  `ManuallyDrop` fields without a `Drop` implementation, so the backend's
  wipe never runs for the long-lived instance (only for the temporary clone
  that `finalize_reset` consumes), and the PMULL backend has no wipe at all
  (an upstream TODO). This is an upstream limitation; it is accepted and
  tracked as open point 12 of the cipher-suite contract.

## Dependency and audit status

- `ml-dsa` (RustCrypto) states in its own README that it has **not** been
  independently audited.
- `slh-dsa` is used at a release-candidate version.
- The post-quantum HPKE mapping follows `draft-ietf-hpke-pq-05`, an
  Internet-Draft, not a final IANA registration.
- `cargo deny` checks RustSec advisories, licences and sources in CI;
  `deny.toml` documents every accepted advisory with a reason.
- Fuzz targets for every parser live in `fuzz/`.
