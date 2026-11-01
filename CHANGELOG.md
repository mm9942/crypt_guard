# Changelog

All notable changes to the CryptGuard crates are documented here. All crates
(`crypt_guard`, `crypt_guard_core`, `crypt_guard_proc`, `crypt_guard_service`,
`crypt_guard_hyper`) are released together under one version.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
`cargo release` turns the `Unreleased` section into the released version.

## [Unreleased]

### Added
- ML-DSA (`MlDsa44Impl`, `MlDsa65Impl`, `MlDsa87Impl`), all additive and
  panic-free:
  - `generate_seed`, `keypair_from_seed`, `try_keypair` and
    `verifying_key_from_seed`: seed-based key management without the
    panicking `OsRng` path;
  - `sign_with_context` (hedged, FIPS 204 randomized variant via `TryOsRng`),
    `sign_with_context_deterministic` (for known-answer tests) and
    `verify_with_context`;
  - `fingerprint`: `SHA3-256` key id bound to the parameter set;
  - constants `PARAMETER_SET_ID`, `VERIFYING_KEY_LEN`, `SIGNATURE_LEN`,
    plus `ML_DSA_SEED_LEN`, `ML_DSA_MAX_CONTEXT_LEN`, `ML_DSA_FINGERPRINT_LEN`.
- `pq_hpke::RecipientPublicKey::fingerprint`: `SHA3-256` key id bound to the KEM.
- Vendored LAMPS / RFC 9881 example keys
  (`crates/core/tests/vectors/ml-dsa-lamps-example-keys.json`) as a
  known-answer test for seed-based key derivation.
- `SECURITY.md` is now actually tracked (it was excluded by `.gitignore`).
- `scripts/release_checks.sh` runs `cargo semver-checks` before a release.
- Building blocks for messengers (new modules, additive, panic-free; the
  randomness they draw themselves comes from `TryOsRng`):
  - `prf`: labelled SHAKE256 PRF/KDF (`prf`, `prf32`) for identifiers,
    capabilities and sub-keys; label, key, input and output length are all
    bound into the derivation.
  - `sharing`: Shamir secret sharing over GF(2^8) (`split`, `combine`,
    `Share`) with constant-time field arithmetic, and SHA3-256 share
    commitments (`commitment`, `verify_commitment`, `check_commitment`) that
    attribute a bad share to its holder; typed `SharingError`
    (`From<SharingError> for CryptError`).
  - `pq_stream`: STREAM chunked AEAD with ChaCha20-Poly1305
    (`StreamEncryptor`, `StreamDecryptor`, final chunk consumes the state),
    detecting reordering, truncation, extension and tampering;
    `derive_stream_key`, `random_prefix`.
  - `pq_multi` (feature `ml-kem-backend`): multi-recipient seal bound to the
    recipient set (`seal_multi`, `open_multi`, `recipient_set_hash`,
    `dummy_wrap`, `MultiRecipientCiphertext::check_recipient_set`).
- `pq_hpke::HpkeEnvelope::open_pinned_zeroizing`: rejects a record whose wire
  suite differs from the locally pinned suite before decapsulation.
- `tests/m0_ext_primitives.rs` with known-answer vectors computed
  independently with Python `hashlib`.
- `crypt_guard_service`: `try_network_handle` (feature `buffer`), the
  panic-free variant of `network_handle`: `Unavailable` without a Tokio
  runtime, `Malformed` for a zero or oversized `queue_bound`/`max_in_flight`.
  `buffer` now depends on `tokio` (`rt`, `sync`) directly; it was already
  pulled in by `tower/buffer`.
- `crypt_guard_service`: per-version key lifecycle metadata. `KeyLifecycle`
  (`created_at_unix_ms`, optional `not_before`/`not_after`/`destroy_after`,
  builder `with_*`, `is_within_validity`, `is_destruction_due`),
  `CryptoOperation::DescribeLifecycle` / `CryptoResponse::Lifecycle`,
  `OpKind::DescribeLifecycle` (`"describe_lifecycle"`, own `OpSet` bit,
  included in `OpSet::READ_PUBLIC`). `InMemoryProvider` stamps creation
  times at generate/rotate; `InMemoryProvider::with_clock` injects a clock.
- `pq_cascade` (new module, additive, panic-free): a selectable one- or
  two-layer AEAD over caller-supplied 32-byte keys, plus a two-layer variant of
  the `HpkeEnvelope` (`CGH3`) container, for the "Maximal" protection level of
  messengers. Nothing existing changes: `DEFAULT_SUITE`, `pq_hpke`, `pq_stream`
  and `pq_multi::seal_multi` keep their signatures and wire formats.
  - `Scheme` (non-exhaustive): `ChaCha20Poly1305` = 1, `Aes256GcmSiv` = 2,
    `XChaCha20Poly1305` = 3 and `Cascade` = 4 (AES-256-GCM-SIV inside,
    XChaCha20-Poly1305 outside). Every scheme expands the plaintext by exactly
    32 bytes (`CASCADE_OVERHEAD`); the single-layer schemes carry 16 zero
    filler bytes inside the AEAD, so the scheme cannot be read from the length.
  - `Cascade`: independent sub-keys per scheme and caller `domain` from one
    32-byte root key via `prf32`; the scheme id is part of every key and of the
    AAD of every layer. `seal`/`open` take a `CascadeNonce` (`Counter` for
    session frames, `Stream` for file chunks, same layout as `pq_stream`);
    `seal_once` consumes the `Cascade` and derives the nonce from the key, so
    one key can never seal two messages. In-place variants avoid copies.
  - `seal_random`/`open_random`: random 192-bit nonce per value (`TryOsRng`),
    for stored values.
  - `MAXIMAL_SUITE` (`MlKem1024P384`, `Shake256`, `XChaCha20Poly1305`),
    `seal_envelope`/`open_envelope`: AES-256-GCM-SIV inside, the HPKE
    XChaCha20-Poly1305 context outside, with one KEM encapsulation. The result
    is a normal `HpkeEnvelope`; the suite is pinned before decapsulation.
  - `CascadeSealer`/`CascadeOpener`: one-shot wrappers around an HPKE context
    for protocols that control `enc` and exporters themselves.
  - Every open failure is the same `CryptError::AuthenticationFailed`; keys
    and intermediate plaintext live in `Zeroizing` buffers.
- `pq_multi` (feature `ml-kem-backend`): `seal_multi_cascade`,
  `open_multi_cascade`, `dummy_cascade_wrap` and `WRAP_PAYLOAD_LEN`. The body
  uses any `Scheme`; every wrap is a `MAXIMAL_SUITE` cascade envelope of
  `version ‖ scheme_id ‖ CEK` (1 751 bytes whatever the scheme, so the body
  scheme is invisible to relays). `open_multi_cascade` calls an `accept`
  callback with the scheme before the body is decrypted (minimum-level
  policies) and returns one opaque error for every failure. The recipient-set
  binding is the same as for `seal_multi`.
- Known-answer vectors for `pq_cascade` and `pq_multi`'s cascade variant,
  computed independently with a Python reference model (`hashlib` plus
  `cryptography`): `crates/core/tests/vectors/pq-cascade-kats.json` (listed in
  `SHA256SUMS`) and `tests/pq_cascade_kats.rs`.

### Changed
- `OpSet::READ_PUBLIC` (and `ALL`) now include `DescribeLifecycle`; grants
  built from `OpKind::Describe` alone must add `OpKind::DescribeLifecycle`.
- `sha3` is built with its `zeroize` feature, so hash state that absorbed
  keys or shares is wiped on drop.

## [3.1.0] - 2026-09-27

### Added
- Security process: `SECURITY.md`, Dependabot (Cargo and Actions),
  `cargo deny` in CI, committed `Cargo.lock`, and `cargo fuzz` targets for
  every parser (`fuzz/`).
- `pq_hpke::generate_recipient_seed` and `RECIPIENT_SEED_LEN`: the
  recommended seed-based key-management workflow.
- Workspace layout: `crypt_guard` is a facade over `crypt_guard_core`; all
  existing `crypt_guard::…` paths keep working.
- `crypt_guard_service` (feature `service`): typed KMS operations,
  non-`Clone` zeroizing `SecretBytes`, `CryptoProvider`, Tower
  `CryptoService`, `InMemoryProvider` (HPKE encrypt/decrypt, wrap/unwrap/
  rewrap, ML-DSA with feature `ml-dsa`, key lifecycle) and
  `PolicyProvider`/`NamespacePolicy`.
- `crypt_guard_hyper` (feature `hyper`): HTTP adapter with the `CGK1` codec,
  bearer-token authentication, bounded zeroizing body collection and the
  `TowerToHyperService` bridge; `kms_server` example.
- Core: `open_zeroizing`/`export_zeroizing`, `HpkeEnvelope::try_to_bytes`,
  `HpkeEnvelope::open_bytes_zeroizing`, `pq_hpke::suite_from_ids`/`suite_ids`,
  `TryOsRng`, `try_generate_recipient_key_pair`, `RecipientKeyPair::into_parts`,
  `Sign::try_hmac`, `From` conversions of all error types into `CryptError`.
- `examples/pq_hpke.rs`.
- README rewritten as a beginner guide: which API to pick, a complete feature
  table (including `service` and `hyper`) with ready-to-copy `Cargo.toml`
  snippets, recipes, a KMS walkthrough, and why the legacy macros exist.
  Every Rust example in it is compiled as a doctest of the facade crate.
- Error layer: `crypt_guard_core::error::ErrorKind` (stable, non-exhaustive
  classification) with `kind()` on every core error type,
  `CryptError::is_transient`, `Result` aliases in core, service and hyper,
  `CryptoServiceError::{crypto_kind, is_retryable}`, `From<CryptError>` for
  `CryptoServiceError`, and a central `AdapterError` in `crypt_guard_hyper`.
  Authentication failures always classify as `ErrorKind::Authentication`
  and carry no variable data.
- HTTP: every response carries `x-request-id`; `503` responses carry
  `Retry-After`.
- CI: `clippy -D warnings` job; non-test code of the v3 modules, service and
  hyper denies `unwrap`/`expect`.

### Changed
- `kem::ml_kem` (`MlKem512Impl`/`MlKem768Impl`/`MlKem1024Impl`) now runs on
  `libcrux-ml-kem` (PQCA / PQ Code Package), the same FIPS 203 implementation
  as `pq_hpke`; the RustCrypto `ml-kem` dependency is gone. Keys and
  ciphertexts are unchanged and interchangeable with the old backend (tested),
  and encapsulation now rejects keys failing the FIPS 203 modulus check.
- `legacy-pqclean` is documented as depending on the unmaintained PQClean
  based `pqcrypto-*` crates (RustSec unmaintained advisories); it stays
  opt-in and migration-only.
- RFC 9180 `SenderContext`/`ReceiverContext` are `Send + Sync`.
- `Debug` of secret-bearing types is redacted; `Key` compares in constant time.
- Secret key files are created with mode `0600` on Unix.
- `Sign::hmac` is deprecated in favour of `Sign::try_hmac`.

### Fixed
- Zeroization of key schedules, hybrid KEM seeds and shared secrets, X448,
  ML-KEM/ML-DSA/SLH-DSA/HKDF temporaries; AES round keys and SLH-DSA signing
  keys are wiped on drop.
- Legacy AES-XTS and XChaCha20-Poly1305 file encryption encrypted an empty
  plaintext instead of the file.
- Legacy decryption no longer continues with empty data after a failed HMAC
  verification.
- Single-feature builds (`aes-ctr`, `aes-xts`, `legacy-aes`,
  `aes-gcm-siv-cipher`, `zip`).
- Panics on crafted key files and in RFC 9180 KEM dispatch.
- Legacy Falcon/Dilithium signing (`legacy-pqclean`): an invalid signature,
  a malformed key or signed message panicked instead of returning
  `SigningErr`; `save_public`/`save_secret` ignored write failures; `load`
  panicked on paths without an extension or not valid UTF-8.
- Legacy ciphers: a caller-supplied nonce/IV that is not hex or has the
  wrong length panicked in the constructor. The Kyber wrappers now reject it
  with `CryptError::InvalidNonce`. Plain XChaCha20 and AES-CTR do not
  authenticate the nonce, so a wrong one used to decrypt to garbage.
- `decrypt_open!` zeroizes the key, signature and buffers before it panics
  on a failed decrypt (previously the unwind skipped the wipe).
- Zeroization: `SignBuilder` (secret key, data), the cgv2 hub `KyberData`
  (secret key; its `Debug` also printed the key), legacy cipher shared
  secrets on `set_shared_secret`, and X448/HPKE-PQ key-schedule temporaries.
- The log file is created owner-only (`0600`) on Unix.
- Legacy AES decryption no longer underflows on an out-of-range padding byte.
- `ZipManager::add_directory` no longer adds a bogus `/` entry.
- Documentation: the legacy `AES` cipher uses ECB mode (not CBC as documented
  before); `SECURITY.md` says never to encrypt new data with it.
- Legacy Kyber AES-CTR and AES-GCM-SIV wrappers printed the ciphertext on
  encryption and the **decrypted plaintext** on decryption to stdout
  (`println!("{:?}", data)`); in a service this ends up in logs. Removed.
- Legacy Kyber ciphers panicked instead of returning an error on a wrong
  passphrase, a tampered ciphertext or a malformed KEM key/ciphertext
  (`unwrap()` in the `Kyber` wrappers and the key controller).
- Legacy AES-XTS panicked (inside `xts-mode`) on inputs whose last sector is
  shorter than one AES block. Because it decrypts before checking the HMAC,
  a crafted ciphertext length could crash the process. Such lengths, and a
  shared secret that is not 64 bytes, are now rejected with
  `CryptError::InvalidDataLength`; the wire format is unchanged. The cgv2
  `AesXts` hub cipher was not affected (it pads to whole sectors and
  verifies its MAC first).
- Legacy `KeyControl::{get_key, save, load}` returned via `unimplemented!()`
  for unsupported key types; they now return
  `CryptError::UnsupportedOperation`.

## [3.0.2]

- Provenance-seed recovery fix (see README release note).
