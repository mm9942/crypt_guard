# Changelog

All notable changes to the CryptGuard crates are documented here. All crates
(`crypt_guard`, `crypt_guard_core`, `crypt_guard_proc`, `crypt_guard_service`,
`crypt_guard_hyper`) are released together under one version.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
`cargo release` turns the `Unreleased` section into the released version.

## [Unreleased]

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
