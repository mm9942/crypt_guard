# CryptGuard v3.1.0

[![Crates.io](https://img.shields.io/badge/crates.io-v3.1.0-blue.svg?style=for-the-badge)](https://crates.io/crates/crypt_guard)
[![MIT licensed](https://img.shields.io/badge/license-MIT-green.svg?style=for-the-badge)](https://github.com/mm9942/crypt_guard/blob/main/LICENSE)
[![Documentation](https://img.shields.io/badge/docs-v3.1.0-yellow.svg?style=for-the-badge)](https://docs.rs/crypt_guard/)
[![CI](https://img.shields.io/github/actions/workflow/status/mm9942/crypt_guard/rust.yml?branch=main&style=for-the-badge&label=CI)](https://github.com/mm9942/crypt_guard/actions/workflows/rust.yml)
[![GitHub Library](https://img.shields.io/badge/github-lib-black.svg?style=for-the-badge)](https://github.com/mm9942/crypt_guard)

CryptGuard is a pure-Rust post-quantum cryptography library and, since 3.1,
a substrate for building key-management services on top of it. Version 3
uses a revision-pinned PQ HPKE protocol as its default encryption transport.

```text
ML-KEM (FIPS 203) -> HPKE KEM and key schedule -> AEAD
```

The default suite is ML-KEM-1024/P-384 with SHAKE256 and
ChaCha20-Poly1305. It prioritizes conservative security and explicit protocol
boundaries over compact ciphertexts.

**What 3.1 adds**

- Zeroizing variants of every API that returns plaintext or exporter output
  (`open_zeroizing`, `export_zeroizing`, `open_bytes_zeroizing`), plus
  zeroization of all intermediate secrets inside the KEM, KDF and key
  schedule.
- A seed-based key-management workflow: `generate_recipient_seed` and
  `derive_recipient_key_pair` keep a 32-byte seed as the only long-lived
  secret.
- `crypt_guard_service` and `crypt_guard_hyper`: a typed, non-`Clone` Tower
  KMS service with an in-memory provider, namespace policies and an HTTP
  adapter, enabled with `--features service` / `--features hyper`.
- Hardened legacy paths, no-panic parsers, fuzz targets, `cargo deny`,
  Dependabot and a scripted release. See [`CHANGELOG.md`](CHANGELOG.md).

## Contents

1. [Installation](#installation)
2. [Quick start](#quick-start)
3. [Key management with seeds](#key-management-with-seeds)
4. [Choose a transport form](#choose-a-transport-form)
5. [Raw Base-mode HPKE](#raw-base-mode-hpke)
6. [PSK-mode HPKE](#psk-mode-hpke)
7. [Suite selection](#suite-selection)
8. [Private AEAD extensions](#private-aead-extensions)
9. [Envelope format and metadata](#envelope-format-and-metadata)
10. [Failure handling and security rules](#failure-handling-and-security-rules)
11. [What the library guarantees](#what-the-library-guarantees)
12. [Signatures](#signatures)
13. [KMS service](#kms-service)
14. [Workspace layout](#workspace-layout)
15. [Feature flags](#feature-flags)
16. [CGv2 migration and legacy support](#cgv2-migration-and-legacy-support)
17. [Security process](#security-process)
18. [Releasing](#releasing)
19. [References](#references)

## Installation

```toml
[dependencies]
crypt_guard = "3.1.0"
```

The default feature set includes the FIPS ML-KEM and ML-DSA backends. No
feature is necessary for the v3 `pq_hpke` API. The default build has no
network, async or HTTP dependencies.

## Quick start

`HpkeEnvelope` is the normal v3 starting point: a self-describing `CGH3`
record sealed under `DEFAULT_SUITE`.

```rust
use crypt_guard::pq_hpke::{
    derive_recipient_key_pair, generate_recipient_seed, HpkeEnvelope, DEFAULT_SUITE,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate the seed once, keep it in your key-management boundary, and
    // derive the key pair from it whenever it is needed.
    let seed = generate_recipient_seed()?;
    let keys = derive_recipient_key_pair(DEFAULT_SUITE.kem(), seed.as_slice())?;

    let info = b"service=payments;protocol=1";
    let aad = b"tenant=acme;record=42";
    let envelope = HpkeEnvelope::seal(
        DEFAULT_SUITE,
        keys.public_key(),
        info,
        aad,
        b"approved transfer payload",
    )?;

    let wire = envelope.try_to_bytes()?;

    // The plaintext comes back in zeroizing memory and is wiped on drop.
    let plaintext = HpkeEnvelope::open_bytes_zeroizing(&wire, keys.private_key(), info, aad)?;
    assert_eq!(plaintext.as_slice(), b"approved transfer payload");
    Ok(())
}
```

A sender gets a fresh encapsulation and a fresh HPKE context for every call
to `seal`. `info` and AAD are never serialized; sender and receiver must share
the same application contract for both (see
[Failure handling](#failure-handling-and-security-rules)).

Run the full example with `cargo run --example pq_hpke`.

## Key management with seeds

The recommended long-lived secret is a 32-byte **provenance seed**, not a
private key:

| Function | Purpose |
|---|---|
| `generate_recipient_seed()` | Fresh seed from the OS CSPRNG, returned as `Zeroizing<[u8; 32]>` |
| `derive_recipient_key_pair(kem, &seed)` | Deterministically derive the key pair (SHAKE256 under a v3 domain separator and the KEM id) |
| `generate_recipient_key_pair(kem)` | Fresh key pair without a seed, for ephemeral use |
| `RecipientKeyPair::into_parts()` | Split into public and private key for separate stores |

Rules:

- Persist the exact 32-byte seed. Do **not** persist
  `RecipientPrivateKey::as_seed_bytes()` as provenance material; some KEMs use
  a larger internal seed, and only the caller seed re-derives the pair.
- Never build a seed by hand or from a password. If you must derive from a
  password, use a memory-hard KDF and feed its output to
  `derive_recipient_key_pair`.
- Distribute only the public key (`RecipientPublicKey::as_bytes()`).
- `RecipientPrivateKey` is not `Clone`; its `Debug` output is redacted.

## Choose a transport form

CryptGuard provides two deliberately separate transport forms.

| Form | Use it when | Contents |
|---|---|---|
| Raw HPKE | The protocol already negotiates suite and `info` out of band | Separate `enc` and ciphertext |
| `HpkeEnvelope` | You need a crypt_guard self-describing record | Protocol magic, version, suite, `enc`, ciphertext |

Use raw transport only with RFC-style AEAD identifiers: AES-128-GCM,
AES-256-GCM, and ChaCha20-Poly1305. Use `HpkeEnvelope` for either the
standardized suites or CryptGuard private AEAD extensions.

## Raw Base-mode HPKE

Raw HPKE is appropriate when your protocol carries `enc` and ciphertext in
separate fields. The suite and `info` are negotiated or persisted by that
protocol, not guessed during decryption.

```rust
use crypt_guard::pq_hpke::{
    generate_recipient_key_pair, setup_base_receiver, setup_base_sender,
    Aead, Kdf, Kem, Suite,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let suite = Suite::new(Kem::MlKem768, Kdf::HkdfSha256, Aead::Aes128Gcm);
    let keys = generate_recipient_key_pair(suite.kem())?;
    let info = b"application=mail;version=1";
    let aad = b"recipient=alice@example.test";

    let (enc, mut sender) = setup_base_sender(suite, keys.public_key(), info)?;
    let ciphertext = sender.seal(aad, b"raw HPKE payload")?;

    let mut receiver = setup_base_receiver(suite, keys.private_key(), &enc, info)?;
    let plaintext = receiver.open_zeroizing(aad, &ciphertext)?;
    assert_eq!(plaintext.as_slice(), b"raw HPKE payload");
    Ok(())
}
```

Sender and recipient contexts are stateful and intentionally not cloneable.
Each successful `seal` or `open` advances the HPKE message sequence and derives
the next nonce internally. Do not serialize a live context for later reuse.
`export_zeroizing` returns exporter output in zeroizing memory.

## PSK-mode HPKE

PSK mode binds an additional symmetric secret to HPKE setup. Both PSK bytes and
their identifier are required. A PSK is not a replacement for recipient public
key validation or authenticated application identity.

```rust
use crypt_guard::pq_hpke::{
    generate_recipient_key_pair, setup_psk_receiver, setup_psk_sender,
    Aead, Kdf, Kem, Suite,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let suite = Suite::new(Kem::MlKem1024, Kdf::HkdfSha384, Aead::Aes256Gcm);
    let keys = generate_recipient_key_pair(suite.kem())?;
    let psk = b"32 bytes from a separate key-management system";
    let psk_id = b"payments-rotation-2026-07";
    let info = b"channel=settlement";
    let aad = b"message=109";

    let (enc, mut sender) = setup_psk_sender(
        suite, keys.public_key(), info, psk, psk_id,
    )?;
    let ciphertext = sender.seal(aad, b"PSK-bound payload")?;

    let mut receiver = setup_psk_receiver(
        suite, keys.private_key(), &enc, info, psk, psk_id,
    )?;
    assert_eq!(receiver.open_zeroizing(aad, &ciphertext)?.as_slice(), b"PSK-bound payload");
    Ok(())
}
```

Base and PSK modes are supported. PQ authenticated KEM modes are deliberately
not exposed by this API.

## Suite selection

Select a suite explicitly whenever the default profile does not match your
deployment. Persist the selected KEM, KDF, and AEAD identifiers with raw
transport records; `pq_hpke::suite_ids` and `pq_hpke::suite_from_ids` map a
suite to and from its wire identifiers.

```rust
use crypt_guard::pq_hpke::{Aead, Kdf, Kem, Suite, DEFAULT_SUITE};

let default_suite = DEFAULT_SUITE;
let pure_pq = Suite::new(Kem::MlKem1024, Kdf::Shake256, Aead::ChaCha20Poly1305);
let hybrid_p256 = Suite::new(Kem::MlKem768P256, Kdf::HkdfSha256, Aead::Aes128Gcm);
let hybrid_x25519 = Suite::new(
    Kem::MlKem768X25519,
    Kdf::HkdfSha256,
    Aead::ChaCha20Poly1305,
);
let hybrid_p384 = Suite::new(Kem::MlKem1024P384, Kdf::HkdfSha384, Aead::Aes256Gcm);

assert_eq!(default_suite.kem(), Kem::MlKem1024P384);
assert_eq!(pure_pq.aead(), Aead::ChaCha20Poly1305);
```

Supported KEM choices are ML-KEM-512, ML-KEM-768, ML-KEM-1024,
ML-KEM-768/P-256, ML-KEM-768/X25519, and ML-KEM-1024/P-384. The ML-KEM and
hybrid mappings are revision-pinned to `draft-ietf-hpke-pq-05` and are not
final IANA assignments.

## Private AEAD extensions

AES-256-GCM-SIV and XChaCha20-Poly1305 are available only in the CryptGuard
envelope namespace. They use private AEAD identifiers and must not be sent to
an implementation expecting an RFC 9180 or IANA suite identifier.

```rust
use crypt_guard::pq_hpke::{
    generate_recipient_key_pair, Aead, HpkeEnvelope, Kdf, Kem, Suite,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let suite = Suite::new(Kem::MlKem768, Kdf::HkdfSha256, Aead::XChaCha20Poly1305);
    assert!(suite.aead().is_private_extension());

    let keys = generate_recipient_key_pair(suite.kem())?;
    let envelope = HpkeEnvelope::seal(
        suite, keys.public_key(), b"object-store", b"object=reports/2026", b"payload",
    )?;
    let plaintext = envelope.open_zeroizing(keys.private_key(), b"object-store", b"object=reports/2026")?;
    assert_eq!(plaintext.as_slice(), b"payload");
    Ok(())
}
```

| AEAD | Identifier | Raw transport | `HpkeEnvelope` |
|---|---:|---:|---:|
| AES-128-GCM | `0x0001` | yes | yes |
| AES-256-GCM | `0x0002` | yes | yes |
| ChaCha20-Poly1305 | `0x0003` | yes | yes |
| AES-256-GCM-SIV | `0xff01` | no | yes |
| XChaCha20-Poly1305 | `0xff02` | no | yes |

## Envelope format and metadata

`HpkeEnvelope` serializes a binary `CGH3` record with envelope version 1.
It contains the protocol magic, version, KEM identifier, KDF identifier, AEAD
identifier, encapsulation length, ciphertext length, encapsulation, and
ciphertext. It does not contain plaintext, `info`, AAD, recipient private key
material, or a shared secret.

`HpkeEnvelope::from_bytes` validates framing and suite identifiers before a
receiver context is constructed; it never panics on malformed input and
rejects trailing bytes. Parsing a CGv2 record as a `CGH3` envelope fails
before decryption. `try_to_bytes` reports an oversized envelope instead of
silently truncating a length field.

## Failure handling and security rules

`open` and `open_zeroizing` return an opaque `Error::AuthenticationFailed`
for wrong AAD, wrong `info`, modified ciphertext, and same-size modified
encapsulations that reach ML-KEM implicit rejection. Do not branch application
behavior on which of those conditions occurred.

```rust
use crypt_guard::pq_hpke::{Error, HpkeEnvelope, RecipientPrivateKey};
use zeroize::Zeroizing;

fn open_record(
    envelope: &HpkeEnvelope,
    key: &RecipientPrivateKey,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    // One error path for every failure: no oracle for the caller.
    envelope.open_zeroizing(key, b"service=payments", b"record=42")
}
```

`HpkeEnvelope::open_bytes_zeroizing` combines parsing and opening; its
`EnvelopeOpenError` distinguishes only "not a valid envelope" from an HPKE
error. Every error type converts into `crypt_guard::error::CryptError` via
`From`, and every authentication failure maps to the single
`CryptError::AuthenticationFailed`.

Treat `info` as a stable setup context such as protocol version or service
name. Treat AAD as authenticated but unencrypted metadata such as tenant,
record type, object identifier, or sender routing data. Do not reuse a sender
context after its sequence is exhausted. Do not put secrets in AAD.

## What the library guarantees

- **Zeroization.** Private keys, seeds, shared secrets, key schedules,
  exporter output and plaintext returned by the `*_zeroizing` APIs live in
  zeroize-on-drop memory. The AEAD, KEM and signature backends are built with
  their `zeroize` features, so expanded keys are wiped too. Plain `open` /
  `export` remain for compatibility and return ordinary `Vec<u8>`.
- **No accidental copies.** `RecipientPrivateKey`, HPKE contexts, signing
  keys and the KMS `SecretBytes` are not `Clone`. Contexts are `Send + Sync`
  and can move between tasks, but not be duplicated.
- **Redacted `Debug`.** No secret-bearing type prints its bytes.
- **Opaque failures.** Decryption reports one error for every cause.
- **No panics on untrusted input.** Envelope, key and encapsulation parsers
  are covered by exhaustive-length and random-input tests and by the fuzz
  targets in `fuzz/`.
- **Bit-identical cryptography.** The RFC 9180 and draft-ietf-hpke-pq-05
  known-answer vectors (`crates/core/tests/vectors`, checksummed) run in
  every CI lane.
- **Fallible randomness.** `TryOsRng` reports an entropy failure instead of
  panicking; `try_generate_recipient_key_pair` does the same for the older
  profile API.

## Signatures

ML-DSA is in the default feature set; SLH-DSA is behind `sign-slhdsa`. Both
zeroize their signing keys on drop.

```rust,no_run
use crypt_guard::kem::backend::OsRng;
use crypt_guard::sign::{ml_dsa::MlDsa65Impl, SignAlgorithm};

let mut rng = OsRng;
let (secret_key, public_key) = MlDsa65Impl::keypair(&mut rng)?;
let signature = MlDsa65Impl::sign(&secret_key, b"signed payload")?;
MlDsa65Impl::verify(&public_key, b"signed payload", &signature)?;
# Ok::<(), crypt_guard::error::CryptError>(())
```

`signed_hpke` adds an application-layer signature over an HPKE transcript;
it is not RFC 9180 Auth mode.

## KMS service

`crypt_guard_service` and `crypt_guard_hyper` turn the library into a
key-management service: key generation, lifecycle, PQ HPKE encrypt/decrypt,
sign/verify and key wrap/unwrap/rewrap, addressed by namespace, key id and
version.

```toml
[dependencies]
crypt_guard = { version = "3.1.0", features = ["hyper"] }   # or "service" for Tower only
```

```rust,no_run
use crypt_guard::service::{
    network_handle, CryptoService, InMemoryProvider, KeyNamespace, NamespacePolicy, OpSet,
    PolicyProvider, Principal, SecretBytes, StackConfig,
};
use crypt_guard::hyper::{into_hyper, BearerTokens, CryptoHttpService, HttpConfig};

# fn main() -> Result<(), Box<dyn std::error::Error>> {
// Who may do what, per namespace. Decrypt/unwrap need SECRET_EGRESS explicitly.
let mut policy = NamespacePolicy::new();
policy.grant(Principal::new("billing"), KeyNamespace::new("billing")?, OpSet::ENCRYPT.union(OpSet::SECRET_EGRESS));

let mut tokens = BearerTokens::new();
tokens.insert(SecretBytes::copy_from_slice(b"<token from your secret store>"), Principal::new("billing"));

// Inside a Tokio runtime:
let provider = PolicyProvider::new(InMemoryProvider::new(), policy);
let handle = network_handle(CryptoService::new(provider), StackConfig::default());
let http = CryptoHttpService::new(handle, HttpConfig::default()).with_authenticator(tokens);
let hyper_service = into_hyper(http); // serve with hyper::server::conn::http1
# let _ = hyper_service;
# Ok(())
# }
```

| Route | Operation |
|---|---|
| `POST /v1/keys` | generate |
| `GET /v1/keys/{ns}/{id}[@v]` | describe |
| `GET /v1/keys/{ns}/{id}[@v]/public` | fetch public key |
| `POST /v1/keys/{ns}/{id}[@v]:{op}` | `encrypt`, `decrypt`, `sign`, `verify`, `rotate`, `disable`, `enable`, `destroy`, `wrap`, `unwrap`, `rewrap` |

Bodies use the length-prefixed `CGK1` frame documented in
`crypt_guard_hyper::codec`.

Security properties:

- All cryptographic state lives in a non-`Clone` `CryptoService`; only the
  bounded `NetworkHandle` (a channel sender) is cloned per connection, which
  is what Hyper's `TowerToHyperService` requires.
- Secret material travels as zeroize-on-drop, non-`Clone` `SecretBytes` from
  ingress (one copy out of the request body) to egress (an owner-backed
  `Bytes` that is wiped when the last network clone drops).
- Ciphertexts are bound to namespace, key id, version, suite and purpose, so
  a blob cannot be replayed against another key, version or as a different
  operation (encrypt vs. wrap).
- Authorization is deny-by-default per principal and namespace. Decrypt and
  unwrap need `SECRET_EGRESS`; rewrap cannot widen egress.
- Every decryption failure returns the same opaque `422`. A caller denied by
  policy sees `404`, identical to a missing key. Bodies are bounded per
  operation class before they are buffered. Bearer tokens are compared in
  constant time and never logged. Every response is `Cache-Control: no-store`.
- Private keys never leave the provider: no export operation exists.

Run the example server (it refuses to start without an explicit admin
token and never generates or prints one):

```sh
CG_KMS_ADMIN_TOKEN=$(openssl rand -hex 32) \
    cargo run -p crypt_guard_hyper --example kms_server
```

Limitations: `InMemoryProvider` keeps keys in memory only; there is no
built-in TLS (front it with a reverse proxy or your own TLS acceptor);
ML-DSA signing in the service requires the `ml-dsa` feature of
`crypt_guard_service` (enabled by the facade's default `ml-dsa-backend`).

## Workspace layout

`crypt_guard` is a facade crate. The cryptography lives in `crypt_guard_core`
and is re-exported unchanged, so all `crypt_guard::…` paths keep working. The
service and transport layers are separate crates that only enter the build
through their features; the default build never depends on Tower, Hyper,
`http-body`, `bytes` or Tokio (enforced in CI by `scripts/check_dep_gates.sh`).

| Crate | Path | Role |
|---|---|---|
| `crypt_guard` | `.` | Public facade |
| `crypt_guard_core` | `crates/core` | Cryptographic mechanisms and protocols |
| `crypt_guard_proc` | `crypt_guard_proc` | Proc macros |
| `crypt_guard_service` | `crates/service` | Typed KMS operations, providers, policy, non-`Clone` Tower `CryptoService` |
| `crypt_guard_hyper` | `crates/hyper` | HTTP routing, codec, authentication, bounded bodies, Hyper bridge |

All crates share one version (`[workspace.package]`) and are released
together.

## Feature flags

| Feature | Default | Purpose |
|---|---:|---|
| `ml-kem-backend` | yes | FIPS ML-KEM-512, ML-KEM-768, ML-KEM-1024 (`kem` module) |
| `ml-dsa-backend` | yes | FIPS ML-DSA-44, ML-DSA-65, ML-DSA-87; also enables ML-DSA keys in the service |
| `sign-slhdsa` | no | SLH-DSA signatures |
| `service` | no | `crypt_guard::service`: Tower KMS service (no HTTP) |
| `hyper` | no | `crypt_guard::hyper`: HTTP adapter and `TowerToHyperService` bridge (implies `service`) |
| `cgv2-compat` | no | CGv2 envelope, builders, and compatibility helpers |
| `legacy-pqclean` | no | Historical Kyber, Falcon, and Dilithium compatibility (enables all legacy ciphers) |
| `legacy-aes`, `aes-ctr`, `aes-xts`, `aes-gcm-siv-cipher` | no | Individual legacy symmetric modes |
| `archive`, `zip` | no | Archive helpers |

Every feature builds on its own; CI checks each one.

## CGv2 migration and legacy support

CGv2 is compatibility-only in v3. Default builds do not expose the legacy
builders or accept CGv2 as a v3 envelope. Existing stored data requires an
explicit migration build.

```toml
[dependencies]
crypt_guard = { version = "3.1.0", features = ["cgv2-compat"] }
```

Migration procedure:

1. Deploy a migration worker with `cgv2-compat` enabled.
2. Read and authenticate the existing CGv2 envelope using the compatibility API.
3. Re-encrypt the recovered plaintext with `pq_hpke::HpkeEnvelope`.
4. Store the `CGH3` bytes and preserve the application contract for `info` and AAD.
5. Remove `cgv2-compat` after all stored data has been migrated.

Never trial-decrypt unknown records with both formats. Store or transmit a
transport discriminator and select the reader directly.

The `legacy-pqclean` feature retains the historical Kyber, Falcon, and
Dilithium path for explicitly managed legacy data. In 3.1 that path got
redacted `Debug`, constant-time key comparison, `0600` key files, zeroizing
key holders and `Sign::try_hmac` (the old `hmac()` swallowed verification
failures and is deprecated). It remains best-effort and is not recommended
for new designs.

## Security process

- Report vulnerabilities privately; see [`SECURITY.md`](SECURITY.md).
- CI on every PR: all test lanes, the per-feature build matrix, dependency
  gates, `cargo deny` (RustSec advisories, licences, sources) and CodeQL.
- Dependabot keeps crates and actions current; cryptographic crates are
  pinned with `=` and their bumps are reviewed in the PR it opens.
- `Cargo.lock` is committed so CI is reproducible and transitive advisories
  are visible.
- Fuzz targets for every parser live in `fuzz/` (`cargo +nightly fuzz run …`).

## Releasing

All crates are released together with [cargo-release](https://github.com/crate-ci/cargo-release):

```sh
scripts/release.sh                   # dry run of the current version
scripts/release.sh minor --execute   # bump, check, tag, publish, push
```

The pre-release hook (`scripts/release_checks.sh`) verifies version
consistency, the changelog, the test-vector checksums, every test lane and
the dependency gates before anything is tagged or published. Publishing
happens in dependency order (`proc` → `core` → `service` → `hyper` →
`crypt_guard`), only from `main`.

## References

- [FIPS 203: ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)
- [FIPS 204: ML-DSA](https://csrc.nist.gov/pubs/fips/204/final)
- [FIPS 205: SLH-DSA](https://csrc.nist.gov/pubs/fips/205/final)
- [RFC 9180: Hybrid Public Key Encryption](https://www.rfc-editor.org/rfc/rfc9180.html)
- [draft-ietf-hpke-pq-05](https://datatracker.ietf.org/doc/draft-ietf-hpke-pq-05/)

Release notes are in [`CHANGELOG.md`](CHANGELOG.md).
