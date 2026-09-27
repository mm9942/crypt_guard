# CryptGuard v3.1.0

[![Crates.io](https://img.shields.io/badge/crates.io-v3.1.0-blue.svg?style=for-the-badge)](https://crates.io/crates/crypt_guard)
[![MIT licensed](https://img.shields.io/badge/license-MIT-green.svg?style=for-the-badge)](https://github.com/mm9942/crypt_guard/blob/main/LICENSE)
[![Documentation](https://img.shields.io/badge/docs-v3.1.0-yellow.svg?style=for-the-badge)](https://docs.rs/crypt_guard/)
[![CI](https://img.shields.io/github/actions/workflow/status/mm9942/crypt_guard/rust.yml?branch=main&style=for-the-badge&label=CI)](https://github.com/mm9942/crypt_guard/actions/workflows/rust.yml)
[![GitHub Library](https://img.shields.io/badge/github-lib-black.svg?style=for-the-badge)](https://github.com/mm9942/crypt_guard)

CryptGuard is a pure-Rust post-quantum cryptography library. It encrypts data
with **ML-KEM** (a NIST-standardized post-quantum key encapsulation mechanism,
FIPS 203) wrapped in **HPKE** (Hybrid Public Key Encryption, RFC 9180 plus a
post-quantum extension), and it signs data with **ML-DSA** and **SLH-DSA**
(post-quantum signature schemes, FIPS 204/205). Since 3.1 it can also run as a
key-management service (**KMS**: a component that generates and holds private
keys for other services, so those services never touch raw key material).

This guide is written for someone who has never used CryptGuard before. It
tells you which API to reach for, how to add the crate, and gives a
copy-pasteable example for every common task. Every example on this page is
compiled and run automatically in CI, so it cannot silently go stale.

```text
ML-KEM (FIPS 203) -> HPKE KEM and key schedule -> AEAD
```

The default suite is ML-KEM-1024/P-384 with SHAKE256 and
ChaCha20-Poly1305 (**AEAD**: Authenticated Encryption with Associated Data —
an encryption mode that also detects tampering). It prioritizes conservative
security and explicit protocol boundaries over compact ciphertexts.

## Contents

1. [Which API do I need?](#which-api-do-i-need)
2. [Installation and feature flags](#installation-and-feature-flags)
3. [Quick start](#quick-start)
4. [Recipes](#recipes)
   - [Generate and store keys with a seed](#generate-and-store-keys-with-a-seed)
   - [Encrypt bytes for storage](#encrypt-bytes-for-storage)
   - [PSK-mode HPKE](#psk-mode-hpke)
   - [Choosing a suite](#choosing-a-suite)
   - [Signatures](#signatures)
   - [Signed HPKE](#signed-hpke)
   - [Error handling](#error-handling)
5. [KMS for beginners](#kms-for-beginners)
   - [In-process, with `service`](#in-process-with-service)
   - [Over HTTP, with `hyper`](#over-http-with-hyper)
   - [Security notes](#security-notes)
6. [Legacy and macros](#legacy-and-macros)
7. [Migrating from 3.0.x / CGv2](#migrating-from-30x--cgv2)
8. [Common mistakes](#common-mistakes)
9. [Workspace layout](#workspace-layout)
10. [Security process](#security-process)
11. [Releasing](#releasing)
12. [References](#references)

## Which API do I need?

| Your situation | Use | Section |
|---|---|---|
| New code, encrypting data to a recipient | `pq_hpke` (this is the default transport) | [Quick start](#quick-start) |
| You need to prove who wrote a message, not hide it | `sign` (ML-DSA, or SLH-DSA behind a feature) | [Signatures](#signatures) |
| One service should hold keys for many other services | `crypt_guard_service` (in-process) or `crypt_guard_hyper` (over HTTP) | [KMS for beginners](#kms-for-beginners) |
| You have data encrypted with CryptGuard ≤ 3.0 (CGv2) or the old Kyber/Falcon/Dilithium macros | `cgv2-compat` / `legacy-pqclean`, migration only | [Legacy and macros](#legacy-and-macros) |

If none of this rings a bell yet: start with [Quick start](#quick-start).

## Installation and feature flags

```toml
[dependencies]
crypt_guard = "3.1.0"
```

The default features are `ml-kem-backend` and `ml-dsa-backend`: encryption
(`pq_hpke`) and ML-DSA signatures work out of the box. The default build has
no network, async or HTTP dependencies — the KMS layers only enter the build
through their own feature flags.

| Feature | Default | Adds | Extra dependencies |
|---|:---:|---|---|
| `ml-kem-backend` | yes | ML-KEM-512/768/1024 (`kem` module) | — |
| `ml-dsa-backend` | yes | ML-DSA-44/65/87 signatures; also enables ML-DSA keys in the service | `ml-dsa` |
| `sign-slhdsa` | no | SLH-DSA signatures (larger, hash-based, more conservative than ML-DSA) | `slh-dsa` |
| `service` | no | `crypt_guard::service`: typed Tower KMS service, no HTTP | `tower-service`, `zeroize`; add `service`'s own `buffer` feature for a cloneable network handle (pulls `tower`) |
| `hyper` | no | `crypt_guard::hyper`: HTTP adapter and the `TowerToHyperService` bridge (implies `service`) | `hyper`, `hyper-util`, `http`, `http-body`, `http-body-util`, `bytes`, plus everything `service`'s `buffer` feature pulls |
| `cgv2-compat` | no | The CGv2 envelope, builders, and compatibility helpers (migration only) | — |
| `legacy-pqclean` | no | Historical Kyber/Falcon/Dilithium path (enables all legacy cipher features below) | `pqcrypto-kyber`, `pqcrypto-falcon`, `pqcrypto-dilithium`, `pqcrypto-traits` |
| `legacy-aes`, `aes-ctr`, `aes-xts`, `aes-gcm-siv-cipher`, `xchacha20poly1305-cipher` | no | Individual legacy symmetric cipher modes used by the macros below | `cbc`/`block-padding`, `ctr`, `xts-mode` (as needed) |
| `archive`, `zip` | no | Archive/zip helpers (`archive!`/`extract!` macros) | `tar`, `xz2`, `flate2`, `zip`, `walkdir` |

Every feature builds on its own; CI checks each one. `cargo run --example
pq_hpke` needs no extra feature.

Ready-to-copy snippets for common combinations:

```toml
# Default: pq_hpke encryption + ML-DSA signatures, nothing else.
[dependencies]
crypt_guard = { version = "3.1.0" }
```

```toml
# KMS, in-process (no HTTP).
[dependencies]
crypt_guard = { version = "3.1.0", features = ["service"] }
```

```toml
# KMS over HTTP.
[dependencies]
crypt_guard = { version = "3.1.0", features = ["hyper"] }
```

```toml
# Signatures including the more conservative, larger SLH-DSA scheme.
[dependencies]
crypt_guard = { version = "3.1.0", features = ["sign-slhdsa"] }
```

```toml
# Migrating stored data from CryptGuard <= 3.0 / the legacy Kyber macros.
[dependencies]
crypt_guard = { version = "3.1.0", features = ["cgv2-compat", "legacy-pqclean"] }
```

## Quick start

`HpkeEnvelope` is the normal v3 starting point: a self-describing `CGH3`
record sealed under `DEFAULT_SUITE`. "Seal" is HPKE's name for "encrypt to a
public key"; "open" is its name for "decrypt with the matching private key".

```rust
use crypt_guard::pq_hpke::{
    derive_recipient_key_pair, generate_recipient_seed, HpkeEnvelope, DEFAULT_SUITE,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Generate a 32-byte seed once, from the OS's random number generator,
    //    and keep it in your key-management boundary (a KMS, an HSM, or at
    //    least a secrets store). It lives in zeroizing memory: it is
    //    overwritten with zeros as soon as it is dropped, and it is never
    //    logged.
    let seed = generate_recipient_seed()?;

    // 2. Derive the actual key pair from the seed whenever you need it. The
    //    same seed always re-derives the same key pair, so you never need to
    //    store the key pair itself, only the seed.
    let keys = derive_recipient_key_pair(DEFAULT_SUITE.kem(), seed.as_slice())?;

    // 3. `info` is the setup context (who/what this channel is for); it does
    //    not change per message. `aad` (Associated Authenticated Data) is
    //    per-message metadata that travels alongside the ciphertext and is
    //    authenticated but not encrypted. Neither is ever written into the
    //    envelope's plaintext, and both must match exactly on open.
    let info = b"service=payments;protocol=1";
    let aad = b"tenant=acme;record=42";
    let envelope = HpkeEnvelope::seal(
        DEFAULT_SUITE,
        keys.public_key(),
        info,
        aad,
        b"approved transfer payload",
    )?;

    // 4. Turn the envelope into bytes for storage or transport.
    let wire = envelope.try_to_bytes()?;

    // 5. On the receiving side: parse the bytes back into an envelope, then
    //    open it. The plaintext comes back in zeroizing memory and is wiped
    //    on drop.
    let received = HpkeEnvelope::from_bytes(&wire)?;
    let plaintext = received.open_zeroizing(keys.private_key(), info, aad)?;
    assert_eq!(plaintext.as_slice(), b"approved transfer payload");
    Ok(())
}
```

A sender gets a fresh encapsulation and a fresh HPKE context on every call to
`seal`; nothing here is reused across messages. Run the full version of this
example with `cargo run --example pq_hpke`.

## Recipes

### Generate and store keys with a seed

Use this whenever you need a long-lived recipient key pair: store the seed,
not the key pair.

```rust
use crypt_guard::pq_hpke::{derive_recipient_key_pair, generate_recipient_seed, DEFAULT_SUITE};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let seed = generate_recipient_seed()?;

    // Store `seed.as_slice()` (32 bytes) in your secrets store. Whenever you
    // need the key pair again, re-derive it from the same seed:
    let keys = derive_recipient_key_pair(DEFAULT_SUITE.kem(), seed.as_slice())?;
    let restored = derive_recipient_key_pair(DEFAULT_SUITE.kem(), seed.as_slice())?;
    assert_eq!(keys.public_key().as_bytes(), restored.public_key().as_bytes());

    // Distribute only the public key.
    let public_bytes = keys.public_key().as_bytes().to_vec();
    assert!(!public_bytes.is_empty());

    // Splitting a key pair into its two halves, e.g. to store them
    // separately:
    let (public, private) = keys.into_parts();
    let _ = (public, private);
    Ok(())
}
```

**Watch out:** persist the exact 32-byte seed from `generate_recipient_seed`.
Do not persist `RecipientPrivateKey::as_seed_bytes()` as your provenance
material — some KEMs use a larger internal seed, and only the seed you
originally generated re-derives the same pair. Never build a seed by hand or
from a password; if you must derive one from a password, run it through a
memory-hard KDF (key derivation function) first and feed *that* output to
`derive_recipient_key_pair`.

### Encrypt bytes for storage

`HpkeEnvelope` already round-trips to and from a single `Vec<u8>`, which is
normally all you need to put a ciphertext in a database column or a file.

```rust
use crypt_guard::pq_hpke::{generate_recipient_key_pair, HpkeEnvelope, DEFAULT_SUITE};
use zeroize::Zeroizing;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let keys = generate_recipient_key_pair(DEFAULT_SUITE.kem())?;
    let info = b"object-store";
    let aad = b"object=reports/2026-09";

    let envelope = HpkeEnvelope::seal(DEFAULT_SUITE, keys.public_key(), info, aad, b"payload")?;
    let stored: Vec<u8> = envelope.try_to_bytes()?;

    // `open_bytes_zeroizing` combines parsing and opening in one call, which
    // is usually what you want when the bytes come straight out of storage.
    let plaintext: Zeroizing<Vec<u8>> =
        HpkeEnvelope::open_bytes_zeroizing(&stored, keys.private_key(), info, aad)?;
    assert_eq!(plaintext.as_slice(), b"payload");
    Ok(())
}
```

**Watch out:** `try_to_bytes` reports an oversized envelope as an error
instead of silently truncating a length field; prefer it over the
non-fallible `to_bytes` for anything you did not just construct yourself in
memory.

### PSK-mode HPKE

Use PSK (Pre-Shared Key) mode when you have an extra symmetric secret from a
separate channel and want to bind it into the HPKE setup, on top of the
recipient's public key. This is raw HPKE, so the encapsulation (`enc`) and
ciphertext travel separately; your own protocol must carry both.

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

**Watch out:** a PSK is not a substitute for validating the recipient's
public key or for authenticating the application identity of the sender —
it only adds a symmetric binding. Sender and receiver contexts are stateful
and not `Clone`; do not serialize a live context for later reuse.

### Choosing a suite

Pick a suite explicitly whenever the default profile does not match your
deployment (interoperating with a peer that expects a specific KEM, for
example).

```rust
use crypt_guard::pq_hpke::{Aead, Kdf, Kem, Suite, DEFAULT_SUITE};

let default_suite = DEFAULT_SUITE;
let pure_pq = Suite::new(Kem::MlKem1024, Kdf::Shake256, Aead::ChaCha20Poly1305);
let hybrid_x25519 = Suite::new(
    Kem::MlKem768X25519,
    Kdf::HkdfSha256,
    Aead::ChaCha20Poly1305,
);

assert_eq!(default_suite.kem(), Kem::MlKem1024P384);
assert_eq!(pure_pq.aead(), Aead::ChaCha20Poly1305);
assert_eq!(hybrid_x25519.kem(), Kem::MlKem768X25519);
```

Supported KEMs are ML-KEM-512, ML-KEM-768, ML-KEM-1024, ML-KEM-768/P-256,
ML-KEM-768/X25519, and ML-KEM-1024/P-384. AES-256-GCM-SIV and
XChaCha20-Poly1305 are CryptGuard-private AEAD extensions and only work
through `HpkeEnvelope`, not raw transport (`pq_hpke::suite_ids` /
`suite_from_ids` map a suite to and from its wire identifiers if you need to
persist one alongside a raw-transport record).

**Watch out:** the ML-KEM and hybrid mappings are revision-pinned to
`draft-ietf-hpke-pq-05` and are not final IANA assignments; do not represent
them as a standardized PQ HPKE registration to another implementation.

### Signatures

ML-DSA is in the default feature set; SLH-DSA is behind `sign-slhdsa`. Use
signatures when you need to prove who produced a message, not to hide its
contents. Both zeroize their signing keys on drop.

```rust,no_run
# #[cfg(feature = "ml-dsa-backend")]
# fn main() -> Result<(), crypt_guard::error::CryptError> {
use crypt_guard::kem::backend::OsRng;
use crypt_guard::sign::{ml_dsa::MlDsa65Impl, SignAlgorithm};

let mut rng = OsRng;
let (secret_key, public_key) = MlDsa65Impl::keypair(&mut rng)?;
let signature = MlDsa65Impl::sign(&secret_key, b"signed payload")?;
MlDsa65Impl::verify(&public_key, b"signed payload", &signature)?;
# Ok(())
# }
# #[cfg(not(feature = "ml-dsa-backend"))] fn main() {}
```

SLH-DSA (hash-based, larger signatures, more conservative security
assumptions than ML-DSA) works the same way, with `SlhDsaShake128fImpl` (or
one of its five siblings) in place of `MlDsa65Impl`:

```rust,no_run
# #[cfg(feature = "sign-slhdsa")]
# fn main() -> Result<(), crypt_guard::error::CryptError> {
use crypt_guard::kem::backend::OsRng;
use crypt_guard::sign::{slh_dsa::SlhDsaShake128fImpl, SignAlgorithm};

let mut rng = OsRng;
let (secret_key, public_key) = SlhDsaShake128fImpl::keypair(&mut rng)?;
let signature = SlhDsaShake128fImpl::sign(&secret_key, b"signed payload")?;
SlhDsaShake128fImpl::verify(&public_key, b"signed payload", &signature)?;
# Ok(())
# }
# #[cfg(not(feature = "sign-slhdsa"))] fn main() {}
```

**Watch out:** `SignAlgorithm` implementors here are not interchangeable with
`pq_hpke` keys; a signing key pair and an HPKE key pair are always distinct
objects, even for the same underlying algorithm family.

### Signed HPKE

`signed_hpke` adds an application-layer signature over the identifiers and
bytes of an HPKE transport message (suite, mode, recipient key id, `info`,
encapsulation, AAD, ciphertext). It is **not** RFC 9180 Auth mode — it is a
separate protocol you must name as such to any peer. The envelope's fields
stay private until `verify` succeeds, so you cannot accidentally consume
attacker-controlled ciphertext before checking the signature.

```rust,no_run
# #[cfg(feature = "ml-dsa-backend")]
# fn main() -> Result<(), Box<dyn std::error::Error>> {
use crypt_guard::hpke::{AeadId, HpkeSuite, KdfId, KemId, Mode};
use crypt_guard::kem::backend::OsRng;
use crypt_guard::sign::{ml_dsa::MlDsa65Impl, SignAlgorithm};
use crypt_guard::signed_hpke::{SignedHpkeBinding, SignedHpkeEnvelope};

let mut rng = OsRng;
let (signing_key, verifying_key) = MlDsa65Impl::keypair(&mut rng)?;

// In real use, `encapsulation` and `ciphertext` are the `enc` and ciphertext
// bytes your HPKE sender context just produced, not literal strings.
let binding = SignedHpkeBinding {
    suite: HpkeSuite::new(KemId::DhKemX25519HkdfSha256, KdfId::HkdfSha256, AeadId::ChaCha20Poly1305),
    mode: Mode::Base,
    recipient_key_id: b"recipient-42",
    info: b"setup info",
    encapsulation: b"encapsulation bytes go here",
    aad: b"application aad",
    ciphertext: b"ciphertext and tag go here",
};

let envelope = SignedHpkeEnvelope::<MlDsa65Impl>::sign(&signing_key, binding)?;
let verified = envelope.verify(&verifying_key)?;
// Only after `verify` succeeds are the signed fields readable.
assert_eq!(verified.info(), b"setup info");
# Ok(())
# }
# #[cfg(not(feature = "ml-dsa-backend"))] fn main() {}
```

**Watch out:** `binding.encapsulation` and `binding.ciphertext` must come from
the same HPKE sender context — this layer signs whatever bytes you give it,
it does not itself run HPKE.

### Error handling

`open` and `open_zeroizing` return one opaque error,
`Error::AuthenticationFailed`, for wrong AAD, wrong `info`, modified
ciphertext, and same-size modified encapsulations that reach ML-KEM's
implicit rejection. This is deliberate: if decryption told callers *why* it
failed, an attacker could use that as an oracle to learn something about the
key or the plaintext one bit at a time. Do not branch application behavior on
which of those conditions occurred.

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

Every error type in the crate — `CryptError`, `pq_hpke::Error`,
`EnvelopeError`, `SignedHpkeError`, and more — exposes a `.kind()` method
that classifies it into a small, stable `ErrorKind` (`Authentication`,
`InvalidInput`, `InvalidKey`, `Unsupported`, `Encoding`, `Io`, `Randomness`,
`Limit`, `Internal`), so you can react to the *class* of a failure without
matching on every variant:

```rust
use crypt_guard::error::{CryptError, ErrorKind};

fn is_retryable(err: &CryptError) -> bool {
    err.kind().is_transient()
}

assert!(!is_retryable(&CryptError::AuthenticationFailed));
assert_eq!(CryptError::AuthenticationFailed.kind(), ErrorKind::Authentication);
```

**Watch out:** never write a `match` that treats `AuthenticationFailed`
differently based on timing, error text, or any other side channel — that
recreates the oracle the opaque error was designed to remove.

## KMS for beginners

A KMS (Key Management Service) is a component that generates and holds
private keys on behalf of other services, so those services can ask "encrypt
this" or "decrypt that" without ever touching the raw key material. CryptGuard
gives you a KMS in two layers: `crypt_guard_service` runs it in your own
process (a Tower `Service`, no HTTP), and `crypt_guard_hyper` puts an HTTP
server in front of it.

### In-process, with `service`

Everything below runs synchronously against an `InMemoryProvider`, CryptGuard's
reference key store (keys live only in memory and are lost when the process
exits — swap in your own `CryptoProvider` for anything durable).

```rust
# #[cfg(feature = "service")]
# fn main() -> Result<(), Box<dyn std::error::Error>> {
use crypt_guard::service::{
    pq_hpke::DEFAULT_SUITE, CryptoContext, CryptoOperation, CryptoProvider, CryptoRequest,
    CryptoResponse, Decrypt, Encrypt, GenerateKey, InMemoryProvider, KeyAlgorithm, KeyId,
    KeyNamespace, RequestId, SecretBytes,
};

let mut provider = InMemoryProvider::new();
let namespace = KeyNamespace::new("app")?;
let id = KeyId::new("k1")?;

// Generate a fresh HPKE key. The private half never leaves the provider.
let generated = CryptoProvider::execute(
    &mut provider,
    CryptoRequest::new(
        RequestId(1),
        CryptoOperation::Generate(GenerateKey {
            namespace,
            id,
            algorithm: KeyAlgorithm::Hpke { suite: DEFAULT_SUITE },
        }),
    ),
)?;
let key = match generated {
    CryptoResponse::KeyCreated { key, .. } => key,
    other => panic!("unexpected response: {other:?}"),
};

let context = CryptoContext {
    info: Box::from(&b"service=payments"[..]),
    aad: Box::from(&b"record=1"[..]),
};

let encrypted = CryptoProvider::execute(
    &mut provider,
    CryptoRequest::new(
        RequestId(2),
        CryptoOperation::Encrypt(Encrypt {
            key: key.clone(),
            plaintext: SecretBytes::copy_from_slice(b"card ending 4242"),
            context: context.clone(),
        }),
    ),
)?;
let ciphertext = match encrypted {
    CryptoResponse::Ciphertext(blob) => blob,
    other => panic!("unexpected response: {other:?}"),
};

let decrypted = CryptoProvider::execute(
    &mut provider,
    CryptoRequest::new(
        RequestId(3),
        CryptoOperation::Decrypt(Decrypt { key, ciphertext, context }),
    ),
)?;
let plaintext = match decrypted {
    CryptoResponse::Plaintext(secret) => secret,
    other => panic!("unexpected response: {other:?}"),
};
assert_eq!(plaintext.as_ref(), b"card ending 4242");
# Ok(())
# }
# #[cfg(not(feature = "service"))] fn main() {}
```

Add a `PolicyProvider` wrapping the same `InMemoryProvider` to enforce
per-caller permissions (who may `encrypt`, who may also `decrypt`, scoped by
namespace):

```rust,no_run
# #[cfg(feature = "service")]
# fn main() {
use crypt_guard::service::{
    InMemoryProvider, KeyNamespace, NamespacePolicy, OpSet, PolicyProvider, Principal,
};

let mut policy = NamespacePolicy::new();
// Decrypt/unwrap need `SECRET_EGRESS` explicitly: encrypting is not enough
// to also read secrets back out.
policy.grant(
    Principal::new("billing"),
    KeyNamespace::new("billing").unwrap(),
    OpSet::ENCRYPT.union(OpSet::SECRET_EGRESS),
);
let _provider = PolicyProvider::new(InMemoryProvider::new(), policy);
# }
# #[cfg(not(feature = "service"))] fn main() {}
```

**Watch out:** `NamespacePolicy` denies by default; a principal with no
grant for a namespace can do nothing there, not "everything" — always add
the grants you need explicitly.

### Over HTTP, with `hyper`

`crypt_guard_hyper` bridges the same `CryptoService` to real HTTP, behind a
bounded `tower::buffer::Buffer` (so the non-`Clone` service can be shared
across connections through a cloneable handle).

```rust,no_run
# #[cfg(feature = "hyper")]
# fn main() -> Result<(), Box<dyn std::error::Error>> {
use crypt_guard::service::{
    network_handle, CryptoService, InMemoryProvider, KeyNamespace, NamespacePolicy, OpSet,
    PolicyProvider, Principal, SecretBytes, StackConfig,
};
use crypt_guard::hyper::{into_hyper, BearerTokens, CryptoHttpService, HttpConfig};

// Who may do what, per namespace.
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
# #[cfg(not(feature = "hyper"))] fn main() {}
```

The runnable reference server is `crates/hyper/examples/kms_server.rs`. It
refuses to start without an explicit admin token and never generates or
prints one itself:

```sh
CG_KMS_ADMIN_TOKEN=$(openssl rand -hex 32) \
    cargo run -p crypt_guard_hyper --example kms_server
```

Route table (bodies are the `CGK1` frame described below, not JSON):

| Route | Operation |
|---|---|
| `POST /v1/keys` | generate |
| `GET /v1/keys/{ns}/{id}[@v]` | describe |
| `GET /v1/keys/{ns}/{id}[@v]/public` | fetch public key |
| `POST /v1/keys/{ns}/{id}[@v]:{op}` | `encrypt`, `decrypt`, `sign`, `verify`, `rotate`, `disable`, `enable`, `destroy`, `wrap`, `unwrap`, `rewrap` |

The client sends and receives one length-prefixed frame per request body
(documented in full in `crypt_guard_hyper::codec`):

```text
magic "CGK1" (4 bytes) | version u8 = 1 | field...
field = length u32, big-endian | that many bytes
```

For example, `encrypt` and `decrypt` both take three fields in this order:
`info`, `aad`, then the opaque payload (plaintext or ciphertext).

Behavior a client should expect:

- Authentication is `Authorization: Bearer <token>`; a missing or wrong token
  is `401 Unauthorized`.
- Every response, success or failure, carries `Cache-Control: no-store` (so
  nothing caches secret-bearing bodies) and an `x-request-id` header.
- A caller denied by policy sees `404 Not Found` by default — identical to a
  key that does not exist, so policy denial is not distinguishable from a
  typo in the key name.
- Every decryption failure (tampering, wrong `aad`, wrong `info`, a
  destroyed key) is the same opaque `422 Unprocessable Entity`.
- A transient `503 Service Unavailable` carries a `Retry-After` header;
  `501 Not Implemented` means the operation or algorithm is not compiled in
  (for example, requesting a signing key when `ml-dsa` is off).

### Security notes

- There is no built-in TLS. Put a reverse proxy or your own TLS acceptor in
  front of the listener before exposing it beyond `localhost`.
- Bearer tokens are compared in constant time and are never logged.
- Ciphertexts are bound to namespace, key id, version, suite and purpose, so
  a blob from one key, version, or operation (encrypt vs. wrap) cannot be
  replayed against another.
- Private keys never leave the provider: there is no export operation.
- `InMemoryProvider` keeps everything in memory only; treat it as a reference
  implementation, not a production key store.

## Legacy and macros

Before v3, CryptGuard's encryption API was a **typestate API**: the Rust type
system encodes which step of a protocol you are in, so
`Kyber<Encryption, Kyber1024, Data, AES>` is a distinct type from
`Kyber<Decryption, Kyber1024, Data, AES>`, and the compiler refuses to let you
call a decrypt method on an encryptor. That is a good property, but it means
every call site needs several `use` imports (`Kyber`, the size marker
`Kyber1024`/`768`/`512`, the mode marker `Data`/`Message`/`Files`, the
direction marker `Encryption`/`Decryption`, and the cipher marker `AES`/…)
and has to spell the full generic type out. The macros below exist purely to
hide that boilerplate behind one line; they expand to exactly the same
typestate calls. They are compiled only behind `legacy-pqclean` (all of them
also zeroize their key/data arguments after the call) and exist for reading
and migrating data that already used them — new code should use `pq_hpke`
instead.

```rust,no_run
# #[cfg(feature = "legacy-pqclean")]
# fn main() -> Result<(), Box<dyn std::error::Error>> {
// The macros expand to typestate calls (`Kyber::<Encryption, Kyber1024, Data, AES>`
// and friends), so these names must be in scope where you call them.
use crypt_guard::{
    decryption, encryption, error::Zeroize, kyber_keypair, Data, Decryption, Encryption,
    KeyControKyber1024, KeyControKyber512, KeyControKyber768, Kyber, Kyber1024, KyberFunctions,
    AES,
};

let (public_key, secret_key) = kyber_keypair!(1024);
let message = b"legacy macro compatibility".to_vec();
let passphrase = "correct horse battery staple";

let (encrypted_payload, kem_ciphertext) =
    encryption!(public_key, 1024, message.clone(), passphrase, AES)?;

let decrypted = decryption!(
    secret_key,
    1024,
    encrypted_payload,
    passphrase,
    kem_ciphertext,
    AES
)?;
assert_eq!(decrypted, message);
# Ok(())
# }
# #[cfg(not(feature = "legacy-pqclean"))] fn main() {}
```

The full macro family, each hiding the same kind of typestate call:

| Macro | Hides a call to | Notes |
|---|---|---|
| `kyber_keypair!(1024 \| 768 \| 512)` | `KeyControKyber1024/768/512::keypair()` | Legacy Kyber KEM key generation |
| `falcon_keypair!(1024 \| 512)` | `Falcon1024/512::keypair()` | Legacy Falcon signature key generation |
| `dilithium_keypair!(5 \| 3 \| 2)` | `Dilithium5/3/2::keypair()` | Legacy Dilithium signature key generation |
| `encryption!(key, size, data, passphrase, CIPHER)` | `Kyber::<Encryption, KyberN, Data, Cipher>::new(..).encrypt_data(..)` | `CIPHER` is one of `AES`, `AES_XTS`, `AES_CBC`, `AES_GCM_SIV`, `AES_CTR`, `XChaCha20`, `XChaCha20Poly1305`; returns a nonce for the modes that need one |
| `decryption!(key, size, data, passphrase, cipher[, nonce], CIPHER)` | the matching `Decryption` call | Modes with a nonce (`AES_GCM_SIV`, `AES_CTR`, `XChaCha20`, `XChaCha20Poly1305`) take it as `Some(nonce)` |
| `encrypt_file!(key, size, path, passphrase, CIPHER)` | `Kyber::<Encryption, ..>::encrypt_file(..)` | `AES` or `XChaCha20` |
| `decrypt_file!(key, size, path, passphrase, cipher[, nonce], CIPHER)` | the matching file decrypt | Same nonce rule as `decryption!` |
| `signature!(Falcon \| Dilithium, key, size, content, Message \| Detached)` | `Signature::<Alg, Mode>::new().signature(..)` | |
| `verify!(Falcon \| Dilithium, key, size, [signature,] content, Message \| Detached)` | the matching `.open(..)` / `.verify(..)` | `Detached` mode takes the signature separately |
| `encrypt_sign!(key, sign_key, content, passphrase)` | Kyber-1024 AES encryption plus a Falcon-1024 signature over the plaintext | Signing then encrypting in one call |
| `decrypt_open!(key, sign_key, content, passphrase, cipher)` | the matching decrypt-then-verify | Panics (`.expect`) on failure — this one does not return a plain `Result` |
| `archive!(path, delete_dir)` / `extract!(path, delete_archive)` / `archive_util!(..)` | `.tar.xz` archiving helpers | Behind `archive`, not `legacy-pqclean` |

A file-based round trip, and a signature, so you can see the nonce and
signature shapes:

```rust,no_run
# #[cfg(feature = "legacy-pqclean")]
# fn main() -> Result<(), Box<dyn std::error::Error>> {
use crypt_guard::{
    decrypt_file, decryption, dilithium_keypair, encrypt_file, encryption, error::Zeroize,
    falcon_keypair, kdf::*, kyber_keypair, signature, verify, Data, Decryption, Encryption, Files,
    KeyControKyber1024, KeyControKyber512, KeyControKyber768, Kyber, Kyber1024, KyberFunctions,
    AES, XChaCha20,
};
use std::fs;

// XChaCha20 needs a saved nonce: keep it (as hex, say) alongside the
// ciphertext, or you cannot decrypt later.
let (public_key, secret_key) = kyber_keypair!(1024);
let (encrypted, cipher, nonce) =
    encryption!(public_key, 1024, b"in memory".to_vec(), "pass", XChaCha20)?;
let recovered = decryption!(
    secret_key, 1024, encrypted, "pass", cipher, Some(nonce), XChaCha20
)?;
assert_eq!(recovered, b"in memory");

// A file round trip with AES needs no nonce.
let dir = tempfile::tempdir()?;
let plain_path = dir.path().join("message.txt");
let encrypted_path = dir.path().join("message.txt.enc");
fs::write(&plain_path, b"file contents")?;
let (public_key, secret_key) = kyber_keypair!(1024);
let (_message, cipher) = encrypt_file!(public_key, 1024, plain_path.clone(), "pass", AES)?;
fs::remove_file(&plain_path)?;
let restored = decrypt_file!(secret_key, 1024, encrypted_path, "pass", cipher, AES)?;
assert_eq!(restored, b"file contents");

// A Dilithium signature over a message.
let (verify_key, sign_key) = dilithium_keypair!(2);
let signed = signature!(Dilithium, sign_key, 2, b"sign me".to_vec(), Message)?;
let opened = verify!(Dilithium, verify_key, 2, signed, Message)?;
assert_eq!(opened, b"sign me");
let _ = falcon_keypair!(512); // Falcon works the same way as Dilithium above.
# Ok(())
# }
# #[cfg(not(feature = "legacy-pqclean"))] fn main() {}
```

**Watch out:**

- The legacy `AES` cipher (`Kyber<.., AES>`) is ECB mode: identical plaintext
  blocks produce identical ciphertext blocks. Its format is kept only so
  existing data can still be decrypted; never encrypt new data with it.
- Any nonce-producing mode (`XChaCha20`, `AES_CTR`, `AES_GCM_SIV`, …) must
  have its nonce saved (as a hex string, for instance) alongside the
  ciphertext — without it, decryption is impossible.
- `legacy-pqclean` depends on the unmaintained `pqcrypto-*` crates (see
  [SECURITY.md](SECURITY.md)). Use it only in an isolated migration worker,
  then move the data to `pq_hpke` and remove the feature.

## Migrating from 3.0.x / CGv2

CGv2 is compatibility-only in v3. Default builds do not expose the legacy
builders or accept CGv2 as a v3 envelope.

```toml
[dependencies]
crypt_guard = { version = "3.1.0", features = ["cgv2-compat"] }
```

1. Deploy a migration worker with `cgv2-compat` enabled.
2. Read and authenticate the existing CGv2 envelope using the compatibility
   API (`crypt_guard::protocol::Envelope`, `crypt_guard::hpke_open`).
3. Re-encrypt the recovered plaintext with `pq_hpke::HpkeEnvelope::seal`.
4. Store the `CGH3` bytes and preserve your application's `info`/`aad`
   contract.
5. Remove `cgv2-compat` after all stored data has been migrated.

Never trial-decrypt an unknown record with both formats. Store or transmit a
transport discriminator and select the reader directly.

## Common mistakes

- **Reusing `info` or `aad` incorrectly.** `info` is the setup context for a
  channel; `aad` is per-message metadata. Mixing them up, or forgetting that
  both must match *exactly* on open, is the most common cause of a surprise
  `AuthenticationFailed`.
- **Losing the seed.** The seed from `generate_recipient_seed` is the only
  long-lived secret you need to keep; lose it and the key pair (and
  everything encrypted to it) is gone.
- **Logging secrets.** Never log a seed, a private key, a plaintext, or a
  bearer token — CryptGuard already zeroizes and redacts its own
  secret-bearing types, but a `println!` of the wrong variable defeats that.
- **Using `legacy-pqclean` for new data.** It exists for migration only; the
  legacy `AES` mode is ECB, and the underlying `pqcrypto-*` crates are
  unmaintained.
- **Exposing the KMS HTTP server without TLS or auth.** `crypt_guard_hyper`
  does not terminate TLS itself and does not require an authenticator unless
  you attach one — both are your responsibility before the service leaves
  `localhost`.
- **Branching on decryption failure reasons.** `AuthenticationFailed` is
  intentionally uninformative; do not try to recover *why* it failed.

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
