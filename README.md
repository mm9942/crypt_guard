# CryptGuard v3.0.1

[![Crates.io](https://img.shields.io/badge/crates.io-v3.0.1-blue.svg?style=for-the-badge)](https://crates.io/crates/crypt_guard)
[![MIT licensed](https://img.shields.io/badge/license-MIT-green.svg?style=for-the-badge)](https://github.com/mm9942/crypt_guard/blob/main/LICENSE)
[![Documentation](https://img.shields.io/badge/docs-v3.0.1-yellow.svg?style=for-the-badge)](https://docs.rs/crypt_guard/)
[![GitHub Library](https://img.shields.io/badge/github-lib-black.svg?style=for-the-badge)](https://github.com/mm9942/crypt_guard)

CryptGuard is a pure-Rust post-quantum cryptography library. Version 3 uses a
revision-pinned PQ HPKE protocol as its default encryption transport.

```text
ML-KEM (FIPS 203) -> HPKE KEM and key schedule -> AEAD
```

The default suite is ML-KEM-1024/P-384 with SHAKE256 and
ChaCha20-Poly1305. It prioritizes conservative security and explicit protocol
boundaries over compact ciphertexts.

## Contents

1. [Installation](#installation)
2. [Choose a transport form](#choose-a-transport-form)
3. [Default encrypted envelope](#default-encrypted-envelope)
4. [Raw Base-mode HPKE](#raw-base-mode-hpke)
5. [PSK-mode HPKE](#psk-mode-hpke)
6. [Suite selection](#suite-selection)
7. [Private AEAD extensions](#private-aead-extensions)
8. [Envelope format and metadata](#envelope-format-and-metadata)
9. [Failure handling and security rules](#failure-handling-and-security-rules)
10. [CGv2 migration](#cgv2-migration)
11. [Signatures and legacy support](#signatures-and-legacy-support)
12. [Feature flags](#feature-flags)

## Installation

```toml
[dependencies]
crypt_guard = "3.0.1"
```

The default feature set includes the FIPS ML-KEM and ML-DSA backends. No
feature is necessary for the v3 `pq_hpke` API.

## Choose a transport form

CryptGuard provides two deliberately separate transport forms.

| Form | Use it when | Contents |
|---|---|---|
| Raw HPKE | The protocol already negotiates suite and `info` out of band | Separate `enc` and ciphertext |
| `HpkeEnvelope` | You need a crypt_guard self-describing record | Protocol magic, version, suite, `enc`, ciphertext |

Use raw transport only with RFC-style AEAD identifiers: AES-128-GCM,
AES-256-GCM, and ChaCha20-Poly1305. Use `HpkeEnvelope` for either the
standardized suites or CryptGuard private AEAD extensions.

`info` and AAD are intentionally not serialized inside `HpkeEnvelope`. The
sender and receiver must have the same application contract for both values.

## Default encrypted envelope

This is the normal v3 starting point. `DEFAULT_SUITE` is
ML-KEM-1024/P-384 with SHAKE256 and ChaCha20-Poly1305.

```rust
use crypt_guard::pq_hpke::{
    generate_recipient_key_pair, HpkeEnvelope, DEFAULT_SUITE,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let keys = generate_recipient_key_pair(DEFAULT_SUITE.kem())?;

    let envelope = HpkeEnvelope::seal(
        DEFAULT_SUITE,
        keys.public_key(),
        b"service=payments;protocol=1",
        b"tenant=acme;record=42",
        b"approved transfer payload",
    )?;

    let bytes = envelope.to_bytes();
    let received = HpkeEnvelope::from_bytes(&bytes)?;
    let plaintext = received.open(
        keys.private_key(),
        b"service=payments;protocol=1",
        b"tenant=acme;record=42",
    )?;

    assert_eq!(plaintext, b"approved transfer payload");
    Ok(())
}
```

Generate recipient key material once, protect the private key seed using your
key-management boundary, and distribute only the public key. A sender gets a
fresh encapsulation and a fresh HPKE context for every call to `seal`.

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
    let plaintext = receiver.open(aad, &ciphertext)?;
    assert_eq!(plaintext, b"raw HPKE payload");
    Ok(())
}
```

Sender and recipient contexts are stateful and intentionally not cloneable.
Each successful `seal` or `open` advances the HPKE message sequence and derives
the next nonce internally. Do not serialize a live context for later reuse.

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
    assert_eq!(receiver.open(aad, &ciphertext)?, b"PSK-bound payload");
    Ok(())
}
```

Base and PSK modes are supported. PQ authenticated KEM modes are deliberately
not exposed by this API.

## Suite selection

Select a suite explicitly whenever the default profile does not match your
deployment. Persist the selected KEM, KDF, and AEAD identifiers with raw
transport records.

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
    assert_eq!(envelope.open(keys.private_key(), b"object-store", b"object=reports/2026")?, b"payload");
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
receiver context is constructed. Parsing a CGv2 record as a `CGH3` envelope
fails before decryption.

## Failure handling and security rules

`open` returns an opaque `Error::AuthenticationFailed` for wrong AAD, wrong
`info`, modified ciphertext, and same-size modified encapsulations that reach
ML-KEM implicit rejection. Do not branch application behavior on which of those
conditions occurred.

```rust
use crypt_guard::pq_hpke::{Error, HpkeEnvelope};

fn open_record(
    envelope: &HpkeEnvelope,
    key: &crypt_guard::pq_hpke::RecipientPrivateKey,
) -> Result<Vec<u8>, Error> {
    match envelope.open(key, b"service=payments", b"record=42") {
        Ok(plaintext) => Ok(plaintext),
        Err(Error::AuthenticationFailed) => Err(Error::AuthenticationFailed),
        Err(error) => Err(error),
    }
}
```

Treat `info` as a stable setup context such as protocol version or service
name. Treat AAD as authenticated but unencrypted metadata such as tenant,
record type, object identifier, or sender routing data. Do not reuse a sender
context after its sequence is exhausted. Do not put secrets in AAD.

## CGv2 migration

CGv2 is compatibility-only in v3. Default builds do not expose the legacy
builders or accept CGv2 as a v3 envelope. Existing stored data requires an
explicit migration build.

```toml
[dependencies]
crypt_guard = { version = "3.0.1", features = ["cgv2-compat"] }
```

Migration procedure:

1. Deploy a migration worker with `cgv2-compat` enabled.
2. Read and authenticate the existing CGv2 envelope using the compatibility API.
3. Re-encrypt the recovered plaintext with `pq_hpke::HpkeEnvelope`.
4. Store the `CGH3` bytes and preserve the application contract for `info` and AAD.
5. Remove `cgv2-compat` after all stored data has been migrated.

Never trial-decrypt unknown records with both formats. Store or transmit a
transport discriminator and select the reader directly.

## Signatures and legacy support

ML-DSA remains available in the default feature set.

```rust,no_run
use crypt_guard::kem::backend::OsRng;
use crypt_guard::sign::{ml_dsa::MlDsa65Impl, SignAlgorithm};

let mut rng = OsRng;
let (secret_key, public_key) = MlDsa65Impl::keypair(&mut rng)?;
let signature = MlDsa65Impl::sign(&secret_key, b"signed payload")?;
MlDsa65Impl::verify(&public_key, b"signed payload", &signature)?;
# Ok::<(), crypt_guard::error::CryptError>(())
```

The `legacy-pqclean` feature retains the historical Kyber, Falcon, and
Dilithium path for explicitly managed legacy data. It is separate from
`cgv2-compat`, which controls the v2 envelope and builder compatibility path.

## Feature flags

| Feature | Default | Purpose |
|---|---:|---|
| `ml-kem-backend` | yes | FIPS ML-KEM-512, ML-KEM-768, ML-KEM-1024 |
| `ml-dsa-backend` | yes | FIPS ML-DSA-44, ML-DSA-65, ML-DSA-87 |
| `sign-slhdsa` | no | SLH-DSA signatures |
| `cgv2-compat` | no | CGv2 envelope, builders, and compatibility helpers |
| `legacy-pqclean` | no | Historical Kyber, Falcon, and Dilithium compatibility |
| `archive` | no | Archive helpers |
| `zip` | no | ZIP helpers |
| `aes-ctr` | no | Legacy AES-CTR support |
| `aes-xts` | no | Legacy AES-XTS support |

## References

- [FIPS 203: ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)
- [FIPS 204: ML-DSA](https://csrc.nist.gov/pubs/fips/204/final)
- [FIPS 205: SLH-DSA](https://csrc.nist.gov/pubs/fips/205/final)
- [RFC 9180: Hybrid Public Key Encryption](https://www.rfc-editor.org/rfc/rfc9180.html)
- [draft-ietf-hpke-pq-05](https://datatracker.ietf.org/doc/draft-ietf-hpke-pq-05/)
