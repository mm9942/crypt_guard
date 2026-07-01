# CryptGuard v2

[![Crates.io](https://img.shields.io/badge/crates.io-v2-blue.svg?style=for-the-badge)](https://crates.io/crates/crypt_guard)
[![MIT licensed](https://img.shields.io/badge/license-MIT-green.svg?style=for-the-badge)](https://github.com/mm9942/crypt_guard/blob/main/LICENSE)
[![Documentation](https://img.shields.io/badge/docs-v2-yellow.svg?style=for-the-badge)](https://docs.rs/crypt_guard/)
[![GitHub Library](https://img.shields.io/badge/github-lib-black.svg?style=for-the-badge)](https://github.com/mm9942/crypt_guard)

`crypt_guard` is a post-quantum sealing library centered on one safe default flow:

```text
ML-KEM (FIPS 203) -> HKDF -> Authenticated Envelope (HPKE-shaped)
```

The primary API produces one self-contained CGv2 envelope. Nonce handling,
key derivation, and KEM encapsulation are all internal — the caller provides
a public key and plaintext and receives a sealed `Envelope` back.

Current release status: `2.0.0`. The Phase 4 safe-default upgrade is
implemented, externally consumer-tested, and test-green. Before publishing,
close the release hygiene gates in
[guides/release-readiness.md](guides/release-readiness.md).

---

## Safe Default: `Encryptor` / `Decryptor`

```rust
use crypt_guard::{Decryptor, Encryptor};
use crypt_guard::XChaCha20Poly1305;
# #[cfg(feature = "ml-kem-backend")]
use crypt_guard::{MlKem768, kem::{KemBackend, ml_kem::MlKem768Impl}};
use crypt_guard::kem::backend::OsRng;

fn main() -> Result<(), crypt_guard::error::CryptError> {
    #[cfg(feature = "ml-kem-backend")]
    {
    let mut rng = OsRng;
    let (public_key, secret_key) = MlKem768Impl::keypair(&mut rng)?;

    // Seal: ML-KEM encapsulate -> HKDF -> XChaCha20-Poly1305 AEAD
    let envelope = Encryptor::<MlKem768, XChaCha20Poly1305>::new()
        .recipient(public_key.as_ref().to_vec())
        .plaintext(b"hello post-quantum world")
        .seal()?;

    // Open: ML-KEM decapsulate -> HKDF -> AEAD verify + decrypt
    let plaintext = Decryptor::<MlKem768, XChaCha20Poly1305>::new()
        .secret_key(secret_key.as_ref().to_vec())
        .open(&envelope)?;

    assert_eq!(plaintext, b"hello post-quantum world");
    }
    Ok(())
}
```

The `Envelope` type is a self-describing serialisable blob:
`{ header, kem_ciphertext, nonce, ciphertext }`. The nonce is
generated internally and bound into the AEAD AAD; callers never
juggle it separately.

---

## What is New in v2

| Area | v1.x | v2 |
|---|---|---|
| KEM | pqcrypto Kyber (NIST Round 3) | **ML-KEM** (FIPS 203 final) |
| Signing | Falcon / Dilithium | **ML-DSA** (FIPS 204) + **SLH-DSA** (FIPS 205) |
| Key schedule | ad-hoc passphrase KDF | **HKDF-SHA256/512** with domain-separated labels |
| Envelope | `(ciphertext, kyber_secret)` tuple | **CGv2 Envelope** — one self-describing blob |
| Nonce | caller-managed, separate artifact | nonce embedded and bound inside envelope |
| Type enforcement | decorative content axis | **compile-enforced** content-axis typestate |
| API shape | macro-first | `Encryptor`/`Decryptor` staged builders (macros still work) |

---

## Protocol: HPKE-shaped CGv2 Envelope

crypt_guard v2 follows the structural pattern of **HPKE (RFC 9180)**
as deployed by Cloudflare, AWS, and Google for post-quantum TLS:

```text
Sender:
  (kem_ct, shared_secret) = ML-KEM.Encapsulate(recipient_pk)
  session_key, base_nonce = HKDF(ikm=shared_secret, salt=kem_ct,
                                  info="crypt_guard:v2:aead:<alg>")
  ciphertext = AEAD.Seal(session_key, nonce, aad, plaintext)
  envelope   = { header, kem_ct, nonce, ciphertext }

Receiver:
  shared_secret = ML-KEM.Decapsulate(kem_ct, recipient_sk)
  session_key   = HKDF(same params)
  plaintext     = AEAD.Open(session_key, nonce, aad, ciphertext)
```

The shared secret is zeroized immediately after key derivation, following the
NIST SP 800-227 direction for KEM-based protocols. The `header` field carries the
algorithm identifiers (`kem_id`, `kdf_id`, `aead_id`) so the
envelope is self-describing and forwards-compatible.

---

## Supported Algorithms

### Key Encapsulation (KEM)

| Marker | Algorithm | Security | Standard |
|---|---|---|---|
| `MlKem512` | ML-KEM-512 | Category 1 | FIPS 203 |
| `MlKem768` | ML-KEM-768 | Category 3 (recommended) | FIPS 203 |
| `MlKem1024` | ML-KEM-1024 | Category 5 | FIPS 203 |

### Authenticated Encryption (AEAD)

| Marker | Algorithm | Notes |
|---|---|---|
| `XChaCha20Poly1305` | XChaCha20-Poly1305 | Default; 24-byte nonce |
| `AesGcmSiv` | AES-256-GCM-SIV | Nonce-misuse resistant |

### Digital Signatures

| Algorithm | Feature | Standard |
|---|---|---|
| ML-DSA-44 / 65 / 87 | `ml-dsa-backend` (default) | FIPS 204 |
| SLH-DSA | `sign-slhdsa` | FIPS 205 |

---

## Feature Flags

| Flag | Default | What it adds |
|---|---|---|
| `ml-kem-backend` | yes | ML-KEM-512/768/1024 (FIPS 203) |
| `ml-dsa-backend` | yes | ML-DSA-44/65/87 (FIPS 204) |
| `sign-slhdsa` | no | SLH-DSA (FIPS 205) |
| `aes-ctr` | no | AES-CTR stream cipher |
| `aes-xts` | no | AES-XTS disk encryption |
| `archive` | no | tar/xz/gz archive helpers |
| `legacy-pqclean` | no | Legacy Kyber/Falcon/Dilithium + old tuple API |

To use only the new FIPS path without legacy code:

```toml
[dependencies]
crypt_guard = { version = "2.0.0", default-features = true }
```

To include the legacy path for reading data encrypted with v1.x:

```toml
[dependencies]
crypt_guard = { version = "2.0.0", features = ["legacy-pqclean"] }
```

---

## Typestate Design: `Kyber<Process, Size, Content, Algorithm>`

The underlying `Kyber<P, S, C, A>` type encodes four axes in the type:

| Axis | Variants |
|---|---|
| Process | `Encryption`, `Decryption` |
| Size | `MlKem512`, `MlKem768`, `MlKem1024` |
| Content | `Data`, `Message`, `Files` |
| Algorithm | `XChaCha20Poly1305`, `AesGcmSiv`, … |

Calling `encrypt_file` on a `Message` instance is a **compile error** (E0599).
The `Encryptor`/`Decryptor` builders use the same underlying type but
expose only the safe `Data` path by default.

---

## Signing

```rust,no_run
use crypt_guard::kem::backend::OsRng;
use crypt_guard::sign::{SignAlgorithm, ml_dsa::MlDsa65Impl};

let mut rng = OsRng;
let (sk, vk) = MlDsa65Impl::keypair(&mut rng)?;
let sig = MlDsa65Impl::sign(&sk, b"my message")?;
MlDsa65Impl::verify(&vk, b"my message", &sig)?;
# Ok::<(), crypt_guard::error::CryptError>(())
```

---

## Architecture

```text
crypt_guard::api           (Encryptor / Decryptor — safe entry points)
  -> crypt_guard::protocol (CGv2 Envelope + Header + AAD construction)
  -> crypt_guard::kem      (ML-KEM backend trait + ML-KEM-512/768/1024)
  -> crypt_guard::kdf      (HKDF-SHA256/512 with domain-separated labels)
  -> crypt_guard::core     (AEAD wiring; typestate Kyber<P,S,C,A>)
  -> crypt_guard::sign     (ML-DSA, SLH-DSA)
  -> crypt_guard::legacy   (pqcrypto Kyber/Falcon/Dilithium — feature-gated)
```

---

## Legacy Compatibility

If you have data encrypted with crypt_guard v1.x (pqcrypto Kyber, tuple-return
API, manual nonce), enable the `legacy-pqclean` feature:

```toml
[dependencies]
crypt_guard = { version = "2.0.0", features = ["legacy-pqclean"] }
```

The old `Kyber<Encryption, Kyber1024, Message, AES>` types, the
`encryption!` / `decryption!` macros, the `kyber_keypair!` macro, and
the tuple-returning `encrypt_msg` / `decrypt_msg` functions remain available
under the `legacy` module and through the crate re-exports.

```rust,ignore
// Legacy usage (requires --features legacy-pqclean)
use crypt_guard::{*, error::*};

let (public_key, secret_key) = kyber_keypair!(1024);
let (ciphertext, kyber_secret) = encryption!(
    public_key.to_owned(), 1024,
    b"hello".to_vec(), "passphrase", AES
)?;
let plaintext = decryption!(
    secret_key.to_owned(), 1024,
    ciphertext, "passphrase", kyber_secret, AES
)?;
```

---

## References

- [FIPS 203 — ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)
- [FIPS 204 — ML-DSA](https://csrc.nist.gov/pubs/fips/204/final)
- [FIPS 205 — SLH-DSA](https://csrc.nist.gov/pubs/fips/205/final)
- [NIST SP 800-227 — Recommendations for Key-Encapsulation Mechanisms](https://csrc.nist.gov/pubs/sp/800/227/final)
- [RFC 9180 — Hybrid Public Key Encryption (HPKE)](https://www.rfc-editor.org/rfc/rfc9180.html)
