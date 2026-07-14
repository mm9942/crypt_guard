# CryptGuard v2.0.4

[![Crates.io](https://img.shields.io/badge/crates.io-v2-blue.svg?style=for-the-badge)](https://crates.io/crates/crypt_guard)
[![MIT licensed](https://img.shields.io/badge/license-MIT-green.svg?style=for-the-badge)](https://github.com/mm9942/crypt_guard/blob/main/LICENSE)
[![Documentation](https://img.shields.io/badge/docs-v2-yellow.svg?style=for-the-badge)](https://docs.rs/crypt_guard/)
[![GitHub Library](https://img.shields.io/badge/github-lib-black.svg?style=for-the-badge)](https://github.com/mm9942/crypt_guard)

`crypt_guard` is a post-quantum sealing library centered on one safe default flow:

```text
ML-KEM (FIPS 203) -> HKDF -> CGv2 authenticated envelope
```

The primary API produces one self-contained CGv2 envelope. Nonce handling,
key derivation, and KEM encapsulation are all internal — the caller provides
a public key and plaintext and receives a sealed `Envelope` back.

Current release version: `2.0.4`. The Phase 4 safe-default upgrade remains the
primary supported path. This release also contains a **partial** RFC 9180 core:
the labeled key schedule, a non-cloneable Base-mode context, RFC nonce
sequencing, exporter derivation, and the registered ChaCha20-Poly1305 AEAD are
implemented. It does **not** yet provide KEM setup or a vector-verified,
interoperable HPKE suite, so `crypt_guard` makes no full RFC 9180 conformance
claim. Separately, the opt-in `hpke-pq-draft-05` feature exposes a
vector-gated Base-mode API for the two pinned
`draft-ietf-hpke-pq-05` ML-KEM profiles. That active Internet-Draft is not an
RFC or a finalized IANA profile; its literal revision is part of the protocol
identity.

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

## Protocol: CGv2 authenticated envelope (not RFC 9180 HPKE)

crypt_guard v2 currently implements its own CGv2 envelope format. It uses a
KEM, HKDF, and AEAD, but it is **not** an implementation of
[RFC 9180 HPKE](https://www.rfc-editor.org/rfc/rfc9180.html): it does not use
the RFC 9180 KEM interface, labeled key schedule, AEAD nonce sequencing, or
wire format, and is not interoperable with RFC 9180 implementations.

The current CGv2 construction is:

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

The `crypt_guard::api::hpke` module is retained as a source-compatible legacy
CGv2 framing API. Its `info` and `aad` arguments are encoded inside an encrypted
HFv1 payload framing; they do not provide RFC 9180 HPKE setup or AEAD-AAD
semantics. The separate `crypt_guard::hpke` module contains only the partial
RFC 9180 core described above; it is not a KEM setup or interoperability API.

---

## Experimental `draft-ietf-hpke-pq-05` Base mode

With the non-default `hpke-pq-draft-05` feature, the additive
`crypt_guard::hpke_pq::draft_ietf_hpke_pq_05` module exposes only these exact,
pinned Base-mode profiles:

- ML-KEM-768 / HKDF-SHA256 / AES-128-GCM
- ML-KEM-1024 / HKDF-SHA384 / AES-256-GCM

It is a **vector-gated experimental implementation of an active Internet
Draft**, not an RFC-standardized post-quantum HPKE profile. There is no
algorithm negotiation or fallback. Applications must store the protocol family,
the literal `draft-ietf-hpke-pq-05` revision, and the exact profile alongside
the separately transported `enc` and ciphertext; they must select this reader
directly rather than trial-decrypting CGv2/HFv1 data.

Enable the feature explicitly; it is intentionally not part of the default
feature set:

```toml
[dependencies]
crypt_guard = { version = "2.0.4", features = ["hpke-pq-draft-05"] }
```

```rust
use crypt_guard::hpke_pq::draft_ietf_hpke_pq_05::{
    generate_recipient_key_pair, setup_base_receiver, setup_base_sender, Profile,
};

let profile = Profile::MlKem768HkdfSha256Aes128Gcm;
let recipient_keys = generate_recipient_key_pair(profile);

// `enc` is a separate transport value. Contexts own nonce sequencing; callers
// supply only setup info and AEAD AAD, never a nonce or a raw shared secret.
let (enc, mut sender) = setup_base_sender(profile, recipient_keys.public_key(), b"service=v1")?;
let ciphertext = sender.seal(b"record metadata", b"payload")?;

let mut recipient = setup_base_receiver(
    profile,
    recipient_keys.private_key(),
    &enc,
    b"service=v1",
)?;
assert_eq!(recipient.open(b"record metadata", &ciphertext)?, b"payload");
# Ok::<(), crypt_guard::hpke_pq::draft_ietf_hpke_pq_05::Error>(())
```

The sender and recipient contexts are intentionally non-`Clone`, advance their
sequence only after a successful AEAD operation, and expose no manual-nonce
API. Wrong AAD, ciphertext, or a same-size modified `enc` all produce the same
opaque authentication failure when opening.

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
| `hpke-pq-draft-05` | no | vector-gated experimental `draft-ietf-hpke-pq-05` Base-mode ML-KEM API; not an RFC-standardized profile |
| `aes-ctr` | no | AES-CTR stream cipher |
| `aes-xts` | no | AES-XTS disk encryption |
| `archive` | no | tar/xz/gz archive helpers |
| `legacy-pqclean` | no | Legacy Kyber/Falcon/Dilithium + old tuple API |

To use only the new FIPS path without legacy code:

```toml
[dependencies]
crypt_guard = { version = "2.0.4", default-features = true }
```

To include the legacy path for reading data encrypted with v1.x:

```toml
[dependencies]
crypt_guard = { version = "2.0.4", features = ["legacy-pqclean"] }
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
crypt_guard = { version = "2.0.4", features = ["legacy-pqclean"] }
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
- [draft-ietf-hpke-pq-05 — Post-Quantum HPKE](https://datatracker.ietf.org/doc/draft-ietf-hpke-pq-05/) (experimental draft mapping; not an RFC)
