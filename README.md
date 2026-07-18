# CryptGuard v3.0.0

[![Crates.io](https://img.shields.io/badge/crates.io-v3-blue.svg?style=for-the-badge)](https://crates.io/crates/crypt_guard)
[![MIT licensed](https://img.shields.io/badge/license-MIT-green.svg?style=for-the-badge)](https://github.com/mm9942/crypt_guard/blob/main/LICENSE)
[![Documentation](https://img.shields.io/badge/docs-v3-yellow.svg?style=for-the-badge)](https://docs.rs/crypt_guard/)
[![GitHub Library](https://img.shields.io/badge/github-lib-black.svg?style=for-the-badge)](https://github.com/mm9942/crypt_guard)

`crypt_guard` is a pure-Rust post-quantum sealing library. Version 3 makes a
revision-pinned PQ HPKE construction the default transport:

```text
ML-KEM (FIPS 203) -> HPKE KEM/KDF schedule -> AEAD
```

The default suite is **ML-KEM-1024/P-384 + SHAKE256 + ChaCha20-Poly1305**.
CGv2 is no longer part of the default public API; read or write CGv2 data only
with the explicit `cgv2-compat` feature during a deliberate migration.

## Default API: `pq_hpke`

`pq_hpke` keeps the HPKE KEM output (`enc`) and ciphertext distinct for raw
transport users, and provides `HpkeEnvelope` (`CGH3`, version 1) for
crypt_guard deployments that need a self-describing record. Setup `info` and
per-message AAD are caller inputs; neither is hidden in encrypted plaintext.

```rust
use crypt_guard::pq_hpke::{
    generate_recipient_key_pair, HpkeEnvelope, DEFAULT_SUITE,
};

let keys = generate_recipient_key_pair(DEFAULT_SUITE.kem())?;
let envelope = HpkeEnvelope::seal(
    DEFAULT_SUITE,
    keys.public_key(),
    b"service=payments",
    b"record=42",
    b"post-quantum payload",
)?;

let encoded = envelope.to_bytes();
let parsed = HpkeEnvelope::from_bytes(&encoded)?;
let plaintext = parsed.open(keys.private_key(), b"service=payments", b"record=42")?;
assert_eq!(plaintext, b"post-quantum payload");
# Ok::<(), Box<dyn std::error::Error>>(())
```

For standardized AEAD suites, raw Base and PSK APIs are available through
`setup_base_sender`, `setup_base_receiver`, `setup_psk_sender`, and
`setup_psk_receiver`. They return / consume separate `Encapsulation` (`enc`)
and stateful sender or recipient contexts.

## Suites and interoperability

The revision-pinned PQ HPKE adapter exposes ML-KEM-512/768/1024 and the
ML-KEM-768/P-256, ML-KEM-768/X25519, and ML-KEM-1024/P-384 hybrid KEMs.
Suite selection is explicit through `Suite::new(Kem, Kdf, Aead)`.

| AEAD | Raw standardized transport | `HpkeEnvelope` |
|---|---:|---:|
| AES-128-GCM | yes | yes |
| AES-256-GCM | yes | yes |
| ChaCha20-Poly1305 | yes | yes |
| AES-256-GCM-SIV | no, crypt_guard private extension | yes |
| XChaCha20-Poly1305 | no, crypt_guard private extension | yes |

The two private extensions use explicit `0xff01` / `0xff02` identifiers. They
must not be represented as RFC 9180 or IANA-interoperable HPKE suites.

The PQ KEM registry and vector corpus are pinned to
`draft-ietf-hpke-pq-05`. This is an Internet-Draft, not an RFC or final IANA
assignment; applications that persist raw artifacts should persist the literal
draft revision and all suite identifiers alongside them.

## Feature flags

| Flag | Default | Purpose |
|---|---:|---|
| `ml-kem-backend` | yes | ML-KEM-512/768/1024 FIPS backend |
| `ml-dsa-backend` | yes | ML-DSA-44/65/87 |
| `cgv2-compat` | no | CGv2 envelope, builders, and legacy HPKE helpers for migration only |
| `legacy-pqclean` | no | Legacy Kyber/Falcon/Dilithium support |
| `sign-slhdsa` | no | SLH-DSA support |

```toml
[dependencies]
crypt_guard = "3.0.0"
```

To migrate CGv2 records, opt in explicitly:

```toml
[dependencies]
crypt_guard = { version = "3.0.0", features = ["cgv2-compat"] }
```

## Migration from v2

1. Deploy a reader with `cgv2-compat` enabled.
2. Decrypt each CGv2 record using the legacy API.
3. Re-encrypt it with `pq_hpke::HpkeEnvelope` and persist the new `CGH3`
   record plus its application `info` / AAD contract.
4. Remove `cgv2-compat` once all records are migrated.

Default v3 builds neither emit nor expose CGv2 ergonomic APIs. Do not
trial-decrypt CGv2 and PQ HPKE records; dispatch by the stored transport type.

## Security properties

- Private key seed handling, ML-KEM validation, implicit rejection, and shared
  secret zeroization remain in the PQCA/libcrux-backed KEM adapter.
- Sender and recipient contexts are non-`Clone`, derive AEAD nonces from the
  HPKE sequence number, and reject sequence wrap.
- Authentication failures for wrong AAD, `info`, ciphertext, or same-size
  tampered encapsulations are intentionally opaque.
- `HpkeEnvelope` authenticates no caller metadata by itself: callers must pass
  matching `info` and AAD when opening.

## References

- [FIPS 203 — ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)
- [FIPS 204 — ML-DSA](https://csrc.nist.gov/pubs/fips/204/final)
- [RFC 9180 — HPKE](https://www.rfc-editor.org/rfc/rfc9180.html)
- [draft-ietf-hpke-pq-05](https://datatracker.ietf.org/doc/draft-ietf-hpke-pq-05/)
