# Fuzz targets

Coverage-guided fuzzing of every parser that accepts untrusted input.
Requires a nightly toolchain and `cargo install cargo-fuzz`.

```sh
cargo +nightly fuzz list
cargo +nightly fuzz run hpke_envelope -- -max_total_time=600
cargo +nightly fuzz run pq_hpke_keys
cargo +nightly fuzz run rfc9180_keys
cargo +nightly fuzz run kms_codec
cargo +nightly fuzz run kms_decrypt
```

| Target | Exercises |
|---|---|
| `hpke_envelope` | `HpkeEnvelope::from_bytes`, `to_bytes`/`try_to_bytes` round trip, suite id mapping, `open_zeroizing` on random envelopes |
| `pq_hpke_keys` | `RecipientPublicKey`, `Encapsulation`, `RecipientPrivateKey::from_seed_bytes` and `derive_recipient_key_pair` for all six KEMs |
| `rfc9180_keys` | `PublicKey`, `PrivateKey` and `EncapsulatedKey::from_bytes` for all five DHKEMs |
| `kms_codec` | `FrameReader` and `decode_request` for all 14 routes |
| `kms_decrypt` | `InMemoryProvider` decrypt/unwrap with arbitrary `CGKC` frames |

The targets compile on stable (`cargo check --manifest-path fuzz/Cargo.toml`),
which CI uses to keep them from rotting; running them needs nightly.
