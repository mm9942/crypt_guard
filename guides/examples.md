# Examples

## Safe default sealing

See `examples/encrypt_xchacha.rs`.

## Safe AES-GCM-SIV sealing

See `examples/encrypt_aes.rs`.

## Legacy macros

See `examples/macro_example.rs`. Treat that example as compatibility-oriented,
not as the primary API.

## Legacy CGv2/HFv1 context binding

`crypt_guard::api::hpke::{seal, open}` is retained only to read and write the
historical CGv2/HFv1 compatibility format. Its `info` and `aad` values are
framed inside encrypted plaintext; it is not RFC 9180 HPKE.

New applications must not label this output as HPKE. Use the separate
`crypt_guard::hpke::rfc9180` API for classic RFC 9180 HPKE. The default
draft-05 PQ transport API below must still store an application-owned
protocol/version/profile discriminator with each payload and dispatch to
exactly one reader. Do not use trial decryption or CGv2 fallback as protocol
detection.

The ML-KEM profile tracked as `draft-ietf-hpke-pq-05` is an active
Internet-Draft, not a standardized RFC profile.

## Experimental draft-05 Base mode

Use the additive, default
revision-named `hpke_pq::draft_ietf_hpke_pq_05` module. It is vector-gated for
the pinned ML-KEM-768/HKDF-SHA256/AES-128-GCM and
ML-KEM-1024/HKDF-SHA384/AES-256-GCM Base-mode profiles. It is not an RFC
standardization claim. Use `setup_base_sender` to obtain a separate `enc` plus
a sender context and `setup_base_receiver` with that exact `enc` to obtain the
recipient context. Contexts derive their own nonces and are non-cloneable.
