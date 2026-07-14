# Security Model

## Safe path

The safe path is:

```text
ML-KEM -> HKDF -> AEAD -> CGv2 envelope
```

## Legacy CGv2/HFv1 compatibility framing

`api::hpke::{seal, open}` and the crate-root `hpke_seal` / `hpke_open` names
are historical compatibility APIs. They produce a CGv2 envelope whose
encrypted plaintext starts with the private `HFv1` framing for `info` and
`aad`; they are not RFC 9180 HPKE and are frozen for source and data
compatibility.

Applications migrating to real HPKE must store an application-owned protocol
family, format version, and exact suite/profile identifier next to each
payload, then select only that reader. They must not trial-decrypt CGv2 as
HPKE, fall back between readers, or reinterpret existing CGv2 bytes as HPKE.

## Properties

- the nonce is generated inside the protocol engine
- the nonce is stored inside the envelope
- header fields, KEM ciphertext, and nonce are authenticated as AAD
- the caller handles one envelope instead of separate ciphertext, KEM ciphertext, and nonce
- the legacy compatibility helper verifies caller-supplied `info` and `aad` on
  open after CGv2 decryption

## Non-goals of the safe API

- raw stream cipher operation
- manual nonce copying
- unauthenticated encryption modes
- panics for malformed user input

## Current limits

- The default builder API does not yet accept typed public/secret key wrappers.
- The legacy helper protects `info` and `aad` inside its encrypted HFv1
  payload framing, not as RFC 9180 setup `info` or AEAD AAD. It will not be
  converted in place.
- `crypt_guard::hpke` currently provides a partial RFC 9180 core (labeled key
  schedule, Base-mode context, nonce sequencing, exporter derivation, and
  ChaCha20-Poly1305) but no KEM setup or vector-verified interoperable suite.
  A complete HPKE API remains additive, with its own `enc`, suite, and
  transport boundary.
- The current `draft-ietf-hpke-pq-05` ML-KEM mapping is an active
  Internet-Draft, not an RFC or standardized profile.
- When `hpke-pq-draft-05` is enabled, the additive
  `hpke_pq::draft_ietf_hpke_pq_05` API exposes only the pinned,
  vector-gated Base-mode profiles. It returns a separately transported `enc`
  and non-cloneable sender/recipient contexts; it deliberately has no manual
  nonce or raw shared-secret API. AAD, ciphertext, and same-size modified
  `enc` failures collapse to one authentication error at `open`.
