# Security Model

## Safe path

The safe path is:

```text
ML-KEM -> HKDF -> AEAD -> CGv2 envelope
```

The HPKE-style helper API is available as `api::hpke::{seal, open}` and as
crate-root `hpke_seal` / `hpke_open`.

## Properties

- the nonce is generated inside the protocol engine
- the nonce is stored inside the envelope
- header fields, KEM ciphertext, and nonce are authenticated as AAD
- the caller handles one envelope instead of separate ciphertext, KEM ciphertext, and nonce
- `api::hpke` verifies caller-supplied `info` and `aad` on open

## Non-goals of the safe API

- raw stream cipher operation
- manual nonce copying
- unauthenticated encryption modes
- panics for malformed user input

## Current limits

- The default builder API does not yet accept typed public/secret key wrappers.
- `info` and `aad` in the HPKE-style helper are currently protected inside the
  encrypted payload framing, not directly in the HKDF `info` parameter.
