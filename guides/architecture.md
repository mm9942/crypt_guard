# Architecture

The rebuild targets a small public surface over a versioned protocol core.

## Layers

1. `api/`
   Exposes `Encryptor` and `Decryptor` with staged builders.
2. `protocol/`
   Defines the CGv2 envelope, header, AAD rules, and wire format.
3. `kem/`
   Wraps ML-KEM backends behind traits and typed wrappers.
4. `kdf/`
   Derives session keys through HKDF with domain separation.
5. `core/hub/`
   Wires algorithms into encrypt/decrypt capability traits.
6. `legacy/`
   Keeps the old compatibility surface out of the default architecture story.

## Current caveats

- The safe public builders still accept raw key bytes. Typed ML-KEM key wrappers
  exist in `kem/`, but they are not yet required at the `Encryptor` /
  `Decryptor` boundary.
- `api::hpke::{seal, open}` binds `info` and `aad` by encrypting a small framing
  header with the plaintext. A future cleanup can thread those values directly
  into the key schedule and AAD metadata path.
- Broad crate-root re-exports remain for compatibility during the v2 transition.

## Direction

- One safe default protocol
- Typed public API
- Legacy compatibility behind a clearly non-primary surface
- Feature-gated optional families
