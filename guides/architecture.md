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
7. `hpke/`
   Holds the partial RFC 9180 core separately from CGv2: labeled key schedule,
   Base-mode context state, nonce sequencing, exporter derivation, and the
   registered ChaCha20-Poly1305 operation. KEM setup and a complete
   interoperable suite API remain additive; they do not reuse `Envelope`.
8. `hpke_pq::draft_ietf_hpke_pq_05/` (feature-gated)
   Holds the exact, vector-gated experimental Base-mode mapping for the pinned
   active IETF draft. It owns typed ML-KEM key material, separate `enc`, and
   non-cloneable AES-GCM contexts; it never serializes as CGv2.

## Protocol boundaries and migration

CGv2 and RFC 9180 HPKE are distinct protocol families. `api::hpke::{seal,
open}` is historical CGv2/HFv1 compatibility framing despite its name: it
creates a CGv2 `Envelope`, and its framed `info` and `aad` are encrypted
plaintext rather than RFC 9180 inputs.

Applications own the record-level protocol discriminator, format version, and
exact suite/profile identifier. They select the corresponding decoder directly;
there is no trial decryption, magic fallback, or downgrade path between CGv2
and HPKE. Existing CGv2 bytes are never reinterpreted as HPKE bytes.

## Current caveats

- The safe public builders still accept raw key bytes. Typed ML-KEM key wrappers
  exist in `kem/`, but they are not yet required at the `Encryptor` /
  `Decryptor` boundary.
- `api::hpke::{seal, open}` is frozen legacy CGv2/HFv1 framing. It must not be
  refactored into real HPKE or gain new HPKE features.
- `hpke/` is not a complete HPKE implementation: its current core has no KEM
  setup and has not passed the full pinned RFC 9180 vector corpus.
- With `hpke-pq-draft-05`, `hpke_pq::draft_ietf_hpke_pq_05` exposes only two
  vector-gated Base-mode profiles, named with the literal draft revision. It
  is an active-Internet-Draft implementation, not an RFC-standardized profile.
- Broad crate-root re-exports remain for compatibility during the v2 transition.
- The ML-KEM mapping named `draft-ietf-hpke-pq-05` is an active Internet-Draft,
  not a standardized RFC profile. Its draft revision is part of the profile
  identity and must remain explicit in code, fixtures, and documentation.

## Direction

- One safe default protocol
- Typed public API
- Legacy compatibility behind a clearly non-primary surface
- Feature-gated optional families
