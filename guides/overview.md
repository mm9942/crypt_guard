# Overview

`crypt_guard` now defaults to ML-KEM + ML-DSA, HKDF-based key derivation, and
one authenticated envelope format.

The current crate version is `2.0.4`. The safe-default Phase 4 upgrade remains
the supported default. Version 2.0.4 also carries a partial RFC 9180 core
(labeled key schedule, Base-mode context, nonce sequencing, export, and
ChaCha20-Poly1305 operations), but it does not yet implement KEM setup or make
a vector-verified interoperable HPKE conformance claim.

The opt-in `hpke-pq-draft-05` feature separately exposes a vector-gated,
revision-named Base-mode API at `hpke_pq::draft_ietf_hpke_pq_05` for the two
pinned `draft-ietf-hpke-pq-05` ML-KEM profiles. It transports `enc` separately
from ciphertext and owns nonce sequencing in non-cloneable contexts. This is
active-Internet-Draft work, not RFC-standardized HPKE and not a replacement for
CGv2.

Use the safe API when you want:

- one self-contained encryption artifact
- no manual nonce handling
- typed encrypt/open entry points
- a path that follows the new design direction

Use the legacy API only when you need compatibility with the older macro- and
tuple-based surfaces. `legacy-pqclean` remains opt-in for that path.
