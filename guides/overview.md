# Overview

`crypt_guard` now defaults to ML-KEM + ML-DSA, HKDF-based key derivation, and
one authenticated envelope format.

The current crate version is `2.0.2`. The safe-default Phase 4 upgrade is
implemented, externally consumer-tested, and test-green. The 2.0.2 patch closes
the post-alpha hardening findings around constant-time HMAC verification,
legacy HKDF key derivation, and secret zeroization.

Use the safe API when you want:

- one self-contained encryption artifact
- no manual nonce handling
- typed encrypt/open entry points
- a path that follows the new design direction

Use the legacy API only when you need compatibility with the older macro- and
tuple-based surfaces. `legacy-pqclean` remains opt-in for that path.
