# Overview

`crypt_guard` now defaults to ML-KEM + ML-DSA, HKDF-based key derivation, and
one authenticated envelope format.

The current crate version is `2.0.0`. The safe-default Phase 4 upgrade is
implemented, externally consumer-tested, and test-green; see
`release-readiness.md` for the publish hygiene checklist.

Use the safe API when you want:

- one self-contained encryption artifact
- no manual nonce handling
- typed encrypt/open entry points
- a path that follows the new design direction

Use the legacy API only when you need compatibility with the older macro- and
tuple-based surfaces. `legacy-pqclean` remains opt-in for that path.
