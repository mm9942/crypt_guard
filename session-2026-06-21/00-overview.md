# Session 2026-06-21 — crypt_guard v2 redesign (cleanup, not redesign-away)

This directory captures everything produced in this working session so the work can
resume cold (including via API) without re-deriving context.

## One-paragraph status

Branch `v2-redesign`, current version `2.0.0`. Phases 1–4 of the redesign are
implemented and green. This session (a) audited the original 1.4.2 conventions in
detail, (b) rebuilt the cipher layer onto a proper `SymmetricCipher` trait (12 copy-paste
impl blocks → 1 generic impl + 6 small impls), (c) enforced the content axis of the
typestate (split `EncryptFunctions`/`DecryptFunctions` into 6 content-gated capability
traits), and (d) researched how the giants + NIST package the (ciphertext + nonce + KEM
secret) bundle — the answer is **HPKE / RFC 9180**, which is the template for the new
high-level layer. The current release matrix is green; see `05-continuation.md` and
`guides/release-readiness.md` before publishing.

## Files in this directory

- `00-overview.md` — this file
- `01-research-hpke-nist-giants.md` — online research: HPKE/RFC 9180, NIST SP 800-227, hybrid PQC, how Cloudflare/AWS/Google do it, with sources, mapped to crypt_guard
- `02-old-conventions-audit.md` — detailed audit of the original 1.4.2 code conventions (the "messy but liked" design)
- `03-status-and-changes.md` — exactly what changed this session, file map, test results, the dual-trait-family finding
- `04-design-and-roadmap.md` — the agreed design direction + phases 4/5 + the HPKE-style high-level API sketch
- `05-continuation.md` — how to resume: commands, disk caveat, checklist

## Maintainer intent (the north star — do not drift from this)

- KEEP the original design (4-axis `Kyber<Process, Size, Content, Algorithm>` typestate,
  the working main macros, the builder). The old code's problem was that it was very
  messy/unorganized, NOT that the design was wrong. Traits/macros were hand-written by
  someone with no macro/trait experience at the time — so the TRAIT DESIGN should get
  genuinely better, same intention.
- NEVER delete a cryptographic capability. Every algorithm/mode stays usable behind a
  `--feature`. Old standard encrypt/decrypt + everything non-core gets ordered under
  `deprecated`/`legacy` and feature-gated, never removed (old data must stay decryptable).
- Goal: a useful, SECURE crypto design that gives a simple solution to "all the mess out
  there" (AES, XChaCha20-Poly1305, the KDFs) AND a new high-level layer that bundles
  (encryption output + nonce + KEM secret) into one thing secured with public/private key
  — i.e. HPKE-style seal/open. See `01-research-*` and `04-design-*`.
