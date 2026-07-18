# Design Direction & Roadmap

---

## North Star

Keep the original 4-axis typestate design:

```
Kyber<Process, Size, Content, Algorithm>
```

Plus the working main macros and the builder. The old code's problem was **messiness, not the design**. The trait design should get genuinely better (proper trait/macro abstractions) with the **same intention**.

### Hard constraints

- **Never delete a crypto capability** — everything stays usable behind a `--feature`.
- Old standard `encrypt`/`decrypt` and non-core surface gets ordered under `deprecated`/`legacy` and feature-gated so old data stays decryptable.
- The macros exist specifically so users need far fewer `use` statements — **preserve that**.

---

## High-Level Goal

A useful, **secure** crypto design that gives a simple solution to "all the mess out there" (AES, XChaCha20-Poly1305, KDFs) **plus** a new high-level layer that bundles `(encryption output + nonce + KEM secret)` into ONE thing secured with a public/private key.

The standardized name for this is **HPKE / RFC 9180** (see `01-research-hpke-nist-giants.md`). crypt_guard's `Envelope { header, kem_ciphertext, nonce, ciphertext }` is already HPKE-shaped.

---

## Roadmap

### Phase 4 — Breaking clean-up (complete)

1. Take `legacy-pqclean` out of the `default` features in `Cargo.toml`.
2. Keep it fully usable via `--features legacy-pqclean`.
3. Order the old tuple API and non-core surface under `legacy`.
4. Keep the main working macros under the legacy feature.
5. Rewrite README + guides for the safe default.
6. Add CI coverage for default, ML-only, and legacy-only lanes.

**Effect:** this is what makes the content-axis typestate enforcement actually bite in the default build.

---

### High-Level Layer — HPKE-style `seal` / `open`

Present a single-shot API over the existing `Sealer`/`Opener` in `src/api/`:

```rust
seal(info, aad, plaintext) -> Envelope
open(envelope, info, aad)  -> plaintext
```

Key schedule alignment:
- Align to HPKE's labeled extract/expand + `suite_id` domain separation (RFC 9180 labels for interop).

Optional: add a **Hybrid KEM** (X-Wing = X25519 + ML-KEM-768) behind the existing `KemBackend` trait as an opt-in feature (e.g. `--features hybrid-xwing`) to match how Cloudflare/AWS/Google deploy PQC. Pure ML-KEM remains valid.

---

### Typestate Enforcement — `trybuild` compile-fail cases

- Process axis (Encryption/Decryption) is already enforced via `trybuild`.
- Content axis enforced via capability traits.
- Content compile-fail cases now live under `tests/ui/` and are exercised by
  `tests/typestate_compile.rs`.
- Default and ML-only builds enforce forbidden content/method pairs.
- Legacy-only keeps the v1.x tuple API available and excludes the content-axis
  fixtures that would intentionally reject that API.

---

### Phase 5 — Hygiene / release polish

- Clear ~220 clippy warnings (~166 auto-fixable via `cargo clippy --fix`).
- Remove dead code.
- Raise doc coverage from 45% toward 100%.
- Make `cargo clippy -- -D warnings` pass; CI warning-clean.
- Move `src/core/kyber/*` into `src/legacy/`.
- Clean release artifacts from the Git index before publishing.
- Keep accepted post-release design debt documented in the release-readiness
  guide.

---

## Target Module Layout (Blueprint)

```
src/
  kem/        # KEM backends (ML-KEM, X-Wing opt-in)
  aead/       # Symmetric cipher impls (XChaCha20Poly, AES-GCM-SIV, ...)
  kdf/        # HKDF, key derivation
  sign/       # ML-DSA, SLH-DSA
  protocol/   # HPKE envelope assembly, suite_id domain separation
  api/        # High-level seal/open single-shot API
  io/         # File I/O helpers
  legacy/     # All pqcrypto-based impls, tuple-return traits, old macros
```
