# Status & Changes This Session

**Branch:** `v2-redesign` | **Version:** `2.0.0`

Phase 4 is now complete: `legacy-pqclean` is no longer a default feature, the
safe ML-KEM/ML-DSA path is default, and the release matrix is green. The crate
has been moved to `2.0.0` after external consumer tests passed; publish only
after the hygiene gates in `guides/release-readiness.md` are closed.

---

## Changes Made

### 1. `src/core/hub/cipher_impls.rs` — New `SymmetricCipher` trait

Rewrote the file onto a single trait:

```rust
trait SymmetricCipher {
    const AEAD_ID: AeadAlgId;
    const NONCE_LEN: usize;
    fn seal(shared_secret, &Header, kem_ct, nonce, plaintext) -> Result<Vec<u8>>;
    fn open(...) -> Result<Vec<u8>>;
}
```

**Six cipher impls:**

| Impl | Type | Nonce | Feature gate |
|---|---|---|---|
| `XChaCha20Poly1305` | AEAD | 24 | — |
| `AesGcmSiv` | AEAD | 12 | — |
| `Aes` (AES-256-CBC + HMAC) | legacy | 0 (IV-embedded) | `legacy-aes` |
| `AesCtr` | stream | 16 | `aes-ctr` |
| `XChaCha20` (raw + HMAC) | stream | 24 | — |
| `AesXts` | disk | 0 | `aes-xts` |

Two shared worker functions `seal_envelope` / `open_envelope` handle KEM + nonce + envelope assembly once. The previous 12 copy-pasted `EncryptFunctions`/`DecryptFunctions` blocks collapsed to **1 generic orchestration each + 6 small cipher impls**. Adding a new cipher now requires exactly one `impl SymmetricCipher`.

---

### 2. `src/core/hub/mod.rs` — Content-gated capability traits

Split `EncryptFunctions`/`DecryptFunctions` into **six content-gated traits**, each implemented only for its content marker:

| Trait | Marker |
|---|---|
| `EncryptData` | `D = Data` |
| `EncryptText` | `D = Message` |
| `EncryptFile` | `D = Files` |
| `DecryptData` | `D = Data` |
| `DecryptText` | `D = Message` |
| `DecryptFile` | `D = Files` |

Effect: calling `encrypt_file` on a `Message` instance is a **compile error E0599** — the content axis is now genuinely enforced, not decorative.

---

### 3. Consumer updates

- `src/lib.rs` — reexports all six capability traits.
- `src/api/seal.rs` — bound changed `EncryptFunctions` → `EncryptData`.
- `src/api/open.rs` — bound changed `DecryptFunctions` → `DecryptData`.
- `src/tests/Phase3Tests.rs` — imports updated; encrypt_msg test changed from `Data` marker to `Message` marker.

---

### 4. Wire format & security

- Wire format kept **byte-identical**.
- The KEM shared secret is now **zeroized after key derivation**.

---

## Current Test Results

| Suite | Count | Status |
|---|---|---|
| `cargo fmt --check` | n/a | pass |
| `cargo test` | 40 unit, 1 trybuild suite with 7 fixtures, 39 doctests + 1 ignored | pass |
| `cargo test --no-default-features --features ml-kem-backend,ml-dsa-backend` | 40 unit, 1 trybuild suite with 7 fixtures, 39 doctests + 1 ignored | pass |
| `cargo test --no-default-features --features legacy-pqclean` | 101 unit, 1 trybuild suite, 38 doctests + 1 ignored | pass |

Release clippy is still Phase 5 hygiene. It should be run before publishing,
then either fixed or explicitly scoped to post-2.0 maintenance.

---

## Key Architecture Finding: Dual Trait Families

`Kyber<...>` carries **two parallel trait families**:

**(a) Legacy `KyberFunctions`**
- Returns `(Vec, Vec)` tuple.
- Used by old `encryption!` macros + `KyberTests`.
- Only compiled under `legacy-pqclean`.

**(b) New content-gated capability traits**
- Returns `Envelope`.
- Used by `Phase3Tests` + `api/`.

**The original problem:** `KyberFunctions` was implemented `impl<KyberSize, ContentStatus> KyberFunctions for Kyber<_, _, ContentStatus, C>` — generic over the content axis. Wherever it was in scope, it provided `encrypt_file`/`encrypt_msg`/`encrypt_data` on **every** content marker, defeating the new content enforcement.

**Current state:** Phase 4 removed `legacy-pqclean` from the default feature
set, so content enforcement now bites in the default and ML-only builds. The
legacy-only build intentionally preserves the old tuple API for v1.x data.

---

## Mess to Clean (Phase 5)

`KyberFunctions` is implemented **twice**:
- `src/legacy/kyber_crypto/*` — feature-gated (correct location).
- `src/core/kyber/*` — old carried-over, unconditional (wrong location).

The `src/core/kyber/*` copies must be moved fully into `src/legacy/`.

The immediate publish blocker is release hygiene, not the core implementation:
remove generated/cache artifacts from the Git index (`old/.cargo-home/**`,
`test.log`) and finish the release lint/docs pass.

---

## Environment Caveat

`/dev/sda1` is ~100% full **system-wide** (only ~2-3 GB is this project). `cargo clean` reclaims ~2.8 GB. Doctest/trybuild linking needs disk headroom or fails with `No space left on device` — this is an **environment error, not a code error** (occurred once this session, resolved by `cargo clean`).
