# Audit — original crypt_guard 1.4.2 conventions (the design the maintainer likes)

A pristine copy of published **crypt_guard 1.4.2** lives at `crypt_guard/old/` (standalone
cargo project, own `[workspace]`, excluded from parent via `exclude = ["old"]`, local
CARGO_HOME + target). Source: `old/.cargo-home/registry/src/index.crates.io-*/crypt_guard-1.4.2/`.
Historical audit note: docs.rs/crates.io published 1.4.2 at the time of this
audit, which was the old design with 45% doc coverage. For current release
status, use `guides/release-readiness.md`.

The design is liked; it was just very unorganized. Concrete findings (evidence):

## ECB at the core (`core/cipher_aes.rs`)
- `encrypt_aes()` is textbook **ECB**: `Aes256::encrypt_block` per 16-byte chunk, no IV, no
  chaining, manual padding. This is the confidentiality bug.
- A correct `aes_cbc_encrypt/decrypt` ALSO exists but is (a) **Aes128** not Aes256, (b) feeds a
  32-byte key into a 16-byte cipher → would panic, (c) **dead code** — `encryption()` calls the
  ECB path, never the CBC one. The right thing was written but never wired.
- `fs::read(...).unwrap()` panics on IO error; commented-out `println!` debug everywhere.

## Result-pollution (`cryptography/cryptographic.rs`)
- EVERY accessor returns `Result<…, CryptError>` though it can never fail (`Ok(self.process)`,
  `Ok(&self.content)`, `Ok(self.safe)`…), forcing `?`-chains with no real error value.
- `content` field means plaintext OR ciphertext depending on phase (overloaded).
- Doc copy-paste errors ("Specifies AES" above `aes_gcm_siv()`/`aes_ctr()`, etc.).

## Hand-copied typestate boilerplate (`core/kyber/mod.rs`, ~720 lines)
- Every size/algo/content switch method spelled out by hand (~25× identical
  `Kyber { kyber_data, hmac_size, … PhantomData }` blocks).
- Switch methods return `Result` though they never fail.
- Switches implemented **asymmetrically** (only some algo combos) → typestate holes already in
  the original.

## Quantitative (library code, non-test)
- **385 panic paths**: 195 `unwrap()`, 190 `expect(`, 5 `unimplemented!`, 5 `panic!`, 1 `todo!`.
- Mixed tabs/spaces in 7 files.
- Misspellings: `KeyControKyber{512,768,1024}`, module `key_controler`.
- `src/core/kdf.rs` is NOT a KDF — it contains Falcon/Dilithium signature logic.
- Tests mostly happy-path; no wrong-key/tamper/malformed/compile-fail coverage.

## Module layering of the original
`builder.rs` (Option-accumulator builder), `core/` (cipher_aes/xchacha/etc. + `kyber/`
typestate hub + `key_controler`), `cryptography/` (`CryptographicInformation` + `CipherX` +
`hmac_sign`), `key_control/`, `utils/` (archive, zip), `macro/`, `log.rs`, `error.rs`.
The macros (`encryption!`/`decryption!`/`encrypt_file!`/`signature!`/`verify!`) are the
high-level layer the maintainer designed specifically so users set FAR fewer `use` statements —
that intent must be preserved.

## What the v2 branch already did right
It KEPT this design: the `Kyber<Process, Size, Content, Algorithm>` 4-axis struct, the macros,
the builder — moved to `src/core/hub/` — and replaced the hand-copied boilerplate with
`impl_size_switch!`/`impl_alg_switch!` macros. The `Sealer`/`Opener` in `src/api/` is only a
thin optional layer on top, not a replacement.
