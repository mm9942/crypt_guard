# Continuation Guide (Resume Cold / via API)

---

## Working Directory

```
/srv/dev-shared/projects/rust/crypt_guard
```

**Branch:** `v2-redesign`

---

## Build & Test Commands

Permissions are already allowlisted in `.claude/settings.local.json` (`Bash(cargo:*)` etc.).

```bash
cargo check
cargo test
cargo clippy --lib
```

**Expected green release matrix:**

```bash
cargo fmt --check
cargo test
cargo test --no-default-features --features ml-kem-backend,ml-dsa-backend
cargo test --no-default-features --features legacy-pqclean
```

---

## Reference Project: crypt_guard 1.4.2

`old/` is the published 1.4.2 comparison project. Build it in isolation:

```bash
export CARGO_HOME=/srv/dev-shared/projects/rust/crypt_guard/old/.cargo-home
export CARGO_TARGET_DIR=/srv/dev-shared/projects/rust/crypt_guard/old/target
cargo build --manifest-path /srv/dev-shared/projects/rust/crypt_guard/old/Cargo.toml
```

Source tree (read-only reference):
```
old/.cargo-home/registry/src/index.crates.io-*/crypt_guard-1.4.2/
```

`old/` has its own `[workspace]` and is excluded from the parent workspace via `exclude = ["old"]` in the root `Cargo.toml`.

---

## Disk Caveat

```bash
df -h /
```

The volume is **~100% full system-wide**. If any build / doctest / trybuild fails with `No space left on device`, run:

```bash
cargo clean   # frees ~2.8 GB
```

This is an **environment error, not a code error.**

---

## Persistent Memory Files

```
/home/mm29942/.claude-auth/projects/-srv-dev-shared-projects-rust-sgh-flow-crypt-guard/memory/
  MEMORY.md            # index
  design-direction.md
  redesign-status.md
```

---

## Active Test Modules

Registered in `src/tests/mod.rs`:

- `ArchiveTests`
- `KyberKeyTests`
- `KyberTests`
- `SignatureTests`
- `MacroTests`
- `LegacyCleanupTests`
- `ze_end`
- `BuilderPatternTests`
- `Phase3Tests`

**Dormant (not in `mod.rs`, do not touch):** `src/tests/kyber_tests.rs` (lowercase) — still uses the old tuple API. Phase-5 cleanup candidate.

---

## Obsidian Assessment Vault

Original redesign plan (read-only reference):

```
/srv/dev-shared/projects/rust/sgh-flow/obsidian/mias-encrypt/
```

Notes: `00-index` through `10`, plus `20-recon/`.

---

## Next-Step Checklist

1. **Release hygiene** — remove generated/cache artifacts from the Git index
   before publishing. `old/.cargo-home/**` and `test.log` must not be part of a
   release commit.

2. **Version status** — the crate is now `2.0.0` after the external consumer
   project passed default, ML-only, and legacy-only tests.

3. **Release docs** — keep README, guides, crate docs, and Cargo metadata in
   agreement with the chosen version.

4. **Phase 5 hygiene** — `cargo clippy --fix`, remove dead code, raise docs to
   100%, move `src/core/kyber/*` → `src/legacy/`.
