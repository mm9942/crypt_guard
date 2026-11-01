---
id: DEC-101
title: New crates (keystore, kms, pyo3): layout, lint contract, error pattern, documentation language
status: proposed
date: 2026-11-01
tags: [decision, workspace, lints, errors, keystore, kms, pyo3]
related:
  - ../plans/crypt-guard-kms-contract.md
  - ../plans/crypt-guard-pyo3-contract.md
---

# DEC-101: New crates: layout, lint contract, error pattern, documentation language

## Context

- crypt_guard is a workspace of `crypt_guard` (facade), `crypt_guard_core`,
  `crypt_guard_proc`, `crypt_guard_service`, `crypt_guard_hyper`
  (`Cargo.toml` `[workspace] members`). Lints are set per crate
  (`#![forbid(unsafe_code)]`, `deny(clippy::unwrap_used, clippy::expect_used)`
  outside tests, `warn(missing_docs)`; `crates/service/src/lib.rs`), and
  the panic-freedom contract is prose in `SECURITY.md`.
- comnet and Harwness, the two consumers that will embed the new crates,
  enforce a stricter contract through workspace lints and `clippy.toml`
  (comnet `Cargo.toml:24-38`): no `unwrap`/`expect`/`panic`/`todo`/
  `unreachable`, no indexing, no unchecked arithmetic, no `print*`, no
  `dbg!`, `unsafe_code = forbid`, hand-written error enums per crate,
  `tracing` only.
- The new crates `crypt_guard_keystore`, `crypt_guard_kms` and
  `crypt_guard_pyo3` touch OS APIs, files, sockets and an interpreter: the
  places where a stray `unwrap` or `[i]` becomes a crash in a daemon.
- `.gitignore` excludes every `*.md` except `README.md`, `CHANGELOG.md`
  and `SECURITY.md`, so plan and decision documents could not be tracked.

## Decision

1. **Layout.** New crates live under `crates/<short>` with the package
   name `crypt_guard_<short>`: `crates/keystore`, `crates/kms`,
   `crates/pyo3`. The binary of `crypt_guard_kms` is `crypt-guard-kms`.
   All three are workspace members; `crypt_guard_pyo3` is `release = false`
   for `cargo release` (wheels are its artefact), the other two are
   released in lockstep.
2. **Lint contract for the new crates** (and, opt-in, for the existing
   ones later): `[workspace.lints]` with the comnet set, `[lints]
   workspace = true` in each new crate, `clippy.toml` with
   `allow-unwrap-in-tests = false`, `allow-expect-in-tests = false`,
   `allow-panic-in-tests = false`, `allow-indexing-slicing-in-tests = false`.
   Existing crates keep their per-crate attributes until they are migrated
   crate by crate (each migration is its own PR, no behaviour change).
3. **Errors.** One hand-written `#[non_exhaustive]` enum per crate in
   `src/error.rs` with `Display` (lower-case, English, no secrets), `Debug`
   delegating to `Display`, `std::error::Error::source`, one `From` per
   foreign error, `pub type Result<T>`. No `anyhow`, no `thiserror`, no
   `Box<dyn Error>` in public returns. `NotImplemented { feature }` replaces
   `todo!`. Service-facing enums map to `crypt_guard_service::CryptoServiceError`
   through an explicit `impl From`.
4. **Tests** return `Result<(), TestError>` where `TestError` is a small
   per-crate enum (pattern of comnet's `define_test_error!`), so tests obey
   the same lints as production code.
5. **Logging.** `tracing` with structured fields only; libraries never
   install a subscriber; the binary installs it in `main` behind `--log`.
   Never logged: seeds, KEKs, plaintexts, tokens, client certificate
   bodies; key references are logged as `namespace/id@version` (not
   secret), peer identities as `uid`/`unit` (not secret).
6. **Documentation language.** Code documentation and `docs/` in
   crypt_guard are English (public crates.io project); the chat with the
   maintainer may be German. `docs/plans/*-contract.md` follow the
   Harwness "Contract-Draft" shape (status, findings with evidence,
   specification, open points, tests); `docs/decisions/DEC-*.md` follow
   this file's YAML header and section order. `.gitignore` gets
   `!docs/**/*.md`.
7. **Dependencies** are added with `cargo add -p <crate>` and the current
   API is read from docs.rs or the registry source, never from memory. Exact
   pins only with a comment in the manifest and a DEC (`arti-client =0.47.0`
   inherits comnet DEC-004).

## Why

- The two embedding projects already run under this contract; a looser
  crypt_guard would be the weakest link in their dependency trees and
  would have to be wrapped again (Harwness copied `crypt_guard_service::memory`
  for exactly this kind of mismatch, `harw-auth-hub/src/sealed/mod.rs:12-20`).
- Workspace lints are mechanical and reviewable; prose rules in
  `SECURITY.md` are not enforced by CI.
- One error enum per crate keeps `ErrorKind` mapping (for the facade and
  the Python exception hierarchy) explicit and total.
- English docs keep crates.io users and the three repositories' reviewers
  on the same text.

## Consequences

- `Cargo.toml` gains `[workspace.lints.rust]` / `[workspace.lints.clippy]`
  and `clippy.toml`; CI's `clippy` job needs no change (it already runs
  `-D warnings` on all targets and features).
- `scripts/check_dep_gates.sh` is extended for the new crates (plan §3.1).
- Migrating the existing crates to the workspace lints is follow-up work
  with its own DECs where a rule cannot be met (for example `OsRng`'s
  infallible `rand_core` error path noted in `SECURITY.md`).
- Open: whether `warn(missing_docs)` becomes `deny` workspace-wide; and
  whether the facade `crypt_guard` should re-export `crypt_guard_keystore`
  under a `keystore` feature (plan §3.1 says yes).
