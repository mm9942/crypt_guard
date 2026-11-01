# Contract draft: `crypt_guard_keystore` + `crypt_guard_kms`

**Status:** draft, not yet approved. Nothing in this document is implemented.
**Owner:** crypt_guard workspace. **Related:** `crypt-guard-pyo3-contract.md`
(§5 KMS client), `DEC-101` (new crate layout and lints), comnet
`docs/plans/crate-api-contract.md` §16/§18, comnet DEC-006/022/023/028,
Harwness `harw-auth-hub`, `harw-secrets`.

Writing convention: this follows the Harwness "Contract-Draft" shape:
status, findings with evidence (`path:line`), specification, open points,
tests. Evidence paths are relative to the three checkouts `crypt_guard/`,
`comnet/`, `Harwness/`.

## 1. Goal

A key-management service that is **the comnet-kms/-vault design as a
stand-alone crate and installable binary**, built only from crypt_guard:

- `crypt_guard_keystore` (library): *where the KEK comes from*. One
  `KekProvider` trait, OS-native backends for Linux, macOS and Windows,
  file/systemd-credential/env/passphrase backends, and user-supplied
  providers. Usable on its own (comnet-vault, Harwness) without the KMS.
- `crypt_guard_kms` (library + binary `crypt-guard-kms`): *what is kept and
  served*. A self-encrypted container holding seeds for every algorithm the
  facade offers, a provider implementing `crypt_guard_service::CryptoProvider`,
  the HTTP API (existing `crypt_guard_hyper` routes), a streamable-HTTP MCP
  endpoint, mTLS, UNIX-socket peer identification (uid/gid + cgroup v2 unit),
  a public-key directory, and optional publication over Tor (arti) or the
  local network.

Private keys never leave the process; clients get public keys, ciphertexts,
signatures, plaintexts under policy, and never seeds or KEKs.

## 2. Findings (evidence)

### 2.1 Containers already in use

| # | Fact | Evidence |
|---|---|---|
| F1 | comnet-vault seals one whole file: header `"CNVS" ‖ ver u8 ‖ generation u64 BE`, XChaCha20-Poly1305 body, AAD `"comnet/vault/v1" ‖ lp32(partition) ‖ generation`, KEK used directly as AEAD key. | `comnet/crates/comnet-vault/src/sealed_file.rs:55-67`, `:183-197`; `file_sealer.rs:139-147` |
| F2 | comnet-vault has a rollback guard: a separate `"CNVG"` generation file; open refuses an older file generation and heals a newer one. | `comnet-vault/src/generation.rs:11-20`; `sealed_file.rs:107-128` |
| F3 | comnet writes atomically with `O_CREAT|O_EXCL|O_NOFOLLOW` 0600 temp, fsync, inode re-check, `renameat`, directory fsync. | `comnet/crates/comnet-hardening/src/fs.rs:587-667` |
| F4 | harw-auth-hub is already a crypt_guard KMS daemon over `AF_UNIX`: `"HAKS"` header, BLAKE3-derived file key, body of per-version 32-byte seeds or tombstones, exclusive flock, **no** rollback guard and **no** KEK rotation. | `Harwness/harw-auth-hub/src/lib.rs:1-27`, `sealed/format.rs:179-224`, `sealed/mod.rs:39-53, 96, 224-226`, `store.rs:541-562` |
| F5 | harw-auth-hub had to copy `crypt_guard_service::memory` byte-for-byte because the module is private. | `Harwness/harw-auth-hub/src/sealed/mod.rs:12-20` |
| F6 | harw-auth-hub adds compare-and-set rotation, `Conflict` on stale version and idempotent generate on top of the service crate. | `Harwness/harw-auth-hub/src/guard.rs:1-40` |
| F7 | harw-secrets wraps per-secret DEKs with PQ-HPKE under a KEK-derived recipient key and re-seals every DEK on `rotate` with staged directory promotion. | `Harwness/harw-secrets/src/envelope.rs:1-13`, `kek.rs:327-338`, `store.rs:605-693` |

### 2.2 KEK provenance

| # | Fact | Evidence |
|---|---|---|
| F8 | comnet-vault KEK order: explicit path → `$CREDENTIALS_DIRECTORY/vault-kek` → `<state_dir>/<name>.kek` (created with a warning). 32 raw bytes or 64 hex, all-zero rejected, file must be regular, non-symlink, euid-owned, `mode & 0o077 == 0`. | `comnet-vault/src/config.rs:358-369`, `file_sealer.rs:95-137`, `comnet-hardening/src/fs.rs:127-130` |
| F9 | comnet-vault TPM2 is a stub (`NotImplemented`), deferred to its own DEC. | `comnet-vault/src/epoch_keys.rs:513-547`; DEC-022 §9 |
| F10 | comnet passphrase presence: Argon2id m=64 MiB, t=3, p=1; wrapped form `0x01 ‖ m ‖ t ‖ p ‖ salt[16] ‖ nonce ‖ ct` with header as AAD. | `comnet-vault/src/presence.rs:11-19, 104-128, 232-250` |
| F11 | harw-secrets `KekProvenance::{KeyFile, OsKeyring{service,account}, EnvSeed{var}}`, selected by config, never auto-detected; keyring 3.6.3 with `apple-native, windows-native, sync-secret-service, crypto-rust`; all keyring errors collapse to `KekUnavailable`. | `Harwness/harw-secrets/src/kek.rs:42-49, 166-193`; `harw-secrets/Cargo.toml:26,39` |
| F12 | harw-secrets checks file mode but not ownership; harw-auth-hub checks both (`ensure_private_regular`). | `harw-secrets/src/kek.rs:58-92`; `Harwness/harw-fsutil/src/perm.rs:30-55` |
| F13 | systemd units deliver the KEK with `LoadCredentialEncrypted=` and copy it into a 0700 `RuntimeDirectory` because the reader demands owner = service user. | `comnet/deploy/systemd/comnet-vaultd.service:26-38` |

### 2.3 Peer identification, hardening, systemd

| # | Fact | Evidence |
|---|---|---|
| F14 | comnet reads `SO_PEERCRED` (`uid, gid, pid`) at accept and fails closed; vaultd maps each uid to exactly one partition, unknown uids get one `PartitionDenied` and are closed. | `comnet-transport/src/local.rs:196-203`; `comnet-vault/src/server.rs:84-118, 210-217` |
| F15 | comnet-kms admits `apicon_uid` on `edge.sock` and `internal_uids` on `internal.sock`. | `comnet-kms/src/endpoints.rs:66-80`, `config.rs:161-165` |
| F16 | harw-auth-hub: `PeerCred` as request extension; uid → principal, else constant-time bearer, never anonymous. | `Harwness/harw-auth-hub/src/server.rs:209-240`, `auth.rs:66-80` |
| F17 | Neither repo reads `/proc/<pid>/cgroup` for peer identification. cgroup v2 appears only as a job-limit backend. | `Harwness/harw-job-linux/src/cgroup.rs:1-22` |
| F18 | comnet-hardening: `PR_SET_NO_NEW_PRIVS`, non-dumpable, `RLIMIT_CORE=0`, `mlockall`, Landlock; `sd-notify` readiness; unit template credited to `harw-auth-hub.service`. | `comnet-hardening/src/linux.rs:5-15`; `deploy/systemd/comnet-vaultd.service:48-88` |

### 2.4 MCP and TLS

| # | Fact | Evidence |
|---|---|---|
| F19 | comnet-mcp is an own implementation on hyper 1 (DEC-006): revisions 2025-06-18 (stateful) and 2026-07-28 (stateless), `/mcp`, 4 MiB body limit, Origin allowlist only when present, no CORS, own SSE encoder, sessions `mcp-` + 32 hex bound to the principal; authentication is done by the listener owner, not the library. | `comnet-mcp/src/lib.rs:6-18`, `http.rs:4-34, 110-147`, `session.rs:1-24`, `origin.rs:1-18`, `server.rs:299-312` |
| F20 | harw-mcp-server: same hyper pattern, loopback only, 64 KiB bodies, 2025-06-18 only, `McpAuthenticator` trait. | `Harwness/harw-mcp-server/src/transport.rs:17-38, 189-192`, `auth.rs` |
| F21 | comnet TLS: rustls 0.23 + aws-lc-rs, TLS 1.3 only, `X25519MLKEM768` only, resumption off, negotiated group asserted after the handshake, `WebPkiClientVerifier` for mTLS, 10 s handshake timeout. | `comnet-transport/src/tls.rs:82-136, 296-300, 386-456`; DEC-002, DEC-009 |
| F22 | comnet arti: `arti-client =0.47.0` with explicit features, never `full`; one onion service per nickname; stream isolation per principal × domain; process-default provider installed before bootstrap. | `comnet-transport/src/arti.rs:1-30`; DEC-004 |
| F23 | crypt_guard_hyper has routes `POST /v1/keys`, `/v1/keys/{ns}/{id}[@v][/public|:{op}]`, CGK1 codec, `Authenticator` trait with constant-time `BearerTokens`, 403→404 hiding. | `crypt_guard/crates/hyper/src/route.rs:1-13`, `auth.rs:16-45`, `error.rs:21-35` |
| F24 | crypt_guard_service: `CryptoOperation` (14 variants + PR `DescribeLifecycle`), `CryptoProvider::execute`, `KeyAlgorithm::{Hpke{suite}, Signature(MlDsa44|65|87)}`, deny-by-default `NamespacePolicy` with `OpSet` presets. | `crypt_guard/crates/service/src/op.rs:203-302`, `provider.rs:19-32`, `key.rs:142-167`, `policy.rs:88-235` |

## 3. Specification

### 3.1 Crates and dependencies

```
crates/keystore   crypt_guard_keystore   lib
crates/kms        crypt_guard_kms        lib + bin crypt-guard-kms
```

Both are workspace members, released in lockstep with the other crates
(`cargo release`). The facade gains features `keystore` and `kms-client`
(client types only, see §3.9); the server never enters the facade. Both
crates adopt the comnet workspace lint set and the hand-written error enum
pattern (DEC-101), and `#![forbid(unsafe_code)]` except where an OS API
requires FFI, which is isolated in one `sys` module per backend with a
`// SAFETY:` justification and its own fuzz/unit tests.

Dependency gates (extension of `scripts/check_dep_gates.sh`): the default
facade still pulls none of `tokio|hyper|rustls|arti|keyring|windows|
security-framework|zbus|tss-esapi`; `crypt_guard_keystore` with default
features pulls none of the OS crates (they sit behind per-OS features).
Transitively banned: `axum`, `actix-web`, `warp`, `rocket`, `reqwest`,
`openssl*`, `native-tls`, `boring*`, `ring` (aws-lc-rs is the only rustls
provider). Direct bans: `anyhow`, `thiserror`, `log`, `env_logger`.

### 3.2 `crypt_guard_keystore`

```rust
/// A 32-byte root secret, zeroized on drop, never Clone, redacted Debug.
pub struct KekSeed(Zeroizing<[u8; 32]>);

/// Identifies which KEK sealed a container (not secret).
pub struct KekId([u8; 16]);   // = SHAKE256("crypt_guard/keystore/kek-id/v1", seed)[..16]

pub trait KekProvider: Send + Sync + 'static {
    /// Stable backend name for logs, config and audit ("key-file", "systemd-credential", …).
    fn backend(&self) -> &'static str;
    /// Load the seed. Fails closed; never creates material unless `create` was requested.
    fn load(&self) -> Result<KekSeed>;
    /// Create a fresh seed in this backend; `Err(Exists)` if one is already there.
    fn create(&self) -> Result<KekSeed>;
    /// Replace the stored seed (used by `kek rotate` after the container was re-sealed).
    fn store(&self, seed: &KekSeed) -> Result<()>;
    /// Destroy the stored seed (crypto-shredding of everything sealed under it).
    fn destroy(&self) -> Result<()>;
    /// What this backend protects against (used by `crypt-guard-kms doctor` and docs).
    fn protection(&self) -> Protection;
}
```

`Protection` is a bitset: `AtRestOnDisk`, `BoundToUser`, `BoundToMachine`,
`BoundToHardware`, `RequiresPresence`, `SurvivesReboot`.

Backends, each behind a feature and selected **only** by configuration
(`[kek] provider = "…"`, F11):

| `provider` | Platform | Implementation | Protection | Crate |
|---|---|---|---|---|
| `key-file` | all | 32 raw bytes or 64 hex (F8); open `O_NOFOLLOW`, regular file, euid-owned, `mode & 0o077 == 0` (F12, both checks); create-new 0600 never overwrites. | AtRest, SurvivesReboot | `rustix` (Linux/macOS), `windows` ACL check (Windows) |
| `systemd-credential` | Linux | `$CREDENTIALS_DIRECTORY/<name>`; name validated against `/`, NUL, `.`, `..`. Recommended: `LoadCredentialEncrypted=` (systemd-creds, TPM2-bound). The copy-to-RuntimeDirectory dance of F13 is avoided: the reader accepts root-owned 0400 files when the directory is `$CREDENTIALS_DIRECTORY`. | AtRest, BoundToMachine(+Hardware via systemd-creds), SurvivesReboot | std |
| `env-seed` | all | 64 hex characters in `$<VAR>` (hex, not raw UTF-8 as in F11, so the value survives shells). CI/headless only; `doctor` warns. | — | std |
| `passphrase` | all | Argon2id with comnet's parameters and wrapped form (F10) around a key-file; prompt via `PresencePrompt` trait (TTY, or a UNIX-socket prompt channel for daemons). | RequiresPresence | `argon2` |
| `os-keyring` | Linux desktop, macOS, Windows | `keyring` 4.x: Secret Service (D-Bus), macOS Keychain (data-protection keychain, `apple-native`), Windows Credential Manager (`windows-native`). Entry `service = "crypt_guard_kms"`, `account = <partition>`; value hex. Error source is **kept** (`KeystoreError::OsKeyring { op, source }`), unlike F11. | BoundToUser, SurvivesReboot | `keyring` (features `apple-native, windows-native, sync-secret-service, crypto-rust`) |
| `linux-kernel-keyring` | Linux | `linux-keyutils`: key type `user`, description `crypt_guard_kms:<partition>`, in the **persistent keyring of the service uid** (`keyctl_get_persistent`), permissions `possessor+uid: read/search`, others none. Material lives in kernel memory, never on disk; must be re-provisioned after reboot unless combined with `systemd-credential`. | BoundToUser, BoundToMachine | `linux-keyutils` |
| `windows-dpapi` | Windows | `CryptProtectData`/`CryptUnprotectData` (`windows` crate, `Win32_Security_Cryptography`), scope `user` or `machine`, optional entropy = partition name; blob stored in `%ProgramData%\crypt_guard_kms\<partition>.kek`. | BoundToUser or BoundToMachine, SurvivesReboot | `windows` |
| `macos-keychain` | macOS | alias of `os-keyring` with `apple-native`; a `data-protection` flag selects the DP keychain (`kSecUseDataProtectionKeychain`) so the entry is per-user and backed by the SEP-derived class keys. | BoundToUser, SurvivesReboot | `keyring` / `security-framework` |
| `tpm2` | Linux (later Windows) | Sealed object under the SRK with an optional PCR policy, via `tss-esapi`. **Stub returning `NotImplemented` in wave 1**, like comnet (F9); real backend needs its own DEC (C build of tss2, pinned alpha vs 7.x). | BoundToHardware, SurvivesReboot | `tss-esapi` (feature) |
| `custom` | all | `Arc<dyn KekProvider>` registered by the embedding program; config names it (`provider = "custom:<name>"`). | declared by the implementor | — |

Composition: `split-kek` combines two providers (`primary` + `secondary`,
e.g. `systemd-credential` + `passphrase`) with
`seed = SHAKE256("crypt_guard/keystore/split/v1" ‖ lp32(a) ‖ lp32(b))`; both
must load. Backup of a KEK is Shamir (`crypt_guard::sharing::split`,
threshold ≥ 2) and lives in `crypt-guard-kms kek backup --shares N --threshold K`.

Domain separation: a provider yields a **root seed**; every use derives a
purpose key, `prf32(root, "crypt_guard/keystore/<purpose>/v1", context)`,
so the same backend entry can protect a container and sign nothing else.

### 3.3 Container `CGKS` (crypt_guard key store)

Whole-file sealed store, mirroring F1/F2/F4 and fixing F4's gaps:

```
file     = header ‖ body
header   = "CGKS" ‖ version u8 = 1 ‖ generation u64 BE ‖ kek_id[16] ‖ aead_id u8 ‖ nonce[24]
body     = AEAD(key = prf32(kek_root, "crypt_guard/keystore/container/v1", kek_id ‖ lp32(partition)),
                nonce, aad = header ‖ lp32(partition), plaintext = wire(StoreState))
aead_id  = 1: XChaCha20-Poly1305 (default), 2: AES-256-GCM-SIV
```

- `StoreState` is a `WireSafe` lp32 structure (same encoding family as the
  CGK1/CGKC frames of `crypt_guard_hyper::codec`): format version, partition
  name, `Vec<KeyRecord>`, audit head hash.
- `KeyRecord { namespace, id, version, algorithm, state, lifecycle,
  created_by, material }` with `material = Seed([u8;32]) | Tombstone`.
  **Only seeds are stored.** Private keys are derived on open
  (`derive_recipient_key_pair`, `MlDsa*Impl::keypair_from_seed`, SLH-DSA
  from seed) and kept in `Zeroizing` memory; `Destroy` overwrites the seed
  with a tombstone and the next write persists it (crypto-shredding at the
  record level, like harw-auth-hub).
- **Rollback guard** (F2): `<state_dir>/_generation/<partition>.generation`
  = `"CGKG" ‖ 1 ‖ u64`. Open refuses `file.generation < guard.generation`
  (`Rollback { file, guard }`), heals `file > guard`. The guard is written
  **after** the file rename and fsync, so a crash between the two leaves a
  healable, never a refusing, state. TPM NV counters are an open point.
- **Atomic write** exactly as F3 (temp with `O_EXCL|O_NOFOLLOW` 0600,
  fsync, inode re-check, `renameat`, dir fsync). Windows: `ReplaceFileW`
  after `FlushFileBuffers`.
- **Single writer:** exclusive advisory lock on `<file>.lock` for the
  process lifetime (`Locked` error otherwise).
- **KEK rotation:** `kek rotate` = load old + new seed, re-seal the body
  under the new key with `generation + 1` and the new `kek_id`, write
  atomically, then `provider.store(new)`, then `old.destroy()` only if the
  provider is distinct; a crash between steps is recoverable because the
  header names the KEK that sealed it (`kek_id` lookup over the configured
  providers' ids). Daily re-seal as in comnet epoch keys is **not** part of
  the KMS (keys are long-lived; comnet's slot seeds are not).
- **Partitions:** one container + one KEK provider per partition
  (`[[partition]] name, state_dir, kek, peers, grants`), so tenant A's
  seeds are never under tenant B's KEK (F14's one-uid-one-partition rule,
  generalized to principals).

### 3.4 Provider and algorithm surface

`crypt_guard_kms::SealedProvider` implements
`crypt_guard_service::CryptoProvider` over a `CGKS` partition. To avoid
F5, `crypt_guard_service` gets an additive, semver-compatible change:

```rust
// crypt_guard_service, new:
pub trait SeedStore: Send + 'static {
    fn get(&self, key: &KeyRef) -> Result<Option<KeyRecordView<'_>>>;
    fn put(&mut self, rec: KeyRecord) -> Result<()>;        // compare-and-set on version (F6)
    fn list(&self, ns: &KeyNamespace) -> Result<Vec<KeyMetadata>>;
    fn commit(&mut self) -> Result<()>;                     // no-op in memory, atomic write in CGKS
}
pub struct SeedProvider<S: SeedStore> { … }               // the existing memory logic, generic
pub type InMemoryProvider = SeedProvider<MemoryStore>;     // unchanged public name and behaviour
```

Algorithms exposed through `KeyAlgorithm` (additive variants, enum stays
`#[non_exhaustive]`):

| Family | `KeyAlgorithm` | Operations |
|---|---|---|
| PQ HPKE (all `pq_hpke::Suite`s: ML-KEM-512/768/1024, hybrids P-256/P-384/X25519, AEAD ChaCha20/AES-GCM/XChaCha/AES-GCM-SIV) | `Hpke { suite }` (exists) | Encrypt/Decrypt (envelope `CGH3`), WrapKey/UnwrapKey/RewrapKey, PublicKey, `SealMulti` (new: `pq_multi::seal_multi` to a recipient set of KMS public keys and/or external public keys) |
| ML-DSA 44/65/87 | `Signature(MlDsa*)` (exists) | Sign/Verify with FIPS 204 context (`sign_with_context`), PublicKey, fingerprint |
| SLH-DSA (feature `sign-slhdsa`) | `Signature(SlhDsa*)` (new) | Sign/Verify, PublicKey |
| Symmetric data key | `Symmetric { aead }` (new) | Encrypt/Decrypt (nonce prefixed, AAD bound to `KeyRef`), `StreamEncrypt`/`StreamDecrypt` (new, `pq_stream`, chunked bodies for files), `DeriveKey` (new, `prf32` with label and context, output never exported unless the grant has `SECRET_EGRESS`) |
| Signed HPKE | composite of an `Hpke` and a `Signature` key | `SealSigned`/`OpenSigned` (new, `signed_hpke`) |

Every new operation gets an `OpKind` bit, a place in the `OpSet` presets
(`SECRET_EGRESS` covers Decrypt, UnwrapKey, StreamDecrypt, DeriveKey export,
OpenSigned) and a CGK1 wire form; `is_secret_egress` stays the single
source of truth for what the policy treats as plaintext return.

### 3.5 Identities and authorization

```rust
pub enum Principal {                       // crypt_guard_service::Principal stays a string;
    // the KMS *derives* it from one of:
    PeerUid { uid: u32 },                  // "uid:1001"
    PeerCgroup { unit: String },           // "unit:myapp.service"
    MtlsSan { uri: String },               // "urn:crypt-guard:principal:billing"
    MtlsSpki { sha256: [u8; 32] },         // "spki:<hex>"
    Token { subject: String },             // "token:<subject>"
}
```

**UNIX socket (Linux):** at accept, `SO_PEERCRED` → `uid, gid, pid` (fail
closed, F14). Then, if the partition has any `unit`/`cgroup_prefix` rule:

1. `SO_PEERPIDFD` (Linux ≥ 6.5) → `pidfd`. Without it, cgroup rules are
   refused at config load (`Config { reason: "cgroup rules need SO_PEERPIDFD"
   }`) unless `peer.allow_pid_reuse_risk = true`.
2. Read `/proc/<pid>/cgroup` (cgroup v2 has exactly one line `0::<path>`;
   v1 or hybrid → `Unsupported`), parse the `.service`/`.scope` unit name
   out of the path (`/system.slice/myapp.service`,
   `/user.slice/user-1000.slice/user@1000.service/app.slice/x.service`).
3. Re-validate: `pidfd_send_signal(pidfd, 0)` succeeds and
   `/proc/<pid>/cgroup` re-read is identical → the identity is bound to a
   live process that has not been replaced. Any failure → `Unauthenticated`.
4. Optional D-Bus confirmation `org.freedesktop.systemd1.Manager.GetUnitByPID`
   is **not** used (no zbus in the daemon; the cgroup path is authoritative
   because only systemd/root can move processes between unit cgroups).

Policy matchers in config: `uid = 1001`, `gid = 950`, `unit =
"myapp.service"`, `cgroup_prefix = "/user.slice/user-1000.slice/"`. A rule
may require both (`uid` *and* `unit`). This answers the "cgroup v2 + Linux
user" question: yes, with the pidfd re-check it is race-free, and the KEK
itself is never handed out — identity only selects a partition and a grant
set, exactly like vaultd's uid → partition.

**macOS / Windows local sockets:** `LOCAL_PEERCRED`/`getpeereid` (macOS) and
`SIO_AF_UNIX_GETPEERPID` + `OpenProcess`/`GetTokenInformation` (Windows)
give uid/SID → `PeerUid`-equivalent principals. No cgroup analogue; the
`unit` matcher is Linux-only and rejected elsewhere at config load.

**mTLS:** rustls 0.23 + aws-lc-rs, TLS 1.3, `X25519MLKEM768` only,
resumption off, negotiated group asserted (F21). Client verifier:
`WebPkiClientVerifier` against the configured CA bundle; the principal is
the single `urn:crypt-guard:principal:<name>` URI SAN, else the SPKI
SHA-256 if listed in `[[peer.spki]]`; a certificate with neither is
`Unauthenticated`. Client certificates are classical P-256/P-384 (no PQ
WebPKI yet, same as comnet DEC-002); a revocation list by SPKI hash is
reloaded on SIGHUP. `crypt-guard-kms ca init|issue` provides a local CA
(`rcgen` with `aws_lc_rs`) for home-network deployments.

**Bearer tokens** (loopback only, same construction as comnet-agentd):
`b64url(wire(claims)).b64url(HMAC-SHA256(secret, "crypt_guard/kms/token/v1" ‖ claims))`
with audience `https://<host>:<port>/`, TTL ≤ 24 h, constant-time verify.

Authorization is `crypt_guard_service::NamespacePolicy` (deny by default,
F24) fed from `[[partition.grant]] principal, namespace, ops = ["encrypt",
"sign", …]`; `PolicyProvider` wraps `SealedProvider`. `decrypt`-class
operations additionally require `egress = true` on the grant.

### 3.6 HTTP API

`crypt_guard_hyper` as it is (F23), served on:

- `unix:` listener (`/run/crypt-guard-kms/<partition>.sock`, mode 0660, or
  systemd socket activation via `LISTEN_FDS`);
- `tls:` listener (`0.0.0.0:8443`, mTLS mandatory);
- `loopback:` listener (`127.0.0.1:8440`, tokens).

Additions to the route table (hyper crate, additive):

| Route | Purpose |
|---|---|
| `GET /v1/keys/{ns}` | list key metadata of a namespace (needs `describe`) |
| `GET /v1/keys/{ns}/{id}@{v}/lifecycle` | PR #24's `DescribeLifecycle` |
| `POST /v1/keys/{ns}/{id}:seal-multi`, `:stream-encrypt`, `:stream-decrypt`, `:derive` | §3.4 operations |
| `GET /v1/public/{ns}` | **public-key directory**: `SignedPublicBundle` = `wire(entries) ‖ ML-DSA-87 signature` by the partition's directory key, with `issued_at`, `expires_at`, `generation`; anonymous when the partition sets `public_directory = true` |
| `GET /healthz` | readiness (internal listener only) |

Bodies stay CGK1 frames; JSON exists only at the MCP boundary (F19).

### 3.7 MCP (streamable HTTP)

Own implementation on hyper, following comnet-mcp and harw-mcp-server
(F19/F20): path `/mcp` on every listener, both revisions 2025-06-18
(stateful, SSE) and 2026-07-28 (stateless), 4 MiB bodies, Origin allowlist
only when present, no CORS, sessions bound to the principal, no batches,
`id != null`. The listener authenticates (uid/cgroup, mTLS, token) and
passes the principal string in; the library never authenticates (F19).

Tools (names stable, inputs JSON Schema, outputs base64 bytes):
`kms.list_keys`, `kms.describe_key`, `kms.public_key`, `kms.generate_key`,
`kms.rotate_key`, `kms.encrypt`, `kms.decrypt`, `kms.sign`, `kms.verify`,
`kms.wrap_key`, `kms.unwrap_key`, `kms.seal_multi`, `kms.derive_key`.
Resources: `kms://{ns}` (directory), `kms://{ns}/{id}/public`,
`kms://{ns}/{id}/lifecycle`; `resources/subscribe` on the directory emits a
notification on rotation. Every tool result carries
`untrusted_content: false` and the `principal` it ran as; `kms.decrypt`
output is flagged `secret_egress: true` so agent frameworks can redact
logs. Tool calls map 1:1 to `CryptoOperation`, so MCP and HTTP share the
policy and audit path.

Open question for the comnet chat: extract comnet-mcp's protocol core
(its only comnet dependencies are `comnet-observe` and
`comnet_proto::BoxFuture`) into a shared crate instead of a second copy.

### 3.8 Tor and local network

- Feature `arti`: `arti-client =0.47.0` with explicit features and the
  comnet pin set (F22, DEC-004). The KMS publishes **one onion service per
  partition** carrying the mTLS listener (the onion gives reachability and
  transport privacy; mTLS still authenticates). The public-key directory
  may additionally be served **without** client certificates on the onion
  (`public_directory_onion = true`), which is the "share my public keys over
  Tor" case. Process-default rustls provider installed before bootstrap,
  stream isolation per principal × destination for outbound (client mode,
  §3.9).
- Without Tor the TLS listener binds a LAN address; `crypt-guard-kms
  doctor` warns if the bind address is not RFC 1918/ULA and mTLS is not
  mandatory. No mDNS/UPnP in wave 1 (open point).

### 3.9 Client library and CLI

`crypt_guard_kms::client` (feature `client`, also re-exported as facade
feature `kms-client`): `unix(path)`, `mtls(url, cert, key, ca)`,
`token(url, token)`, optional `via_tor(onion)`; methods mirror
`CryptoOperation`; the Python bindings wrap this (pyo3 contract §5).

Binary `crypt-guard-kms`:

```
crypt-guard-kms init     --config <toml>            # create partitions, KEK material, directory key
crypt-guard-kms serve    --config <toml> --log <LEVEL> [--log-format text|json]
crypt-guard-kms doctor   --config <toml>            # permissions, provider availability, protection report
crypt-guard-kms kek      rotate|backup|restore      # §3.3
crypt-guard-kms key      generate|list|describe|rotate|disable|enable|destroy|public
crypt-guard-kms ca       init|issue|revoke          # local mTLS CA
crypt-guard-kms token    issue --subject … --ttl …  # loopback tokens
crypt-guard-kms export   public --signed            # SignedPublicBundle to stdout
```

`main` returns `ExitCode`; tracing subscriber only here; `--log` on every
subcommand; no `println!` (CLI output goes through a `Write` sink).

### 3.10 Hardening, deployment, audit

- Linux start-up order as comnet-vaultd: tracing → rustls provider →
  config → hardening (`no_new_privs`, non-dumpable, `RLIMIT_CORE=0`,
  `mlockall`, Landlock allowing only state dir, socket dir, credentials
  dir) → runtime → partitions (open + rollback check) → listeners →
  `sd_notify(READY=1)`, `WATCHDOG` every 15 s.
- `deploy/systemd/crypt-guard-kms.service` + `.socket`, `sysusers.d`,
  `tmpfiles.d` copied from comnet DEC-028 patterns (`LoadCredentialEncrypted=kek-<partition>`,
  `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`, `PrivateNetwork=no`
  only when a TLS/onion listener is configured). launchd plist and a
  Windows service wrapper (`windows-service` crate) are documented, not
  shipped, in wave 1.
- Audit: append-only, hash-chained event log per partition
  (`audit.cgal`, `prev_hash ‖ event`), ML-DSA-65 checkpoints every N events
  (harw-secrets design); the event is written **before** the operation
  takes effect; the current head hash is stored in `StoreState` so the log
  and the container cannot be rolled back independently. Logged fields:
  principal, op, `KeyRef`, outcome, never payloads.

## 4. Dependencies (exact `cargo add` lines for the orchestrator)

```
# keystore
cargo add -p crypt_guard_keystore crypt_guard_core --path crates/core
cargo add -p crypt_guard_keystore zeroize --features derive
cargo add -p crypt_guard_keystore rustix --features fs,process
cargo add -p crypt_guard_keystore argon2 --optional
cargo add -p crypt_guard_keystore keyring --optional --no-default-features --features apple-native,windows-native,sync-secret-service,crypto-rust
cargo add -p crypt_guard_keystore linux-keyutils --optional --target 'cfg(target_os = "linux")'
cargo add -p crypt_guard_keystore windows --optional --features Win32_Security_Cryptography,Win32_Foundation --target 'cfg(windows)'
cargo add -p crypt_guard_keystore tss-esapi --optional --target 'cfg(target_os = "linux")'   # stub only in wave 1
# kms
cargo add -p crypt_guard_kms crypt_guard_service --path crates/service --features buffer,ml-dsa
cargo add -p crypt_guard_kms crypt_guard_hyper --path crates/hyper
cargo add -p crypt_guard_kms crypt_guard_keystore --path crates/keystore
cargo add -p crypt_guard_kms tokio --features rt-multi-thread,net,io-util,sync,time,signal,macros
cargo add -p crypt_guard_kms hyper --features server,http1
cargo add -p crypt_guard_kms hyper-util --features tokio,server,http1
cargo add -p crypt_guard_kms http http-body http-body-util bytes futures-util
cargo add -p crypt_guard_kms rustls --no-default-features --features std,aws_lc_rs,prefer-post-quantum
cargo add -p crypt_guard_kms tokio-rustls --no-default-features --features aws_lc_rs
cargo add -p crypt_guard_kms rustls-pemfile rcgen --features aws_lc_rs
cargo add -p crypt_guard_kms serde --features derive && cargo add -p crypt_guard_kms serde_json toml   # config + MCP boundary only
cargo add -p crypt_guard_kms clap --features derive
cargo add -p crypt_guard_kms tracing tracing-subscriber --features env-filter,fmt,json
cargo add -p crypt_guard_kms sd-notify landlock --target 'cfg(target_os = "linux")'
cargo add -p crypt_guard_kms arti-client@=0.47.0 --optional --no-default-features --features tokio,rustls,onion-service-service,onion-service-client,static-sqlite
```

Versions seen on crates.io on 2026-11-01: `keyring 4.2.0` (Harwness uses
3.6.3: the 4.x API must be read before use), `linux-keyutils 0.2.5`,
`tss-esapi 8.0.0-alpha.4` (7.x is the last stable), `windows 0.62.2`,
`rustls 0.23.x` stable (`0.24.0-dev.2` exists, not used), `tokio-rustls
0.26.6`, `aws-lc-rs 1.19.0`, `rcgen` current, `arti-client 0.47.0`,
`clap 4.6.7`, `toml 1.1.8`.

## 5. Waves

1. **W1 keystore:** trait, `key-file`, `systemd-credential`, `env-seed`,
   `passphrase`, `os-keyring`, `linux-kernel-keyring`, `windows-dpapi`,
   `tpm2` stub, `split-kek`, Shamir backup; tests with a `MemoryProvider`.
2. **W2 container + provider:** `CGKS`, generation guard, atomic write,
   `SeedStore` refactor in `crypt_guard_service`, `SealedProvider`,
   compare-and-set rotation, tombstones, KEK rotation.
3. **W3 daemon:** config, partitions, UNIX listener with uid/cgroup
   identity, loopback tokens, hyper API, hardening, systemd units, CLI,
   `doctor`.
4. **W4 mTLS + directory:** rustls listener, local CA, `SignedPublicBundle`,
   `GET /v1/public/{ns}`, SPKI revocation.
5. **W5 MCP:** both revisions, tools/resources, conformance tests against
   a reference client.
6. **W6 Tor + client + Python:** arti feature, `client` module, facade
   `kms-client`, pyo3 §5.
7. **W7 audit + algorithms:** hash-chained audit, SLH-DSA/symmetric/stream/
   multi/derive operations, new routes and tools.

## 6. Open points

1. **comnet-mcp extraction** into a shared crate (asked in the comnet chat).
2. **comnet-vault on `crypt_guard_keystore`** instead of `KeyFileSealer`
   (asked). If yes, `KekProvider` must stay object-safe and `no_std`-free
   only; Android Keystore would become a `custom` provider in comnet-ffi.
3. **TPM2 backend:** tss-esapi 7.x vs 8 alpha, C toolchain in CI, PCR
   policy shape. Own DEC.
4. **macOS Secure Enclave** wrap of the KEK (P-256 ECIES via
   `security-framework`): later feature `macos-secure-enclave`.
5. **Rollback guard vs. full-directory restore:** TPM NV counter or an
   external witness (`SignedPublicBundle.generation` published to clients
   already gives a weak witness). Same residual risk as comnet DEC-022.
6. **Service-crate change** `SeedProvider<S: SeedStore>`: must be checked
   with `cargo semver-checks` (PR #24 adds that gate); `InMemoryProvider`
   stays a type alias with identical behaviour.
7. **Windows peer identity** (`SIO_AF_UNIX_GETPEERPID` is undocumented on
   some builds): fallback is loopback tokens only.
8. mDNS/UPnP discovery for the home-network case: not in wave 1.
9. PyPI / packaging of the binary (deb/rpm/msi/pkg): separate plan.

## 7. Tests (acceptance)

- Keystore: every backend behind a mock (`keyring::mock`, temp dirs, env),
  permission failures (`0644`, foreign owner, symlink) refuse to load,
  `split-kek` deterministic, Shamir backup/restore round trip, `KekId`
  stable KAT.
- Container: KATs for header/AAD bytes, open with wrong KEK →
  `AuthenticationFailed` (opaque), generation rollback refused, healing on
  `file > guard`, crash simulation between rename and guard write, KEK
  rotation under a different `kek_id`, tombstones survive re-seal, fuzz
  target `cgks_header_decode`.
- Provider: the existing `crypt_guard_service` test suite passes against
  `SealedProvider` unchanged (same semantics as `InMemoryProvider`), plus
  compare-and-set rotation and idempotent generate (F6 behaviours).
- Peer identity: unit tests with synthetic `/proc/<pid>/cgroup` content
  (v2, v1, hybrid, user slice, nested scope), pidfd re-check failure →
  `Unauthenticated`, config rejection without `SO_PEERPIDFD`.
- mTLS: rcgen CA, good cert / wrong SAN / no SAN / revoked SPKI / classical
  group only → handshake refused; negotiated group assertion.
- HTTP + MCP: contract tests for every route and tool in both MCP
  revisions, Origin/Accept/Content-Type/413 rules, SSE keep-alive, session
  binding to the principal (foreign session id → unknown).
- Dependency gates extended; `cargo deny` with all features; clippy
  `-D warnings` on `--all-features` and defaults; release checks include
  `cargo semver-checks`.
