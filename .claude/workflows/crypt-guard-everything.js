export const meta = {
  name: 'crypt-guard-everything',
  description: 'Phase-4 default flip + content compile-fail tests + HPKE high-level layer + README + 100% doc coverage + clippy hygiene, fanned out across Sonnet subagents',
  phases: [
    { title: 'Foundation', detail: 'flip default (remove legacy-pqclean), fix fallout, both builds green' },
    { title: 'Build', detail: 'parallel: trybuild content tests, HPKE seal/open layer, README+crate-doc' },
    { title: 'DocCoverage', detail: 'parallel by module: /// docs to ~100%' },
    { title: 'Hygiene', detail: 'clippy --fix whole crate + final verify' },
  ],
}

const ROOT = '/srv/dev-shared/projects/rust/sgh-flow/crypt_guard'
const M = 'sonnet'
const RULES = `Working dir: ${ROOT} (branch v2-redesign). HARD RULES: never delete a cryptographic capability; additive/feature-gated changes only; keep the original Kyber<Process,Size,Content,Algorithm> design and the working main macros. Context docs you SHOULD read first: ${ROOT}/session-2026-06-21/04-design-and-roadmap.md and 01-research-hpke-nist-giants.md and 03-status-and-changes.md. cargo is allowlisted. If a build fails with "No space left on device" run \`cargo clean\` (env issue, not code) and retry; check \`df -h /\`.`

const FOUND_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['ok', 'summary', 'files_changed'],
  properties: {
    ok: { type: 'boolean', description: 'true iff BOTH cargo test (default) green (>=111 unit, doctests pass) AND cargo check --no-default-features --features ml-kem-backend,ml-dsa-backend compiles' },
    summary: { type: 'string' },
    files_changed: { type: 'array', items: { type: 'string' } },
  },
}

// ── Phase 1: Foundation (gate) ────────────────────────────────────────────────
phase('Foundation')
const foundation = await agent(
  `${RULES}

TASK: Flip the default features and make EVERYTHING green.
1. In ${ROOT}/Cargo.toml change \`default = ["legacy-pqclean","ml-kem-backend","ml-dsa-backend"]\` to \`default = ["ml-kem-backend","ml-dsa-backend"]\` (remove legacy-pqclean from DEFAULT only; keep the feature definition so \`--features legacy-pqclean\` still works).
2. Now \`cargo test\` uses the non-legacy path. Fix all fallout WITHOUT deleting capabilities:
   - The crate-level //! doc examples in src/lib.rs use legacy-only macros (kyber_keypair!, encryption!, decryption!, encrypt_file!) which are now gated behind legacy-pqclean. For each such doctest that no longer compiles under default, either mark its fence \`\`\`rust,ignore (preferred minimal fix) OR convert it to the new Encryptor/Decryptor API. Keep at least the existing api/Phase3 examples working.
   - Any other default-build compile errors: fix with additive #[cfg(feature="...")] gates (same approach already used this session).
3. ACCEPTANCE (verify yourself, iterate until both hold):
   A) \`cargo test\` (default) compiles and runs; unit tests pass (>=111) and doctests pass (0 failed).
   B) \`cargo check --no-default-features --features ml-kem-backend,ml-dsa-backend\` compiles (0 errors).
   Also confirm \`cargo build --features legacy-pqclean\` still compiles (legacy still reachable).
Return the schema. Set ok=true ONLY if A and B both pass.`,
  { label: 'flip-default', phase: 'Foundation', model: M, schema: FOUND_SCHEMA },
)

if (!foundation || !foundation.ok) {
  log(`Foundation did NOT reach green (${foundation ? 'ok=false' : 'null'}). Skipping build/doc/hygiene to avoid building on a red tree. Summary: ${foundation ? foundation.summary : 'agent died'}`)
  return { aborted: true, foundation }
}
log(`Foundation green. ${foundation.summary}`)

// ── Phase 2: parallel build-out (disjoint file ownership) ─────────────────────
phase('Build')
const build = await parallel([
  () => agent(
    `${RULES}

TASK (OWN ONLY: ${ROOT}/tests/ui/ and ${ROOT}/tests/typestate_compile.rs): add trybuild compile-fail cases that PROVE the content-axis typestate enforcement now bites (default build no longer has legacy KyberFunctions). Add cases such as: encrypt_file called on a Kyber<Encryption,_,Message,_> instance (must fail to compile); decrypt_msg on a Files instance; encrypt_data on a Files instance. Use the public paths the existing ui/*.rs cases use (look at the current tests/ui/*.rs for the import style: \`use crypt_guard::...\`). The trybuild harness is tests/typestate_compile.rs (globs tests/ui/*.rs). Generate the .stderr files by running \`TRYBUILD=overwrite cargo test --test typestate_compile\` then re-run \`cargo test --test typestate_compile\` to confirm green. Do NOT touch any file outside tests/ui/ and tests/typestate_compile.rs. Return: list of new cases + final test output line.`,
    { label: 'trybuild-content', phase: 'Build', model: M },
  ),
  () => agent(
    `${RULES}

TASK (OWN ONLY: ${ROOT}/src/api/ — files seal.rs, open.rs, mod.rs, and a NEW file hpke.rs): build an HPKE-style (RFC 9180) single-shot high-level layer on top of the existing envelope, WITHOUT breaking the existing Encryptor/Decryptor. Read session-2026-06-21/01-research-hpke-nist-giants.md first. Add to src/api/hpke.rs a thin ergonomic API mirroring HPKE single-shot SealBase/OpenBase: e.g. \`seal<K,A>(recipient_pk: &[u8], info: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Envelope, CryptError>\` and \`open<K,A>(recipient_sk: &[u8], info: &[u8], aad: &[u8], envelope: &Envelope) -> Result<Vec<u8>, CryptError>\`, where K: KyberSizeVariant, A: AuthenticatedAead. Wire it through the existing Encryptor/Decryptor + envelope path (the envelope already binds header||kem_ct||nonce as AAD; thread the caller \`aad\` and \`info\` into build_aad/metadata if feasible, otherwise document the current binding and leave a TODO referencing the HPKE key-schedule alignment). Re-export the new fns from src/api/mod.rs and src/lib.rs is OWNED BY ANOTHER AGENT — do NOT edit lib.rs; instead make api/mod.rs pub-export them and note in your return that lib.rs needs \`pub use api::{seal as hpke_seal, open as hpke_open}\` added later. Add module-level //! and item /// docs. Add at least 2 unit tests (roundtrip; wrong-aad/wrong-info fails). Verify \`cargo test --lib\` (default) stays green. Do NOT touch files outside src/api/. Return: API added + test result.`,
    { label: 'hpke-layer', phase: 'Build', model: M },
  ),
  () => agent(
    `${RULES}

TASK (OWN ONLY: ${ROOT}/README.md and the crate-level //! doc header at the TOP of ${ROOT}/src/lib.rs): rewrite both to reflect crypt_guard v2.0 (2.0.0-alpha.1). The published docs/README still describe 1.4.2 (old Kyber<...>, ECB AES, separate nonce). New story: FIPS ML-KEM/ML-DSA/SLH-DSA, one authenticated Envelope (KEM->HKDF->AEAD, nonce inside the envelope, HPKE-shaped), content-axis-enforced typestate, the safe Encryptor/Decryptor API as the primary example, and legacy Kyber/Falcon/Dilithium available behind \`--features legacy-pqclean\`. Update the crates.io/docs badge versions from v1.2 to v2.0. Keep a short "Legacy compatibility" section. Ensure any \`\`\`rust doc example in the crate header COMPILES under default features (use the Encryptor/Decryptor or Kyber Phase-3 API, NOT the legacy macros; mark legacy snippets \`\`\`rust,ignore). Verify with \`cargo test --doc\` that the crate-header doctests pass. Do NOT edit any src file other than the //! header block at the very top of src/lib.rs (do not touch the macro definitions or the pub use blocks lower in lib.rs). Return: summary of changes + doctest result.`,
    { label: 'readme-cratedoc', phase: 'Build', model: M },
  ),
])
log(`Build phase done: ${build.filter(Boolean).length}/3 agents returned.`)

// ── Phase 3: doc coverage fan-out (disjoint module dirs) ──────────────────────
phase('DocCoverage')
const DOC_GROUPS = [
  { key: 'kem', dirs: 'src/kem/' },
  { key: 'sign', dirs: 'src/sign/' },
  { key: 'kdf+protocol', dirs: 'src/kdf/ and src/protocol/' },
  { key: 'core-hub', dirs: 'src/core/hub/ (mod.rs, cipher_impls.rs, macros.rs)' },
  { key: 'keyctl+builder', dirs: 'src/key_control/ and src/builder.rs and src/markers.rs' },
]
const docs = await parallel(DOC_GROUPS.map(g => () => agent(
  `${RULES}

TASK (OWN ONLY these paths: ${g.dirs}): raise Rust doc coverage toward 100% for PUBLIC items in these files ONLY. For every pub fn/struct/enum/trait/type/impl missing a /// doc, add concise but complete rustdoc following the project's CLAUDE.md doc standard (one-line summary; Arguments/Returns/Errors where relevant; no invented behavior — describe what the code actually does). Add //! module headers where missing. DO NOT change any logic, signatures, or cfg gates. DO NOT touch files outside ${g.dirs}. After editing, run \`cargo doc --no-deps\` and \`cargo test --lib\` (default) to confirm nothing broke. Return: count of items documented + any item you intentionally skipped and why.`,
  { label: `doc:${g.key}`, phase: 'DocCoverage', model: M },
)))
log(`DocCoverage done: ${docs.filter(Boolean).length}/${DOC_GROUPS.length} groups.`)

// ── Phase 4: hygiene (whole-crate, solo last) ─────────────────────────────────
phase('Hygiene')
const hygiene = await agent(
  `${RULES}

TASK (whole crate — you run LAST, after all other agents): mechanical hygiene only, no behavior change.
1. Run \`cargo clippy --fix --allow-dirty --lib\` to auto-apply the safe suggestions (needless 'as usize' casts, needless Ok(..)? , needless mut, closure-in-place). Then run \`cargo clippy --fix --allow-dirty --tests\` if safe.
2. Manually clear remaining easy warnings: unused imports, dead-code that is genuinely unused (gate behind #[cfg] or #[allow(dead_code)] WITH a comment if it is legacy-kept — do NOT delete crypto code), needless &str .clone() noop calls. For the deprecated-Kyber512/768/1024 internal uses, the #[allow(deprecated)] attributes that clippy says are "ignored on macro invocations" should be moved to the items or removed.
3. Do NOT change the default features, do NOT remove capabilities, do NOT alter the HPKE layer or new tests/docs logically.
4. ACCEPTANCE (verify, iterate): \`cargo test\` (default) green (unit >=111, integration incl. typestate_compile, doctests 0 failed); \`cargo check --no-default-features --features ml-kem-backend,ml-dsa-backend\` clean; report the remaining \`cargo clippy --lib\` warning count (target: large reduction from ~220).
Return: before/after warning counts + final test/check status.`,
  { label: 'clippy-hygiene', phase: 'Hygiene', model: M },
)

return {
  foundation: foundation.summary,
  build: build.map((b, i) => ({ agent: ['trybuild', 'hpke', 'readme'][i], result: b })),
  docCoverage: docs,
  hygiene,
}
