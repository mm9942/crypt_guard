# Feature Flags

The current release build matrix has three lanes: default, ML-only, and
legacy-only.

## Current matrix

- `ml-kem-backend`
  Default. Enables the Rust-native ML-KEM path used by the safe API.
- `ml-dsa-backend`
  Default. Enables the ML-DSA signature backend.
- `legacy-pqclean`
  Opt-in only. Preserves the older Kyber/Falcon/Dilithium compatibility surface.
- `hpke_pq`
  Default and revision-pinned. Provides the public, revision-named
  `hpke_pq::draft_ietf_hpke_pq_05` compatibility Base-mode API plus the
  revision-pinned `draft_ietf_hpke_pq_05_full` registry. The currently
  operational profiles are FIPS 203 ML-KEM-512/768/1024 plus the vector-verified
  MLKEM768-P256 and MLKEM1024-P384 hybrids. MLKEM768-X25519 remains typed
  fail-closed until its complete vectors are implemented. It is
  gated by the vendored draft-05 vectors. The
  active Internet-Draft is not an RFC or a finalized IANA profile, so this is
  not a standardized PQ HPKE feature.

CI runs the default lane, the ML-only lane, and the legacy-only lane.

## Release commands

```bash
cargo test
cargo test --no-default-features --features ml-kem-backend,ml-dsa-backend
cargo test --no-default-features --features legacy-pqclean
cargo test --no-default-features --test hpke_pq_draft05_public
```

## Intent

- core defaults should stay small and modern
- optional families should be additive
- legacy should mean compatibility, not future direction
