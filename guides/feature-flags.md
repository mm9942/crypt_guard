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
- `hpke-pq-draft-05`
  Opt-in and experimental. Enables the public, revision-named
  `hpke_pq::draft_ietf_hpke_pq_05` Base-mode API for the two pinned FIPS 203
  ML-KEM-768/1024 profiles. It is gated by the vendored draft-05 vectors. The
  active Internet-Draft is not an RFC or a finalized IANA profile, so this is
  not a standardized PQ HPKE feature.

CI runs the default lane, the ML-only lane, and the legacy-only lane.

## Release commands

```bash
cargo test
cargo test --no-default-features --features ml-kem-backend,ml-dsa-backend
cargo test --no-default-features --features legacy-pqclean
cargo test --no-default-features --features hpke-pq-draft-05 --test hpke_pq_draft05_public
```

## Intent

- core defaults should stay small and modern
- optional families should be additive
- legacy should mean compatibility, not future direction
