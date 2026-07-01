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

CI runs the default lane, the ML-only lane, and the legacy-only lane.

## Release commands

```bash
cargo test
cargo test --no-default-features --features ml-kem-backend,ml-dsa-backend
cargo test --no-default-features --features legacy-pqclean
```

## Intent

- core defaults should stay small and modern
- optional families should be additive
- legacy should mean compatibility, not future direction
