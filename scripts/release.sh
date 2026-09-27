#!/usr/bin/env bash
# Release every workspace crate in lockstep via cargo-release.
#
#   scripts/release.sh                    # dry run: release the current version
#   scripts/release.sh patch|minor|major  # dry run with a version bump
#   scripts/release.sh minor --execute    # really bump, tag, publish and push
#
# Requires `cargo install cargo-release` and a crates.io token
# (`cargo login` or CARGO_REGISTRY_TOKEN). Configuration: release.toml.
set -euo pipefail
cd "$(dirname "$0")/.."
command -v cargo-release >/dev/null || {
    echo "cargo-release is not installed: cargo install cargo-release" >&2
    exit 1
}
exec cargo release --workspace "$@"
