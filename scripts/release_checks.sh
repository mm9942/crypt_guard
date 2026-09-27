#!/usr/bin/env bash
# Release gate, run by cargo-release (pre-release-hook) before the release
# commit is created. Any failure aborts the release: nothing is committed,
# tagged or published.
#
#   scripts/release_checks.sh <new-version>
set -euo pipefail

version="${1:?usage: release_checks.sh <new-version>}"
cd "$(dirname "$0")/.."

step() { printf '\n==> %s\n' "$*"; }

step "all crates are at $version"
cargo metadata --no-deps --format-version 1 | python3 -c '
import json, sys
want = sys.argv[1]
bad = [(p["name"], p["version"]) for p in json.load(sys.stdin)["packages"] if p["version"] != want]
if bad:
    sys.exit(f"version mismatch (expected {want}): {bad}")
' "$version"

step "CHANGELOG has release notes"
grep -q '^## \[Unreleased\]' CHANGELOG.md || { echo "CHANGELOG.md needs an '## [Unreleased]' section" >&2; exit 1; }

step "vendored test vectors are intact"
sh crates/core/tests/vectors/verify_provenance.sh

if [ "${DRY_RUN:-false}" = "true" ]; then
    step "dry run: skipping tests and dependency gates (they run with --execute)"
    exit 0
fi

step "tests"
cargo test -p crypt_guard -p crypt_guard_core
cargo test -p crypt_guard -p crypt_guard_core --no-default-features --features legacy-pqclean
cargo test -p crypt_guard -p crypt_guard_core --features cgv2-compat,legacy-pqclean
cargo test -p crypt_guard_core --features sign-slhdsa
cargo test -p crypt_guard_service --all-features
cargo test -p crypt_guard_hyper
cargo test -p crypt_guard --features hyper

step "transport dependencies stay behind their features"
./scripts/check_dep_gates.sh

step "release checks passed for $version"
