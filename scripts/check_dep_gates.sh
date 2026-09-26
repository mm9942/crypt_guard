#!/usr/bin/env bash
# Enforce that transport dependencies only appear behind their features.
#
#   crypt_guard (default)           must not pull hyper, http, tower or tokio
#   crypt_guard --features service  must not pull hyper or http
set -euo pipefail

tree() {
    cargo tree -p crypt_guard -e normal --prefix none "$@" | awk '{print $1}' | sort -u
}

check() {
    local label=$1 pattern=$2
    shift 2
    local hits
    hits=$(tree "$@" | grep -E "^(${pattern})$" || true)
    if [[ -n "$hits" ]]; then
        echo "FAIL [$label]: forbidden dependencies:" >&2
        echo "$hits" | sed 's/^/  - /' >&2
        return 1
    fi
    echo "ok   [$label]"
}

transport='hyper|hyper-util|http|http-body|http-body-util|bytes|tower|tower-service|tower-layer|tokio'
check "default" "$transport"
check "no-default + legacy-pqclean" "$transport" --no-default-features --features legacy-pqclean
check "service" 'hyper|hyper-util|http|http-body|http-body-util|bytes' --features service

# The hyper feature must actually bring in the bridge.
if ! tree --features hyper | grep -qx 'hyper-util'; then
    echo "FAIL [hyper]: hyper-util missing" >&2
    exit 1
fi
echo "ok   [hyper]"
