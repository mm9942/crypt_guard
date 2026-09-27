#!/usr/bin/env sh
# Verify only already-vendored HPKE vector bytes. This script never fetches.
set -eu

vector_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
manifest="$vector_dir/SHA256SUMS"

fail() {
    printf '%s\n' "$*" >&2
    exit 1
}

[ -f "$manifest" ] || fail "missing checksum manifest: $manifest"

entry_count=0
seen_filenames='
'
while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in
        '' | \#*) continue ;;
    esac

    # GNU sha256sum's binary-mode manifest grammar is exactly:
    # <64 lowercase hex characters><ASCII space>*<safe basename>
    # Parse it in shell rather than relying on a glob with 64 repeated atoms:
    # POSIX shell case patterns have no counted repetition, and that glob
    # rejected legitimate GNU sha256sum output.
    case "$line" in
        *' '*)
            digest=${line%% *}
            remainder=${line#* }
            ;;
        *) fail "invalid checksum manifest entry: $line" ;;
    esac
    case "$digest" in
        '' | *[!0-9a-f]*) fail "invalid checksum digest: $line" ;;
    esac
    [ "${#digest}" -eq 64 ] || fail "invalid checksum digest length: $line"

    case "$remainder" in
        \**) filename=${remainder#\*} ;;
        *) fail "invalid checksum manifest entry: $line" ;;
    esac
    [ "$line" = "$digest *$filename" ] || fail "invalid checksum manifest entry: $line"

    case "$filename" in
        '' | *[!A-Za-z0-9._-]* | *'/'* | '.' | '..')
            fail "unsafe manifest filename: $filename"
            ;;
        *.json) ;;
        *) fail "manifest entry is not a JSON vector: $filename" ;;
    esac
    [ -f "$vector_dir/$filename" ] && [ ! -L "$vector_dir/$filename" ] || \
        fail "manifest file is missing or not a regular local file: $filename"

    case "$seen_filenames" in
        *"
$filename
"*) fail "manifest filename is not unique: $filename" ;;
    esac
    seen_filenames="${seen_filenames}${filename}
"
    entry_count=$((entry_count + 1))
done < "$manifest"

[ "$entry_count" -gt 0 ] || fail 'checksum manifest has no vector entries'

for vector in "$vector_dir"/*.json; do
    [ -e "$vector" ] || continue
    filename=${vector##*/}
    case "$seen_filenames" in
        *"
$filename
"*) : ;;
        *) fail "JSON vector file lacks exactly one manifest entry: $filename" ;;
    esac
done

(
    cd "$vector_dir"
    sha256sum --check --strict SHA256SUMS
)
