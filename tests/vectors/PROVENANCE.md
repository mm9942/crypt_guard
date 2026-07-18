# HPKE test-vector provenance

This directory is intentionally offline-only. `cargo test` and
`verify_provenance.sh` consume only files checked into this repository; neither
downloads vector material.

## Vendored corpora

The files below were retrieved on 2026-07-14 from immutable raw GitHub URLs.
The listed byte counts and SHA-256 digests were calculated locally before the
files were retained. `SHA256SUMS` is the authoritative local-byte manifest.

| Local filename | Corpus | Immutable source | Commit | Bytes | SHA-256 | Retrieved |
| --- | --- | --- | --- | ---: | --- | --- |
| `rfc9180-test-vectors.json` | RFC 9180 HPKE vectors | `https://raw.githubusercontent.com/cfrg/draft-irtf-cfrg-hpke/5f503c564da00b0687b3de75f1dfbdfc4079ad31/test-vectors.json` | `5f503c564da00b0687b3de75f1dfbdfc4079ad31` | 5,892,257 | `61fc662f01996cd06d713dacf5e133167bd309a1f329442d53f1e21a47b3ede6` | 2026-07-14 |
| `hpke-pq-draft-05-test-vectors.json` | `draft-ietf-hpke-pq-05` vectors | `https://raw.githubusercontent.com/hpkewg/hpke-pq/11b5b9541e9976fc9ce25902011d20dacc089066/test-vectors.json` | `11b5b9541e9976fc9ce25902011d20dacc089066` | 122,735 | `35c59f4a0132e5631e50ac039d8ca3a72e99f5e92dfd94d45338d6ae243f613c` | 2026-07-14 |

The PQ draft is mutable work-in-progress. Do not substitute vectors from a
later draft, a branch head, or an implementation mirror.

## Local verification

Run:

```sh
bash tests/vectors/verify_provenance.sh
```

The script rejects malformed or duplicate manifest entries, manifest paths
outside this directory, checksum entries for missing files, and JSON vector
files without exactly one manifest entry. It then invokes `sha256sum --check
--strict` against the local files. It never opens a network connection.
