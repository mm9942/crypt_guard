# Research — how the giants + NIST package (ciphertext + nonce + KEM secret)

Research date: 2026-06-21. The maintainer's question: "what does everyone use to secure
the result (encryption output + nonce + KEM secret output) with a public/private key, like
Cloudflare etc.? Look at how the giants or NIST do it."

## Answer: it's HPKE (RFC 9180)

**Hybrid Public Key Encryption** is the exact, standardized answer to "bundle a KEM
ciphertext + an AEAD ciphertext (+ internally-managed nonce) into one public-key sealed
blob." It is a composition of **KEM + KDF + AEAD**, any valid combination is a valid
instantiation. Cloudflare drove it (CIRCL library); it's an IRTF/CFRG RFC.

### Single-shot API (this is the high-level shape crypt_guard should mirror)

```
def SealBase(pkR, info, aad, pt):
    enc, ctx = SetupBaseS(pkR, info)   # KEM encapsulate -> shared_secret -> key schedule
    ct = ctx.Seal(aad, pt)             # AEAD encrypt
    return enc, ct                     # enc = KEM ciphertext, ct = AEAD ciphertext

def OpenBase(enc, skR, info, aad, ct):
    ctx = SetupBaseR(enc, skR, info)   # KEM decapsulate -> shared_secret -> same schedule
    return ctx.Open(aad, ct)
```

The sender output is `(enc, ct)` — KEM ciphertext + AEAD ciphertext. That is exactly the
crypt_guard "encryption output + kyber secret output" pairing, and the nonce is NOT a third
artifact the user juggles — HPKE derives a base nonce in the key schedule and never
transmits it.

### Key schedule (the part crypt_guard half-invented; HPKE does it properly)

```
KeyScheduleS(mode, shared_secret, info, psk, psk_id):
    psk_id_hash = LabeledExtract("", "psk_id_hash", psk_id)
    info_hash   = LabeledExtract("", "info_hash", info)
    key_schedule_context = concat(mode, psk_id_hash, info_hash)
    secret          = LabeledExtract(shared_secret, "secret", psk)
    key             = LabeledExpand(secret, "key",        key_schedule_context, Nk)
    base_nonce      = LabeledExpand(secret, "base_nonce", key_schedule_context, Nn)
    exporter_secret = LabeledExpand(secret, "exp",        key_schedule_context, Nh)
    return Context(key, base_nonce, 0, exporter_secret)

LabeledExtract(salt, label, ikm):
    labeled_ikm = concat("HPKE-v1", suite_id, label, ikm); return Extract(salt, labeled_ikm)
LabeledExpand(prk, label, info, L):
    labeled_info = concat(I2OSP(L,2), "HPKE-v1", suite_id, label, info); return Expand(prk, labeled_info, L)

suite_id = concat("HPKE", I2OSP(kem_id,2), I2OSP(kdf_id,2), I2OSP(aead_id,2))
```

Per-message nonce: `ComputeNonce(seq) = base_nonce XOR I2OSP(seq, Nn)`; `seq` increments
per Seal, fails on overflow. Nonces are derived, never transmitted.

- `info` (setup-time): binds the whole context to application data (identities, versions).
- `aad` (per-message): authenticated-not-encrypted, binds framing/metadata.
- `exporter_secret`: lets apps derive extra secrets / use non-standard AEADs.

### How this maps onto the current crypt_guard envelope

crypt_guard already does a *crypt_guard-flavored* HPKE in `src/core/hub/cipher_impls.rs`:
- KEM encapsulate (ML-KEM) -> shared_secret  ≈ HPKE Encap
- `HKDF(salt = kem_ct, label = "crypt_guard:v2:aead:<alg>")` -> session key  ≈ HPKE key schedule (but ad-hoc labels, salt=kem_ct instead of HPKE's structured key_schedule_context)
- nonce in the Envelope, bound via `build_aad(header || kem_ct || nonce)`  ≈ HPKE base_nonce + AAD, except crypt_guard stores the random nonce in the envelope rather than deriving+counter
- `Envelope { header, kem_ciphertext, nonce, ciphertext }`  ≈ HPKE `(enc, ct)` + a self-describing header

**Design takeaway:** crypt_guard's envelope is already HPKE-shaped. To be "richtig richtig"
we can either (a) keep the crypt_guard envelope but align the key schedule to HPKE's
labeled-extract/expand + suite_id domain separation, or (b) adopt RFC 9180 labels verbatim
for full interop. The high-level `Sealer`/`Opener` (`src/api/`) should present the HPKE
single-shot `seal(info, aad, pt) -> envelope` / `open(envelope, info, aad) -> pt` shape.

## NIST's own guidance: SP 800-227 (Sept 2025)

"Recommendations for Key-Encapsulation Mechanisms" — the operational playbook that sits
beside FIPS 203 (ML-KEM). It defines KEM properties and how to use KEMs securely in real
protocols (i.e., exactly the "don't feed the shared secret raw into a cipher — run it
through a KDF, bind context" guidance crypt_guard needs). Pair with SP 800-56C (KDF) and
FIPS 203/204/205. **Action:** cite SP 800-227 as the rationale for the HKDF key schedule and
for never using the ML-KEM shared secret directly as an AEAD key.

## How the giants do hybrid PQC (the public/private-key securing)

The production pattern everywhere is **hybrid KEM**: classical ECDH (X25519) combined with
ML-KEM-768, so a break in either one alone is not fatal ("harvest now, decrypt later"
defense).

- **Cloudflare:** X25519 + ML-KEM-768 (formerly Kyber768) in production TLS and to origins;
  also hybrid ML-KEM in IPsec/IKEv2. Early ML-KEM adopter; authored HPKE/CIRCL.
- **AWS:** KMS, ACM, Secrets Manager, S3, CloudFront use hybrid ECDH + ML-KEM for TLS key
  establishment. AWS Encryption SDK separately popularized **envelope encryption** (a data
  key wrapped by a KEK) — conceptually the same "wrap the symmetric key with public-key" move.
- **Google Cloud KMS:** quantum-safe KEMs (ML-KEM) exposed as a KMS primitive.
- **IETF:** `draft-ietf-tls-ecdhe-mlkem` (hybrid ECDHE-MLKEM for TLS 1.3); **X-Wing** =
  standardized combiner of X25519 + ML-KEM-768 as a single hybrid KEM.

**Design takeaway for crypt_guard:** to match the giants, the KEM axis should be able to be
a **hybrid KEM** (X25519 + ML-KEM-768 = X-Wing) behind the existing `KemBackend` trait, as
an opt-in feature (`hybrid-xwing` or similar). This is a clean fit: `KemBackend` already
abstracts encapsulate/decapsulate; X-Wing is just another backend. Keep pure ML-KEM as a
valid choice; offer hybrid for the "like Cloudflare" posture.

## Sources

- RFC 9180 — Hybrid Public Key Encryption: https://www.rfc-editor.org/rfc/rfc9180.html
- Cloudflare — "HPKE: Standardizing public-key encryption (finally!)": https://blog.cloudflare.com/hybrid-public-key-encryption/
- NIST SP 800-227 (final, Sept 2025): https://csrc.nist.gov/pubs/sp/800/227/final
- NIST news — SP 800-227 published: https://www.nist.gov/news-events/news/2025/09/recommendations-key-encapsulation-mechanisms-nist-publishes-sp-800-227
- Cloudflare PQC docs: https://developers.cloudflare.com/ssl/post-quantum-cryptography/
- Cloudflare — post-quantum to origins (X25519+Kyber768): https://blog.cloudflare.com/post-quantum-to-origins/
- AWS — ML-KEM PQ TLS in KMS/ACM/Secrets Manager: https://aws.amazon.com/blogs/security/ml-kem-post-quantum-tls-now-supported-in-aws-kms-acm-and-secrets-manager/
- Google Cloud — quantum-safe KEMs in Cloud KMS: https://cloud.google.com/blog/products/identity-security/announcing-quantum-safe-key-encapsulation-mechanisms-in-cloud-kms
- IETF draft — hybrid ECDHE-MLKEM for TLS 1.3: https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/
- FIPS 203 ML-KEM: https://csrc.nist.gov/pubs/fips/203/final
