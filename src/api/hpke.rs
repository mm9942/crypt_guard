//! HPKE-style (RFC 9180) single-shot `seal` / `open` API.
//!
//! # Responsibility scope
//! This module presents an ergonomic single-shot API that mirrors the shape of RFC 9180's
//! `SealBase` / `OpenBase` over the existing CGv2 [`Envelope`] protocol. It accepts
//! caller-supplied `info` (setup-time context) and `aad` (per-message additional authenticated
//! data) and threads them through the encryption in a fully authenticated way.
//!
//! # Key types exported
//! - [`seal`] — single-shot encrypt: produces an [`Envelope`].
//! - [`open`] — single-shot decrypt: verifies and returns the plaintext.
//!
//! # AAD / info binding — current implementation
//! The existing [`SymmetricCipher`](crate::core::hub::cipher_impls) layer builds its AEAD
//! associated data as:
//!
//! ```text
//! AEAD-AAD = magic || version || kem_alg || aead_alg || kdf_alg || flags
//!          || len(kem_ct) || kem_ct || nonce || metadata   (metadata = b"")
//! ```
//!
//! The `metadata` slot (the fourth argument to
//! [`build_aad`](crate::protocol::aad::build_aad)) is the correct hook for passing caller
//! `info` and `aad` into the AEAD's associated data. Because the cipher impls currently
//! hard-code `b""` there, we cannot inject caller bytes into the AEAD AAD without modifying
//! files outside `src/api/`.
//!
//! **Current approach:** `info` and `aad` are serialised into a 16-byte-prefixed framing
//! header that is *prepended to the plaintext* before encryption. The AEAD tag therefore
//! covers this framing unconditionally; any mismatch of `info` or `aad` on `open` is
//! detected as an [`AuthenticationFailed`](crate::error::CryptError::AuthenticationFailed)
//! or [`ContextBindingMismatch`](crate::error::CryptError::InvalidEnvelope) error.
//!
//! ```text
//! framed_plaintext = MAGIC(4) || len_info(4 LE-u32) || info || len_aad(4 LE-u32) || aad
//!                  || plaintext
//! ```
//!
//! On `open` the framing is parsed, `info` and `aad` are verified to match the caller's
//! values, and the original plaintext is returned.
//!
//! # TODO — HPKE key-schedule alignment
//! To align fully with RFC 9180's labeled extract/expand + `suite_id` domain separation,
//! the following changes are needed (tracked as Phase 5/6 work):
//!
//! 1. **Thread `info` into the key schedule**: pass `info` as the `info` argument to
//!    `HKDF-Expand` alongside the label, replacing the current plain label string in
//!    [`derive_session_key`](crate::kdf::derive_session_key). This matches RFC 9180 §5.1's
//!    `LabeledExpand(secret, "key", key_schedule_context, Nk)` where
//!    `key_schedule_context = concat(mode, psk_id_hash, info_hash)`.
//!
//! 2. **Thread `aad` into `build_aad`**: plumb caller `aad` into the `metadata` argument of
//!    [`build_aad`](crate::protocol::aad::build_aad). This requires modifying
//!    `SymmetricCipher::seal`/`open` in `src/core/hub/cipher_impls.rs` to accept a
//!    `metadata: &[u8]` parameter, and propagating it through `seal_envelope` / `open_envelope`.
//!
//! 3. **suite_id domain separation**: prepend `b"HPKE" || I2OSP(kem_id,2) || I2OSP(kdf_id,2)
//!    || I2OSP(aead_id,2)` to every HKDF call (RFC 9180 §4 `LabeledExtract`).
//!
//! When those changes land, the framing prefix used here should be removed in favour of true
//! AEAD-AAD binding, and this module updated accordingly.
//!
//! # Concurrency
//! Both functions are stateless and `Send + Sync`. The underlying ML-KEM and AEAD operations
//! allocate only on the stack/heap of the calling thread.
//!
//! # Errors
//! - [`CryptError::MissingPublicKey`]: empty `recipient_pk` slice.
//! - [`CryptError::MissingSecretKey`]: empty `recipient_sk` slice.
//! - [`CryptError::EncapsulationError`]: ML-KEM encapsulation failed.
//! - [`CryptError::DecapsulationError`]: ML-KEM decapsulation failed.
//! - [`CryptError::EncryptionFailed`]: AEAD seal failed.
//! - [`CryptError::AuthenticationFailed`]: AEAD tag invalid — wrong key or tampered envelope.
//! - [`CryptError::InvalidEnvelope`]: framing header corrupt or `info`/`aad` mismatch.
//!
//! # Examples
//! ```rust,no_run
//! # fn main() -> Result<(), crypt_guard::error::CryptError> {
//! use crypt_guard::api::hpke;
//! use crypt_guard::{MlKem768, XChaCha20Poly1305};
//! # #[cfg(feature = "ml-kem-backend")] {
//! use crypt_guard::kem::{KemBackend, backend::OsRng, ml_kem::MlKem768Impl};
//!
//! let mut rng = OsRng;
//! let (pk, sk) = MlKem768Impl::keypair(&mut rng)?;
//!
//! let envelope = hpke::seal::<MlKem768, XChaCha20Poly1305>(
//!     pk.as_ref(),
//!     b"my-app v1.0",
//!     b"recipient-id:alice",
//!     b"hello, post-quantum world",
//! )?;
//!
//! let plaintext = hpke::open::<MlKem768, XChaCha20Poly1305>(
//!     sk.as_ref(),
//!     b"my-app v1.0",
//!     b"recipient-id:alice",
//!     &envelope,
//! )?;
//!
//! assert_eq!(plaintext, b"hello, post-quantum world");
//! # Ok::<(), crypt_guard::error::CryptError>(())?;
//! # }
//! # Ok(())
//! # }
//! ```

use crate::{
    api::{AuthenticatedAead, Decryptor, Encryptor},
    core::hub::{DecryptData, EncryptData, Kyber, KyberSizeVariant},
    error::CryptError,
    markers::{Data, Decryption, Encryption},
    protocol::Envelope,
};

// ── Framing constants ──────────────────────────────────────────────────────────

/// 4-byte magic marker that opens the HPKE framing prefix.
///
/// Chosen to be distinct from all CGv2 envelope magic (`b"CGv2"`) so that a
/// raw envelope cannot be confused with a framed payload.
const HPKE_FRAME_MAGIC: &[u8; 4] = b"HFv1";

// ── Public API ────────────────────────────────────────────────────────────────

/// Single-shot HPKE-style seal: encrypt `plaintext` for `recipient_pk`.
///
/// # Description
/// Mirrors RFC 9180 `SealBase(pkR, info, aad, pt)`. The function:
///
/// 1. Serialises `info` and `aad` into a 4-field framing header that is prepended to
///    `plaintext` (see module-level docs for the byte layout).
/// 2. Calls the existing [`Encryptor`] builder to KEM-encapsulate, derive a session
///    key, and AEAD-seal the framed payload into a CGv2 [`Envelope`].
///
/// Because the framing is part of the plaintext the AEAD tag authenticates, any
/// modification of `info`, `aad`, or the ciphertext is detected on [`open`].
///
/// # Type parameters
/// - `K` — ML-KEM size marker, e.g. [`crate::core::hub::MlKem768`].
///   Must implement [`KyberSizeVariant`].
/// - `A` — Authenticated AEAD marker, e.g. [`XChaCha20Poly1305`].
///   Must implement [`AuthenticatedAead`].
///
/// # Arguments
/// - `recipient_pk` (`&[u8]`): recipient's ML-KEM public key bytes.
/// - `info` (`&[u8]`): setup-time context bound to the whole session (application
///   version, protocol name, identities). Authenticated but **encrypted** in this
///   implementation; see module-level TODO for the HPKE key-schedule alignment plan.
/// - `aad` (`&[u8]`): per-message additional authenticated data (request ID, sequence
///   number, framing metadata). Authenticated but **encrypted** in this implementation.
/// - `plaintext` (`&[u8]`): the message to encrypt.
///
/// # Returns
/// `Ok(Envelope)` — the CGv2 authenticated envelope. Pass this to [`open`] to recover
/// `plaintext`.
///
/// # Errors
/// - [`CryptError::MissingPublicKey`]: `recipient_pk` is empty.
/// - [`CryptError::EncapsulationError`]: ML-KEM encapsulation failed.
/// - [`CryptError::EncryptionFailed`]: AEAD seal failed.
///
/// # Concurrency
/// Stateless. Safe to call from multiple threads concurrently; each call is independent.
///
/// # Examples
/// ```rust,no_run
/// # fn main() -> Result<(), crypt_guard::error::CryptError> {
/// use crypt_guard::api::hpke;
/// use crypt_guard::{MlKem768, XChaCha20Poly1305};
/// # #[cfg(feature = "ml-kem-backend")] {
/// use crypt_guard::kem::{KemBackend, backend::OsRng, ml_kem::MlKem768Impl};
///
/// let (pk, _sk) = MlKem768Impl::keypair(&mut OsRng)?;
/// let env = hpke::seal::<MlKem768, XChaCha20Poly1305>(
///     pk.as_ref(), b"app-v1", b"aad", b"secret",
/// )?;
/// assert!(!env.ciphertext.is_empty());
/// # Ok::<(), crypt_guard::error::CryptError>(())?;
/// # }
/// # Ok(())
/// # }
/// ```
pub fn seal<K, A>(
    recipient_pk: &[u8],
    info: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Envelope, CryptError>
where
    K: KyberSizeVariant,
    A: AuthenticatedAead,
    Kyber<Encryption, K, Data, A>: EncryptData,
{
    if recipient_pk.is_empty() {
        return Err(CryptError::MissingPublicKey);
    }
    let framed = frame_plaintext(info, aad, plaintext);
    Encryptor::<K, A>::new()
        .recipient(recipient_pk.to_vec())
        .plaintext(framed)
        .seal()
}

/// Single-shot HPKE-style open: decrypt and authenticate an [`Envelope`].
///
/// # Description
/// Mirrors RFC 9180 `OpenBase(enc, skR, info, aad, ct)`. The function:
///
/// 1. Calls the existing [`Decryptor`] builder to KEM-decapsulate, derive the session
///    key, and AEAD-open the envelope.
/// 2. Parses the 4-field framing header from the recovered payload.
/// 3. **Verifies** that the `info` and `aad` bytes in the framing match the caller's
///    supplied values. Returns [`CryptError::InvalidEnvelope`] on mismatch.
/// 4. Returns the original plaintext.
///
/// # Type parameters
/// - `K` — ML-KEM size marker matching the one used in [`seal`].
/// - `A` — Authenticated AEAD marker matching the one used in [`seal`].
///
/// # Arguments
/// - `recipient_sk` (`&[u8]`): recipient's ML-KEM secret key bytes.
/// - `info` (`&[u8]`): must equal the `info` passed to [`seal`].
/// - `aad` (`&[u8]`): must equal the `aad` passed to [`seal`].
/// - `envelope` (`&Envelope`): the envelope returned by [`seal`].
///
/// # Returns
/// `Ok(Vec<u8>)` — the original plaintext.
///
/// # Errors
/// - [`CryptError::MissingSecretKey`]: `recipient_sk` is empty.
/// - [`CryptError::DecapsulationError`]: ML-KEM decapsulation failed (wrong key or
///   corrupted KEM ciphertext).
/// - [`CryptError::AuthenticationFailed`]: AEAD authentication tag invalid — envelope
///   has been tampered with.
/// - [`CryptError::InvalidEnvelope`]: framing header is malformed, or `info` / `aad`
///   do not match.
///
/// # Concurrency
/// Stateless. Safe to call from multiple threads concurrently.
///
/// # Examples
/// ```rust,no_run
/// # fn main() -> Result<(), crypt_guard::error::CryptError> {
/// use crypt_guard::api::hpke;
/// use crypt_guard::{MlKem768, XChaCha20Poly1305};
/// # #[cfg(feature = "ml-kem-backend")] {
/// use crypt_guard::kem::{KemBackend, backend::OsRng, ml_kem::MlKem768Impl};
///
/// let (pk, sk) = MlKem768Impl::keypair(&mut OsRng)?;
/// let env = hpke::seal::<MlKem768, XChaCha20Poly1305>(pk.as_ref(), b"ctx", b"aad", b"hi")?;
/// let pt  = hpke::open::<MlKem768, XChaCha20Poly1305>(sk.as_ref(), b"ctx", b"aad", &env)?;
/// assert_eq!(pt, b"hi");
/// # Ok::<(), crypt_guard::error::CryptError>(())?;
/// # }
/// # Ok(())
/// # }
/// ```
pub fn open<K, A>(
    recipient_sk: &[u8],
    info: &[u8],
    aad: &[u8],
    envelope: &Envelope,
) -> Result<Vec<u8>, CryptError>
where
    K: KyberSizeVariant,
    A: AuthenticatedAead,
    Kyber<Decryption, K, Data, A>: DecryptData,
{
    if recipient_sk.is_empty() {
        return Err(CryptError::MissingSecretKey);
    }
    let framed = Decryptor::<K, A>::new()
        .secret_key(recipient_sk.to_vec())
        .open(envelope)?;
    unframe_plaintext(&framed, info, aad)
}

// ── Framing helpers ───────────────────────────────────────────────────────────

/// Serialise `info` and `aad` into a length-prefixed framing header and prepend it to
/// `plaintext`.
///
/// # Wire layout
/// ```text
/// magic     (4 bytes) = b"HFv1"
/// len_info  (4 bytes, LE u32)
/// info      (variable)
/// len_aad   (4 bytes, LE u32)
/// aad       (variable)
/// plaintext (variable)
/// ```
///
/// The entire blob is passed to the AEAD as plaintext; the tag therefore covers `info`,
/// `aad`, and the original `plaintext` unconditionally.
fn frame_plaintext(info: &[u8], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let cap = HPKE_FRAME_MAGIC.len() + 4 + info.len() + 4 + aad.len() + plaintext.len();
    let mut out = Vec::with_capacity(cap);
    out.extend_from_slice(HPKE_FRAME_MAGIC);
    out.extend_from_slice(&(info.len() as u32).to_le_bytes());
    out.extend_from_slice(info);
    out.extend_from_slice(&(aad.len() as u32).to_le_bytes());
    out.extend_from_slice(aad);
    out.extend_from_slice(plaintext);
    out
}

/// Parse and verify the framing header from `framed`, checking that the embedded `info`
/// and `aad` match the caller-supplied values.
///
/// # Returns
/// The original plaintext slice, cloned into a `Vec<u8>`.
///
/// # Errors
/// [`CryptError::InvalidEnvelope`] if:
/// - `framed` is too short for the header.
/// - Magic bytes do not match [`HPKE_FRAME_MAGIC`].
/// - Any length field overflows the buffer.
/// - The embedded `info` or `aad` differs from the caller's values.
fn unframe_plaintext(
    framed: &[u8],
    expected_info: &[u8],
    expected_aad: &[u8],
) -> Result<Vec<u8>, CryptError> {
    // Minimum: 4 magic + 4 len_info + 4 len_aad = 12 bytes before plaintext.
    if framed.len() < 12 {
        return Err(CryptError::InvalidEnvelope);
    }

    let mut pos = 0usize;

    // Magic check.
    if &framed[pos..pos + 4] != HPKE_FRAME_MAGIC {
        return Err(CryptError::InvalidEnvelope);
    }
    pos += 4;

    // Read info.
    let info = read_field(framed, &mut pos)?;

    // Read aad.
    let aad = read_field(framed, &mut pos)?;

    // Verify both fields match caller expectations.
    if info != expected_info {
        return Err(CryptError::InvalidEnvelope);
    }
    if aad != expected_aad {
        return Err(CryptError::InvalidEnvelope);
    }

    // Remaining bytes are the original plaintext.
    Ok(framed[pos..].to_vec())
}

/// Read a 4-byte LE-u32 length-prefixed field from `data` at `*pos`, advancing `*pos`.
///
/// # Errors
/// [`CryptError::InvalidEnvelope`] if there are not enough bytes for the length prefix
/// or the declared field length.
fn read_field<'a>(data: &'a [u8], pos: &mut usize) -> Result<&'a [u8], CryptError> {
    if *pos + 4 > data.len() {
        return Err(CryptError::InvalidEnvelope);
    }
    let len =
        u32::from_le_bytes([data[*pos], data[*pos + 1], data[*pos + 2], data[*pos + 3]]) as usize;
    *pos += 4;
    if *pos + len > data.len() {
        return Err(CryptError::InvalidEnvelope);
    }
    let field = &data[*pos..*pos + len];
    *pos += len;
    Ok(field)
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(all(test, feature = "ml-kem-backend"))]
mod tests {
    use super::*;
    use crate::core::hub::MlKem768;
    use crate::kem::{backend::OsRng, ml_kem::MlKem768Impl, KemBackend};
    use crate::markers::XChaCha20Poly1305;

    // Convenience: generate a fresh ML-KEM-768 key pair.
    fn keygen() -> (Vec<u8>, Vec<u8>) {
        let mut rng = OsRng;
        let (pk, sk) = MlKem768Impl::keypair(&mut rng).expect("ML-KEM-768 keygen must not fail");
        (pk.as_ref().to_vec(), sk.as_ref().to_vec())
    }

    // ── Framing helpers ────────────────────────────────────────────────────────

    #[test]
    fn test_frame_roundtrip_empty_fields() {
        let info = b"";
        let aad = b"";
        let pt = b"secret payload";
        let framed = frame_plaintext(info, aad, pt);
        let recovered = unframe_plaintext(&framed, info, aad).expect("unframe must succeed");
        assert_eq!(recovered, pt);
    }

    #[test]
    fn test_frame_roundtrip_non_empty_fields() {
        let info = b"crypt_guard:hpke:v1";
        let aad = b"request-id=abc123";
        let pt = b"the actual plaintext bytes";
        let framed = frame_plaintext(info, aad, pt);
        let recovered = unframe_plaintext(&framed, info, aad).expect("unframe must succeed");
        assert_eq!(recovered, pt);
    }

    #[test]
    fn test_frame_wrong_info_rejected() {
        let framed = frame_plaintext(b"correct-info", b"aad", b"pt");
        let err = unframe_plaintext(&framed, b"wrong-info", b"aad");
        assert!(
            matches!(err, Err(CryptError::InvalidEnvelope)),
            "mismatched info must return InvalidEnvelope, got: {:?}",
            err
        );
    }

    #[test]
    fn test_frame_wrong_aad_rejected() {
        let framed = frame_plaintext(b"info", b"correct-aad", b"pt");
        let err = unframe_plaintext(&framed, b"info", b"wrong-aad");
        assert!(
            matches!(err, Err(CryptError::InvalidEnvelope)),
            "mismatched aad must return InvalidEnvelope, got: {:?}",
            err
        );
    }

    #[test]
    fn test_frame_truncated_rejected() {
        let framed = frame_plaintext(b"info", b"aad", b"pt");
        // A 5-byte slice is too short for the 12-byte minimum header.
        let err = unframe_plaintext(&framed[..5], b"info", b"aad");
        assert!(matches!(err, Err(CryptError::InvalidEnvelope)));
    }

    #[test]
    fn test_frame_bad_magic_rejected() {
        let mut framed = frame_plaintext(b"info", b"aad", b"pt");
        framed[0] ^= 0xFF; // corrupt magic byte
        let err = unframe_plaintext(&framed, b"info", b"aad");
        assert!(matches!(err, Err(CryptError::InvalidEnvelope)));
    }

    // ── seal / open roundtrip ──────────────────────────────────────────────────

    /// Happy-path: seal then open with matching info + aad recovers the original plaintext.
    #[test]
    fn test_hpke_seal_open_roundtrip() {
        let (pk, sk) = keygen();
        let info = b"app:crypt_guard:v2";
        let aad = b"session-id=deadbeef";
        let plaintext = b"hello, post-quantum world";

        let envelope = seal::<MlKem768, XChaCha20Poly1305>(&pk, info, aad, plaintext)
            .expect("seal must succeed");

        let recovered = open::<MlKem768, XChaCha20Poly1305>(&sk, info, aad, &envelope)
            .expect("open must succeed");

        assert_eq!(
            recovered, plaintext,
            "recovered plaintext must equal original"
        );
    }

    /// Wrong info on open must fail (even with correct aad and secret key).
    #[test]
    fn test_hpke_open_wrong_info_fails() {
        let (pk, sk) = keygen();
        let info = b"correct-info";
        let aad = b"aad";
        let plaintext = b"sensitive data";

        let envelope = seal::<MlKem768, XChaCha20Poly1305>(&pk, info, aad, plaintext)
            .expect("seal must succeed");

        let result = open::<MlKem768, XChaCha20Poly1305>(&sk, b"wrong-info", aad, &envelope);
        assert!(
            result.is_err(),
            "open with wrong info must fail, but got Ok({:?})",
            result.ok()
        );
    }

    /// Wrong aad on open must fail (even with correct info and secret key).
    #[test]
    fn test_hpke_open_wrong_aad_fails() {
        let (pk, sk) = keygen();
        let info = b"info";
        let aad = b"correct-aad";
        let plaintext = b"sensitive data";

        let envelope = seal::<MlKem768, XChaCha20Poly1305>(&pk, info, aad, plaintext)
            .expect("seal must succeed");

        let result = open::<MlKem768, XChaCha20Poly1305>(&sk, info, b"wrong-aad", &envelope);
        assert!(
            result.is_err(),
            "open with wrong aad must fail, but got Ok({:?})",
            result.ok()
        );
    }

    /// Wrong secret key must fail at the AEAD layer (decapsulation or authentication).
    #[test]
    fn test_hpke_open_wrong_key_fails() {
        let (pk, _sk_correct) = keygen();
        let (_pk2, sk_wrong) = keygen();
        let info = b"info";
        let aad = b"aad";
        let plaintext = b"sensitive data";

        let envelope = seal::<MlKem768, XChaCha20Poly1305>(&pk, info, aad, plaintext)
            .expect("seal must succeed");

        let result = open::<MlKem768, XChaCha20Poly1305>(&sk_wrong, info, aad, &envelope);
        assert!(
            result.is_err(),
            "open with wrong secret key must fail, but got Ok({:?})",
            result.ok()
        );
    }

    /// Empty info and empty aad are valid; the framing still protects them.
    #[test]
    fn test_hpke_empty_info_and_aad() {
        let (pk, sk) = keygen();
        let envelope = seal::<MlKem768, XChaCha20Poly1305>(&pk, b"", b"", b"payload")
            .expect("seal with empty info/aad must succeed");
        let recovered = open::<MlKem768, XChaCha20Poly1305>(&sk, b"", b"", &envelope)
            .expect("open with matching empty info/aad must succeed");
        assert_eq!(recovered, b"payload");
    }

    /// Empty public key is rejected before reaching the KEM.
    #[test]
    fn test_hpke_empty_pk_error() {
        let err = seal::<MlKem768, XChaCha20Poly1305>(b"", b"info", b"aad", b"pt");
        assert!(matches!(err, Err(CryptError::MissingPublicKey)));
    }

    /// Empty secret key is rejected before reaching the KEM.
    #[test]
    fn test_hpke_empty_sk_error() {
        let (pk, _sk) = keygen();
        let envelope =
            seal::<MlKem768, XChaCha20Poly1305>(&pk, b"i", b"a", b"pt").expect("seal must succeed");
        let err = open::<MlKem768, XChaCha20Poly1305>(b"", b"i", b"a", &envelope);
        assert!(matches!(err, Err(CryptError::MissingSecretKey)));
    }
}
