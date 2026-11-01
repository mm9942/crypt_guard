//! Multi-recipient PQ HPKE seal bound to the recipient set.
//!
//! # Responsibility scope
//! Encrypts one payload for many recipients (a group message, a shared file
//! key) with a single body ciphertext and one small key wrap per recipient,
//! and binds every part to the exact set of recipients. This module composes
//! [`crate::pq_hpke::HpkeEnvelope`] and ChaCha20-Poly1305; it defines no wire
//! container of its own beyond [`MultiRecipientCiphertext`].
//!
//! # Construction
//! ```text
//! set_hash = SHA3-256("crypt_guard/v3/recipient-set" ‖ u32_be(n) ‖ sort(fp_1 … fp_n))
//! CEK      = 32 random bytes (TryOsRng), used for exactly one body
//! body     = ChaCha20-Poly1305(CEK, nonce = 0^12, aad = header_aad ‖ set_hash, payload)
//! info_i   = "crypt_guard/v3/multi-recipient/wrap" ‖ lp32(info) ‖ set_hash ‖ fp_i
//! wrap_i   = HpkeEnvelope::seal(suite, pk_i, info_i, aad = header_aad, CEK).to_bytes()
//! ```
//! `fp_i` is [`RecipientPublicKey::fingerprint`]. The set hash is
//! order-independent (the fingerprints are sorted), so every member can
//! recompute it from its own view of the membership; duplicates are rejected.
//!
//! The all-zero body nonce is safe **only** because every CEK is fresh,
//! random and encrypts a single body; never reuse a CEK.
//!
//! # Security properties
//! - A wrap opens only with the recipient's key, the same `info`, the same
//!   `header_aad`, the same set hash and the recipient's own fingerprint.
//! - Changing the recipient set, the header or the body makes opening fail.
//! - The set hash is authenticated as *the sender's claim*. To check it
//!   against the group you expect, call
//!   [`MultiRecipientCiphertext::check_recipient_set`].
//! - This is not sender authentication: anyone holding the recipients'
//!   public keys can produce a valid ciphertext. Sign the result (for
//!   example with [`crate::signed_hpke`] or ML-DSA) where that matters.
//! - [`dummy_wrap`] produces wraps of the same size as real ones, to pad the
//!   visible recipient count. Shuffle real and dummy wraps if their position
//!   must not reveal anything, and tell each recipient its index out of band.
//!
//! # Key types exported
//! - [`MultiRecipientCiphertext`] — body, wraps and recipient-set hash.
//! - [`seal_multi`], [`open_multi`], [`recipient_set_hash`], [`dummy_wrap`].
//!
//! # Concurrency
//! Pure functions apart from OS randomness; callable from any thread.
//!
//! # Errors
//! All functions return [`CryptError`]:
//! - [`CryptError::InvalidParameters`]: empty or duplicate recipient set,
//!   wrap index out of range, `info` too long for its length prefix.
//! - [`CryptError::AuthenticationFailed`]: any open failure (wrong key, `info`,
//!   AAD, set hash, or modified wrap/body). Opaque by design.
//! - [`CryptError::UnsupportedAlgorithm`]: wrap suite differs from the pinned suite.
//! - [`CryptError::InvalidEnvelope`]: a wrap does not decode.
//! - Other mapped [`crate::pq_hpke::Error`] values (for example a key for a
//!   different KEM, [`CryptError::InvalidKeyType`]).
//!
//! # Examples
//! ```rust
//! use crypt_guard_core::pq_hpke::{generate_recipient_key_pair, DEFAULT_SUITE};
//! use crypt_guard_core::pq_multi::{open_multi, seal_multi};
//!
//! # fn main() -> Result<(), crypt_guard_core::error::CryptError> {
//! let alice = generate_recipient_key_pair(DEFAULT_SUITE.kem())?;
//! let bob = generate_recipient_key_pair(DEFAULT_SUITE.kem())?;
//! let ct = seal_multi(
//!     DEFAULT_SUITE,
//!     &[alice.public_key(), bob.public_key()],
//!     b"group=7;epoch=3",
//!     b"chat/v1",
//!     b"hello group",
//! )?;
//! let bob_fp = bob.public_key().fingerprint();
//! let plain = open_multi(
//!     DEFAULT_SUITE, bob.private_key(), &bob_fp, &ct, 1, b"group=7;epoch=3", b"chat/v1",
//! )?;
//! assert_eq!(&plain[..], b"hello group");
//! # Ok(())
//! # }
//! ```

// Panic-freedom contract: see SECURITY.md
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use sha3::{Digest, Sha3_256};
use zeroize::Zeroizing;

use crate::error::CryptError;
use crate::kem::backend::rand_core_010::TryRng;
use crate::kem::backend::TryOsRng;
use crate::pq_hpke::{
    derive_recipient_key_pair, HpkeEnvelope, RecipientPrivateKey, RecipientPublicKey, Suite,
    RECIPIENT_SEED_LEN,
};

/// Length in bytes of the content-encryption key carried in every wrap.
pub const CEK_LEN: usize = 32;

/// Length in bytes of a recipient fingerprint and of the recipient-set hash.
pub const RECIPIENT_SET_HASH_LEN: usize = 32;

/// Domain label of [`recipient_set_hash`].
const RECIPIENT_SET_LABEL: &[u8] = b"crypt_guard/v3/recipient-set";

/// Domain label prefixed to the HPKE `info` of every wrap.
const WRAP_INFO_LABEL: &[u8] = b"crypt_guard/v3/multi-recipient/wrap";

/// HPKE `info` of a [`dummy_wrap`]; nobody can open it, so it binds nothing.
const DUMMY_INFO: &[u8] = b"crypt_guard/v3/multi-recipient/dummy";

/// Body nonce. Safe only because each CEK is random and seals exactly one body.
const BODY_NONCE: [u8; 12] = [0u8; 12];

/// Fixed error text for an unavailable OS entropy source (no secret data).
const ENTROPY_UNAVAILABLE: &str = "os entropy source unavailable";

/// One payload encrypted for a set of recipients.
///
/// # Description
/// - `body`: ChaCha20-Poly1305 ciphertext of the payload under the CEK.
/// - `wraps`: one [`HpkeEnvelope`] encoding per recipient, in the order of
///   the `recipients` passed to [`seal_multi`]; [`dummy_wrap`]s may be
///   appended or mixed in.
/// - `recipient_set_hash`: [`recipient_set_hash`] of the recipients'
///   fingerprints, authenticated by every wrap and by the body.
///
/// All fields are public data; the type carries no secrets.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MultiRecipientCiphertext {
    /// Payload ciphertext and tag.
    pub body: Vec<u8>,
    /// One serialized [`HpkeEnvelope`] per recipient (plus optional dummies).
    pub wraps: Vec<Vec<u8>>,
    /// Hash of the sorted recipient fingerprints.
    pub recipient_set_hash: [u8; RECIPIENT_SET_HASH_LEN],
}

impl MultiRecipientCiphertext {
    /// Check that this ciphertext was sealed for exactly `fingerprints`.
    ///
    /// # Description
    /// Recomputes [`recipient_set_hash`] from the caller's expected membership
    /// (any order) and compares it with the embedded hash. Call it before or
    /// after [`open_multi`] when the group membership matters.
    ///
    /// # Errors
    /// - [`CryptError::InvalidParameters`]: `fingerprints` empty or with duplicates.
    /// - [`CryptError::AuthenticationFailed`]: the sets differ.
    pub fn check_recipient_set(
        &self,
        fingerprints: &[[u8; RECIPIENT_SET_HASH_LEN]],
    ) -> Result<(), CryptError> {
        if recipient_set_hash(fingerprints)? == self.recipient_set_hash {
            Ok(())
        } else {
            Err(CryptError::AuthenticationFailed)
        }
    }
}

/// Hash a set of recipient fingerprints, independent of their order.
///
/// # Description
/// `SHA3-256("crypt_guard/v3/recipient-set" ‖ u32_be(n) ‖ fp_(1) ‖ … ‖ fp_(n))`
/// over the fingerprints sorted in ascending byte order.
///
/// # Errors
/// - [`CryptError::InvalidParameters`]: the set is empty, contains a
///   duplicate fingerprint, or has more than `u32::MAX` members.
pub fn recipient_set_hash(
    fingerprints: &[[u8; RECIPIENT_SET_HASH_LEN]],
) -> Result<[u8; RECIPIENT_SET_HASH_LEN], CryptError> {
    if fingerprints.is_empty() {
        return Err(CryptError::InvalidParameters);
    }
    let count = u32::try_from(fingerprints.len()).map_err(|_| CryptError::InvalidParameters)?;
    let mut sorted = fingerprints.to_vec();
    sorted.sort_unstable();
    if sorted
        .windows(2)
        .any(|pair| matches!(pair, [a, b] if a == b))
    {
        return Err(CryptError::InvalidParameters);
    }
    let mut h = Sha3_256::new();
    Digest::update(&mut h, RECIPIENT_SET_LABEL);
    Digest::update(&mut h, count.to_be_bytes());
    for fingerprint in &sorted {
        Digest::update(&mut h, fingerprint);
    }
    Ok(h.finalize().into())
}

/// Build `WRAP_INFO_LABEL ‖ lp32(info) ‖ set_hash ‖ fingerprint`.
fn wrap_info(
    info: &[u8],
    set_hash: &[u8; RECIPIENT_SET_HASH_LEN],
    fingerprint: &[u8; RECIPIENT_SET_HASH_LEN],
) -> Result<Vec<u8>, CryptError> {
    let info_len = u32::try_from(info.len()).map_err(|_| CryptError::InvalidParameters)?;
    let capacity = WRAP_INFO_LABEL
        .len()
        .checked_add(4)
        .and_then(|n| n.checked_add(info.len()))
        .and_then(|n| n.checked_add(2 * RECIPIENT_SET_HASH_LEN))
        .ok_or(CryptError::InvalidParameters)?;
    let mut out = Vec::with_capacity(capacity);
    out.extend_from_slice(WRAP_INFO_LABEL);
    out.extend_from_slice(&info_len.to_be_bytes());
    out.extend_from_slice(info);
    out.extend_from_slice(set_hash);
    out.extend_from_slice(fingerprint);
    Ok(out)
}

/// Build the body AAD `header_aad ‖ set_hash` (the hash has a fixed length,
/// so the concatenation is unambiguous).
fn body_aad(
    header_aad: &[u8],
    set_hash: &[u8; RECIPIENT_SET_HASH_LEN],
) -> Result<Vec<u8>, CryptError> {
    let capacity = header_aad
        .len()
        .checked_add(RECIPIENT_SET_HASH_LEN)
        .ok_or(CryptError::InvalidParameters)?;
    let mut out = Vec::with_capacity(capacity);
    out.extend_from_slice(header_aad);
    out.extend_from_slice(set_hash);
    Ok(out)
}

fn random_bytes_32() -> Result<Zeroizing<[u8; 32]>, CryptError> {
    let mut out = Zeroizing::new([0u8; 32]);
    TryRng::try_fill_bytes(&mut TryOsRng, out.as_mut_slice())
        .map_err(|_| CryptError::CustomError(ENTROPY_UNAVAILABLE.to_owned()))?;
    Ok(out)
}

/// Seal `payload` once for every recipient in `recipients`.
///
/// # Arguments
/// - `suite` (`Suite`): the pinned HPKE suite; every key must use its KEM.
/// - `recipients` (`&[&RecipientPublicKey]`): at least one, no duplicates.
///   `wraps[i]` belongs to `recipients[i]`.
/// - `header_aad` (`&[u8]`): public header authenticated by body and wraps
///   (group id, epoch, message id, ...).
/// - `info` (`&[u8]`): HPKE application context, as for [`HpkeEnvelope::seal`].
/// - `payload` (`&[u8]`): the plaintext.
///
/// # Errors
/// - [`CryptError::InvalidParameters`]: empty or duplicate recipients, or
///   `info` too long.
/// - [`CryptError::InvalidKeyType`]: a key is for a different KEM than `suite`.
/// - [`CryptError::EncryptionFailed`]: the body AEAD refused the payload.
/// - [`CryptError::CustomError`] (fixed text): OS entropy failure while
///   drawing the CEK. The KEM encapsulation inside [`HpkeEnvelope::seal`]
///   uses the `pq_hpke` sender RNG, as every `pq_hpke` seal does.
pub fn seal_multi(
    suite: Suite,
    recipients: &[&RecipientPublicKey],
    header_aad: &[u8],
    info: &[u8],
    payload: &[u8],
) -> Result<MultiRecipientCiphertext, CryptError> {
    let fingerprints: Vec<[u8; RECIPIENT_SET_HASH_LEN]> =
        recipients.iter().map(|pk| pk.fingerprint()).collect();
    let set_hash = recipient_set_hash(&fingerprints)?;

    let cek = random_bytes_32()?;
    let aad = body_aad(header_aad, &set_hash)?;
    let key: &Key = (&*cek).into();
    let body_nonce = BODY_NONCE;
    let nonce: &Nonce = (&body_nonce).into();
    let body = ChaCha20Poly1305::new(key)
        .encrypt(
            nonce,
            Payload {
                msg: payload,
                aad: &aad,
            },
        )
        .map_err(|_| CryptError::EncryptionFailed)?;

    let mut wraps = Vec::with_capacity(recipients.len());
    for (recipient, fingerprint) in recipients.iter().zip(fingerprints.iter()) {
        let info_i = wrap_info(info, &set_hash, fingerprint)?;
        let envelope = HpkeEnvelope::seal(suite, recipient, &info_i, header_aad, cek.as_slice())?;
        wraps.push(envelope.try_to_bytes()?);
    }

    Ok(MultiRecipientCiphertext {
        body,
        wraps,
        recipient_set_hash: set_hash,
    })
}

/// Open the wrap at `wrap_index` with `recipient` and decrypt the body.
///
/// # Arguments
/// - `suite` (`Suite`): the locally pinned suite; a wrap with any other wire
///   suite is rejected before decapsulation.
/// - `recipient` (`&RecipientPrivateKey`): this recipient's private key.
/// - `my_fingerprint` (`&[u8; 32]`): [`RecipientPublicKey::fingerprint`] of
///   this recipient's own public key.
/// - `ct` (`&MultiRecipientCiphertext`): the received ciphertext.
/// - `wrap_index` (`usize`): position of this recipient's wrap.
/// - `header_aad`, `info`: exactly as passed to [`seal_multi`].
///
/// # Returns
/// The payload in zeroizing memory.
///
/// # Errors
/// - [`CryptError::InvalidParameters`]: `wrap_index` out of range.
/// - [`CryptError::InvalidEnvelope`] / [`CryptError::UnsupportedEnvelopeVersion`]:
///   the wrap does not decode.
/// - [`CryptError::UnsupportedAlgorithm`]: the wrap's suite is not `suite`.
/// - [`CryptError::AuthenticationFailed`]: wrong key, `info`, AAD, fingerprint
///   or set hash, or a modified wrap or body.
pub fn open_multi(
    suite: Suite,
    recipient: &RecipientPrivateKey,
    my_fingerprint: &[u8; RECIPIENT_SET_HASH_LEN],
    ct: &MultiRecipientCiphertext,
    wrap_index: usize,
    header_aad: &[u8],
    info: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptError> {
    let wrap = ct
        .wraps
        .get(wrap_index)
        .ok_or(CryptError::InvalidParameters)?;
    let envelope = HpkeEnvelope::from_bytes(wrap)?;
    let info_i = wrap_info(info, &ct.recipient_set_hash, my_fingerprint)?;
    let cek = envelope.open_pinned_zeroizing(suite, recipient, &info_i, header_aad)?;
    let cek: &[u8; CEK_LEN] = cek
        .as_slice()
        .try_into()
        .map_err(|_| CryptError::AuthenticationFailed)?;

    let aad = body_aad(header_aad, &ct.recipient_set_hash)?;
    let key: &Key = cek.into();
    let body_nonce = BODY_NONCE;
    let nonce: &Nonce = (&body_nonce).into();
    ChaCha20Poly1305::new(key)
        .decrypt(
            nonce,
            Payload {
                msg: &ct.body,
                aad: &aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| CryptError::AuthenticationFailed)
}

/// Produce a random-looking wrap of the same size as a real one for `suite`.
///
/// # Description
/// Seals a random 32-byte value to a throwaway key pair derived from a fresh
/// [`TryOsRng`] seed and discarded immediately. Without the throwaway key the
/// result is indistinguishable from a real wrap; no one can open it. Use it
/// to pad [`MultiRecipientCiphertext::wraps`] to a fixed count.
///
/// # Errors
/// - [`CryptError::CustomError`] (fixed text): OS entropy failure.
/// - Mapped [`crate::pq_hpke::Error`] values if `suite` cannot seal (for
///   example an Export-Only AEAD).
pub fn dummy_wrap(suite: Suite) -> Result<Vec<u8>, CryptError> {
    let seed = random_bytes_32()?;
    let seed: &[u8; RECIPIENT_SEED_LEN] = &seed;
    let throwaway = derive_recipient_key_pair(suite.kem(), seed)?;
    let filler = random_bytes_32()?;
    let envelope = HpkeEnvelope::seal(
        suite,
        throwaway.public_key(),
        DUMMY_INFO,
        b"",
        filler.as_slice(),
    )?;
    Ok(envelope.try_to_bytes()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), CryptError>;

    #[test]
    fn recipient_set_hash_known_answer_and_order_independence() -> TestResult {
        // python3: sha3_256(b"crypt_guard/v3/recipient-set" + be32(3)
        //                   + b"\x11"*32 + b"\x22"*32 + b"\x33"*32)
        let expected = "6a8745ab84032280632a2eb0ee12b89eedc0b1b1d32f78e56a1ecba9ffd7bbba";
        let a = recipient_set_hash(&[[0x33; 32], [0x11; 32], [0x22; 32]])?;
        let b = recipient_set_hash(&[[0x11; 32], [0x22; 32], [0x33; 32]])?;
        assert_eq!(hex::encode(a), expected);
        assert_eq!(a, b);
        Ok(())
    }

    #[test]
    fn recipient_set_hash_rejects_empty_and_duplicates() {
        assert!(matches!(
            recipient_set_hash(&[]),
            Err(CryptError::InvalidParameters)
        ));
        assert!(matches!(
            recipient_set_hash(&[[1; 32], [2; 32], [1; 32]]),
            Err(CryptError::InvalidParameters)
        ));
    }

    #[test]
    fn wrap_info_layout() -> TestResult {
        let info = wrap_info(b"ctx", &[0xAA; 32], &[0xBB; 32])?;
        let mut expected = WRAP_INFO_LABEL.to_vec();
        expected.extend_from_slice(&[0, 0, 0, 3]);
        expected.extend_from_slice(b"ctx");
        expected.extend_from_slice(&[0xAA; 32]);
        expected.extend_from_slice(&[0xBB; 32]);
        assert_eq!(info, expected);
        Ok(())
    }
}
