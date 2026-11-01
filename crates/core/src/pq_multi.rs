//! Multi-recipient PQ HPKE seal bound to the recipient set.
//!
//! # Responsibility scope
//! Encrypts one payload for many recipients (a group message, a shared file
//! key) with a single body ciphertext and one small key wrap per recipient,
//! and binds every part to the exact set of recipients. This module composes
//! [`crate::pq_hpke::HpkeEnvelope`] and ChaCha20-Poly1305; it defines no wire
//! container of its own beyond [`MultiRecipientCiphertext`]. The `*_cascade`
//! functions compose [`crate::pq_cascade`] instead (see "Cascade variant").
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
//! # Cascade variant ([`seal_multi_cascade`], [`open_multi_cascade`], [`dummy_cascade_wrap`])
//! The body uses a selectable [`crate::pq_cascade::Scheme`] (one or two AEAD
//! layers), the wraps are always [`crate::pq_cascade`] envelopes under
//! [`crate::pq_cascade::MAXIMAL_SUITE`], so every wrap looks the same whatever
//! the body scheme is:
//! ```text
//! set_hash = recipient_set_hash(fps)                  // unchanged
//! CEK      = 32 random bytes (TryOsRng), Zeroizing
//! wrap_pt  = WRAP_VERSION u8 ‖ scheme_id u8 ‖ CEK     // WRAP_PAYLOAD_LEN = 34 bytes
//! info_i   = "crypt_guard/v3/multi-recipient/wrap" ‖ lp32(info) ‖ set_hash ‖ fp_i   // unchanged
//! wrap_i   = pq_cascade::seal_envelope(MAXIMAL_SUITE, pk_i, info_i, header_aad, wrap_pt).try_to_bytes()
//! body     = Cascade::new(scheme, CEK, "crypt_guard/v3/multi-recipient/body")
//!                .seal_once(aad = header_aad ‖ set_hash, payload)         // |payload| + 32
//! ```
//! A wrap is `20 + 1665 + 34 + 32 = 1751` bytes for every scheme and for
//! [`dummy_cascade_wrap`]. [`open_multi_cascade`] opens the wrap (suite pinned
//! before decapsulation), checks the wrap version and scheme id, asks the
//! caller's `accept` callback whether that scheme is allowed (tenant minimum)
//! **before** the body is decrypted, and only then opens the body. The scheme
//! byte is bound into the body keys and AAD, so a manipulated scheme byte can
//! never open the body under another scheme. Every failure of
//! [`open_multi_cascade`] is the same opaque [`CryptError::AuthenticationFailed`].
//! Cascade and plain ([`seal_multi`]) ciphertexts are domain separated by the
//! envelope AAD and cannot be opened by the other family's functions.
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
//! - [`seal_multi_cascade`], [`open_multi_cascade`], [`dummy_cascade_wrap`],
//!   [`WRAP_PAYLOAD_LEN`] — the cascade variant.
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
//! The cascade functions add: [`CryptError::UnsupportedAlgorithm`] when the
//! sealing `suite` is not [`crate::pq_cascade::MAXIMAL_SUITE`], and
//! [`CryptError::AuthenticationFailed`] for **every** failure of
//! [`open_multi_cascade`] (including a wrong pinned suite, an out-of-range
//! `wrap_index`, an undecodable wrap, a bad wrap version or scheme id and
//! `accept` returning `false`), so a failed open reveals nothing.
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
use crate::pq_cascade::{self, Cascade, Scheme, MAXIMAL_SUITE};
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

/// Length in bytes of the plaintext sealed in every cascade wrap:
/// `WRAP_VERSION u8 ‖ scheme_id u8 ‖ CEK[32]`.
///
/// A cascade wrap ([`seal_multi_cascade`], [`dummy_cascade_wrap`]) is
/// therefore `20 + 1665 + 34 + 32 = 1751` bytes for every body scheme.
pub const WRAP_PAYLOAD_LEN: usize = 34;

/// Version byte of the cascade wrap plaintext.
const WRAP_VERSION: u8 = 1;

/// `pq_cascade` domain of the cascade body (keys, nonce and AAD context).
const MULTI_BODY: &[u8] = b"crypt_guard/v3/multi-recipient/body";

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

/// Draw the random filler of a [`dummy_cascade_wrap`] ([`WRAP_PAYLOAD_LEN`] bytes).
fn random_wrap_filler() -> Result<Zeroizing<[u8; WRAP_PAYLOAD_LEN]>, CryptError> {
    let mut out = Zeroizing::new([0u8; WRAP_PAYLOAD_LEN]);
    TryRng::try_fill_bytes(&mut TryOsRng, out.as_mut_slice())
        .map_err(|_| CryptError::CustomError(ENTROPY_UNAVAILABLE.to_owned()))?;
    Ok(out)
}

/// Build the cascade wrap plaintext `WRAP_VERSION ‖ scheme_id ‖ CEK`.
///
/// The buffer is allocated with its final capacity, so it never reallocates
/// (and never leaves an unwiped copy of the CEK behind), and it is wiped on drop.
fn wrap_payload(scheme: Scheme, cek: &[u8; CEK_LEN]) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(WRAP_PAYLOAD_LEN));
    out.push(WRAP_VERSION);
    out.push(scheme.id());
    out.extend_from_slice(cek);
    out
}

/// Parse a cascade wrap plaintext into the body scheme and the CEK.
///
/// Every defect (length, version byte, unknown scheme id) is the same opaque
/// [`CryptError::AuthenticationFailed`]; the plaintext is already authenticated
/// at this point, so a defect means a foreign or buggy sender, not a probe.
fn parse_wrap_payload(payload: &[u8]) -> Result<(Scheme, &[u8; CEK_LEN]), CryptError> {
    let (head, cek) = payload
        .split_first_chunk::<2>()
        .ok_or(CryptError::AuthenticationFailed)?;
    let [version, scheme_id] = *head;
    let cek: &[u8; CEK_LEN] = cek
        .try_into()
        .map_err(|_| CryptError::AuthenticationFailed)?;
    if version != WRAP_VERSION {
        return Err(CryptError::AuthenticationFailed);
    }
    let scheme = Scheme::from_id(scheme_id).ok_or(CryptError::AuthenticationFailed)?;
    Ok((scheme, cek))
}

/// Seal `payload` once for every recipient with a selectable body scheme.
///
/// # Description
/// Like [`seal_multi`], but the body is sealed with a [`Scheme`] (one or two
/// AEAD layers, always `payload + 32` bytes) and every wrap is a
/// [`pq_cascade::seal_envelope`] under [`MAXIMAL_SUITE`] whose plaintext is
/// `WRAP_VERSION ‖ scheme_id ‖ CEK` ([`WRAP_PAYLOAD_LEN`] = 34). All wraps are
/// 1 751 bytes whatever `scheme` is. The recipient-set binding, the `info`
/// layout and the body AAD (`header_aad ‖ set_hash`) are the same as for
/// [`seal_multi`]; the CEK is fresh per call and seals exactly one body
/// ([`Cascade::seal_once`] consumes the key schedule).
///
/// # Arguments
/// - `suite` (`Suite`): must be [`MAXIMAL_SUITE`]; every key must use its KEM.
/// - `scheme` (`Scheme`): body scheme; its id travels only inside the wraps.
/// - `recipients` (`&[&RecipientPublicKey]`): at least one, no duplicates.
///   `wraps[i]` belongs to `recipients[i]`.
/// - `header_aad` (`&[u8]`): public header authenticated by body and wraps.
/// - `info` (`&[u8]`): application context bound into every wrap.
/// - `payload` (`&[u8]`): the plaintext.
///
/// # Errors
/// - [`CryptError::UnsupportedAlgorithm`]: `suite` is not [`MAXIMAL_SUITE`].
/// - [`CryptError::InvalidParameters`]: empty or duplicate recipients, or
///   `info` too long.
/// - [`CryptError::InvalidKeyType`]: a key is for a different KEM than `suite`.
/// - [`CryptError::CustomError`] (fixed text): OS entropy failure while
///   drawing the CEK. The KEM encapsulation inside
///   [`pq_cascade::seal_envelope`] uses the `pq_hpke` sender RNG, as every
///   `pq_hpke` seal does (see `SECURITY.md`).
/// - Errors of [`Cascade::new`], [`Cascade::seal_once`] and
///   [`pq_cascade::seal_envelope`].
///
/// # Concurrency
/// Pure function apart from OS randomness; callable from any thread.
///
/// # Examples
/// ```rust
/// use crypt_guard_core::pq_cascade::{Scheme, MAXIMAL_SUITE};
/// use crypt_guard_core::pq_hpke::generate_recipient_key_pair;
/// use crypt_guard_core::pq_multi::{open_multi_cascade, seal_multi_cascade};
///
/// # fn main() -> Result<(), crypt_guard_core::error::CryptError> {
/// let bob = generate_recipient_key_pair(MAXIMAL_SUITE.kem())?;
/// let ct = seal_multi_cascade(
///     MAXIMAL_SUITE,
///     Scheme::Cascade,
///     &[bob.public_key()],
///     b"group=7;epoch=3",
///     b"chat/v1",
///     b"hello group",
/// )?;
/// let bob_fp = bob.public_key().fingerprint();
/// let (scheme, plain) = open_multi_cascade(
///     MAXIMAL_SUITE,
///     bob.private_key(),
///     &bob_fp,
///     &ct,
///     0,
///     b"group=7;epoch=3",
///     b"chat/v1",
///     &|scheme| scheme >= Scheme::Aes256GcmSiv, // tenant minimum
/// )?;
/// assert_eq!(scheme, Scheme::Cascade);
/// assert_eq!(&plain[..], b"hello group");
/// # Ok(())
/// # }
/// ```
pub fn seal_multi_cascade(
    suite: Suite,
    scheme: Scheme,
    recipients: &[&RecipientPublicKey],
    header_aad: &[u8],
    info: &[u8],
    payload: &[u8],
) -> Result<MultiRecipientCiphertext, CryptError> {
    if suite != MAXIMAL_SUITE {
        return Err(CryptError::UnsupportedAlgorithm);
    }
    let fingerprints: Vec<[u8; RECIPIENT_SET_HASH_LEN]> =
        recipients.iter().map(|pk| pk.fingerprint()).collect();
    let set_hash = recipient_set_hash(&fingerprints)?;

    let cek = random_bytes_32()?;
    let aad = body_aad(header_aad, &set_hash)?;
    // `seal_once` consumes the key schedule: this CEK seals this one body.
    let body = Cascade::new(scheme, &cek, MULTI_BODY)?.seal_once(&aad, payload)?;

    let wrap_pt = wrap_payload(scheme, &cek);
    let mut wraps = Vec::with_capacity(recipients.len());
    for (recipient, fingerprint) in recipients.iter().zip(fingerprints.iter()) {
        let info_i = wrap_info(info, &set_hash, fingerprint)?;
        let envelope = pq_cascade::seal_envelope(
            suite,
            recipient,
            &info_i,
            header_aad,
            wrap_pt.as_slice(),
        )?;
        wraps.push(envelope.try_to_bytes()?);
    }

    Ok(MultiRecipientCiphertext {
        body,
        wraps,
        recipient_set_hash: set_hash,
    })
}

/// Open a [`seal_multi_cascade`] ciphertext as one recipient.
///
/// # Description
/// Opens the wrap at `wrap_index` (the wire suite is pinned to `suite` before
/// decapsulation), checks `wrap_pt[0] == WRAP_VERSION` and
/// [`Scheme::from_id`]`(wrap_pt[1])`, calls `accept(scheme)` **before** the
/// body is touched (tenant minimum: return `false` to refuse a scheme that is
/// too weak), and then opens the body under that scheme.
///
/// # Arguments
/// - `suite` (`Suite`): the locally pinned suite; must be [`MAXIMAL_SUITE`].
/// - `recipient` (`&RecipientPrivateKey`): this recipient's private key.
/// - `my_fingerprint` (`&[u8; 32]`): [`RecipientPublicKey::fingerprint`] of
///   this recipient's own public key.
/// - `ct` (`&MultiRecipientCiphertext`): the received ciphertext.
/// - `wrap_index` (`usize`): position of this recipient's wrap.
/// - `header_aad`, `info`: exactly as passed to [`seal_multi_cascade`].
/// - `accept` (`&dyn Fn(Scheme) -> bool`): policy callback, called at most
///   once, only for a wrap that authenticated; it must not block.
///
/// # Returns
/// The scheme the sender used and the payload in zeroizing memory.
///
/// # Errors
/// - [`CryptError::AuthenticationFailed`]: **every** failure, deliberately
///   indistinguishable: wrong key, `info`, AAD, fingerprint or set hash, a
///   modified wrap or body, a wire suite other than the pinned one, a
///   `suite` argument other than [`MAXIMAL_SUITE`], an undecodable wrap,
///   `wrap_index` out of range, a bad wrap version or unknown scheme id, and
///   `accept` returning `false`. No partial plaintext is returned.
///
/// # Concurrency
/// Pure function; callable from any thread.
// The eight parameters are the contract signature (`cipher-suite-contract.md` 2.2.4).
#[allow(clippy::too_many_arguments)]
pub fn open_multi_cascade(
    suite: Suite,
    recipient: &RecipientPrivateKey,
    my_fingerprint: &[u8; RECIPIENT_SET_HASH_LEN],
    ct: &MultiRecipientCiphertext,
    wrap_index: usize,
    header_aad: &[u8],
    info: &[u8],
    accept: &dyn Fn(Scheme) -> bool,
) -> Result<(Scheme, Zeroizing<Vec<u8>>), CryptError> {
    // One funnel: whatever went wrong inside, the caller sees the same error.
    open_multi_cascade_inner(
        suite,
        recipient,
        my_fingerprint,
        ct,
        wrap_index,
        header_aad,
        info,
        accept,
    )
    .map_err(|_| CryptError::AuthenticationFailed)
}

/// Fallible core of [`open_multi_cascade`]; its error is collapsed by the caller.
#[allow(clippy::too_many_arguments)]
fn open_multi_cascade_inner(
    suite: Suite,
    recipient: &RecipientPrivateKey,
    my_fingerprint: &[u8; RECIPIENT_SET_HASH_LEN],
    ct: &MultiRecipientCiphertext,
    wrap_index: usize,
    header_aad: &[u8],
    info: &[u8],
    accept: &dyn Fn(Scheme) -> bool,
) -> Result<(Scheme, Zeroizing<Vec<u8>>), CryptError> {
    if suite != MAXIMAL_SUITE {
        return Err(CryptError::AuthenticationFailed);
    }
    let wrap = ct
        .wraps
        .get(wrap_index)
        .ok_or(CryptError::AuthenticationFailed)?;
    let envelope = HpkeEnvelope::from_bytes(wrap)?;
    let info_i = wrap_info(info, &ct.recipient_set_hash, my_fingerprint)?;
    // Pins the wire suite before decapsulation.
    let wrap_pt = pq_cascade::open_envelope(suite, &envelope, recipient, &info_i, header_aad)?;
    let (scheme, cek) = parse_wrap_payload(wrap_pt.as_slice())?;
    if !accept(scheme) {
        return Err(CryptError::AuthenticationFailed);
    }
    let aad = body_aad(header_aad, &ct.recipient_set_hash)?;
    let body = Cascade::new(scheme, cek, MULTI_BODY)?.open_once(&aad, &ct.body)?;
    Ok((scheme, body))
}

/// Produce a random-looking cascade wrap of the same size as a real one.
///
/// # Description
/// Seals [`WRAP_PAYLOAD_LEN`] (34) random bytes with
/// [`pq_cascade::seal_envelope`] to a throwaway key pair derived from a fresh
/// [`TryOsRng`] seed and discarded immediately. The result is byte-length equal
/// (1 751) and header-identical to every real wrap of [`seal_multi_cascade`];
/// nobody can open it. Use it to pad [`MultiRecipientCiphertext::wraps`] to a
/// fixed count.
///
/// # Arguments
/// - `suite` (`Suite`): must be [`MAXIMAL_SUITE`].
///
/// # Errors
/// - [`CryptError::UnsupportedAlgorithm`]: `suite` is not [`MAXIMAL_SUITE`].
/// - [`CryptError::CustomError`] (fixed text): OS entropy failure.
/// - Mapped [`crate::pq_hpke::Error`] values from key derivation or sealing.
///
/// # Concurrency
/// Pure function apart from OS randomness; callable from any thread.
pub fn dummy_cascade_wrap(suite: Suite) -> Result<Vec<u8>, CryptError> {
    if suite != MAXIMAL_SUITE {
        return Err(CryptError::UnsupportedAlgorithm);
    }
    let seed = random_bytes_32()?;
    let seed: &[u8; RECIPIENT_SEED_LEN] = &seed;
    let throwaway = derive_recipient_key_pair(suite.kem(), seed)?;
    let filler = random_wrap_filler()?;
    let envelope = pq_cascade::seal_envelope(
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

    const ALL_SCHEMES: [Scheme; 4] = [
        Scheme::ChaCha20Poly1305,
        Scheme::Aes256GcmSiv,
        Scheme::XChaCha20Poly1305,
        Scheme::Cascade,
    ];

    #[test]
    fn wrap_payload_len_is_version_scheme_and_cek() {
        assert_eq!(WRAP_PAYLOAD_LEN, 1 + 1 + CEK_LEN);
        assert_eq!(WRAP_PAYLOAD_LEN, 34);
        assert_eq!(WRAP_VERSION, 1);
    }

    #[test]
    fn wrap_payload_layout_and_round_trip() -> TestResult {
        let cek = [0x5Au8; CEK_LEN];
        for scheme in ALL_SCHEMES {
            let payload = wrap_payload(scheme, &cek);
            assert_eq!(payload.len(), WRAP_PAYLOAD_LEN);
            assert_eq!(payload.first().copied(), Some(WRAP_VERSION));
            assert_eq!(payload.get(1).copied(), Some(scheme.id()));
            assert_eq!(payload.get(2..), Some(cek.as_slice()));
            let (parsed, parsed_cek) = parse_wrap_payload(payload.as_slice())?;
            assert_eq!(parsed, scheme);
            assert_eq!(parsed_cek, &cek);
        }
        Ok(())
    }

    #[test]
    fn parse_wrap_payload_rejects_every_defect_opaquely() {
        let good = wrap_payload(Scheme::Cascade, &[0x11u8; CEK_LEN]);
        let mut cases: Vec<Vec<u8>> = vec![Vec::new(), vec![WRAP_VERSION], vec![WRAP_VERSION, 4]];
        // Wrong lengths (one byte short, one byte long).
        cases.push(good.iter().copied().take(WRAP_PAYLOAD_LEN - 1).collect());
        let mut long = good.to_vec();
        long.push(0x11);
        cases.push(long);
        // Wrong version bytes.
        for version in [0u8, 2, 0xFF] {
            let mut bad = good.to_vec();
            if let Some(first) = bad.first_mut() {
                *first = version;
            }
            cases.push(bad);
        }
        // Unknown scheme ids (0 and everything above the four defined ones).
        for id in [0u8, 5, 15, 0xFF] {
            let mut bad = good.to_vec();
            if let Some(second) = bad.get_mut(1) {
                *second = id;
            }
            cases.push(bad);
        }
        for case in cases {
            assert!(
                matches!(
                    parse_wrap_payload(&case),
                    Err(CryptError::AuthenticationFailed)
                ),
                "defective wrap payload of {} bytes was accepted",
                case.len()
            );
        }
    }
}
