//! Two-layer "cascade" AEAD and the "Maximal" HPKE cascade envelope.
//!
//! # Responsibility scope
//! Owns every raw AEAD call that an application needs on top of
//! [`crate::pq_hpke`]: a keyed, domain-separated AEAD with a fixed overhead of
//! 32 bytes for **every** scheme ([`Cascade`]), a random-nonce mode for values
//! at rest ([`seal_random`] / [`open_random`]), and a two-layer HPKE envelope
//! with a single KEM encapsulation ([`seal_envelope`] / [`open_envelope`],
//! [`CascadeSealer`] / [`CascadeOpener`]). It defines no wire container of its
//! own: the envelope is an ordinary [`crate::pq_hpke::HpkeEnvelope`] (`CGH3`)
//! under [`MAXIMAL_SUITE`]. Nothing in `pq_hpke`, `pq_stream` or
//! [`crate::pq_hpke::DEFAULT_SUITE`] changes.
//!
//! # Schemes
//! | [`Scheme`] | id | layers | ciphertext |
//! |---|---|---|---|
//! | `ChaCha20Poly1305` | 1 | 1 | `pt ‖ 0^16` under ChaCha20-Poly1305, `\|pt\| + 32` |
//! | `Aes256GcmSiv` | 2 | 1 | `pt ‖ 0^16` under AES-256-GCM-SIV, `\|pt\| + 32` |
//! | `XChaCha20Poly1305` | 3 | 1 | `pt ‖ 0^16` under XChaCha20-Poly1305, `\|pt\| + 32` |
//! | `Cascade` | 4 | 2 | inner AES-256-GCM-SIV(`pt`), outer XChaCha20-Poly1305(`inner`), `\|pt\| + 32` |
//!
//! Every scheme expands the plaintext by exactly [`CASCADE_OVERHEAD`] = 32
//! bytes, so an observer of the ciphertext length cannot tell the schemes
//! apart. Single-layer schemes append 16 zero bytes of authenticated filler
//! *inside* the AEAD; after a successful AEAD check the filler is verified to
//! be zero, otherwise the open fails.
//!
//! # Construction
//! ```text
//! lp32(x)  = u32_be(len(x)) ‖ x
//! ctx      = scheme_id u8 ‖ lp32(domain)
//! k_in     = prf32(root, "crypt_guard/v3/cascade/inner",  ctx)
//! k_out    = prf32(root, "crypt_guard/v3/cascade/outer",  ctx)
//! k_one    = prf32(root, "crypt_guard/v3/cascade/single", ctx)
//! n24      = nonce (see below); AES-GCM-SIV / ChaCha20-Poly1305 use n24[..12]
//! aad_x    = "crypt_guard/v3/cascade/aad/{inner|outer|single}" ‖ ctx ‖ aad
//! Cascade  : inner = AES-256-GCM-SIV(k_in, n24, aad_in, pt)
//!            ct    = XChaCha20-Poly1305(k_out, n24, aad_out, inner)
//! single   : ct    = AEAD(k_one, n24, aad_one, pt ‖ 0^16)
//! ```
//! The scheme id is part of both the key derivation and the AAD of every
//! layer, so a ciphertext of one scheme never opens under another scheme, and
//! a manipulated level byte cannot downgrade anything. Opening always checks
//! the outer layer first; a forged ciphertext never reaches the inner layer.
//!
//! ## Nonces
//! | Mode | `n24` | Uniqueness |
//! |---|---|---|
//! | [`Cascade::seal_once`] | `prf(root, "…/nonce", ctx, 24)` | the root key seals exactly one message; `seal_once` **consumes** the [`Cascade`] |
//! | [`CascadeNonce::Counter`] | `domain ‖ 0 0 0 ‖ n u64 BE ‖ 0^12` | caller (atomic sequence number, key per direction) |
//! | [`CascadeNonce::Stream`] | `prefix ‖ index u32 BE ‖ last u8 ‖ 0^12` | caller (chunk index, key per file) |
//! | [`seal_random`] | 192 random bits, sent as prefix `n24 ‖ ct` | random; `n24` is bound into key and AAD |
//!
//! Uniqueness of `Counter` and `Stream` nonces is the caller's duty; the
//! library cannot check it. AES-256-GCM-SIV and the inner layer of the cascade
//! tolerate a repeat (they leak only equality), the single-layer ChaCha20 and
//! XChaCha20 schemes do not.
//!
//! ## HPKE cascade envelope
//! ```text
//! (enc, ctx) = setup_base_sender_inner(MAXIMAL_SUITE, pk, info)       // one encapsulation
//! k_in       = ctx.export("crypt_guard/v3/cascade/hpke/inner-key",   32)
//! n_in       = ctx.export("crypt_guard/v3/cascade/hpke/inner-nonce", 12)
//! inner      = AES-256-GCM-SIV(k_in, n_in, "…/hpke/aad/inner" ‖ lp32(aad), pt)   // |pt| + 16
//! outer      = ctx.seal("…/hpke/aad/outer" ‖ lp32(aad), inner)                   // |pt| + 32
//! envelope   = HpkeEnvelope::new(MAXIMAL_SUITE, enc, outer)
//! ```
//! The fixed inner nonce is safe only because one KEM encapsulation seals
//! exactly **one** inner layer; [`seal_envelope`] and [`CascadeSealer`] enforce
//! that. An envelope is indistinguishable from an ordinary [`MAXIMAL_SUITE`]
//! `HpkeEnvelope` whose plaintext is `|pt| + 16` bytes long.
//!
//! # Key types exported
//! - [`MAXIMAL_SUITE`] and the size constants [`KEY_LEN`], [`TAG_LEN`],
//!   [`CASCADE_OVERHEAD`], [`NONCE_LEN`].
//! - [`Scheme`], [`CascadeNonce`], [`Cascade`].
//! - [`seal_random`], [`open_random`].
//! - [`seal_envelope`], [`open_envelope`], [`CascadeSealer`], [`CascadeOpener`].
//!
//! # Secrets and zeroization
//! [`Cascade`] holds its sub-keys in [`Zeroizing`] arrays, is not `Clone`, and
//! prints a redacted `Debug`. Raw AEAD objects are created per call from those
//! bytes; they wipe their keys on drop (`chacha20poly1305`) or hold an AES key
//! schedule that is wiped with the `zeroize` feature of `aes`. Buffers that
//! briefly hold plaintext are [`Zeroizing`]. Known gap of a third-party crate:
//! `aes-gcm-siv` derives per-nonce sub-keys inside a `polyval::Polyval` that is
//! not reliably wiped (its optional `zeroize` feature is off by default and,
//! even when on, has no effect on the `x86`/`x86_64` hardware backend of
//! `polyval` 0.6.2; see `SECURITY.md`), so those message-specific sub-keys
//! (not `root`, not `k_in`) can remain in freed stack memory.
//!
//! # Concurrency
//! Pure functions apart from OS randomness. [`Cascade`] has no interior state,
//! is `Send + Sync` and may be shared as `Arc<Cascade>` by many tasks; the
//! consuming [`Cascade::seal_once`] is deliberately not callable through an
//! `Arc`. [`CascadeSealer`] and [`CascadeOpener`] are single-owner state
//! machines (`&mut self`).
//!
//! # Errors
//! All functions return [`CryptError`]:
//! - [`CryptError::AuthenticationFailed`]: every failed *open* (wrong key,
//!   domain, scheme, nonce, AAD, filler, truncated or modified bytes, wrong
//!   wire suite, wrong HPKE `info`). One opaque error on purpose.
//! - [`CryptError::InvalidParameters`]: programmer errors (all-zero root,
//!   empty domain, wrong in-place buffer length, all-zero stream prefix, a
//!   second [`CascadeSealer::seal`], a reserved exporter context).
//! - [`CryptError::UnsupportedAlgorithm`]: a suite other than [`MAXIMAL_SUITE`]
//!   was requested, or a context with a non-XChaCha20-Poly1305 AEAD was wrapped.
//! - [`CryptError::CustomError`] (fixed text): OS entropy failure.
//! - Mapped [`crate::pq_hpke::Error`] values from the sealing side (for example
//!   [`CryptError::InvalidKeyType`] for a key of another KEM). The KEM
//!   encapsulation inside [`seal_envelope`] uses the `pq_hpke` sender RNG, like
//!   every `pq_hpke` seal (see `SECURITY.md`).
//!
//! Errors never carry key or plaintext bytes.
//!
//! # Examples
//! ```rust
//! use crypt_guard_core::pq_cascade::{Cascade, CascadeNonce, Scheme};
//!
//! # fn main() -> Result<(), crypt_guard_core::error::CryptError> {
//! let root = [0x42u8; 32];
//! // One message per root key: `seal_once` consumes the `Cascade`.
//! let sealed = Cascade::new(Scheme::Cascade, &root, b"example/body/v1")?
//!     .seal_once(b"header", b"hello")?;
//! assert_eq!(sealed.len(), 5 + 32);
//! let plain = Cascade::new(Scheme::Cascade, &root, b"example/body/v1")?
//!     .open_once(b"header", &sealed)?;
//! assert_eq!(&plain[..], b"hello");
//!
//! // Many messages under one key: the caller supplies a unique nonce.
//! let frames = Cascade::new(Scheme::XChaCha20Poly1305, &root, b"example/frame/v1")?;
//! let nonce = CascadeNonce::Counter { domain: 1, n: 7 };
//! let frame = frames.seal(&nonce, b"", b"payload")?;
//! assert_eq!(&frames.open(&nonce, b"", &frame)?[..], b"payload");
//! # Ok(())
//! # }
//! ```
//!
//! ```rust
//! use crypt_guard_core::pq_cascade::{open_envelope, seal_envelope, MAXIMAL_SUITE};
//! use crypt_guard_core::pq_hpke::generate_recipient_key_pair;
//!
//! # fn main() -> Result<(), crypt_guard_core::error::CryptError> {
//! let keys = generate_recipient_key_pair(MAXIMAL_SUITE.kem())?;
//! let envelope = seal_envelope(MAXIMAL_SUITE, keys.public_key(), b"info", b"aad", b"payload")?;
//! let plain = open_envelope(MAXIMAL_SUITE, &envelope, keys.private_key(), b"info", b"aad")?;
//! assert_eq!(&plain[..], b"payload");
//! # Ok(())
//! # }
//! ```

// Panic-freedom contract: see SECURITY.md
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

use core::fmt;

use aes_gcm_siv::{Aes256GcmSiv, Nonce as SivNonce, Tag as SivTag};
use chacha20poly1305::{
    aead::{AeadInPlace, KeyInit},
    ChaCha20Poly1305, Nonce as ChaChaNonce, Tag as ChaChaTag, XChaCha20Poly1305, XNonce,
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::CryptError;
use crate::kem::backend::rand_core_010::TryRng;
use crate::kem::backend::TryOsRng;
use crate::pq_hpke::{
    setup_base_receiver_inner, setup_base_sender_inner, Aead, Encapsulation, HpkeEnvelope, Kdf,
    Kem, RecipientContext, RecipientPrivateKey, RecipientPublicKey, SenderContext, Suite,
};
use crate::prf::{prf, prf32};

/// The "Maximal" suite: `(MlKem1024P384, Shake256, XChaCha20Poly1305)`, wire ids
/// `(0x0051, 0x0011, 0xff02)`.
///
/// # Description
/// KEM = ML-KEM-1024 + P-384 hybrid (the KEM of
/// [`crate::pq_hpke::DEFAULT_SUITE`]), KDF = SHAKE256, AEAD = crypt_guard's
/// private XChaCha20-Poly1305 extension for the outer layer of
/// [`seal_envelope`]. The inner layer (AES-256-GCM-SIV) is not part of the
/// suite id. [`crate::pq_hpke::DEFAULT_SUITE`] is unchanged.
pub const MAXIMAL_SUITE: Suite =
    Suite::new(Kem::MlKem1024P384, Kdf::Shake256, Aead::XChaCha20Poly1305);

/// Length in bytes of a root key and of every derived layer key.
pub const KEY_LEN: usize = 32;

/// Length in bytes of one authentication tag (or of the single-layer filler).
pub const TAG_LEN: usize = 16;

/// Bytes added to every plaintext by every [`Scheme`] (`2 × TAG_LEN`).
pub const CASCADE_OVERHEAD: usize = 32;

/// Length in bytes of the cascade nonce (`n24`) and of the random-mode prefix.
pub const NONCE_LEN: usize = 24;

// Compile-time guard: the fixed overhead is exactly two tags.
const _: () = assert!(CASCADE_OVERHEAD == 2 * TAG_LEN);

/// Nonce length of AES-256-GCM-SIV and ChaCha20-Poly1305 (`n24[..12]`).
const SHORT_NONCE_LEN: usize = 12;

/// PRF label: inner-layer key of [`Scheme::Cascade`].
const L_IN: &[u8] = b"crypt_guard/v3/cascade/inner";
/// PRF label: outer-layer key of [`Scheme::Cascade`].
const L_OUT: &[u8] = b"crypt_guard/v3/cascade/outer";
/// PRF label: key of the single-layer schemes.
const L_ONE: &[u8] = b"crypt_guard/v3/cascade/single";
/// PRF label: derived nonce of the one-shot mode.
const L_NONCE: &[u8] = b"crypt_guard/v3/cascade/nonce";
/// Domain prefix of the random mode.
const L_RANDOM: &[u8] = b"crypt_guard/v3/cascade/random";
/// AAD prefix: inner layer.
const A_IN: &[u8] = b"crypt_guard/v3/cascade/aad/inner";
/// AAD prefix: outer layer.
const A_OUT: &[u8] = b"crypt_guard/v3/cascade/aad/outer";
/// AAD prefix: single-layer schemes.
const A_ONE: &[u8] = b"crypt_guard/v3/cascade/aad/single";
/// HPKE exporter context: inner key of the envelope.
const H_KEY: &[u8] = b"crypt_guard/v3/cascade/hpke/inner-key";
/// HPKE exporter context: inner nonce of the envelope.
const H_NONCE: &[u8] = b"crypt_guard/v3/cascade/hpke/inner-nonce";
/// AAD prefix: inner layer of the envelope.
const H_AAD_IN: &[u8] = b"crypt_guard/v3/cascade/hpke/aad/inner";
/// AAD prefix: outer layer of the envelope.
const H_AAD_OUT: &[u8] = b"crypt_guard/v3/cascade/hpke/aad/outer";
/// Exporter contexts with this prefix are reserved for the envelope itself.
const RESERVED_EXPORT_PREFIX: &[u8] = b"crypt_guard/v3/cascade/";

/// Fixed error text for an unavailable OS entropy source (no secret data).
const ENTROPY_UNAVAILABLE: &str = "os entropy source unavailable";

/// Cipher scheme of a [`Cascade`].
///
/// # Description
/// The numeric ids are stable wire values (they equal the comnet `SuiteLevel`
/// ids). The derived order is the strength order
/// `ChaCha20Poly1305 < Aes256GcmSiv < XChaCha20Poly1305 < Cascade`.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum Scheme {
    /// ChaCha20-Poly1305 over `pt ‖ 0^16` (id 1, one layer).
    ChaCha20Poly1305 = 1,
    /// AES-256-GCM-SIV over `pt ‖ 0^16` (id 2, one layer).
    Aes256GcmSiv = 2,
    /// XChaCha20-Poly1305 over `pt ‖ 0^16` (id 3, one layer).
    XChaCha20Poly1305 = 3,
    /// Inner AES-256-GCM-SIV, outer XChaCha20-Poly1305 (id 4, two layers).
    Cascade = 4,
}

impl Scheme {
    /// The stable wire id of this scheme (1 to 4).
    pub const fn id(self) -> u8 {
        self as u8
    }

    /// Parse a wire id; `0` and unknown ids yield `None`.
    pub const fn from_id(id: u8) -> Option<Scheme> {
        match id {
            1 => Some(Scheme::ChaCha20Poly1305),
            2 => Some(Scheme::Aes256GcmSiv),
            3 => Some(Scheme::XChaCha20Poly1305),
            4 => Some(Scheme::Cascade),
            _ => None,
        }
    }

    /// Number of AEAD layers: 2 for [`Scheme::Cascade`], otherwise 1.
    pub const fn layers(self) -> u8 {
        match self {
            Scheme::Cascade => 2,
            Scheme::ChaCha20Poly1305 | Scheme::Aes256GcmSiv | Scheme::XChaCha20Poly1305 => 1,
        }
    }
}

/// Nonce source of the **reusable** calls [`Cascade::seal`] / [`Cascade::open`].
///
/// # Description
/// The 24 bytes (`n24`) of the construction are assembled inside [`Cascade`].
/// The derived one-shot nonce is deliberately *not* a variant: it is reachable
/// only through the consuming [`Cascade::seal_once`], so one root key cannot
/// seal two messages under the same derived nonce.
///
/// Uniqueness of the values is the caller's duty (see the module docs).
#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CascadeNonce {
    /// `domain ‖ 0 0 0 ‖ n u64 BE ‖ 0^12`: session frames (`domain` is the
    /// direction byte, `n` the atomic sequence number).
    Counter {
        /// Direction or purpose byte.
        domain: u8,
        /// Sequence number; never reuse a value under the same key.
        n: u64,
    },
    /// `prefix ‖ index u32 BE ‖ last u8 ‖ 0^12`: file chunks, the layout of
    /// [`crate::pq_stream`]. An all-zero `prefix` is rejected.
    Stream {
        /// Non-zero per-stream prefix.
        prefix: [u8; 7],
        /// Chunk index.
        index: u32,
        /// `true` for the final chunk only.
        last: bool,
    },
}

impl CascadeNonce {
    /// Assemble the 24-byte nonce.
    ///
    /// # Errors
    /// - [`CryptError::InvalidParameters`]: an all-zero stream prefix.
    fn to_n24(self) -> Result<[u8; NONCE_LEN], CryptError> {
        let mut out = [0u8; NONCE_LEN];
        match self {
            CascadeNonce::Counter { domain, n } => {
                let head = [domain, 0, 0, 0];
                let counter = n.to_be_bytes();
                for (dst, src) in out.iter_mut().zip(head.iter().chain(counter.iter())) {
                    *dst = *src;
                }
            }
            CascadeNonce::Stream {
                prefix,
                index,
                last,
            } => {
                if is_all_zero(&prefix) {
                    return Err(CryptError::InvalidParameters);
                }
                let index = index.to_be_bytes();
                let flag = [u8::from(last)];
                for (dst, src) in out
                    .iter_mut()
                    .zip(prefix.iter().chain(index.iter()).chain(flag.iter()))
                {
                    *dst = *src;
                }
            }
        }
        Ok(out)
    }
}

/// The raw AEAD primitive of one layer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Prim {
    /// ChaCha20-Poly1305 with `n24[..12]`.
    ChaCha,
    /// AES-256-GCM-SIV with `n24[..12]`.
    AesSiv,
    /// XChaCha20-Poly1305 with all of `n24`.
    XChaCha,
}

/// Constant-time-style zero test (no early exit).
fn is_all_zero(bytes: &[u8]) -> bool {
    bytes.iter().fold(0u8, |acc, b| acc | *b) == 0
}

/// Copy a tag slice into a fixed array.
fn tag_to_array(tag: &[u8]) -> Result<[u8; TAG_LEN], CryptError> {
    <[u8; TAG_LEN]>::try_from(tag).map_err(|_| CryptError::EncryptionFailed)
}

/// Write a tag into a 16-byte slot.
fn put_tag(slot: &mut [u8], tag: &[u8; TAG_LEN]) -> Result<(), CryptError> {
    let slot: &mut [u8; TAG_LEN] = slot.try_into().map_err(|_| CryptError::InvalidParameters)?;
    *slot = *tag;
    Ok(())
}

/// The first 12 bytes of a cascade nonce.
fn short_nonce(n24: &[u8; NONCE_LEN]) -> Result<&[u8; SHORT_NONCE_LEN], CryptError> {
    n24.first_chunk::<SHORT_NONCE_LEN>()
        .ok_or(CryptError::InvalidParameters)
}

/// ChaCha20-Poly1305 in place, detached tag.
fn chacha_seal(
    key: &[u8],
    nonce: &[u8; SHORT_NONCE_LEN],
    aad: &[u8],
    buf: &mut [u8],
) -> Result<[u8; TAG_LEN], CryptError> {
    let cipher =
        ChaCha20Poly1305::new_from_slice(key).map_err(|_| CryptError::InvalidParameters)?;
    let nonce: &ChaChaNonce = nonce.into();
    let tag = cipher
        .encrypt_in_place_detached(nonce, aad, buf)
        .map_err(|_| CryptError::EncryptionFailed)?;
    tag_to_array(tag.as_slice())
}

/// ChaCha20-Poly1305 open in place, detached tag.
fn chacha_open(
    key: &[u8],
    nonce: &[u8; SHORT_NONCE_LEN],
    aad: &[u8],
    buf: &mut [u8],
    tag: &[u8; TAG_LEN],
) -> Result<(), CryptError> {
    let cipher =
        ChaCha20Poly1305::new_from_slice(key).map_err(|_| CryptError::InvalidParameters)?;
    let nonce: &ChaChaNonce = nonce.into();
    let tag: &ChaChaTag = tag.into();
    cipher
        .decrypt_in_place_detached(nonce, aad, buf, tag)
        .map_err(|_| CryptError::AuthenticationFailed)
}

/// XChaCha20-Poly1305 in place, detached tag.
fn xchacha_seal(
    key: &[u8],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    buf: &mut [u8],
) -> Result<[u8; TAG_LEN], CryptError> {
    let cipher =
        XChaCha20Poly1305::new_from_slice(key).map_err(|_| CryptError::InvalidParameters)?;
    let nonce: &XNonce = nonce.into();
    let tag = cipher
        .encrypt_in_place_detached(nonce, aad, buf)
        .map_err(|_| CryptError::EncryptionFailed)?;
    tag_to_array(tag.as_slice())
}

/// XChaCha20-Poly1305 open in place, detached tag.
fn xchacha_open(
    key: &[u8],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    buf: &mut [u8],
    tag: &[u8; TAG_LEN],
) -> Result<(), CryptError> {
    let cipher =
        XChaCha20Poly1305::new_from_slice(key).map_err(|_| CryptError::InvalidParameters)?;
    let nonce: &XNonce = nonce.into();
    let tag: &ChaChaTag = tag.into();
    cipher
        .decrypt_in_place_detached(nonce, aad, buf, tag)
        .map_err(|_| CryptError::AuthenticationFailed)
}

/// AES-256-GCM-SIV in place, detached tag.
fn siv_seal(
    key: &[u8],
    nonce: &[u8; SHORT_NONCE_LEN],
    aad: &[u8],
    buf: &mut [u8],
) -> Result<[u8; TAG_LEN], CryptError> {
    let cipher = Aes256GcmSiv::new_from_slice(key).map_err(|_| CryptError::InvalidParameters)?;
    let nonce: &SivNonce = nonce.into();
    let tag = cipher
        .encrypt_in_place_detached(nonce, aad, buf)
        .map_err(|_| CryptError::EncryptionFailed)?;
    tag_to_array(tag.as_slice())
}

/// AES-256-GCM-SIV open in place, detached tag. On a tag mismatch the crate
/// re-encrypts the buffer, so no unauthenticated plaintext is left behind.
fn siv_open(
    key: &[u8],
    nonce: &[u8; SHORT_NONCE_LEN],
    aad: &[u8],
    buf: &mut [u8],
    tag: &[u8; TAG_LEN],
) -> Result<(), CryptError> {
    let cipher = Aes256GcmSiv::new_from_slice(key).map_err(|_| CryptError::InvalidParameters)?;
    let nonce: &SivNonce = nonce.into();
    let tag: &SivTag = tag.into();
    cipher
        .decrypt_in_place_detached(nonce, aad, buf, tag)
        .map_err(|_| CryptError::AuthenticationFailed)
}

/// Seal `buf` in place with one primitive and return the detached tag.
fn aead_seal(
    prim: Prim,
    key: &[u8; KEY_LEN],
    n24: &[u8; NONCE_LEN],
    aad: &[u8],
    buf: &mut [u8],
) -> Result<[u8; TAG_LEN], CryptError> {
    match prim {
        Prim::XChaCha => xchacha_seal(key, n24, aad, buf),
        Prim::ChaCha => chacha_seal(key, short_nonce(n24)?, aad, buf),
        Prim::AesSiv => siv_seal(key, short_nonce(n24)?, aad, buf),
    }
}

/// Open `buf` in place with one primitive against a detached tag.
fn aead_open(
    prim: Prim,
    key: &[u8; KEY_LEN],
    n24: &[u8; NONCE_LEN],
    aad: &[u8],
    buf: &mut [u8],
    tag: &[u8; TAG_LEN],
) -> Result<(), CryptError> {
    match prim {
        Prim::XChaCha => xchacha_open(key, n24, aad, buf, tag),
        Prim::ChaCha => chacha_open(key, short_nonce(n24)?, aad, buf, tag),
        Prim::AesSiv => siv_open(key, short_nonce(n24)?, aad, buf, tag),
    }
}

/// Build `scheme_id u8 ‖ lp32(domain)`.
fn build_ctx(scheme: Scheme, domain: &[u8]) -> Result<Vec<u8>, CryptError> {
    let len = u32::try_from(domain.len()).map_err(|_| CryptError::InvalidParameters)?;
    let capacity = domain
        .len()
        .checked_add(5)
        .ok_or(CryptError::InvalidParameters)?;
    let mut ctx = Vec::with_capacity(capacity);
    ctx.push(scheme.id());
    ctx.extend_from_slice(&len.to_be_bytes());
    ctx.extend_from_slice(domain);
    Ok(ctx)
}

/// Build the per-layer AAD `label ‖ ctx ‖ aad`.
fn layer_aad(label: &[u8], ctx: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptError> {
    let capacity = label
        .len()
        .checked_add(ctx.len())
        .and_then(|n| n.checked_add(aad.len()))
        .ok_or(CryptError::InvalidParameters)?;
    let mut out = Vec::with_capacity(capacity);
    out.extend_from_slice(label);
    out.extend_from_slice(ctx);
    out.extend_from_slice(aad);
    Ok(out)
}

/// Build the envelope AAD `label ‖ lp32(aad)`.
fn hpke_aad(label: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptError> {
    let len = u32::try_from(aad.len()).map_err(|_| CryptError::InvalidParameters)?;
    let capacity = label
        .len()
        .checked_add(4)
        .and_then(|n| n.checked_add(aad.len()))
        .ok_or(CryptError::InvalidParameters)?;
    let mut out = Vec::with_capacity(capacity);
    out.extend_from_slice(label);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(aad);
    Ok(out)
}

/// Derive one 32-byte layer key.
fn derive_key(
    root: &[u8; KEY_LEN],
    label: &[u8],
    ctx: &[u8],
) -> Result<Zeroizing<[u8; KEY_LEN]>, CryptError> {
    prf32(root, label, ctx).map_err(|_| CryptError::InvalidParameters)
}

/// A scheme-keyed AEAD with a fixed overhead of [`CASCADE_OVERHEAD`] bytes.
///
/// # Description
/// Derives independent sub-keys from a 32-byte `root` key and a constant
/// protocol `domain` and offers three families of calls:
/// - [`Self::seal_once`] / [`Self::open_once`]: the root key seals exactly one
///   message under a derived nonce; `seal_once` consumes the value.
/// - [`Self::seal`] / [`Self::open`]: a caller-supplied [`CascadeNonce`] for
///   many messages under one key.
/// - the `*_in_place` variants of both, which avoid copies for large buffers.
///
/// The type is not `Clone`, holds its keys in zeroizing memory and prints a
/// redacted `Debug`. See the module docs for the exact construction.
///
/// # Concurrency
/// No interior state; `Send + Sync`. `Arc<Cascade>` can be used from many tasks
/// for the reusable calls.
///
/// # Examples
/// ```rust
/// use crypt_guard_core::pq_cascade::{Cascade, CascadeNonce, Scheme};
///
/// # fn main() -> Result<(), crypt_guard_core::error::CryptError> {
/// let cascade = Cascade::new(Scheme::Cascade, &[9u8; 32], b"example/session/v1")?;
/// let nonce = CascadeNonce::Counter { domain: 1, n: 0 };
/// let ct = cascade.seal(&nonce, b"frame-header", b"hello")?;
/// assert_eq!(ct.len(), 5 + 32);
/// assert_eq!(&cascade.open(&nonce, b"frame-header", &ct)?[..], b"hello");
/// # Ok(())
/// # }
/// ```
pub struct Cascade {
    scheme: Scheme,
    /// `scheme_id u8 ‖ lp32(domain)`.
    ctx: Vec<u8>,
    /// `k_in` for [`Scheme::Cascade`], otherwise the single-layer key.
    first: Zeroizing<[u8; KEY_LEN]>,
    /// `k_out`, only for [`Scheme::Cascade`].
    outer: Option<Zeroizing<[u8; KEY_LEN]>>,
    /// `prf(root, "…/nonce", ctx, 24)`, used only by the one-shot calls.
    once_nonce: Zeroizing<[u8; NONCE_LEN]>,
}

impl ZeroizeOnDrop for Cascade {}

impl fmt::Debug for Cascade {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Cascade")
            .field("scheme", &self.scheme)
            .finish_non_exhaustive()
    }
}

impl Cascade {
    /// Derive the layer keys and the one-shot nonce for `scheme`.
    ///
    /// # Arguments
    /// - `scheme` (`Scheme`): the cipher scheme.
    /// - `root` (`&[u8; 32]`): the secret root key (a CEK, a per-file stream
    ///   key, a per-direction key, a KEK, an HPKE export); not all zero.
    /// - `domain` (`&[u8]`): constant protocol label such as
    ///   `"comnet/session/frame/v1"`; not empty.
    ///
    /// # Errors
    /// - [`CryptError::InvalidParameters`]: all-zero `root`, empty `domain`, or
    ///   a `domain` longer than `u32::MAX` bytes.
    pub fn new(scheme: Scheme, root: &[u8; KEY_LEN], domain: &[u8]) -> Result<Cascade, CryptError> {
        if domain.is_empty() || is_all_zero(root) {
            return Err(CryptError::InvalidParameters);
        }
        let ctx = build_ctx(scheme, domain)?;
        let (first, outer) = match scheme {
            Scheme::Cascade => (
                derive_key(root, L_IN, &ctx)?,
                Some(derive_key(root, L_OUT, &ctx)?),
            ),
            Scheme::ChaCha20Poly1305 | Scheme::Aes256GcmSiv | Scheme::XChaCha20Poly1305 => {
                (derive_key(root, L_ONE, &ctx)?, None)
            }
        };
        let mut once_nonce = Zeroizing::new([0u8; NONCE_LEN]);
        prf(root, L_NONCE, &ctx, once_nonce.as_mut_slice())
            .map_err(|_| CryptError::InvalidParameters)?;
        Ok(Cascade {
            scheme,
            ctx,
            first,
            outer,
            once_nonce,
        })
    }

    /// The scheme this value was built for.
    pub const fn scheme(&self) -> Scheme {
        self.scheme
    }

    /// The raw primitive of a single-layer scheme; `None` for the cascade.
    const fn single_prim(&self) -> Option<Prim> {
        match self.scheme {
            Scheme::Cascade => None,
            Scheme::ChaCha20Poly1305 => Some(Prim::ChaCha),
            Scheme::Aes256GcmSiv => Some(Prim::AesSiv),
            Scheme::XChaCha20Poly1305 => Some(Prim::XChaCha),
        }
    }

    /// Seal `plaintext`; the output is `|plaintext| + CASCADE_OVERHEAD` bytes.
    ///
    /// # Arguments
    /// - `nonce` (`&CascadeNonce`): unique per message under this key; the
    ///   caller guarantees uniqueness (atomic sequence number, chunk index).
    /// - `aad` (`&[u8]`): authenticated, not encrypted.
    ///
    /// # Errors
    /// - [`CryptError::InvalidParameters`]: an all-zero stream prefix.
    /// - [`CryptError::EncryptionFailed`]: the AEAD refused the input (too large).
    pub fn seal(
        &self,
        nonce: &CascadeNonce,
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptError> {
        let n24 = nonce.to_n24()?;
        self.seal_alloc(&n24, aad, plaintext)
    }

    /// Open a ciphertext produced by [`Self::seal`] with the same nonce and AAD.
    ///
    /// # Errors
    /// - [`CryptError::InvalidParameters`]: an all-zero stream prefix.
    /// - [`CryptError::AuthenticationFailed`]: every other failure (wrong key,
    ///   domain, scheme, nonce, AAD, filler, truncated or modified bytes).
    pub fn open(
        &self,
        nonce: &CascadeNonce,
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CryptError> {
        let n24 = nonce.to_n24()?;
        self.open_alloc(&n24, aad, ciphertext)
    }

    /// Seal exactly one message under the derived nonce and consume `self`.
    ///
    /// # Description
    /// `n24 = prf(root, "crypt_guard/v3/cascade/nonce", ctx, 24)`. Because the
    /// root key may seal only one message in this mode, the call takes `self`
    /// by value: a second `seal_once` on the same value does not compile.
    ///
    /// ```compile_fail,E0382
    /// use crypt_guard_core::pq_cascade::{Cascade, Scheme};
    ///
    /// # fn main() -> Result<(), crypt_guard_core::error::CryptError> {
    /// let cascade = Cascade::new(Scheme::Cascade, &[7u8; 32], b"example/domain")?;
    /// let _first = cascade.seal_once(b"", b"first")?;
    /// let _second = cascade.seal_once(b"", b"second")?; // use of moved value
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    /// - [`CryptError::EncryptionFailed`]: the AEAD refused the input (too large).
    pub fn seal_once(self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptError> {
        self.seal_alloc(&self.once_nonce, aad, plaintext)
    }

    /// Open a ciphertext produced by [`Self::seal_once`].
    ///
    /// # Description
    /// May be called repeatedly: repeating an open is harmless.
    ///
    /// # Errors
    /// - [`CryptError::AuthenticationFailed`]: any failure.
    pub fn open_once(
        &self,
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CryptError> {
        self.open_alloc(&self.once_nonce, aad, ciphertext)
    }

    /// Seal in place.
    ///
    /// # Description
    /// `buf.len()` must equal `plain_len + CASCADE_OVERHEAD`. On input
    /// `buf[..plain_len]` is the plaintext and the last 32 bytes are scratch
    /// space that is overwritten. On success the whole buffer is the
    /// ciphertext, byte-identical to [`Self::seal`].
    ///
    /// # Errors
    /// - [`CryptError::InvalidParameters`]: wrong buffer length or an all-zero
    ///   stream prefix.
    /// - [`CryptError::EncryptionFailed`]: the AEAD refused the input.
    pub fn seal_in_place(
        &self,
        nonce: &CascadeNonce,
        aad: &[u8],
        buf: &mut [u8],
        plain_len: usize,
    ) -> Result<(), CryptError> {
        let n24 = nonce.to_n24()?;
        self.seal_in_place_n(&n24, aad, buf, plain_len)
    }

    /// Open in place and return the plaintext sub-slice `buf[..len - 32]`.
    ///
    /// # Description
    /// On [`CryptError::AuthenticationFailed`] the whole buffer is overwritten
    /// with zeros (no unauthenticated or partial plaintext survives). On
    /// [`CryptError::InvalidParameters`] nothing was decrypted and the buffer
    /// is unchanged.
    ///
    /// # Errors
    /// - [`CryptError::InvalidParameters`]: an all-zero stream prefix.
    /// - [`CryptError::AuthenticationFailed`]: every other failure, including a
    ///   buffer shorter than [`CASCADE_OVERHEAD`].
    pub fn open_in_place<'a>(
        &self,
        nonce: &CascadeNonce,
        aad: &[u8],
        buf: &'a mut [u8],
    ) -> Result<&'a mut [u8], CryptError> {
        let n24 = nonce.to_n24()?;
        self.open_in_place_with(&n24, aad, buf)
    }

    /// In-place variant of [`Self::seal_once`]; consumes `self`.
    ///
    /// # Errors
    /// Same as [`Self::seal_in_place`], without the stream-prefix case.
    pub fn seal_once_in_place(
        self,
        aad: &[u8],
        buf: &mut [u8],
        plain_len: usize,
    ) -> Result<(), CryptError> {
        self.seal_in_place_n(&self.once_nonce, aad, buf, plain_len)
    }

    /// In-place variant of [`Self::open_once`].
    ///
    /// # Errors
    /// [`CryptError::AuthenticationFailed`]; the buffer is wiped on failure.
    pub fn open_once_in_place<'a>(
        &self,
        aad: &[u8],
        buf: &'a mut [u8],
    ) -> Result<&'a mut [u8], CryptError> {
        self.open_in_place_with(&self.once_nonce, aad, buf)
    }

    /// Allocating seal under an assembled nonce.
    fn seal_alloc(
        &self,
        n24: &[u8; NONCE_LEN],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptError> {
        let total = plaintext
            .len()
            .checked_add(CASCADE_OVERHEAD)
            .ok_or(CryptError::InvalidParameters)?;
        // The working buffer holds the plaintext until it is encrypted in place.
        let mut buf = Zeroizing::new(Vec::<u8>::with_capacity(total));
        buf.extend_from_slice(plaintext);
        buf.resize(total, 0);
        self.seal_in_place_n(n24, aad, buf.as_mut_slice(), plaintext.len())?;
        Ok(core::mem::take(&mut *buf))
    }

    /// Allocating open under an assembled nonce.
    fn open_alloc(
        &self,
        n24: &[u8; NONCE_LEN],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CryptError> {
        let mut buf = Zeroizing::new(ciphertext.to_vec());
        let plain_len = self.open_in_place_n(n24, aad, buf.as_mut_slice())?;
        buf.truncate(plain_len);
        Ok(buf)
    }

    /// In-place seal under an assembled nonce.
    fn seal_in_place_n(
        &self,
        n24: &[u8; NONCE_LEN],
        aad: &[u8],
        buf: &mut [u8],
        plain_len: usize,
    ) -> Result<(), CryptError> {
        let mid = plain_len
            .checked_add(TAG_LEN)
            .ok_or(CryptError::InvalidParameters)?;
        let total = plain_len
            .checked_add(CASCADE_OVERHEAD)
            .ok_or(CryptError::InvalidParameters)?;
        if buf.len() != total {
            return Err(CryptError::InvalidParameters);
        }
        // `body` = plaintext + 16 scratch bytes, `tail` = the 16 outer-tag bytes.
        let (body, tail) = buf
            .split_at_mut_checked(mid)
            .ok_or(CryptError::InvalidParameters)?;
        let (plain, slot) = body
            .split_at_mut_checked(plain_len)
            .ok_or(CryptError::InvalidParameters)?;
        match self.single_prim() {
            None => {
                let k_out = self.outer.as_ref().ok_or(CryptError::InvalidParameters)?;
                let aad_in = layer_aad(A_IN, &self.ctx, aad)?;
                let tag_in = aead_seal(Prim::AesSiv, &self.first, n24, &aad_in, plain)?;
                put_tag(slot, &tag_in)?;
                // The outer layer authenticates the inner ciphertext including its tag.
                let aad_out = layer_aad(A_OUT, &self.ctx, aad)?;
                let tag_out = aead_seal(Prim::XChaCha, k_out, n24, &aad_out, body)?;
                put_tag(tail, &tag_out)
            }
            Some(prim) => {
                // Authenticated filler: 16 zero bytes inside the AEAD.
                slot.fill(0);
                let aad_one = layer_aad(A_ONE, &self.ctx, aad)?;
                let tag = aead_seal(prim, &self.first, n24, &aad_one, body)?;
                put_tag(tail, &tag)
            }
        }
    }

    /// In-place open under an assembled nonce; returns the plaintext length.
    ///
    /// Any failure wipes `buf` and is reported as the opaque
    /// [`CryptError::AuthenticationFailed`].
    fn open_in_place_n(
        &self,
        n24: &[u8; NONCE_LEN],
        aad: &[u8],
        buf: &mut [u8],
    ) -> Result<usize, CryptError> {
        let result = self.open_in_place_checked(n24, aad, buf);
        if result.is_err() {
            buf.zeroize();
        }
        result
    }

    /// The fallible part of [`Self::open_in_place_n`] (no wiping).
    fn open_in_place_checked(
        &self,
        n24: &[u8; NONCE_LEN],
        aad: &[u8],
        buf: &mut [u8],
    ) -> Result<usize, CryptError> {
        let mid = buf
            .len()
            .checked_sub(TAG_LEN)
            .ok_or(CryptError::AuthenticationFailed)?;
        let plain_len = mid
            .checked_sub(TAG_LEN)
            .ok_or(CryptError::AuthenticationFailed)?;
        let (body, tail) = buf
            .split_at_mut_checked(mid)
            .ok_or(CryptError::AuthenticationFailed)?;
        let tag_out =
            <[u8; TAG_LEN]>::try_from(&*tail).map_err(|_| CryptError::AuthenticationFailed)?;
        match self.single_prim() {
            None => {
                let k_out = self
                    .outer
                    .as_ref()
                    .ok_or(CryptError::AuthenticationFailed)?;
                let aad_out = layer_aad(A_OUT, &self.ctx, aad)
                    .map_err(|_| CryptError::AuthenticationFailed)?;
                aead_open(Prim::XChaCha, k_out, n24, &aad_out, body, &tag_out)
                    .map_err(|_| CryptError::AuthenticationFailed)?;
                // `body` is now `inner ciphertext ‖ inner tag`.
                let tag_in = body
                    .get(plain_len..)
                    .and_then(|t| <[u8; TAG_LEN]>::try_from(t).ok())
                    .ok_or(CryptError::AuthenticationFailed)?;
                let ct_in = body
                    .get_mut(..plain_len)
                    .ok_or(CryptError::AuthenticationFailed)?;
                let aad_in = layer_aad(A_IN, &self.ctx, aad)
                    .map_err(|_| CryptError::AuthenticationFailed)?;
                aead_open(Prim::AesSiv, &self.first, n24, &aad_in, ct_in, &tag_in)
                    .map_err(|_| CryptError::AuthenticationFailed)?;
            }
            Some(prim) => {
                let aad_one = layer_aad(A_ONE, &self.ctx, aad)
                    .map_err(|_| CryptError::AuthenticationFailed)?;
                aead_open(prim, &self.first, n24, &aad_one, body, &tag_out)
                    .map_err(|_| CryptError::AuthenticationFailed)?;
                // The filler is checked only after the AEAD verified it.
                let filler = body
                    .get(plain_len..)
                    .ok_or(CryptError::AuthenticationFailed)?;
                if !is_all_zero(filler) {
                    return Err(CryptError::AuthenticationFailed);
                }
            }
        }
        Ok(plain_len)
    }

    /// In-place open that returns the plaintext sub-slice.
    fn open_in_place_with<'a>(
        &self,
        n24: &[u8; NONCE_LEN],
        aad: &[u8],
        buf: &'a mut [u8],
    ) -> Result<&'a mut [u8], CryptError> {
        let plain_len = self.open_in_place_n(n24, aad, buf)?;
        buf.get_mut(..plain_len)
            .ok_or(CryptError::AuthenticationFailed)
    }
}

/// Draw the 24-byte random-mode nonce from the OS.
fn random_n24() -> Result<[u8; NONCE_LEN], CryptError> {
    let mut n24 = [0u8; NONCE_LEN];
    TryRng::try_fill_bytes(&mut TryOsRng, &mut n24)
        .map_err(|_| CryptError::CustomError(ENTROPY_UNAVAILABLE.to_owned()))?;
    Ok(n24)
}

/// Build `"crypt_guard/v3/cascade/random" ‖ lp32(domain) ‖ n24`.
fn random_domain(domain: &[u8], n24: &[u8; NONCE_LEN]) -> Result<Vec<u8>, CryptError> {
    let len = u32::try_from(domain.len()).map_err(|_| CryptError::InvalidParameters)?;
    let capacity = L_RANDOM
        .len()
        .checked_add(4)
        .and_then(|n| n.checked_add(domain.len()))
        .and_then(|n| n.checked_add(NONCE_LEN))
        .ok_or(CryptError::InvalidParameters)?;
    let mut out = Vec::with_capacity(capacity);
    out.extend_from_slice(L_RANDOM);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(domain);
    out.extend_from_slice(n24);
    Ok(out)
}

/// Random mode with a given nonce (the public call draws it from the OS).
fn seal_random_with(
    scheme: Scheme,
    root: &[u8; KEY_LEN],
    domain: &[u8],
    n24: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptError> {
    let derived = random_domain(domain, n24)?;
    let cascade = Cascade::new(scheme, root, &derived)?;
    let total = plaintext
        .len()
        .checked_add(CASCADE_OVERHEAD)
        .and_then(|n| n.checked_add(NONCE_LEN))
        .ok_or(CryptError::InvalidParameters)?;
    // `n24 ‖ plaintext ‖ 32 scratch bytes`; the tail is encrypted in place.
    let mut buf = Zeroizing::new(Vec::<u8>::with_capacity(total));
    buf.extend_from_slice(n24);
    buf.extend_from_slice(plaintext);
    buf.resize(total, 0);
    let body = buf
        .get_mut(NONCE_LEN..)
        .ok_or(CryptError::InvalidParameters)?;
    cascade.seal_once_in_place(aad, body, plaintext.len())?;
    Ok(core::mem::take(&mut *buf))
}

/// Seal `plaintext` under a fresh random 192-bit nonce (store values, vault files).
///
/// # Description
/// Draws `n24` from the OS (`TryOsRng`), derives all keys and the nonce from
/// `domain' = "crypt_guard/v3/cascade/random" ‖ lp32(domain) ‖ n24`, and returns
/// `n24 ‖ ct`. Every value therefore has its own keys; collisions are excluded
/// by the 192-bit nonce, and `n24` is authenticated (it sits in key and AAD).
///
/// # Arguments
/// - `scheme` (`Scheme`): the cipher scheme.
/// - `root` (`&[u8; 32]`): the secret root key (for example a KEK); not all zero.
/// - `domain` (`&[u8]`): constant label per use; not empty.
/// - `aad` (`&[u8]`): authenticated, not encrypted.
///
/// # Returns
/// `n24 ‖ ct`, `|plaintext| + NONCE_LEN + CASCADE_OVERHEAD` bytes.
///
/// # Errors
/// - [`CryptError::InvalidParameters`]: all-zero `root` or empty `domain`.
/// - [`CryptError::CustomError`] (fixed text): OS entropy failure.
/// - [`CryptError::EncryptionFailed`]: the AEAD refused the input.
///
/// # Examples
/// ```rust
/// use crypt_guard_core::pq_cascade::{open_random, seal_random, Scheme};
///
/// # fn main() -> Result<(), crypt_guard_core::error::CryptError> {
/// let kek = [0x11u8; 32];
/// let sealed = seal_random(Scheme::Cascade, &kek, b"example/store/v1", b"row-7", b"value")?;
/// assert_eq!(sealed.len(), 5 + 24 + 32);
/// let plain = open_random(Scheme::Cascade, &kek, b"example/store/v1", b"row-7", &sealed)?;
/// assert_eq!(&plain[..], b"value");
/// # Ok(())
/// # }
/// ```
pub fn seal_random(
    scheme: Scheme,
    root: &[u8; KEY_LEN],
    domain: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptError> {
    if domain.is_empty() || is_all_zero(root) {
        return Err(CryptError::InvalidParameters);
    }
    let n24 = random_n24()?;
    seal_random_with(scheme, root, domain, &n24, aad, plaintext)
}

/// Open the output of [`seal_random`].
///
/// # Errors
/// - [`CryptError::InvalidParameters`]: all-zero `root` or empty `domain`.
/// - [`CryptError::AuthenticationFailed`]: every other failure (wrong key,
///   domain, scheme, AAD, truncated or modified bytes, input shorter than
///   `NONCE_LEN + CASCADE_OVERHEAD`).
pub fn open_random(
    scheme: Scheme,
    root: &[u8; KEY_LEN],
    domain: &[u8],
    aad: &[u8],
    sealed: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptError> {
    if domain.is_empty() || is_all_zero(root) {
        return Err(CryptError::InvalidParameters);
    }
    let (n24, ciphertext) = sealed
        .split_first_chunk::<NONCE_LEN>()
        .ok_or(CryptError::AuthenticationFailed)?;
    let derived = random_domain(domain, n24).map_err(|_| CryptError::AuthenticationFailed)?;
    let cascade = Cascade::new(scheme, root, &derived)?;
    cascade.open_once(aad, ciphertext)
}

/// Reject every suite other than [`MAXIMAL_SUITE`] (caller-side configuration).
fn require_maximal(suite: Suite) -> Result<(), CryptError> {
    if suite == MAXIMAL_SUITE {
        Ok(())
    } else {
        Err(CryptError::UnsupportedAlgorithm)
    }
}

/// Reject exporter contexts that collide with the envelope's own labels.
fn check_export_context(context: &[u8]) -> Result<(), CryptError> {
    if context.starts_with(RESERVED_EXPORT_PREFIX) {
        Err(CryptError::InvalidParameters)
    } else {
        Ok(())
    }
}

/// Copy a 12-byte exporter output into zeroizing memory.
fn short_nonce_from(export: &[u8]) -> Result<Zeroizing<[u8; SHORT_NONCE_LEN]>, CryptError> {
    <[u8; SHORT_NONCE_LEN]>::try_from(export)
        .map(Zeroizing::new)
        .map_err(|_| CryptError::InvalidParameters)
}

/// Seal one message into a two-layer [`MAXIMAL_SUITE`] [`HpkeEnvelope`].
///
/// # Description
/// One KEM encapsulation; the inner AES-256-GCM-SIV key and nonce come from the
/// HPKE exporter of the same context, the outer layer is the HPKE
/// XChaCha20-Poly1305 seal. The result is a normal `CGH3` container of
/// `20 + 1665 + |plaintext| + 32` bytes (see the module docs). `info` and `aad`
/// are never put into the envelope.
///
/// # Arguments
/// - `suite` (`Suite`): must be [`MAXIMAL_SUITE`].
/// - `recipient` (`&RecipientPublicKey`): a key of the ML-KEM-1024+P-384 KEM.
/// - `info` (`&[u8]`): HPKE application context.
/// - `aad` (`&[u8]`): authenticated by both layers.
///
/// # Errors
/// - [`CryptError::UnsupportedAlgorithm`]: `suite != MAXIMAL_SUITE`.
/// - [`CryptError::InvalidParameters`]: `aad` longer than `u32::MAX` bytes, or
///   `info` too long for HPKE.
/// - [`CryptError::InvalidKeyType`]: `recipient` is for a different KEM.
/// - [`CryptError::EncryptionFailed`]: the inner AEAD refused the input.
pub fn seal_envelope(
    suite: Suite,
    recipient: &RecipientPublicKey,
    info: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<HpkeEnvelope, CryptError> {
    require_maximal(suite)?;
    let (encapsulation, ctx) = setup_base_sender_inner(MAXIMAL_SUITE, recipient, info)?;
    let mut sealer = CascadeSealer::new(ctx)?;
    let ciphertext = sealer.seal(aad, plaintext)?;
    Ok(HpkeEnvelope::new(MAXIMAL_SUITE, &encapsulation, ciphertext))
}

/// Open an envelope produced by [`seal_envelope`].
///
/// # Description
/// The wire suite of `envelope` is pinned to `expected` **before** the
/// decapsulation. Every failure after that point is the same opaque
/// [`CryptError::AuthenticationFailed`]; no partial plaintext is returned.
///
/// # Arguments
/// - `expected` (`Suite`): the locally pinned suite; must be [`MAXIMAL_SUITE`].
/// - `envelope` (`&HpkeEnvelope`): the received container.
/// - `recipient` (`&RecipientPrivateKey`): the recipient's private key.
/// - `info`, `aad` (`&[u8]`): exactly as passed to [`seal_envelope`].
///
/// # Errors
/// - [`CryptError::UnsupportedAlgorithm`]: `expected != MAXIMAL_SUITE` (a local
///   configuration error; nothing attacker-controlled).
/// - [`CryptError::AuthenticationFailed`]: everything else, including a wire
///   suite other than `expected`.
pub fn open_envelope(
    expected: Suite,
    envelope: &HpkeEnvelope,
    recipient: &RecipientPrivateKey,
    info: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptError> {
    require_maximal(expected)?;
    if envelope.suite() != expected {
        return Err(CryptError::AuthenticationFailed);
    }
    let encapsulation = Encapsulation::from_bytes(expected.kem(), envelope.encapsulation())
        .map_err(|_| CryptError::AuthenticationFailed)?;
    let ctx = setup_base_receiver_inner(expected, recipient, &encapsulation, info)
        .map_err(|_| CryptError::AuthenticationFailed)?;
    let mut opener = CascadeOpener::new(ctx).map_err(|_| CryptError::AuthenticationFailed)?;
    opener.open(aad, envelope.ciphertext())
}

/// Single-use two-layer sealer on an HPKE sender context.
///
/// # Description
/// For callers that must control `enc`, a frame header as AAD and further
/// exports themselves (anonymous sync, break-glass shares). The sealer owns the
/// context (which is not `Clone`) and allows exactly **one** [`Self::seal`]:
/// the inner key and nonce come from the HPKE exporter and do not depend on the
/// HPKE message sequence, so a second inner seal would repeat them. Exporter
/// contexts starting with `crypt_guard/v3/cascade/` are refused so no caller can
/// derive the inner key.
///
/// # Concurrency
/// Single-owner state machine (`&mut self`).
///
/// # Examples
/// ```rust
/// use crypt_guard_core::pq_cascade::{CascadeOpener, CascadeSealer, MAXIMAL_SUITE};
/// use crypt_guard_core::pq_hpke::{
///     generate_recipient_key_pair, setup_base_receiver_inner, setup_base_sender_inner,
/// };
///
/// # fn main() -> Result<(), crypt_guard_core::error::CryptError> {
/// let keys = generate_recipient_key_pair(MAXIMAL_SUITE.kem())?;
/// let (enc, sender) = setup_base_sender_inner(MAXIMAL_SUITE, keys.public_key(), b"info")?;
/// let mut sealer = CascadeSealer::new(sender)?;
/// let ct = sealer.seal(b"aad", b"payload")?;
/// let response_key = sealer.export_zeroizing(b"example/response", 32)?;
///
/// let receiver = setup_base_receiver_inner(MAXIMAL_SUITE, keys.private_key(), &enc, b"info")?;
/// let mut opener = CascadeOpener::new(receiver)?;
/// assert_eq!(&opener.open(b"aad", &ct)?[..], b"payload");
/// assert_eq!(
///     opener.export_zeroizing(b"example/response", 32)?.as_slice(),
///     response_key.as_slice()
/// );
/// # Ok(())
/// # }
/// ```
pub struct CascadeSealer {
    ctx: SenderContext,
    sealed: bool,
}

impl fmt::Debug for CascadeSealer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CascadeSealer")
            .field("sealed", &self.sealed)
            .finish_non_exhaustive()
    }
}

impl CascadeSealer {
    /// Wrap a sender context whose AEAD is XChaCha20-Poly1305.
    ///
    /// # Errors
    /// - [`CryptError::UnsupportedAlgorithm`]: the context's AEAD is not
    ///   [`Aead::XChaCha20Poly1305`].
    pub fn new(ctx: SenderContext) -> Result<CascadeSealer, CryptError> {
        if ctx.suite().aead() != Aead::XChaCha20Poly1305 {
            return Err(CryptError::UnsupportedAlgorithm);
        }
        Ok(CascadeSealer { ctx, sealed: false })
    }

    /// Seal the one message of this context; the output is `|plaintext| + 32` bytes.
    ///
    /// # Description
    /// The single-use flag is set before any work, so a failed attempt cannot
    /// be retried on the same context.
    ///
    /// # Errors
    /// - [`CryptError::InvalidParameters`]: a second call, or `aad` longer than
    ///   `u32::MAX` bytes.
    /// - [`CryptError::EncryptionFailed`]: the inner AEAD refused the input.
    /// - Mapped HPKE errors from the outer seal.
    pub fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptError> {
        if self.sealed {
            return Err(CryptError::InvalidParameters);
        }
        self.sealed = true;
        let aad_in = hpke_aad(H_AAD_IN, aad)?;
        let aad_out = hpke_aad(H_AAD_OUT, aad)?;
        let k_in = self.ctx.export_zeroizing(H_KEY, KEY_LEN)?;
        let n_in = short_nonce_from(
            self.ctx
                .export_zeroizing(H_NONCE, SHORT_NONCE_LEN)?
                .as_slice(),
        )?;
        let capacity = plaintext
            .len()
            .checked_add(TAG_LEN)
            .ok_or(CryptError::InvalidParameters)?;
        // Holds the plaintext until the inner layer encrypted it in place.
        let mut inner = Zeroizing::new(Vec::<u8>::with_capacity(capacity));
        inner.extend_from_slice(plaintext);
        let tag = siv_seal(k_in.as_slice(), &n_in, &aad_in, inner.as_mut_slice())?;
        inner.extend_from_slice(&tag);
        self.ctx
            .seal(&aad_out, inner.as_slice())
            .map_err(CryptError::from)
    }

    /// Export a secret from the HPKE context (for example a response key).
    ///
    /// # Errors
    /// - [`CryptError::InvalidParameters`]: `context` starts with
    ///   `crypt_guard/v3/cascade/`, or `len` is out of range for the KDF.
    pub fn export_zeroizing(
        &self,
        context: &[u8],
        len: usize,
    ) -> Result<Zeroizing<Vec<u8>>, CryptError> {
        check_export_context(context)?;
        self.ctx
            .export_zeroizing(context, len)
            .map_err(CryptError::from)
    }
}

/// Single-use two-layer opener on an HPKE recipient context.
///
/// # Description
/// Counterpart of [`CascadeSealer`]. [`Self::open`] succeeds at most once: after
/// the outer layer verified, the HPKE sequence has advanced and the opener is
/// locked, whatever the inner layer says. A failed outer check does not lock
/// (HPKE advances its sequence only on success), so a forged message cannot
/// desynchronize the context. Every error is the opaque
/// [`CryptError::AuthenticationFailed`], including a call on a locked opener.
///
/// # Concurrency
/// Single-owner state machine (`&mut self`).
pub struct CascadeOpener {
    ctx: RecipientContext,
    opened: bool,
}

impl fmt::Debug for CascadeOpener {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CascadeOpener")
            .field("opened", &self.opened)
            .finish_non_exhaustive()
    }
}

impl CascadeOpener {
    /// Wrap a recipient context whose AEAD is XChaCha20-Poly1305.
    ///
    /// # Errors
    /// - [`CryptError::UnsupportedAlgorithm`]: the context's AEAD is not
    ///   [`Aead::XChaCha20Poly1305`].
    pub fn new(ctx: RecipientContext) -> Result<CascadeOpener, CryptError> {
        if ctx.suite().aead() != Aead::XChaCha20Poly1305 {
            return Err(CryptError::UnsupportedAlgorithm);
        }
        Ok(CascadeOpener { ctx, opened: false })
    }

    /// Open the one message of this context.
    ///
    /// # Errors
    /// - [`CryptError::AuthenticationFailed`]: any failure, or the opener is
    ///   already locked by an earlier outer-layer success.
    pub fn open(
        &mut self,
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CryptError> {
        if self.opened {
            return Err(CryptError::AuthenticationFailed);
        }
        let aad_in = hpke_aad(H_AAD_IN, aad).map_err(|_| CryptError::AuthenticationFailed)?;
        let aad_out = hpke_aad(H_AAD_OUT, aad).map_err(|_| CryptError::AuthenticationFailed)?;
        // Outer layer first; on success this is the inner ciphertext (|pt| + 16).
        let mut inner = self
            .ctx
            .open_zeroizing(&aad_out, ciphertext)
            .map_err(|_| CryptError::AuthenticationFailed)?;
        // HPKE advanced its sequence: lock regardless of the inner result.
        self.opened = true;
        let k_in = self
            .ctx
            .export_zeroizing(H_KEY, KEY_LEN)
            .map_err(|_| CryptError::AuthenticationFailed)?;
        let n_in = self
            .ctx
            .export_zeroizing(H_NONCE, SHORT_NONCE_LEN)
            .map_err(|_| CryptError::AuthenticationFailed)?;
        let n_in =
            short_nonce_from(n_in.as_slice()).map_err(|_| CryptError::AuthenticationFailed)?;
        let plain_len = inner
            .len()
            .checked_sub(TAG_LEN)
            .ok_or(CryptError::AuthenticationFailed)?;
        let tag_in = inner
            .get(plain_len..)
            .and_then(|t| <[u8; TAG_LEN]>::try_from(t).ok())
            .ok_or(CryptError::AuthenticationFailed)?;
        let ct_in = inner
            .get_mut(..plain_len)
            .ok_or(CryptError::AuthenticationFailed)?;
        siv_open(k_in.as_slice(), &n_in, &aad_in, ct_in, &tag_in)
            .map_err(|_| CryptError::AuthenticationFailed)?;
        inner.truncate(plain_len);
        Ok(inner)
    }

    /// Export a secret from the HPKE context.
    ///
    /// # Errors
    /// - [`CryptError::InvalidParameters`]: `context` starts with
    ///   `crypt_guard/v3/cascade/`, or `len` is out of range for the KDF.
    pub fn export_zeroizing(
        &self,
        context: &[u8],
        len: usize,
    ) -> Result<Zeroizing<Vec<u8>>, CryptError> {
        check_export_context(context)?;
        self.ctx
            .export_zeroizing(context, len)
            .map_err(CryptError::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hpke_pq::draft_ietf_hpke_pq_05_full::setup_base_sender_with_ikm_e;
    use crate::pq_hpke::{derive_recipient_key_pair, generate_recipient_key_pair, DEFAULT_SUITE};
    use crate::pq_stream::StreamEncryptor;
    use chacha20poly1305::aead::{Aead as _, Payload};

    type TestResult = Result<(), CryptError>;

    fn missing() -> CryptError {
        CryptError::CustomError("test fixture missing".to_owned())
    }

    const ROOT: [u8; 32] = [
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
        26, 27, 28, 29, 30, 31, 32,
    ];
    const DOMAIN: &[u8] = b"crypt_guard/test/cascade";
    const AAD: &[u8] = b"aad-1";
    const PT: &[u8] = b"cascade known answer";
    const PREFIX: [u8; 7] = [0, 0, 0, 0, 0, 0, 1];
    const RANDOM_N24: [u8; 24] = [
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae,
        0xaf, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
    ];
    const ALL: [Scheme; 4] = [
        Scheme::ChaCha20Poly1305,
        Scheme::Aes256GcmSiv,
        Scheme::XChaCha20Poly1305,
        Scheme::Cascade,
    ];
    const COUNTER: CascadeNonce = CascadeNonce::Counter { domain: 1, n: 5 };

    // Known answers from the Python reference model (contract Annex A).
    const K_IN: &str = "29eecf9a61cb966250a804b1e531c86ace2802ab217d9a1b8800d74a3cef0292";
    const K_OUT: &str = "0b6df53cdb3e6329fe08c6fe5407857f7e29b8d36f26315da007695562b214f9";
    const K_ONE_CASCADE: &str = "583d269f6ab03d2bcadf39dd2fbd9abd774c26f143df0ce9c6f972e9389589bd";
    const K_ONE_XCHACHA: &str = "58d81669dd4795a3b6a4da233d5457f79b593db66e6255e74776987d035f0b2a";
    const K_ONE_AESSIV: &str = "2102f5469119816ad0d688e01cc989dca845c9218b012a48509ce5a5ebcd5a7c";
    const K_ONE_CHACHA: &str = "36ff7bfbe6df1ee33b991468ce48b8b1a2001e47ceb6a318e4debb7c4f007195";
    const NONCE_ONCE_CASCADE: &str = "e0fbac1160eeeec3cdf30d68d18a7586b88e68d6be2858af";
    const NONCE_COUNTER: &str = "010000000000000000000005000000000000000000000000";
    const NONCE_STREAM_FALSE: &str = "000000000000010000000300000000000000000000000000";
    const NONCE_STREAM_TRUE: &str = "000000000000010000000301000000000000000000000000";
    const CT_COUNTER_CASCADE: &str =
        "71b3d7c5e2cc0ec27edec4dd0949e0039d80207ee810c95567adb765640b7c1a79b269fe0bba036e20b52090685895bbe46fc06b";
    const CT_ONCE_CASCADE: &str =
        "a649da40579f391994babd7f2ebef1217b13efe922f5cf6c61ff6723237ff270c0e65d57be1c5d7107dad7fe419dc59ccc362f10";
    const CT_STREAM_CASCADE: &str =
        "1af3e77dec051584db464a63a695e45d63d1eb26835926adca9508b0bfa12878d6d2093f2d80cd13c032e4af8c1b63604010f18b";
    const CT_RANDOM_CASCADE: &str =
        "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7057f374419c4fdc4aae3e6a494831e67db98e6ef20e3f00f27501fbaf827112c2df118fa802cc302a0f0e41019ab7084def2c80d";
    const CT_COUNTER_XCHACHA: &str =
        "432f81fce4584c0be14cc6e5641387f84f21c702fb8ce953256ab62e90e182ff7c3f16972f93fd002116bb28f25953f67e36778c";
    const CT_ONCE_XCHACHA: &str =
        "dcfa76956289816bc5e41abf0f0d43a07692602aa44ed867e5421a97187b1ad78ccf902cacf91dcbd2ec283a99493f2df5fe5a66";
    const CT_STREAM_XCHACHA: &str =
        "2717fd1b0c76f9cfc533f9d2d889b397bc1b652e9e7b9516de9ab9036ec2fd6d6922f875519c602a5babc293a8dcfa92d6ddbc08";
    const CT_RANDOM_XCHACHA: &str =
        "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b78494ed04dd0b3c9f06777616d067b1dfd539de95fe3e71946370dd4615618170954cae1be1ef20bff322e4663db30db37832c4ac";
    const CT_COUNTER_AESSIV: &str =
        "b6428725da3ab72ca71605ae5c0e93fd9e8729215eff00d1c88dbd2c03649960632d737c8a28c82812d90adce5a5db899b5fc2f5";
    const CT_ONCE_AESSIV: &str =
        "19754ce11f6f7c0b3f2a6e68d6071b89ca5bc6e120eaa5f27abfcd4d665063a158d4445966e6cdfbbdbda70cd0b9a231c6723beb";
    const CT_STREAM_AESSIV: &str =
        "3a1730a82622c9fa5643863251efd4a1a7be525fa81cab1eafb6e1f28ba4468cee67db6285e7b013c843744981c95bee60f8c331";
    const CT_RANDOM_AESSIV: &str =
        "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b73d3191633bfc5e7b4f2e1f014cc1bc0031597c9889986cbc8935957fc5cc4de57a70444ca42a879dac9caddb3fd42dc7a6f1d431";
    const CT_COUNTER_CHACHA: &str =
        "975ab325c73f69cf5e2633291eb9d7384a7b4893189aa5e581391226b9ed33f89dea2a5784b25164f3e542f1ec3c52d9ef4ecc4c";
    const CT_ONCE_CHACHA: &str =
        "e8bcf516fa6c771c812493cfa955fa9e059d2bb3d741f6123c1ff2418e1989bca08f3bb25605ca74ccfb6eb32acb9512b0881117";
    const CT_STREAM_CHACHA: &str =
        "ec640920f6c0d61458ac45df2ebb8968cd9c6475c61709308d78759d20e2628e035178396d8825f71d4d3e22d230852e06c6eab6";
    const CT_RANDOM_CHACHA: &str =
        "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7223b95e1ec2a0be7b7d29680de01fcb9821bf7f60d038302c4f50cc9d014d367329279047dc242a790b308e83f196f270eb904a8";
    const CT_STREAM_LAST_CASCADE: &str =
        "1ce90b5ed61e3be892e424ae37b90dca8041e4ccffd3b8b12707a4b6abb1e346a09202e1de2a5ff3452270d8d91de6de73fe0dcf";
    const CT_COUNTER_EMPTY_CASCADE: &str =
        "d142338bc004cb1b2b3261467341acf9989fc4bb5e14fe94091664cdaeaa276f";
    const CT_COUNTER_EMPTY_CHACHA: &str =
        "f43bc046a65b0cef35485c5e7099b6564691a5ababc6f49b9d153ddff034d97f";

    fn is_auth_failed<T>(result: &Result<T, CryptError>) -> bool {
        matches!(result, Err(CryptError::AuthenticationFailed))
    }

    fn is_invalid<T>(result: &Result<T, CryptError>) -> bool {
        matches!(result, Err(CryptError::InvalidParameters))
    }

    /// Seal with one raw primitive and return `ct ‖ tag`.
    fn raw_seal(
        prim: Prim,
        key: &[u8; 32],
        n24: &[u8; 24],
        aad: &[u8],
        pt: &[u8],
    ) -> Result<Vec<u8>, CryptError> {
        let mut buf = pt.to_vec();
        let tag = aead_seal(prim, key, n24, aad, &mut buf)?;
        buf.extend_from_slice(&tag);
        Ok(buf)
    }

    fn flip(bytes: &[u8], pos: usize, mask: u8) -> Result<Vec<u8>, CryptError> {
        let mut out = bytes.to_vec();
        *out.get_mut(pos).ok_or_else(missing)? ^= mask;
        Ok(out)
    }

    fn pattern(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8 ^ 0x5a).collect()
    }

    #[test]
    fn scheme_ids_layers_and_order() {
        for scheme in ALL {
            assert_eq!(Scheme::from_id(scheme.id()), Some(scheme));
        }
        assert_eq!(Scheme::ChaCha20Poly1305.id(), 1);
        assert_eq!(Scheme::Aes256GcmSiv.id(), 2);
        assert_eq!(Scheme::XChaCha20Poly1305.id(), 3);
        assert_eq!(Scheme::Cascade.id(), 4);
        assert_eq!(Scheme::from_id(0), None);
        for id in 5u8..=255 {
            assert_eq!(Scheme::from_id(id), None);
        }
        assert_eq!(Scheme::Cascade.layers(), 2);
        assert_eq!(Scheme::XChaCha20Poly1305.layers(), 1);
        assert_eq!(Scheme::Aes256GcmSiv.layers(), 1);
        assert_eq!(Scheme::ChaCha20Poly1305.layers(), 1);
        assert!(Scheme::ChaCha20Poly1305 < Scheme::Aes256GcmSiv);
        assert!(Scheme::Aes256GcmSiv < Scheme::XChaCha20Poly1305);
        assert!(Scheme::XChaCha20Poly1305 < Scheme::Cascade);
    }

    #[test]
    fn maximal_suite_ids() {
        assert_eq!(MAXIMAL_SUITE.kem().id(), 0x0051);
        assert_eq!(MAXIMAL_SUITE.kdf().id(), 0x0011);
        assert_eq!(MAXIMAL_SUITE.aead().id(), 0xff02);
        assert_eq!(MAXIMAL_SUITE.kem(), DEFAULT_SUITE.kem());
        assert_ne!(MAXIMAL_SUITE, DEFAULT_SUITE);
    }

    #[test]
    fn cascade_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Cascade>();
        assert_send_sync::<CascadeNonce>();
        assert_send_sync::<Scheme>();
    }

    #[test]
    fn kat_xchacha_draft_a31() -> TestResult {
        // draft-irtf-cfrg-xchacha-03 A.3.1.
        let key: [u8; 32] = <[u8; 32]>::try_from(
            hex::decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")?
                .as_slice(),
        )
        .map_err(|_| missing())?;
        let nonce: [u8; 24] = <[u8; 24]>::try_from(
            hex::decode("404142434445464748494a4b4c4d4e4f5051525354555657")?.as_slice(),
        )
        .map_err(|_| missing())?;
        let aad = hex::decode("50515253c0c1c2c3c4c5c6c7")?;
        let pt = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let ct = raw_seal(Prim::XChaCha, &key, &nonce, &aad, pt)?;
        assert_eq!(ct.len(), pt.len() + 16);
        assert_eq!(
            hex::encode(ct.get(..16).ok_or_else(missing)?),
            "bd6d179d3e83d43b9576579493c0e939"
        );
        assert_eq!(
            hex::encode(ct.get(ct.len() - 16..).ok_or_else(missing)?),
            "c0875924c1c7987947deafd8780acf49"
        );
        // And back through the opening primitive.
        let (body, tag) = ct.split_at(ct.len() - 16);
        let tag = <[u8; 16]>::try_from(tag).map_err(|_| missing())?;
        let mut buf = body.to_vec();
        aead_open(Prim::XChaCha, &key, &nonce, &aad, &mut buf, &tag)?;
        assert_eq!(buf.as_slice(), pt.as_slice());
        Ok(())
    }

    #[test]
    fn kat_aes_gcm_siv_rfc8452() -> TestResult {
        // RFC 8452 Appendix C.2 (AES-256-GCM-SIV): key 0x01 ‖ 0^31, nonce 0x03 ‖ 0^11.
        let mut key = [0u8; 32];
        *key.first_mut().ok_or_else(missing)? = 1;
        let mut n24 = [0u8; 24];
        *n24.first_mut().ok_or_else(missing)? = 3;
        let empty = raw_seal(Prim::AesSiv, &key, &n24, b"", b"")?;
        assert_eq!(
            hex::encode(empty.as_slice()),
            "07f5f4169bbf55a8400cd47ea6fd400f"
        );
        let eight = raw_seal(
            Prim::AesSiv,
            &key,
            &n24,
            b"",
            &hex::decode("0100000000000000")?,
        )?;
        assert_eq!(
            hex::encode(eight.as_slice()),
            "c2ef328e5c71c83b843122130f7364b761e0b97427e3df28"
        );
        let twelve = raw_seal(
            Prim::AesSiv,
            &key,
            &n24,
            b"",
            &hex::decode("010000000000000000000000")?,
        )?;
        assert_eq!(
            hex::encode(twelve.as_slice()),
            "9aab2aeb3faa0a34aea8e2b18ca50da9ae6559e48fd10f6e5c9ca17e"
        );
        Ok(())
    }

    #[test]
    fn kat_subkeys_and_ctx_layout() -> TestResult {
        let ctx = build_ctx(Scheme::Cascade, DOMAIN)?;
        let mut expected = vec![4u8, 0, 0, 0, 24];
        expected.extend_from_slice(DOMAIN);
        assert_eq!(ctx, expected);

        let cascade = Cascade::new(Scheme::Cascade, &ROOT, DOMAIN)?;
        assert_eq!(hex::encode(*cascade.first), K_IN);
        let k_out = cascade.outer.as_ref().ok_or_else(missing)?;
        assert_eq!(hex::encode(**k_out), K_OUT);
        // k_one(Cascade) is never used by the scheme; it must be independent.
        let k_one = derive_key(&ROOT, L_ONE, &ctx)?;
        assert_eq!(hex::encode(*k_one), K_ONE_CASCADE);
        assert_ne!(hex::encode(*k_one), K_IN);
        assert_ne!(hex::encode(*k_one), K_OUT);

        for (scheme, expected) in [
            (Scheme::XChaCha20Poly1305, K_ONE_XCHACHA),
            (Scheme::Aes256GcmSiv, K_ONE_AESSIV),
            (Scheme::ChaCha20Poly1305, K_ONE_CHACHA),
        ] {
            let c = Cascade::new(scheme, &ROOT, DOMAIN)?;
            assert_eq!(hex::encode(*c.first), expected);
            assert!(c.outer.is_none());
        }
        Ok(())
    }

    #[test]
    fn kat_nonces() -> TestResult {
        let once = Cascade::new(Scheme::Cascade, &ROOT, DOMAIN)?;
        assert_eq!(hex::encode(*once.once_nonce), NONCE_ONCE_CASCADE);
        assert_eq!(hex::encode(COUNTER.to_n24()?), NONCE_COUNTER);
        let stream = CascadeNonce::Stream {
            prefix: PREFIX,
            index: 3,
            last: false,
        };
        assert_eq!(hex::encode(stream.to_n24()?), NONCE_STREAM_FALSE);
        let last = CascadeNonce::Stream {
            prefix: PREFIX,
            index: 3,
            last: true,
        };
        assert_eq!(hex::encode(last.to_n24()?), NONCE_STREAM_TRUE);
        Ok(())
    }

    #[test]
    fn kat_cascade_vectors() -> TestResult {
        let stream = CascadeNonce::Stream {
            prefix: PREFIX,
            index: 3,
            last: false,
        };
        let last = CascadeNonce::Stream {
            prefix: PREFIX,
            index: 3,
            last: true,
        };
        let table = [
            (
                Scheme::Cascade,
                CT_COUNTER_CASCADE,
                CT_ONCE_CASCADE,
                CT_STREAM_CASCADE,
                CT_RANDOM_CASCADE,
            ),
            (
                Scheme::XChaCha20Poly1305,
                CT_COUNTER_XCHACHA,
                CT_ONCE_XCHACHA,
                CT_STREAM_XCHACHA,
                CT_RANDOM_XCHACHA,
            ),
            (
                Scheme::Aes256GcmSiv,
                CT_COUNTER_AESSIV,
                CT_ONCE_AESSIV,
                CT_STREAM_AESSIV,
                CT_RANDOM_AESSIV,
            ),
            (
                Scheme::ChaCha20Poly1305,
                CT_COUNTER_CHACHA,
                CT_ONCE_CHACHA,
                CT_STREAM_CHACHA,
                CT_RANDOM_CHACHA,
            ),
        ];
        for (scheme, counter, once, stream_ct, random) in table {
            let c = Cascade::new(scheme, &ROOT, DOMAIN)?;
            let ct = c.seal(&COUNTER, AAD, PT)?;
            assert_eq!(ct.len(), PT.len() + 32);
            assert_eq!(hex::encode(ct.as_slice()), counter, "counter {scheme:?}");
            assert_eq!(c.open(&COUNTER, AAD, &ct)?.as_slice(), PT);

            let ct = c.seal(&stream, AAD, PT)?;
            assert_eq!(hex::encode(ct.as_slice()), stream_ct, "stream {scheme:?}");
            assert_eq!(c.open(&stream, AAD, &ct)?.as_slice(), PT);

            let ct = Cascade::new(scheme, &ROOT, DOMAIN)?.seal_once(AAD, PT)?;
            assert_eq!(hex::encode(ct.as_slice()), once, "once {scheme:?}");
            assert_eq!(c.open_once(AAD, &ct)?.as_slice(), PT);

            let sealed = seal_random_with(scheme, &ROOT, DOMAIN, &RANDOM_N24, AAD, PT)?;
            assert_eq!(hex::encode(sealed.as_slice()), random, "random {scheme:?}");
            assert_eq!(
                open_random(scheme, &ROOT, DOMAIN, AAD, &sealed)?.as_slice(),
                PT
            );
        }
        let c = Cascade::new(Scheme::Cascade, &ROOT, DOMAIN)?;
        let ct = c.seal(&last, AAD, PT)?;
        assert_eq!(hex::encode(ct.as_slice()), CT_STREAM_LAST_CASCADE);
        assert_eq!(c.open(&last, AAD, &ct)?.as_slice(), PT);
        // The final-chunk flag is part of the nonce: the same bytes do not open as non-final.
        assert!(is_auth_failed(&c.open(&stream, AAD, &ct)));

        let empty = c.seal(&COUNTER, AAD, b"")?;
        assert_eq!(hex::encode(empty.as_slice()), CT_COUNTER_EMPTY_CASCADE);
        assert_eq!(c.open(&COUNTER, AAD, &empty)?.len(), 0);
        let c1 = Cascade::new(Scheme::ChaCha20Poly1305, &ROOT, DOMAIN)?;
        let empty = c1.seal(&COUNTER, AAD, b"")?;
        assert_eq!(hex::encode(empty.as_slice()), CT_COUNTER_EMPTY_CHACHA);
        assert_eq!(c1.open(&COUNTER, AAD, &empty)?.len(), 0);
        Ok(())
    }

    #[test]
    fn cascade_matches_manual_composition() -> TestResult {
        // Rebuild the cascade with the allocating RustCrypto API (an independent
        // code path from the in-place helpers) and compare byte for byte.
        let c = Cascade::new(Scheme::Cascade, &ROOT, DOMAIN)?;
        let n24 = COUNTER.to_n24()?;
        let k_out = c.outer.as_ref().ok_or_else(missing)?;
        let aad_in = layer_aad(A_IN, &c.ctx, AAD)?;
        let aad_out = layer_aad(A_OUT, &c.ctx, AAD)?;
        let siv = Aes256GcmSiv::new_from_slice(c.first.as_slice()).map_err(|_| missing())?;
        let n12_bytes =
            <[u8; 12]>::try_from(n24.get(..12).ok_or_else(missing)?).map_err(|_| missing())?;
        let n12: &SivNonce = (&n12_bytes).into();
        let inner = siv
            .encrypt(
                n12,
                Payload {
                    msg: PT,
                    aad: &aad_in,
                },
            )
            .map_err(|_| missing())?;
        assert_eq!(inner.len(), PT.len() + 16);
        let xc = XChaCha20Poly1305::new_from_slice(k_out.as_slice()).map_err(|_| missing())?;
        let xnonce: &XNonce = (&n24).into();
        let outer = xc
            .encrypt(
                xnonce,
                Payload {
                    msg: &inner,
                    aad: &aad_out,
                },
            )
            .map_err(|_| missing())?;
        assert_eq!(outer, c.seal(&COUNTER, AAD, PT)?);
        Ok(())
    }

    #[test]
    fn every_scheme_is_pt_plus_32() -> TestResult {
        for scheme in ALL {
            let c = Cascade::new(scheme, &ROOT, DOMAIN)?;
            for len in [0usize, 1, 15, 16, 17, 31, 32, 33, 255, 4096, 65536] {
                let pt = pattern(len);
                let ct = c.seal(&COUNTER, AAD, &pt)?;
                assert_eq!(ct.len(), len + CASCADE_OVERHEAD, "{scheme:?} {len}");
                assert_eq!(c.open(&COUNTER, AAD, &ct)?.as_slice(), pt.as_slice());
            }
        }
        Ok(())
    }

    #[test]
    fn bit_flip_in_any_byte_fails() -> TestResult {
        for scheme in ALL {
            let c = Cascade::new(scheme, &ROOT, DOMAIN)?;
            let ct = c.seal(&COUNTER, AAD, PT)?;
            for pos in 0..ct.len() {
                for mask in [0x01u8, 0x80] {
                    let bad = flip(&ct, pos, mask)?;
                    assert!(
                        is_auth_failed(&c.open(&COUNTER, AAD, &bad)),
                        "{scheme:?} byte {pos} mask {mask:#x}"
                    );
                }
            }
        }
        Ok(())
    }

    #[test]
    fn truncation_and_extension_fail() -> TestResult {
        for scheme in ALL {
            let c = Cascade::new(scheme, &ROOT, DOMAIN)?;
            let ct = c.seal(&COUNTER, AAD, PT)?;
            for cut in 1..=ct.len() {
                let short = ct.get(..ct.len() - cut).ok_or_else(missing)?;
                assert!(
                    is_auth_failed(&c.open(&COUNTER, AAD, short)),
                    "{scheme:?} cut {cut}"
                );
            }
            let mut longer = ct.clone();
            longer.push(0);
            assert!(is_auth_failed(&c.open(&COUNTER, AAD, &longer)));
            assert!(is_auth_failed(&c.open(&COUNTER, AAD, b"")));
        }
        Ok(())
    }

    #[test]
    fn wrong_aad_domain_scheme_nonce_root_fail() -> TestResult {
        for scheme in ALL {
            let c = Cascade::new(scheme, &ROOT, DOMAIN)?;
            let ct = c.seal(&COUNTER, AAD, PT)?;
            assert!(is_auth_failed(&c.open(&COUNTER, b"aad-2", &ct)));
            assert!(is_auth_failed(&c.open(&COUNTER, b"", &ct)));
            let other_nonce = CascadeNonce::Counter { domain: 1, n: 6 };
            assert!(is_auth_failed(&c.open(&other_nonce, AAD, &ct)));
            let other_dir = CascadeNonce::Counter { domain: 2, n: 5 };
            assert!(is_auth_failed(&c.open(&other_dir, AAD, &ct)));

            let other_domain = Cascade::new(scheme, &ROOT, b"crypt_guard/test/other")?;
            assert!(is_auth_failed(&other_domain.open(&COUNTER, AAD, &ct)));

            let mut other_root = ROOT;
            *other_root.first_mut().ok_or_else(missing)? ^= 1;
            let other = Cascade::new(scheme, &other_root, DOMAIN)?;
            assert!(is_auth_failed(&other.open(&COUNTER, AAD, &ct)));
        }
        Ok(())
    }

    #[test]
    fn scheme_flip_cannot_open() -> TestResult {
        for a in ALL {
            let ct = Cascade::new(a, &ROOT, DOMAIN)?.seal(&COUNTER, AAD, PT)?;
            for b in ALL {
                if a == b {
                    continue;
                }
                let opener = Cascade::new(b, &ROOT, DOMAIN)?;
                assert!(
                    is_auth_failed(&opener.open(&COUNTER, AAD, &ct)),
                    "{a:?} opened as {b:?}"
                );
            }
        }
        Ok(())
    }

    #[test]
    fn single_layer_filler_must_be_zero() -> TestResult {
        let n24 = COUNTER.to_n24()?;
        for (scheme, prim) in [
            (Scheme::ChaCha20Poly1305, Prim::ChaCha),
            (Scheme::Aes256GcmSiv, Prim::AesSiv),
            (Scheme::XChaCha20Poly1305, Prim::XChaCha),
        ] {
            let c = Cascade::new(scheme, &ROOT, DOMAIN)?;
            let aad_one = layer_aad(A_ONE, &c.ctx, AAD)?;
            // Control: the zero filler is exactly what `seal` produces.
            let mut body = PT.to_vec();
            body.extend_from_slice(&[0u8; 16]);
            let good = raw_seal(prim, &c.first, &n24, &aad_one, &body)?;
            assert_eq!(good, c.seal(&COUNTER, AAD, PT)?);
            assert_eq!(c.open(&COUNTER, AAD, &good)?.as_slice(), PT);
            // A correctly authenticated ciphertext with a non-zero filler is refused.
            let mut dirty = PT.to_vec();
            dirty.extend_from_slice(&[0u8; 15]);
            dirty.push(1);
            let bad = raw_seal(prim, &c.first, &n24, &aad_one, &dirty)?;
            assert!(is_auth_failed(&c.open(&COUNTER, AAD, &bad)), "{scheme:?}");
        }
        Ok(())
    }

    #[test]
    fn layer_removal_and_swap_are_rejected() -> TestResult {
        let c = Cascade::new(Scheme::Cascade, &ROOT, DOMAIN)?;
        let n24 = COUNTER.to_n24()?;
        let k_out = c.outer.as_ref().ok_or_else(missing)?;
        let aad_in = layer_aad(A_IN, &c.ctx, AAD)?;
        let aad_out = layer_aad(A_OUT, &c.ctx, AAD)?;

        // Outer layer removed: only the inner ciphertext, padded to the same length.
        let mut inner_only = raw_seal(Prim::AesSiv, &c.first, &n24, &aad_in, PT)?;
        inner_only.extend_from_slice(&[0u8; 16]);
        assert_eq!(inner_only.len(), PT.len() + 32);
        assert!(is_auth_failed(&c.open(&COUNTER, AAD, &inner_only)));

        // Inner layer removed: only the outer layer over `pt ‖ 0^16`.
        let mut body = PT.to_vec();
        body.extend_from_slice(&[0u8; 16]);
        let outer_only = raw_seal(Prim::XChaCha, k_out, &n24, &aad_out, &body)?;
        assert_eq!(outer_only.len(), PT.len() + 32);
        assert!(is_auth_failed(&c.open(&COUNTER, AAD, &outer_only)));

        // Layers swapped: XChaCha20 inside, AES-GCM-SIV outside.
        let swapped_inner = raw_seal(Prim::XChaCha, k_out, &n24, &aad_out, PT)?;
        let swapped = raw_seal(Prim::AesSiv, &c.first, &n24, &aad_in, &swapped_inner)?;
        assert!(is_auth_failed(&c.open(&COUNTER, AAD, &swapped)));

        // Keys swapped: the right layers with each other's keys.
        let wrong_inner = raw_seal(Prim::AesSiv, k_out, &n24, &aad_in, PT)?;
        let wrong = raw_seal(Prim::XChaCha, &c.first, &n24, &aad_out, &wrong_inner)?;
        assert!(is_auth_failed(&c.open(&COUNTER, AAD, &wrong)));

        // Control: the correct order with the correct keys is `seal`.
        let inner = raw_seal(Prim::AesSiv, &c.first, &n24, &aad_in, PT)?;
        let right = raw_seal(Prim::XChaCha, k_out, &n24, &aad_out, &inner)?;
        assert_eq!(right, c.seal(&COUNTER, AAD, PT)?);
        Ok(())
    }

    #[test]
    fn counter_nonce_matches_session_layout() -> TestResult {
        // `dir ‖ 000 ‖ seq u64 BE` followed by 12 zero bytes.
        let n = CascadeNonce::Counter {
            domain: 0x7f,
            n: 0x0102_0304_0506_0708,
        }
        .to_n24()?;
        assert_eq!(
            n,
            [0x7f, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        let first = short_nonce(&n)?;
        assert_eq!(first, &[0x7fu8, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8]);
        Ok(())
    }

    #[test]
    fn stream_nonce_matches_pq_stream_layout() -> TestResult {
        // The first 12 bytes are exactly the pq_stream nonce `prefix ‖ counter ‖ flag`,
        // so a single-layer ChaCha20 chunk equals the pq_stream chunk under the same key and AAD.
        let key = [0x33u8; 32];
        let prefix = [1u8, 2, 3, 4, 5, 6, 7];
        let chunk = pattern(100);
        let mut enc = StreamEncryptor::new(&key, prefix)?;
        for _ in 0..3 {
            enc.encrypt_next(&chunk, b"file")?;
        }
        let expected_next = enc.encrypt_next(&chunk, b"file")?;
        let mut enc = StreamEncryptor::new(&key, prefix)?;
        for _ in 0..3 {
            enc.encrypt_next(&chunk, b"file")?;
        }
        let expected_last = enc.encrypt_last(&chunk, b"file")?;

        for (last, expected) in [(false, expected_next), (true, expected_last)] {
            let n24 = CascadeNonce::Stream {
                prefix,
                index: 3,
                last,
            }
            .to_n24()?;
            assert_eq!(n24.get(..7), Some(prefix.as_slice()));
            assert_eq!(n24.get(7..11), Some(3u32.to_be_bytes().as_slice()));
            assert_eq!(n24.get(11), Some(&u8::from(last)));
            assert!(n24.get(12..).ok_or_else(missing)?.iter().all(|b| *b == 0));
            let ct = raw_seal(Prim::ChaCha, &key, &n24, b"file", &chunk)?;
            assert_eq!(ct, expected, "last {last}");
        }
        Ok(())
    }

    #[test]
    fn stream_prefix_zero_rejected() -> TestResult {
        let zero = CascadeNonce::Stream {
            prefix: [0u8; 7],
            index: 0,
            last: false,
        };
        for scheme in ALL {
            let c = Cascade::new(scheme, &ROOT, DOMAIN)?;
            assert!(is_invalid(&c.seal(&zero, AAD, PT)));
            assert!(is_invalid(&c.open(&zero, AAD, &[0u8; 64])));
            let mut buf = vec![0u8; PT.len() + 32];
            assert!(is_invalid(&c.seal_in_place(&zero, AAD, &mut buf, PT.len())));
            assert!(is_invalid(&c.open_in_place(&zero, AAD, &mut buf)));
        }
        Ok(())
    }

    #[test]
    fn stream_indices_and_flags_give_distinct_ciphertexts() -> TestResult {
        let c = Cascade::new(Scheme::XChaCha20Poly1305, &ROOT, DOMAIN)?;
        let mut seen = Vec::new();
        for index in 0..4u32 {
            for last in [false, true] {
                let nonce = CascadeNonce::Stream {
                    prefix: PREFIX,
                    index,
                    last,
                };
                let ct = c.seal(&nonce, AAD, PT)?;
                assert!(!seen.contains(&ct));
                // A chunk opens only at its own position.
                for other in 0..4u32 {
                    let wrong = CascadeNonce::Stream {
                        prefix: PREFIX,
                        index: other,
                        last,
                    };
                    assert_eq!(c.open(&wrong, AAD, &ct).is_ok(), other == index);
                }
                seen.push(ct);
            }
        }
        Ok(())
    }

    #[test]
    fn zero_root_and_empty_domain_rejected() {
        for scheme in ALL {
            assert!(is_invalid(&Cascade::new(scheme, &[0u8; 32], DOMAIN)));
            assert!(is_invalid(&Cascade::new(scheme, &ROOT, b"")));
            assert!(is_invalid(&seal_random(
                scheme, &[0u8; 32], DOMAIN, AAD, PT
            )));
            assert!(is_invalid(&seal_random(scheme, &ROOT, b"", AAD, PT)));
            assert!(is_invalid(&open_random(
                scheme, &[0u8; 32], DOMAIN, AAD, PT
            )));
            assert!(is_invalid(&open_random(scheme, &ROOT, b"", AAD, PT)));
        }
    }

    #[test]
    fn debug_is_redacted() -> TestResult {
        for scheme in ALL {
            let c = Cascade::new(scheme, &ROOT, DOMAIN)?;
            let text = format!("{c:?}");
            assert!(text.contains("Cascade"));
            assert!(text.contains(&format!("{scheme:?}")));
            for secret in [
                hex::encode(ROOT),
                hex::encode(*c.first),
                hex::encode(*c.once_nonce),
                K_IN.to_owned(),
                K_OUT.to_owned(),
            ] {
                assert!(!text.contains(&secret), "{text}");
            }
            assert!(!text.contains("1, 2, 3"));
        }
        Ok(())
    }

    #[test]
    fn once_nonce_is_per_scheme_and_domain() -> TestResult {
        let mut nonces: Vec<[u8; NONCE_LEN]> = Vec::new();
        for scheme in ALL {
            for domain in [DOMAIN, b"crypt_guard/test/other".as_slice()] {
                let c = Cascade::new(scheme, &ROOT, domain)?;
                let nonce: [u8; NONCE_LEN] = *c.once_nonce;
                assert!(!nonces.contains(&nonce));
                nonces.push(nonce);
            }
        }
        // Deterministic for one (root, scheme, domain): the root key is a one-shot key.
        let a = Cascade::new(Scheme::Cascade, &ROOT, DOMAIN)?.seal_once(AAD, PT)?;
        let b = Cascade::new(Scheme::Cascade, &ROOT, DOMAIN)?.seal_once(AAD, PT)?;
        assert_eq!(a, b);
        let c = Cascade::new(Scheme::Cascade, &ROOT, DOMAIN)?.seal_once(b"aad-2", PT)?;
        assert_ne!(a, c);
        // Opening may be repeated.
        let opener = Cascade::new(Scheme::Cascade, &ROOT, DOMAIN)?;
        assert_eq!(opener.open_once(AAD, &a)?.as_slice(), PT);
        assert_eq!(opener.open_once(AAD, &a)?.as_slice(), PT);
        assert!(is_auth_failed(&opener.open_once(b"aad-2", &a)));
        Ok(())
    }

    #[test]
    fn in_place_equals_allocating() -> TestResult {
        for scheme in ALL {
            let c = Cascade::new(scheme, &ROOT, DOMAIN)?;
            for len in [0usize, 1, 16, 100, 4097] {
                let pt = pattern(len);
                let expected = c.seal(&COUNTER, AAD, &pt)?;

                let mut buf = pt.clone();
                buf.resize(len + CASCADE_OVERHEAD, 0xee); // scratch content is ignored
                c.seal_in_place(&COUNTER, AAD, &mut buf, len)?;
                assert_eq!(buf, expected, "{scheme:?} {len}");
                let plain = c.open_in_place(&COUNTER, AAD, &mut buf)?;
                assert_eq!(&*plain, pt.as_slice());

                let expected_once = Cascade::new(scheme, &ROOT, DOMAIN)?.seal_once(AAD, &pt)?;
                let mut buf = pt.clone();
                buf.resize(len + CASCADE_OVERHEAD, 0xee);
                Cascade::new(scheme, &ROOT, DOMAIN)?.seal_once_in_place(AAD, &mut buf, len)?;
                assert_eq!(buf, expected_once, "{scheme:?} {len}");
                let plain = c.open_once_in_place(AAD, &mut buf)?;
                assert_eq!(&*plain, pt.as_slice());
            }
        }
        Ok(())
    }

    #[test]
    fn in_place_rejects_wrong_buffer_length() -> TestResult {
        let c = Cascade::new(Scheme::Cascade, &ROOT, DOMAIN)?;
        for len in [0usize, 5, PT.len() + 31, PT.len() + 33] {
            let mut buf = vec![0u8; len];
            assert!(is_invalid(&c.seal_in_place(
                &COUNTER,
                AAD,
                &mut buf,
                PT.len()
            )));
        }
        let mut buf = vec![0u8; 40];
        assert!(is_invalid(&c.seal_in_place(
            &COUNTER,
            AAD,
            &mut buf,
            usize::MAX
        )));
        Ok(())
    }

    #[test]
    fn open_in_place_wipes_the_buffer_on_failure() -> TestResult {
        for scheme in ALL {
            let c = Cascade::new(scheme, &ROOT, DOMAIN)?;
            let ct = c.seal(&COUNTER, AAD, PT)?;
            // Tampered tag.
            let mut buf = flip(&ct, ct.len() - 1, 1)?;
            assert!(is_auth_failed(&c.open_in_place(&COUNTER, AAD, &mut buf)));
            assert!(buf.iter().all(|b| *b == 0), "{scheme:?} tag");
            // Wrong AAD on a valid ciphertext: no plaintext may remain.
            let mut buf = ct.clone();
            assert!(is_auth_failed(
                &c.open_in_place(&COUNTER, b"nope", &mut buf)
            ));
            assert!(buf.iter().all(|b| *b == 0), "{scheme:?} aad");
            // Too short.
            let mut buf = vec![0xffu8; 31];
            assert!(is_auth_failed(&c.open_in_place(&COUNTER, AAD, &mut buf)));
            assert!(buf.iter().all(|b| *b == 0));
        }
        Ok(())
    }

    #[test]
    fn single_layer_filler_failure_wipes_the_plaintext() -> TestResult {
        let n24 = COUNTER.to_n24()?;
        let c = Cascade::new(Scheme::XChaCha20Poly1305, &ROOT, DOMAIN)?;
        let aad_one = layer_aad(A_ONE, &c.ctx, AAD)?;
        let mut dirty = PT.to_vec();
        dirty.extend_from_slice(&[7u8; 16]);
        let mut bad = raw_seal(Prim::XChaCha, &c.first, &n24, &aad_one, &dirty)?;
        assert!(is_auth_failed(&c.open_in_place(&COUNTER, AAD, &mut bad)));
        assert!(bad.iter().all(|b| *b == 0));
        Ok(())
    }

    #[test]
    fn random_mode_roundtrip_and_distinct_keys() -> TestResult {
        for scheme in ALL {
            let a = seal_random(scheme, &ROOT, DOMAIN, AAD, PT)?;
            let b = seal_random(scheme, &ROOT, DOMAIN, AAD, PT)?;
            assert_eq!(a.len(), PT.len() + NONCE_LEN + CASCADE_OVERHEAD);
            assert_ne!(a, b, "{scheme:?}: nonce must be fresh");
            assert_eq!(open_random(scheme, &ROOT, DOMAIN, AAD, &a)?.as_slice(), PT);
            assert_eq!(open_random(scheme, &ROOT, DOMAIN, AAD, &b)?.as_slice(), PT);

            assert!(is_auth_failed(&open_random(
                scheme,
                &ROOT,
                b"crypt_guard/test/other",
                AAD,
                &a
            )));
            assert!(is_auth_failed(&open_random(
                scheme, &ROOT, DOMAIN, b"aad-2", &a
            )));
            for other in ALL {
                if other != scheme {
                    assert!(is_auth_failed(&open_random(other, &ROOT, DOMAIN, AAD, &a)));
                }
            }
            for pos in 0..a.len() {
                let bad = flip(&a, pos, 0x01)?;
                assert!(
                    is_auth_failed(&open_random(scheme, &ROOT, DOMAIN, AAD, &bad)),
                    "{scheme:?} {pos}"
                );
            }
            for cut in 1..=a.len() {
                let short = a.get(..a.len() - cut).ok_or_else(missing)?;
                assert!(is_auth_failed(&open_random(
                    scheme, &ROOT, DOMAIN, AAD, short
                )));
            }
        }
        // Different nonces give independent keys (and a nonce swap does not open).
        let other_n24 = [0x55u8; NONCE_LEN];
        let d1 = random_domain(DOMAIN, &RANDOM_N24)?;
        let d2 = random_domain(DOMAIN, &other_n24)?;
        let c1 = Cascade::new(Scheme::Cascade, &ROOT, &d1)?;
        let c2 = Cascade::new(Scheme::Cascade, &ROOT, &d2)?;
        assert_ne!(*c1.first, *c2.first);
        assert_ne!(*c1.once_nonce, *c2.once_nonce);
        let s1 = seal_random_with(Scheme::Cascade, &ROOT, DOMAIN, &RANDOM_N24, AAD, PT)?;
        let mut spliced = other_n24.to_vec();
        spliced.extend_from_slice(s1.get(NONCE_LEN..).ok_or_else(missing)?);
        assert!(is_auth_failed(&open_random(
            Scheme::Cascade,
            &ROOT,
            DOMAIN,
            AAD,
            &spliced
        )));
        Ok(())
    }

    fn maximal_keys() -> Result<crate::pq_hpke::RecipientKeyPair, CryptError> {
        Ok(derive_recipient_key_pair(
            MAXIMAL_SUITE.kem(),
            &[0x5au8; 32],
        )?)
    }

    const INFO: &[u8] = b"cascade/test/info";
    const ENV_AAD: &[u8] = b"cascade/test/aad";

    #[test]
    fn envelope_roundtrip_and_len() -> TestResult {
        let keys = maximal_keys()?;
        assert_eq!(keys.public_key().as_bytes().len(), 1665);
        for len in [0usize, 1, 34, 1000] {
            let pt = pattern(len);
            let envelope = seal_envelope(MAXIMAL_SUITE, keys.public_key(), INFO, ENV_AAD, &pt)?;
            assert_eq!(envelope.suite(), MAXIMAL_SUITE);
            assert_eq!(envelope.encapsulation().len(), 1665);
            assert_eq!(envelope.ciphertext().len(), len + CASCADE_OVERHEAD);
            let bytes = envelope.try_to_bytes()?;
            assert_eq!(bytes.len(), 20 + 1665 + len + 32);
            // CGH3, version 1, kem 0x0051, kdf 0x0011, aead 0xff02.
            assert_eq!(bytes.get(..4), Some(b"CGH3".as_slice()));
            assert_eq!(bytes.get(4..6), Some([0u8, 1].as_slice()));
            assert_eq!(
                bytes.get(6..12),
                Some([0x00u8, 0x51, 0x00, 0x11, 0xff, 0x02].as_slice())
            );
            let parsed = HpkeEnvelope::from_bytes(&bytes)?;
            let plain = open_envelope(MAXIMAL_SUITE, &parsed, keys.private_key(), INFO, ENV_AAD)?;
            assert_eq!(plain.as_slice(), pt.as_slice());
        }
        Ok(())
    }

    #[test]
    fn envelope_suite_pinned_before_decapsulation() -> TestResult {
        let keys = maximal_keys()?;
        // A DEFAULT_SUITE envelope (valid hybrid KEM, ChaCha20-Poly1305) is refused.
        let default = HpkeEnvelope::seal(DEFAULT_SUITE, keys.public_key(), INFO, ENV_AAD, PT)?;
        assert!(is_auth_failed(&open_envelope(
            MAXIMAL_SUITE,
            &default,
            keys.private_key(),
            INFO,
            ENV_AAD
        )));
        // A header claiming another KEM/KDF/AEAD never reaches the key.
        let envelope = seal_envelope(MAXIMAL_SUITE, keys.public_key(), INFO, ENV_AAD, PT)?;
        let bytes = envelope.try_to_bytes()?;
        for (range, replacement) in [
            (6usize..8, [0x00u8, 0x42]), // ML-KEM-1024 without the hybrid part
            (8..10, [0x00, 0x03]),       // HKDF-SHA512
            (10..12, [0x00, 0x03]),      // ChaCha20-Poly1305
            (10..12, [0xff, 0x01]),      // AES-256-GCM-SIV
        ] {
            let mut forged = bytes.clone();
            let slot = forged.get_mut(range).ok_or_else(missing)?;
            slot.copy_from_slice(&replacement);
            // Either the container does not parse or the pin rejects it; never anything else.
            if let Ok(parsed) = HpkeEnvelope::from_bytes(&forged) {
                assert!(is_auth_failed(&open_envelope(
                    MAXIMAL_SUITE,
                    &parsed,
                    keys.private_key(),
                    INFO,
                    ENV_AAD
                )));
            }
        }
        // The pinned suite itself must be Maximal; that is a local configuration error.
        for other in [
            DEFAULT_SUITE,
            Suite::new(Kem::MlKem1024P384, Kdf::Shake256, Aead::Aes256GcmSiv),
            Suite::new(Kem::MlKem768, Kdf::Shake256, Aead::XChaCha20Poly1305),
        ] {
            assert!(matches!(
                open_envelope(other, &envelope, keys.private_key(), INFO, ENV_AAD),
                Err(CryptError::UnsupportedAlgorithm)
            ));
            assert!(matches!(
                seal_envelope(other, keys.public_key(), INFO, ENV_AAD, PT),
                Err(CryptError::UnsupportedAlgorithm)
            ));
        }
        Ok(())
    }

    #[test]
    fn envelope_open_error_is_opaque() -> TestResult {
        let keys = maximal_keys()?;
        let other = derive_recipient_key_pair(MAXIMAL_SUITE.kem(), &[0x6bu8; 32])?;
        let envelope = seal_envelope(MAXIMAL_SUITE, keys.public_key(), INFO, ENV_AAD, PT)?;
        let open = |e: &HpkeEnvelope, key: &RecipientPrivateKey, info: &[u8], aad: &[u8]| {
            open_envelope(MAXIMAL_SUITE, e, key, info, aad)
        };
        assert!(is_auth_failed(&open(
            &envelope,
            other.private_key(),
            INFO,
            ENV_AAD
        )));
        assert!(is_auth_failed(&open(
            &envelope,
            keys.private_key(),
            b"other-info",
            ENV_AAD
        )));
        assert!(is_auth_failed(&open(
            &envelope,
            keys.private_key(),
            INFO,
            b"other-aad"
        )));
        assert!(is_auth_failed(&open(
            &envelope,
            keys.private_key(),
            INFO,
            b""
        )));

        let bytes = envelope.try_to_bytes()?;
        let enc_len = envelope.encapsulation().len();
        let last = bytes.len() - 1;
        for pos in [
            20,                // first byte of the ML-KEM part of enc
            20 + 1000,         // inside the ML-KEM ciphertext
            20 + 1568,         // first byte of the P-384 point
            20 + enc_len - 1,  // last byte of enc
            20 + enc_len,      // first ciphertext byte
            20 + enc_len + 10, // inside the ciphertext
            last - 16,         // inside the outer tag
            last,              // last tag byte
        ] {
            let forged = HpkeEnvelope::from_bytes(&flip(&bytes, pos, 0x01)?)?;
            assert!(
                is_auth_failed(&open(&forged, keys.private_key(), INFO, ENV_AAD)),
                "pos {pos}"
            );
        }
        // Truncated and extended ciphertext (rebuilt container with matching lengths).
        let ct = envelope.ciphertext();
        let enc = Encapsulation::from_bytes(MAXIMAL_SUITE.kem(), envelope.encapsulation())?;
        for variant in [
            ct.get(..ct.len() - 1).ok_or_else(missing)?.to_vec(),
            ct.get(..16).ok_or_else(missing)?.to_vec(),
            Vec::new(),
            [ct, [0u8].as_slice()].concat(),
        ] {
            let forged = HpkeEnvelope::new(MAXIMAL_SUITE, &enc, variant);
            assert!(is_auth_failed(&open(
                &forged,
                keys.private_key(),
                INFO,
                ENV_AAD
            )));
        }
        Ok(())
    }

    #[test]
    fn envelope_is_not_a_plain_maximal_hpke_envelope() -> TestResult {
        let keys = maximal_keys()?;
        // A normal Maximal envelope over `pt` is not a cascade envelope.
        let plain = HpkeEnvelope::seal(MAXIMAL_SUITE, keys.public_key(), INFO, ENV_AAD, PT)?;
        assert!(is_auth_failed(&open_envelope(
            MAXIMAL_SUITE,
            &plain,
            keys.private_key(),
            INFO,
            ENV_AAD
        )));
        // The cascade envelope is a normal Maximal container whose plaintext is `|pt| + 16`
        // bytes of inner ciphertext, reachable only with the outer-layer AAD.
        let envelope = seal_envelope(MAXIMAL_SUITE, keys.public_key(), INFO, ENV_AAD, PT)?;
        assert!(envelope.open(keys.private_key(), INFO, ENV_AAD).is_err());
        let outer_aad = hpke_aad(H_AAD_OUT, ENV_AAD)?;
        let inner = envelope.open_zeroizing(keys.private_key(), INFO, &outer_aad)?;
        assert_eq!(inner.len(), PT.len() + 16);
        assert_ne!(inner.get(..PT.len()), Some(PT));
        Ok(())
    }

    #[test]
    fn envelope_deterministic_matches_manual_composition() -> TestResult {
        let keys = maximal_keys()?;
        let ikm_e = [0x11u8; 80];
        let (enc, ctx) =
            setup_base_sender_with_ikm_e(MAXIMAL_SUITE, keys.public_key(), INFO, &ikm_e)?;
        assert_eq!(enc.as_bytes().len(), 1665);
        let mut sealer = CascadeSealer::new(ctx)?;
        let sealed = sealer.seal(ENV_AAD, PT)?;
        assert_eq!(sealed.len(), PT.len() + 32);

        // Second identical context: same encapsulation, same exporter secrets.
        let (enc2, mut ctx2) =
            setup_base_sender_with_ikm_e(MAXIMAL_SUITE, keys.public_key(), INFO, &ikm_e)?;
        assert_eq!(enc.as_bytes(), enc2.as_bytes());
        let k_in = ctx2.export_zeroizing(H_KEY, 32)?;
        let n_in = ctx2.export_zeroizing(H_NONCE, 12)?;
        assert_eq!(k_in.len(), 32);
        assert_eq!(n_in.len(), 12);
        assert_ne!(k_in.get(..12), n_in.get(..12));

        // Inner layer with the allocating RustCrypto API, outer layer with the HPKE seal.
        let n12 = <[u8; 12]>::try_from(n_in.as_slice()).map_err(|_| missing())?;
        let nonce: &SivNonce = (&n12).into();
        let siv = Aes256GcmSiv::new_from_slice(k_in.as_slice()).map_err(|_| missing())?;
        let inner = siv
            .encrypt(
                nonce,
                Payload {
                    msg: PT,
                    aad: &hpke_aad(H_AAD_IN, ENV_AAD)?,
                },
            )
            .map_err(|_| missing())?;
        assert_eq!(inner.len(), PT.len() + 16);
        let outer = ctx2.seal(&hpke_aad(H_AAD_OUT, ENV_AAD)?, &inner)?;
        assert_eq!(outer, sealed);

        let envelope = HpkeEnvelope::new(MAXIMAL_SUITE, &enc, sealed);
        let bytes = envelope.try_to_bytes()?;
        assert_eq!(bytes.len(), 20 + 1665 + PT.len() + 32);
        let plain = open_envelope(MAXIMAL_SUITE, &envelope, keys.private_key(), INFO, ENV_AAD)?;
        assert_eq!(plain.as_slice(), PT);
        Ok(())
    }

    #[test]
    fn envelope_inner_key_is_independent_of_the_outer_layer() -> TestResult {
        let keys = maximal_keys()?;
        let ikm_e = [0x22u8; 80];
        let (enc, ctx) =
            setup_base_sender_with_ikm_e(MAXIMAL_SUITE, keys.public_key(), INFO, &ikm_e)?;
        let mut receiver =
            setup_base_receiver_inner(MAXIMAL_SUITE, keys.private_key(), &enc, INFO)?;
        // Both sides export the same inner key and nonce; different contexts differ.
        let k_s = ctx.export_zeroizing(H_KEY, 32)?;
        let k_r = receiver.export_zeroizing(H_KEY, 32)?;
        assert_eq!(k_s.as_slice(), k_r.as_slice());
        let n_s = ctx.export_zeroizing(H_NONCE, 12)?;
        let n_r = receiver.export_zeroizing(H_NONCE, 12)?;
        assert_eq!(n_s.as_slice(), n_r.as_slice());
        let other = ctx.export_zeroizing(b"app/other", 32)?;
        assert_ne!(k_s.as_slice(), other.as_slice());
        // Knowing the outer layer alone (the HPKE key schedule) is not enough: opening the
        // container with the outer AAD yields only the inner ciphertext.
        let mut sealer = CascadeSealer::new(ctx)?;
        let sealed = sealer.seal(ENV_AAD, PT)?;
        let inner = receiver.open(&hpke_aad(H_AAD_OUT, ENV_AAD)?, &sealed)?;
        assert_eq!(inner.len(), PT.len() + 16);
        assert_ne!(inner.get(..PT.len()), Some(PT));
        Ok(())
    }

    fn pure_suite(aead: Aead) -> Suite {
        Suite::new(Kem::MlKem768, Kdf::Shake256, aead)
    }

    #[test]
    fn context_sealer_requires_xchacha() -> TestResult {
        let keys = generate_recipient_key_pair(Kem::MlKem768)?;
        for aead in [Aead::ChaCha20Poly1305, Aead::Aes256GcmSiv] {
            let (enc, ctx) = setup_base_sender_inner(pure_suite(aead), keys.public_key(), INFO)?;
            assert!(matches!(
                CascadeSealer::new(ctx),
                Err(CryptError::UnsupportedAlgorithm)
            ));
            let rctx = setup_base_receiver_inner(pure_suite(aead), keys.private_key(), &enc, INFO)?;
            assert!(matches!(
                CascadeOpener::new(rctx),
                Err(CryptError::UnsupportedAlgorithm)
            ));
        }
        Ok(())
    }

    #[test]
    fn context_sealer_is_single_shot() -> TestResult {
        let keys = generate_recipient_key_pair(Kem::MlKem768)?;
        let suite = pure_suite(Aead::XChaCha20Poly1305);
        let (enc, ctx) = setup_base_sender_inner(suite, keys.public_key(), INFO)?;
        let mut sealer = CascadeSealer::new(ctx)?;
        let first = sealer.seal(ENV_AAD, PT)?;
        assert!(is_invalid(&sealer.seal(ENV_AAD, PT)));
        assert!(is_invalid(&sealer.seal(b"other", b"other")));
        assert!(format!("{sealer:?}").contains("sealed: true"));
        // The first message is intact.
        let rctx = setup_base_receiver_inner(suite, keys.private_key(), &enc, INFO)?;
        let mut opener = CascadeOpener::new(rctx)?;
        assert_eq!(opener.open(ENV_AAD, &first)?.as_slice(), PT);
        Ok(())
    }

    #[test]
    fn context_sealer_rejects_cascade_export_labels() -> TestResult {
        let keys = generate_recipient_key_pair(Kem::MlKem768)?;
        let suite = pure_suite(Aead::XChaCha20Poly1305);
        let (enc, ctx) = setup_base_sender_inner(suite, keys.public_key(), INFO)?;
        let sealer = CascadeSealer::new(ctx)?;
        let rctx = setup_base_receiver_inner(suite, keys.private_key(), &enc, INFO)?;
        let opener = CascadeOpener::new(rctx)?;
        let reserved: [&[u8]; 5] = [
            H_KEY,
            H_NONCE,
            RESERVED_EXPORT_PREFIX,
            b"crypt_guard/v3/cascade/anything",
            b"crypt_guard/v3/cascade/hpke/inner-key-2",
        ];
        for label in reserved {
            assert!(is_invalid(&sealer.export_zeroizing(label, 32)), "{label:?}");
            assert!(is_invalid(&opener.export_zeroizing(label, 32)), "{label:?}");
        }
        // Everything else is passed through and agrees on both sides.
        for label in [
            b"comnet/anon/response".as_slice(),
            b"crypt_guard/v3/cascade".as_slice(),
            b"app/x".as_slice(),
        ] {
            let s = sealer.export_zeroizing(label, 32)?;
            let r = opener.export_zeroizing(label, 32)?;
            assert_eq!(s.as_slice(), r.as_slice());
            assert_eq!(s.len(), 32);
        }
        Ok(())
    }

    #[test]
    fn context_opener_locks_only_after_success() -> TestResult {
        let keys = generate_recipient_key_pair(Kem::MlKem768)?;
        let suite = pure_suite(Aead::XChaCha20Poly1305);
        let (enc, ctx) = setup_base_sender_inner(suite, keys.public_key(), INFO)?;
        let mut sealer = CascadeSealer::new(ctx)?;
        let sealed = sealer.seal(ENV_AAD, PT)?;
        let rctx = setup_base_receiver_inner(suite, keys.private_key(), &enc, INFO)?;
        let mut opener = CascadeOpener::new(rctx)?;
        // Failed attempts do not lock (and do not desynchronize the context).
        assert!(is_auth_failed(&opener.open(b"wrong-aad", &sealed)));
        assert!(is_auth_failed(&opener.open(
            ENV_AAD,
            sealed.get(..sealed.len() - 1).ok_or_else(missing)?
        )));
        assert!(is_auth_failed(&opener.open(ENV_AAD, &flip(&sealed, 3, 1)?)));
        assert!(format!("{opener:?}").contains("opened: false"));
        // The genuine message opens once.
        assert_eq!(opener.open(ENV_AAD, &sealed)?.as_slice(), PT);
        assert!(format!("{opener:?}").contains("opened: true"));
        // Afterwards the opener is locked, even for the identical message.
        assert!(is_auth_failed(&opener.open(ENV_AAD, &sealed)));
        Ok(())
    }

    #[test]
    fn context_opener_rejects_an_inner_forgery_and_locks() -> TestResult {
        // A sender that knows the outer key but not the inner key can produce a valid outer
        // layer around garbage; the opener rejects it and, since the HPKE sequence advanced,
        // stays locked.
        let keys = generate_recipient_key_pair(Kem::MlKem768)?;
        let suite = pure_suite(Aead::XChaCha20Poly1305);
        let (enc, mut raw_sender) = setup_base_sender_inner(suite, keys.public_key(), INFO)?;
        let garbage = pattern(PT.len() + 16);
        let forged = raw_sender.seal(&hpke_aad(H_AAD_OUT, ENV_AAD)?, &garbage)?;
        let rctx = setup_base_receiver_inner(suite, keys.private_key(), &enc, INFO)?;
        let mut opener = CascadeOpener::new(rctx)?;
        assert!(is_auth_failed(&opener.open(ENV_AAD, &forged)));
        assert!(format!("{opener:?}").contains("opened: true"));
        assert!(is_auth_failed(&opener.open(ENV_AAD, &forged)));
        Ok(())
    }

    #[test]
    fn envelope_aad_is_bound_and_seals_are_fresh() -> TestResult {
        // The AAD is bound in both layers: swapping only the AAD fails even when the
        // caller passes the other layer's expectation.
        let keys = maximal_keys()?;
        let a = seal_envelope(MAXIMAL_SUITE, keys.public_key(), INFO, b"aad-a", PT)?;
        assert!(is_auth_failed(&open_envelope(
            MAXIMAL_SUITE,
            &a,
            keys.private_key(),
            INFO,
            b"aad-b"
        )));
        assert_eq!(
            open_envelope(MAXIMAL_SUITE, &a, keys.private_key(), INFO, b"aad-a")?.as_slice(),
            PT
        );
        // Two seals of the same input differ (fresh encapsulation).
        let b = seal_envelope(MAXIMAL_SUITE, keys.public_key(), INFO, b"aad-a", PT)?;
        assert_ne!(a.try_to_bytes()?, b.try_to_bytes()?);
        Ok(())
    }
}
