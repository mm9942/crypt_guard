//! HKDF-SHA256 and HKDF-SHA512 key schedule with domain separation.
//!
//! # Responsibility scope
//! This module derives session keys from KEM shared secrets using HKDF (RFC 5869).
//! It owns the domain-separation label constants and the `derive_session_key` function.
//! Input validation and type conversion stay in this module; the caller never sees raw
//! arrays or output bytes — only the `SessionKey` newtype.
//!
//! # Key types exported
//! - [`derive_session_key`] — primary derivation function (SHA-256 backed)
//! - [`derive_session_key_sha512`] — SHA-512 backed variant
//! - Label constants: [`LABEL_XCHACHA20POLY1305`], [`LABEL_AESGCMSIV`], [`LABEL_GENERIC`]
//!
//! # Concurrency
//! All functions are pure (no shared state). `Send + Sync` trivially.
//!
//! # Errors
//! Returns [`CryptError::CustomError`] if the HKDF output length is invalid (>255 * HashLen).
//! In practice this never occurs because the output is always 32 bytes.
//!
//! # Examples
//! ```rust,no_run
//! use crypt_guard::kdf::{derive_session_key, LABEL_XCHACHA20POLY1305};
//! use crypt_guard::kdf::types::HkdfSalt;
//!
//! let shared_secret = vec![0u8; 32];
//! let salt = HkdfSalt::zero(32);
//! let session_key = derive_session_key(&shared_secret, &salt, LABEL_XCHACHA20POLY1305).unwrap();
//! assert_eq!(session_key.as_ref().len(), 32);
//! ```

use hkdf::Hkdf;
use sha2_011::{Sha256, Sha512};
use crate::error::CryptError;
use crate::kdf::types::{HkdfSalt, SessionKey};

/// Domain separation label for XChaCha20-Poly1305 AEAD.
///
/// # Description
/// Used as the `info` parameter to HKDF-Expand. Ensures that session keys derived for
/// different AEAD algorithms are independent even from the same shared secret.
pub const LABEL_XCHACHA20POLY1305: &[u8] =
    b"crypt_guard:v2:aead:xchacha20poly1305";

/// Domain separation label for AES-256-GCM-SIV AEAD.
pub const LABEL_AESGCMSIV: &[u8] =
    b"crypt_guard:v2:aead:aes-gcm-siv";

/// Domain separation label for AES-256-CBC (legacy HMAC mode).
pub const LABEL_AES: &[u8] =
    b"crypt_guard:v2:aead:aes-cbc-hmac";

/// Domain separation label for XChaCha20 (stream, no authentication).
pub const LABEL_XCHACHA20: &[u8] =
    b"crypt_guard:v2:aead:xchacha20";

/// Generic domain separation label for unnamed AEAD algorithms.
pub const LABEL_GENERIC: &[u8] =
    b"crypt_guard:v2:aead:generic";

/// Derive a 32-byte session key from a KEM shared secret using HKDF-SHA256.
///
/// # Description
/// Implements the key schedule: `HKDF(salt, shared_secret, label) → 32-byte SessionKey`.
/// The `label` parameter provides algorithm-level domain separation so that session keys
/// for different AEAD algorithms derived from the same shared secret are independent.
///
/// Use one of the provided label constants (`LABEL_*`) for known algorithm names, or
/// supply an arbitrary `b"crypt_guard:v2:aead:<your-alg>"` prefix for custom algorithms.
///
/// # Arguments
/// - `shared_secret` (`&[u8]`): the KEM shared secret bytes (IKM in HKDF terms).
/// - `salt` (`&HkdfSalt`): the HKDF salt (use `HkdfSalt::zero(32)` if no random salt is
///   available; HKDF handles the zero-salt case as specified in RFC 5869 §2.2).
/// - `label` (`&[u8]`): domain-separation context string (the `info` parameter).
///
/// # Returns
/// `Ok(SessionKey)` — a 32-byte zeroizing session key.
///
/// # Errors
/// - [`CryptError::CustomError`]: HKDF output length was invalid. Cannot occur in practice
///   because the output length is always 32 bytes.
///
/// # Concurrency
/// Pure function; no shared state. Safe to call concurrently.
///
/// # Examples
/// ```rust,no_run
/// use crypt_guard::kdf::{derive_session_key, LABEL_XCHACHA20POLY1305};
/// use crypt_guard::kdf::types::HkdfSalt;
///
/// let ss = vec![42u8; 32];
/// let salt = HkdfSalt::zero(32);
/// let key = derive_session_key(&ss, &salt, LABEL_XCHACHA20POLY1305).unwrap();
/// assert_eq!(key.as_ref().len(), 32);
/// ```
pub fn derive_session_key(
    shared_secret: &[u8],
    salt: &HkdfSalt,
    label: &[u8],
) -> Result<SessionKey, CryptError> {
    let hk = Hkdf::<Sha256>::new(Some(salt.as_ref()), shared_secret);
    let mut okm = [0u8; 32];
    hk.expand(label, &mut okm)
        .map_err(|_| CryptError::CustomError("HKDF expand failed: invalid output length".to_owned()))?;
    Ok(SessionKey::from_bytes(okm))
}

/// Derive a 32-byte session key from a KEM shared secret using HKDF-SHA512.
///
/// # Description
/// SHA-512 backed variant of [`derive_session_key`]. Preferred when the hash of the
/// shared secret must be 512-bit before truncation (e.g. for suite-level compliance).
/// The output is still 32 bytes (the first 256 bits of the 512-bit PRK).
///
/// # Arguments
/// - `shared_secret` (`&[u8]`): the KEM shared secret bytes.
/// - `salt` (`&HkdfSalt`): the HKDF salt.
/// - `label` (`&[u8]`): domain-separation context string.
///
/// # Returns
/// `Ok(SessionKey)` — a 32-byte zeroizing session key.
///
/// # Errors
/// - [`CryptError::CustomError`]: HKDF output length was invalid.
///
/// # Concurrency
/// Pure function; no shared state. Safe to call concurrently.
///
/// # Examples
/// ```rust,no_run
/// use crypt_guard::kdf::{derive_session_key_sha512, LABEL_AESGCMSIV};
/// use crypt_guard::kdf::types::HkdfSalt;
///
/// let ss = vec![42u8; 32];
/// let salt = HkdfSalt::zero(64);
/// let key = derive_session_key_sha512(&ss, &salt, LABEL_AESGCMSIV).unwrap();
/// assert_eq!(key.as_ref().len(), 32);
/// ```
pub fn derive_session_key_sha512(
    shared_secret: &[u8],
    salt: &HkdfSalt,
    label: &[u8],
) -> Result<SessionKey, CryptError> {
    let hk = Hkdf::<Sha512>::new(Some(salt.as_ref()), shared_secret);
    let mut okm = [0u8; 32];
    hk.expand(label, &mut okm)
        .map_err(|_| CryptError::CustomError("HKDF-SHA512 expand failed: invalid output length".to_owned()))?;
    Ok(SessionKey::from_bytes(okm))
}
