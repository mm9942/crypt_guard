//! Typed newtypes for HKDF key schedule inputs and outputs.
//!
//! # Responsibility scope
//! All key-schedule material newtypes live here: salt, intermediate HMAC key, and session key.
//! Every secret-bearing type implements [`zeroize::ZeroizeOnDrop`].
//!
//! # Key types exported
//! - [`HkdfSalt`] — KDF salt (not secret; no zeroization required)
//! - [`HmacKey`] — intermediate HMAC key (`ZeroizeOnDrop`)
//! - [`SessionKey`] — final 32-byte session key (`ZeroizeOnDrop`)
//!
//! # Concurrency
//! All types are `Send + Sync`.
//!
//! # Examples
//! ```rust,no_run
//! use crypt_guard::kdf::types::{HkdfSalt, SessionKey};
//! let salt = HkdfSalt::from_bytes(vec![0u8; 32]);
//! let key = SessionKey::from_bytes([0u8; 32]);
//! assert_eq!(key.as_ref().len(), 32);
//! ```

use zeroize::ZeroizeOnDrop;

/// HKDF salt input.
///
/// # Description
/// Not secret material; the salt is often a random nonce or a fixed domain constant.
/// No zeroization performed on drop.
///
/// # Concurrency
/// `Send + Sync`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HkdfSalt(Vec<u8>);

impl HkdfSalt {
    /// Construct from arbitrary bytes.
    ///
    /// # Arguments
    /// - `bytes` (`Vec<u8>`): salt bytes.
    ///
    /// # Returns
    /// A new `HkdfSalt`.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Construct a zero-filled salt of the given length.
    ///
    /// # Arguments
    /// - `len` (`usize`): desired length in bytes.
    ///
    /// # Returns
    /// An `HkdfSalt` filled with `len` zero bytes (this is HKDF's "no salt" convention).
    pub fn zero(len: usize) -> Self {
        Self(vec![0u8; len])
    }
}

impl AsRef<[u8]> for HkdfSalt {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Intermediate HMAC key produced by the HKDF extract step.
///
/// # Description
/// This is the pseudorandom key (PRK) from `HKDF-Extract`. Secret-bearing; zeroized on drop.
///
/// # Concurrency
/// `Send + Sync`.
#[derive(ZeroizeOnDrop)]
pub struct HmacKey(Vec<u8>);

impl HmacKey {
    /// Construct from raw bytes.
    ///
    /// # Arguments
    /// - `bytes` (`Vec<u8>`): PRK bytes.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for HmacKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// 32-byte session key derived by HKDF-Expand.
///
/// # Description
/// The final output of the key schedule. Always 32 bytes (suitable for AES-256 and
/// XChaCha20-Poly1305). Secret-bearing; zeroized on drop.
///
/// # Concurrency
/// `Send + Sync`.
#[derive(ZeroizeOnDrop)]
pub struct SessionKey([u8; 32]);

impl SessionKey {
    /// Construct from a 32-byte array.
    ///
    /// # Arguments
    /// - `bytes` (`[u8; 32]`): the raw session key bytes.
    ///
    /// # Returns
    /// A new `SessionKey`.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for SessionKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
